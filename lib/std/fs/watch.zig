// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const builtin = @import("builtin");
const event = std.event;
const assert = std.debug.assert;
const testing = std.testing;
const os = std.os;
const mem = std.mem;
const windows = os.windows;
const Loop = event.Loop;
const fd_t = os.fd_t;
const File = std.fs.File;
const Allocator = mem.Allocator;

const global_event_loop = Loop.instance orelse
    @compileError("std.fs.Watch currently only works with event-based I/O");

const WatchEventId = enum {
    CloseWrite,
    Delete,
};

const WatchEventError = error{
    UserResourceLimitReached,
    SystemResources,
    AccessDenied,
    Unexpected, // TODO remove this possibility
};

pub fn Watch(comptime V: type) type {
    return struct {
        channel: event.Channel(Event.Error!Event),
        os_data: OsData,
        allocator: *Allocator,

        const OsData = switch (builtin.os.tag) {
            // TODO https://github.com/ziglang/zig/issues/3778
            .macos, .freebsd, .netbsd, .dragonfly, .openbsd => KqOsData,
            .linux => LinuxOsData,
            .windows => WindowsOsData,

            else => @compileError("Unsupported OS"),
        };

        const KqOsData = struct {
            table_lock: event.Lock,
            file_table: FileTable,

            const FileTable = std.StringHashMapUnmanaged(*Put);
            const Put = struct {
                putter_frame: @Frame(kqPutEvents),
                cancelled: bool = false,
                value: V,
            };
        };

        const WindowsOsData = struct {
            table_lock: event.Lock,
            dir_table: DirTable,
            cancelled: bool = false,

            const DirTable = std.StringHashMapUnmanaged(*Dir);
            const FileTable = std.StringHashMapUnmanaged(V);

            const Dir = struct {
                putter_frame: @Frame(windowsDirReader),
                file_table: FileTable,
                dir_handle: os.windows.HANDLE,
            };
        };

        const LinuxOsData = struct {
            putter_frame: @Frame(linuxEventPutter),
            inotify_fd: i32,
            wd_table: WdTable,
            table_lock: event.Lock,
            cancelled: bool = false,

            const WdTable = std.AutoHashMapUnmanaged(i32, Dir);
            const FileTable = std.StringHashMapUnmanaged(V);

            const Dir = struct {
                dirname: []const u8,
                file_table: FileTable,
            };
        };

        const Self = @This();

        pub const Event = struct {
            id: Id,
            data: V,
            dirname: []const u8,
            basename: []const u8,

            pub const Id = WatchEventId;
            pub const Error = WatchEventError;
        };

        pub fn init(allocator: *Allocator, event_buf_count: usize) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            switch (builtin.os.tag) {
                .linux => {
                    const inotify_fd = try os.inotify_init1(os.linux.IN_NONBLOCK | os.linux.IN_CLOEXEC);
                    errdefer os.close(inotify_fd);

                    self.* = Self{
                        .allocator = allocator,
                        .channel = undefined,
                        .os_data = OsData{
                            .putter_frame = undefined,
                            .inotify_fd = inotify_fd,
                            .wd_table = OsData.WdTable.init(allocator),
                            .table_lock = event.Lock{},
                        },
                    };

                    var buf = try allocator.alloc(Event.Error!Event, event_buf_count);
                    self.channel.init(buf);
                    self.os_data.putter_frame = async self.linuxEventPutter();
                    return self;
                },

                .windows => {
                    self.* = Self{
                        .allocator = allocator,
                        .channel = undefined,
                        .os_data = OsData{
                            .table_lock = event.Lock{},
                            .dir_table = OsData.DirTable.init(allocator),
                        },
                    };

                    var buf = try allocator.alloc(Event.Error!Event, event_buf_count);
                    self.channel.init(buf);
                    return self;
                },

                .macos, .freebsd, .netbsd, .dragonfly, .openbsd => {
                    self.* = Self{
                        .allocator = allocator,
                        .channel = undefined,
                        .os_data = OsData{
                            .table_lock = event.Lock{},
                            .file_table = OsData.FileTable.init(allocator),
                        },
                    };

                    var buf = try allocator.alloc(Event.Error!Event, event_buf_count);
                    self.channel.init(buf);
                    return self;
                },
                else => @compileError("Unsupported OS"),
            }
        }

        pub fn deinit(self: *Self) void {
            switch (builtin.os.tag) {
                .macos, .freebsd, .netbsd, .dragonfly, .openbsd => {
                    var it = self.os_data.file_table.iterator();
                    while (it.next()) |entry| {
                        const key = entry.key_ptr.*;
                        const value = entry.value_ptr.*;
                        value.cancelled = true;
                        // @TODO Close the fd here?
                        await value.putter_frame;
                        self.allocator.free(key);
                        self.allocator.destroy(value);
                    }
                },
                .linux => {
                    self.os_data.cancelled = true;
                    {
                        // Remove all directory watches linuxEventPutter will take care of
                        // cleaning up the memory and closing the inotify fd.
                        var dir_it = self.os_data.wd_table.keyIterator();
                        while (dir_it.next()) |wd_key| {
                            const rc = os.linux.inotify_rm_watch(self.os_data.inotify_fd, wd_key.*);
                            // Errno can only be EBADF, EINVAL if either the inotify fs or the wd are invalid
                            std.debug.assert(rc == 0);
                        }
                    }
                    await self.os_data.putter_frame;
                },
                .windows => {
                    self.os_data.cancelled = true;
                    var dir_it = self.os_data.dir_table.iterator();
                    while (dir_it.next()) |dir_entry| {
                        if (windows.kernel32.CancelIoEx(dir_entry.value.dir_handle, null) != 0) {
                            // We canceled the pending ReadDirectoryChangesW operation, but our
                            // frame is still suspending, now waiting indefinitely.
                            // Thus, it is safe to resume it ourslves
                            resume dir_entry.value.putter_frame;
                        } else {
                            std.debug.assert(windows.kernel32.GetLastError() == .NOT_FOUND);
                            // We are at another suspend point, we can await safely for the
                            // function to exit the loop
                            await dir_entry.value.putter_frame;
                        }

                        self.allocator.free(dir_entry.key_ptr.*);
                        var file_it = dir_entry.value.file_table.keyIterator();
                        while (file_it.next()) |file_entry| {
                            self.allocator.free(file_entry.*);
                        }
                        dir_entry.value.file_table.deinit(self.allocator);
                        self.allocator.destroy(dir_entry.value_ptr.*);
                    }
                    self.os_data.dir_table.deinit(self.allocator);
                },
                else => @compileError("Unsupported OS"),
            }
            self.allocator.free(self.channel.buffer_nodes);
            self.channel.deinit();
            self.allocator.destroy(self);
        }

        pub fn addFile(self: *Self, file_path: []const u8, value: V) !?V {
            switch (builtin.os.tag) {
                .macos, .freebsd, .netbsd, .dragonfly, .openbsd => return addFileKEvent(self, file_path, value),
                .linux => return addFileLinux(self, file_path, value),
                .windows => return addFileWindows(self, file_path, value),
                else => @compileError("Unsupported OS"),
            }
        }

        fn addFileKEvent(self: *Self, file_path: []const u8, value: V) !?V {
            var realpath_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const realpath = try os.realpath(file_path, &realpath_buf);

            const held = self.os_data.table_lock.acquire();
            defer held.release();

            const gop = try self.os_data.file_table.getOrPut(self.allocator, realpath);
            errdefer assert(self.os_data.file_table.remove(realpath));
            if (gop.found_existing) {
                const prev_value = gop.value_ptr.value;
                gop.value_ptr.value = value;
                return prev_value;
            }

            gop.key_ptr.* = try self.allocator.dupe(u8, realpath);
            errdefer self.allocator.free(gop.key_ptr.*);
            gop.value_ptr.* = try self.allocator.create(OsData.Put);
            errdefer self.allocator.destroy(gop.value_ptr.*);
            gop.value_ptr.* = .{
                .putter_frame = undefined,
                .value = value,
            };

            // @TODO Can I close this fd and get an error from bsdWaitKev?
            const flags = if (comptime builtin.target.isDarwin()) os.O_SYMLINK | os.O_EVTONLY else 0;
            const fd = try os.open(realpath, flags, 0);
            gop.value_ptr.putter_frame = async self.kqPutEvents(fd, gop.key_ptr.*, gop.value_ptr.*);
            return null;
        }

        fn kqPutEvents(self: *Self, fd: os.fd_t, file_path: []const u8, put: *OsData.Put) void {
            global_event_loop.beginOneEvent();
            defer {
                global_event_loop.finishOneEvent();
                // @TODO: Remove this if we force close otherwise
                os.close(fd);
            }

            // We need to manually do a bsdWaitKev to access the fflags.
            var resume_node = event.Loop.ResumeNode.Basic{
                .base = .{
                    .id = .Basic,
                    .handle = @frame(),
                    .overlapped = event.Loop.ResumeNode.overlapped_init,
                },
                .kev = undefined,
            };

            var kevs = [1]os.Kevent{undefined};
            const kev = &kevs[0];

            while (!put.cancelled) {
                kev.* = os.Kevent{
                    .ident = @intCast(usize, fd),
                    .filter = os.EVFILT_VNODE,
                    .flags = os.EV_ADD | os.EV_ENABLE | os.EV_CLEAR | os.EV_ONESHOT |
                        os.NOTE_WRITE | os.NOTE_DELETE | os.NOTE_REVOKE,
                    .fflags = 0,
                    .data = 0,
                    .udata = @ptrToInt(&resume_node.base),
                };
                suspend {
                    global_event_loop.beginOneEvent();
                    errdefer global_event_loop.finishOneEvent();

                    const empty_kevs = &[0]os.Kevent{};
                    _ = os.kevent(global_event_loop.os_data.kqfd, &kevs, empty_kevs, null) catch |err| switch (err) {
                        error.EventNotFound,
                        error.ProcessNotFound,
                        error.Overflow,
                        => unreachable,
                        error.AccessDenied, error.SystemResources => |e| {
                            self.channel.put(e);
                            continue;
                        },
                    };
                }

                if (kev.flags & os.EV_ERROR != 0) {
                    self.channel.put(os.unexpectedErrno(os.errno(kev.data)));
                    continue;
                }

                if (kev.fflags & os.NOTE_DELETE != 0 or kev.fflags & os.NOTE_REVOKE != 0) {
                    self.channel.put(Self.Event{
                        .id = .Delete,
                        .data = put.value,
                        .dirname = std.fs.path.dirname(file_path) orelse "/",
                        .basename = std.fs.path.basename(file_path),
                    });
                } else if (kev.fflags & os.NOTE_WRITE != 0) {
                    self.channel.put(Self.Event{
                        .id = .CloseWrite,
                        .data = put.value,
                        .dirname = std.fs.path.dirname(file_path) orelse "/",
                        .basename = std.fs.path.basename(file_path),
                    });
                }
            }
        }

        fn addFileLinux(self: *Self, file_path: []const u8, value: V) !?V {
            const dirname = std.fs.path.dirname(file_path) orelse if (file_path[0] == '/') "/" else ".";
            const basename = std.fs.path.basename(file_path);

            const wd = try os.inotify_add_watch(
                self.os_data.inotify_fd,
                dirname,
                os.linux.IN_CLOSE_WRITE | os.linux.IN_ONLYDIR | os.linux.IN_DELETE | os.linux.IN_EXCL_UNLINK,
            );
            // wd is either a newly created watch or an existing one.

            const held = self.os_data.table_lock.acquire();
            defer held.release();

            const gop = try self.os_data.wd_table.getOrPut(self.allocator, wd);
            errdefer assert(self.os_data.wd_table.remove(wd));
            if (!gop.found_existing) {
                gop.value_ptr.* = OsData.Dir{
                    .dirname = try self.allocator.dupe(u8, dirname),
                    .file_table = OsData.FileTable.init(self.allocator),
                };
            }

            const dir = gop.value_ptr;
            const file_table_gop = try dir.file_table.getOrPut(self.allocator, basename);
            errdefer assert(dir.file_table.remove(basename));
            if (file_table_gop.found_existing) {
                const prev_value = file_table_gop.value_ptr.*;
                file_table_gop.value_ptr.* = value;
                return prev_value;
            } else {
                file_table_gop.key_ptr.* = try self.allocator.dupe(u8, basename);
                file_table_gop.value_ptr.* = value;
                return null;
            }
        }

        fn addFileWindows(self: *Self, file_path: []const u8, value: V) !?V {
            // TODO we might need to convert dirname and basename to canonical file paths ("short"?)
            const dirname = std.fs.path.dirname(file_path) orelse if (file_path[0] == '/') "/" else ".";
            var dirname_path_space: windows.PathSpace = undefined;
            dirname_path_space.len = try std.unicode.utf8ToUtf16Le(&dirname_path_space.data, dirname);
            dirname_path_space.data[dirname_path_space.len] = 0;

            const basename = std.fs.path.basename(file_path);
            var basename_path_space: windows.PathSpace = undefined;
            basename_path_space.len = try std.unicode.utf8ToUtf16Le(&basename_path_space.data, basename);
            basename_path_space.data[basename_path_space.len] = 0;

            const held = self.os_data.table_lock.acquire();
            defer held.release();

            const gop = try self.os_data.dir_table.getOrPut(self.allocator, dirname);
            errdefer assert(self.os_data.dir_table.remove(dirname));
            if (gop.found_existing) {
                const dir = gop.value_ptr.*;

                const file_gop = try dir.file_table.getOrPut(self.allocator, basename);
                errdefer assert(dir.file_table.remove(basename));
                if (file_gop.found_existing) {
                    const prev_value = file_gop.value_ptr.*;
                    file_gop.value_ptr.* = value;
                    return prev_value;
                } else {
                    file_gop.value_ptr.* = value;
                    file_gop.key_ptr.* = try self.allocator.dupe(u8, basename);
                    return null;
                }
            } else {
                const dir_handle = try windows.OpenFile(dirname_path_space.span(), .{
                    .dir = std.fs.cwd().fd,
                    .access_mask = windows.FILE_LIST_DIRECTORY,
                    .creation = windows.FILE_OPEN,
                    .io_mode = .evented,
                    .open_dir = true,
                });
                errdefer windows.CloseHandle(dir_handle);

                const dir = try self.allocator.create(OsData.Dir);
                errdefer self.allocator.destroy(dir);

                gop.key_ptr.* = try self.allocator.dupe(u8, dirname);
                errdefer self.allocator.free(gop.key_ptr.*);

                dir.* = OsData.Dir{
                    .file_table = OsData.FileTable.init(self.allocator),
                    .putter_frame = undefined,
                    .dir_handle = dir_handle,
                };
                gop.value_ptr.* = dir;
                try dir.file_table.put(self.allocator, try self.allocator.dupe(u8, basename), value);
                dir.putter_frame = async self.windowsDirReader(dir, gop.key_ptr.*);
                return null;
            }
        }

        fn windowsDirReader(self: *Self, dir: *OsData.Dir, dirname: []const u8) void {
            defer os.close(dir.dir_handle);
            var resume_node = Loop.ResumeNode.Basic{
                .base = Loop.ResumeNode{
                    .id = .Basic,
                    .handle = @frame(),
                    .overlapped = windows.OVERLAPPED{
                        .Internal = 0,
                        .InternalHigh = 0,
                        .DUMMYUNIONNAME = .{
                            .DUMMYSTRUCTNAME = .{
                                .Offset = 0,
                                .OffsetHigh = 0,
                            },
                        },
                        .hEvent = null,
                    },
                },
            };

            var event_buf: [4096]u8 align(@alignOf(windows.FILE_NOTIFY_INFORMATION)) = undefined;

            global_event_loop.beginOneEvent();
            defer global_event_loop.finishOneEvent();

            while (!self.os_data.cancelled) main_loop: {
                suspend {
                    _ = windows.kernel32.ReadDirectoryChangesW(
                        dir.dir_handle,
                        &event_buf,
                        event_buf.len,
                        windows.FALSE, // watch subtree
                        windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_DIR_NAME |
                            windows.FILE_NOTIFY_CHANGE_ATTRIBUTES | windows.FILE_NOTIFY_CHANGE_SIZE |
                            windows.FILE_NOTIFY_CHANGE_LAST_WRITE | windows.FILE_NOTIFY_CHANGE_LAST_ACCESS |
                            windows.FILE_NOTIFY_CHANGE_CREATION | windows.FILE_NOTIFY_CHANGE_SECURITY,
                        null, // number of bytes transferred (unused for async)
                        &resume_node.base.overlapped,
                        null, // completion routine - unused because we use IOCP
                    );
                }

                var bytes_transferred: windows.DWORD = undefined;
                if (windows.kernel32.GetOverlappedResult(
                    dir.dir_handle,
                    &resume_node.base.overlapped,
                    &bytes_transferred,
                    windows.FALSE,
                ) == 0) {
                    const potential_error = windows.kernel32.GetLastError();
                    const err = switch (potential_error) {
                        .OPERATION_ABORTED, .IO_INCOMPLETE => err_blk: {
                            if (self.os_data.cancelled)
                                break :main_loop
                            else
                                break :err_blk windows.unexpectedError(potential_error);
                        },
                        else => |err| windows.unexpectedError(err),
                    };
                    self.channel.put(err);
                } else {
                    var ptr: [*]u8 = &event_buf;
                    const end_ptr = ptr + bytes_transferred;
                    while (@ptrToInt(ptr) < @ptrToInt(end_ptr)) {
                        const ev = @ptrCast(*const windows.FILE_NOTIFY_INFORMATION, ptr);
                        const emit = switch (ev.Action) {
                            windows.FILE_ACTION_REMOVED => WatchEventId.Delete,
                            windows.FILE_ACTION_MODIFIED => .CloseWrite,
                            else => null,
                        };
                        if (emit) |id| {
                            const basename_ptr = @ptrCast([*]u16, ptr + @sizeOf(windows.FILE_NOTIFY_INFORMATION));
                            const basename_utf16le = basename_ptr[0 .. ev.FileNameLength / 2];
                            var basename_data: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                            const basename = basename_data[0 .. std.unicode.utf16leToUtf8(&basename_data, basename_utf16le) catch unreachable];

                            if (dir.file_table.getEntry(basename)) |entry| {
                                self.channel.put(Event{
                                    .id = id,
                                    .data = entry.value_ptr.*,
                                    .dirname = dirname,
                                    .basename = entry.key_ptr.*,
                                });
                            }
                        }

                        if (ev.NextEntryOffset == 0) break;
                        ptr = @alignCast(@alignOf(windows.FILE_NOTIFY_INFORMATION), ptr + ev.NextEntryOffset);
                    }
                }
            }
        }

        pub fn removeFile(self: *Self, file_path: []const u8) !?V {
            switch (builtin.os.tag) {
                .linux => {
                    const dirname = std.fs.path.dirname(file_path) orelse if (file_path[0] == '/') "/" else ".";
                    const basename = std.fs.path.basename(file_path);

                    const held = self.os_data.table_lock.acquire();
                    defer held.release();

                    const dir = self.os_data.wd_table.get(dirname) orelse return null;
                    if (dir.file_table.fetchRemove(basename)) |file_entry| {
                        self.allocator.free(file_entry.key);
                        return file_entry.value;
                    }
                    return null;
                },
                .windows => {
                    const dirname = std.fs.path.dirname(file_path) orelse if (file_path[0] == '/') "/" else ".";
                    const basename = std.fs.path.basename(file_path);

                    const held = self.os_data.table_lock.acquire();
                    defer held.release();

                    const dir = self.os_data.dir_table.get(dirname) orelse return null;
                    if (dir.file_table.fetchRemove(basename)) |file_entry| {
                        self.allocator.free(file_entry.key);
                        return file_entry.value;
                    }
                    return null;
                },
                .macos, .freebsd, .netbsd, .dragonfly, .openbsd => {
                    var realpath_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                    const realpath = try os.realpath(file_path, &realpath_buf);

                    const held = self.os_data.table_lock.acquire();
                    defer held.release();

                    const entry = self.os_data.file_table.getEntry(realpath) orelse return null;
                    entry.value_ptr.cancelled = true;
                    // @TODO Close the fd here?
                    await entry.value_ptr.putter_frame;
                    self.allocator.free(entry.key_ptr.*);
                    self.allocator.destroy(entry.value_ptr.*);

                    assert(self.os_data.file_table.remove(realpath));
                },
                else => @compileError("Unsupported OS"),
            }
        }

        fn linuxEventPutter(self: *Self) void {
            global_event_loop.beginOneEvent();

            defer {
                std.debug.assert(self.os_data.wd_table.count() == 0);
                self.os_data.wd_table.deinit(self.allocator);
                os.close(self.os_data.inotify_fd);
                self.allocator.free(self.channel.buffer_nodes);
                self.channel.deinit();
                global_event_loop.finishOneEvent();
            }

            var event_buf: [4096]u8 align(@alignOf(os.linux.inotify_event)) = undefined;

            while (!self.os_data.cancelled) {
                const bytes_read = global_event_loop.read(self.os_data.inotify_fd, &event_buf, false) catch unreachable;

                var ptr: [*]u8 = &event_buf;
                const end_ptr = ptr + bytes_read;
                while (@ptrToInt(ptr) < @ptrToInt(end_ptr)) {
                    const ev = @ptrCast(*const os.linux.inotify_event, ptr);
                    if (ev.mask & os.linux.IN_CLOSE_WRITE == os.linux.IN_CLOSE_WRITE) {
                        const basename_ptr = ptr + @sizeOf(os.linux.inotify_event);
                        const basename = std.mem.span(@ptrCast([*:0]u8, basename_ptr));

                        const dir = &self.os_data.wd_table.get(ev.wd).?;
                        if (dir.file_table.getEntry(basename)) |file_value| {
                            self.channel.put(Event{
                                .id = .CloseWrite,
                                .data = file_value.value_ptr.*,
                                .dirname = dir.dirname,
                                .basename = file_value.key_ptr.*,
                            });
                        }
                    } else if (ev.mask & os.linux.IN_IGNORED == os.linux.IN_IGNORED) {
                        // Directory watch was removed
                        const held = self.os_data.table_lock.acquire();
                        defer held.release();
                        if (self.os_data.wd_table.fetchRemove(ev.wd)) |wd_entry| {
                            var file_it = wd_entry.value.file_table.keyIterator();
                            while (file_it.next()) |file_entry| {
                                self.allocator.free(file_entry.*);
                            }
                            self.allocator.free(wd_entry.value.dirname);
                            wd_entry.value.file_table.deinit(self.allocator);
                        }
                    } else if (ev.mask & os.linux.IN_DELETE == os.linux.IN_DELETE) {
                        // File or directory was removed or deleted
                        const basename_ptr = ptr + @sizeOf(os.linux.inotify_event);
                        const basename = std.mem.span(@ptrCast([*:0]u8, basename_ptr));

                        const dir = &self.os_data.wd_table.get(ev.wd).?;
                        if (dir.file_table.getEntry(basename)) |file_value| {
                            self.channel.put(Event{
                                .id = .Delete,
                                .data = file_value.value_ptr.*,
                                .dirname = dir.dirname,
                                .basename = file_value.key_ptr.*,
                            });
                        }
                    }

                    ptr = @alignCast(@alignOf(os.linux.inotify_event), ptr + @sizeOf(os.linux.inotify_event) + ev.len);
                }
            }
        }
    };
}

const test_tmp_dir = "std_event_fs_test";

test "write a file, watch it, write it again, delete it" {
    if (!std.io.is_async) return error.SkipZigTest;
    // TODO https://github.com/ziglang/zig/issues/1908
    if (builtin.single_threaded) return error.SkipZigTest;

    try std.fs.cwd().makePath(test_tmp_dir);
    defer std.fs.cwd().deleteTree(test_tmp_dir) catch {};

    return testWriteWatchWriteDelete(std.testing.allocator);
}

fn testWriteWatchWriteDelete(allocator: *Allocator) !void {
    const file_path = try std.fs.path.join(allocator, &[_][]const u8{ test_tmp_dir, "file.txt" });
    defer allocator.free(file_path);

    const contents =
        \\line 1
        \\line 2
    ;
    const line2_offset = 7;

    // first just write then read the file
    try std.fs.cwd().writeFile(file_path, contents);

    const read_contents = try std.fs.cwd().readFileAlloc(allocator, file_path, 1024 * 1024);
    defer allocator.free(read_contents);
    try testing.expectEqualSlices(u8, contents, read_contents);

    // now watch the file
    var watch = try Watch(void).init(allocator, 0);
    defer watch.deinit();

    try testing.expect((try watch.addFile(file_path, {})) == null);

    var ev = async watch.channel.get();
    var ev_consumed = false;
    defer if (!ev_consumed) {
        _ = await ev;
    };

    // overwrite line 2
    const file = try std.fs.cwd().openFile(file_path, .{ .read = true, .write = true });
    {
        defer file.close();
        const write_contents = "lorem ipsum";
        var iovec = [_]os.iovec_const{.{
            .iov_base = write_contents,
            .iov_len = write_contents.len,
        }};
        _ = try file.pwritevAll(&iovec, line2_offset);
    }

    switch ((try await ev).id) {
        .CloseWrite => {
            ev_consumed = true;
        },
        .Delete => @panic("wrong event"),
    }

    const contents_updated = try std.fs.cwd().readFileAlloc(allocator, file_path, 1024 * 1024);
    defer allocator.free(contents_updated);

    try testing.expectEqualSlices(u8,
        \\line 1
        \\lorem ipsum
    , contents_updated);

    ev = async watch.channel.get();
    ev_consumed = false;

    try std.fs.cwd().deleteFile(file_path);
    switch ((try await ev).id) {
        .Delete => {
            ev_consumed = true;
        },
        .CloseWrite => @panic("wrong event"),
    }
}

// TODO Test: Add another file watch, remove the old file watch, get an event in the new
