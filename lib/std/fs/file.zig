// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const os = std.os;
const io = std.io;
const mem = std.mem;
const math = std.math;
const assert = std.debug.assert;
const windows = os.windows;
const Os = std.builtin.Os;
const maxInt = std.math.maxInt;
const is_windows = builtin.os.tag == .windows;

pub const File = struct {
    /// The OS-specific file descriptor or file handle.
    handle: os.fd_t,

    /// On some systems, such as Linux, file system file descriptors are incapable of non-blocking I/O.
    /// This forces us to perform asynchronous I/O on a dedicated thread, to achieve non-blocking
    /// file-system I/O. To do this, `File` must be aware of whether it is a file system file descriptor,
    /// or, more specifically, whether the I/O is always blocking.
    capable_io_mode: io.ModeOverride = io.default_mode,

    /// Furthermore, even when `std.io.mode` is async, it is still sometimes desirable to perform blocking I/O,
    /// although not by default. For example, when printing a stack trace to stderr.
    /// This field tracks both by acting as an overriding I/O mode. When not building in async I/O mode,
    /// the type only has the `.blocking` tag, making it a zero-bit type.
    intended_io_mode: io.ModeOverride = io.default_mode,

    pub const Mode = os.mode_t;
    pub const INode = os.ino_t;

    pub const Kind = enum {
        BlockDevice,
        CharacterDevice,
        Directory,
        NamedPipe,
        SymLink,
        File,
        UnixDomainSocket,
        Whiteout,
        Unknown,
    };

    pub const default_mode = switch (builtin.os.tag) {
        .windows => 0,
        .wasi => 0,
        else => 0o666,
    };

    pub const OpenError = error{
        SharingViolation,
        PathAlreadyExists,
        FileNotFound,
        AccessDenied,
        PipeBusy,
        NameTooLong,
        /// On Windows, file paths must be valid Unicode.
        InvalidUtf8,
        /// On Windows, file paths cannot contain these characters:
        /// '/', '*', '?', '"', '<', '>', '|'
        BadPathName,
        Unexpected,
    } || os.OpenError || os.FlockError;

    pub const Lock = enum { None, Shared, Exclusive };

    /// TODO https://github.com/ziglang/zig/issues/3802
    pub const OpenFlags = struct {
        read: bool = true,
        write: bool = false,

        /// Open the file with an advisory lock to coordinate with other processes
        /// accessing it at the same time. An exclusive lock will prevent other
        /// processes from acquiring a lock. A shared lock will prevent other
        /// processes from acquiring a exclusive lock, but does not prevent
        /// other process from getting their own shared locks.
        ///
        /// The lock is advisory, except on Linux in very specific cirsumstances[1].
        /// This means that a process that does not respect the locking API can still get access
        /// to the file, despite the lock.
        ///
        /// On these operating systems, the lock is acquired atomically with
        /// opening the file:
        /// * Darwin
        /// * DragonFlyBSD
        /// * FreeBSD
        /// * Haiku
        /// * NetBSD
        /// * OpenBSD
        /// On these operating systems, the lock is acquired via a separate syscall
        /// after opening the file:
        /// * Linux
        /// * Windows
        ///
        /// [1]: https://www.kernel.org/doc/Documentation/filesystems/mandatory-locking.txt
        lock: Lock = .None,

        /// Sets whether or not to wait until the file is locked to return. If set to true,
        /// `error.WouldBlock` will be returned. Otherwise, the file will wait until the file
        /// is available to proceed.
        /// In async I/O mode, non-blocking at the OS level is
        /// determined by `intended_io_mode`, and `true` means `error.WouldBlock` is returned,
        /// and `false` means `error.WouldBlock` is handled by the event loop.
        lock_nonblocking: bool = false,

        /// Setting this to `.blocking` prevents `O_NONBLOCK` from being passed even
        /// if `std.io.is_async`. It allows the use of `nosuspend` when calling functions
        /// related to opening the file, reading, writing, and locking.
        intended_io_mode: io.ModeOverride = io.default_mode,

        /// Set this to allow the opened file to automatically become the
        /// controlling TTY for the current process.
        allow_ctty: bool = false,
    };

    /// TODO https://github.com/ziglang/zig/issues/3802
    pub const CreateFlags = struct {
        /// Whether the file will be created with read access.
        read: bool = false,

        /// If the file already exists, and is a regular file, and the access
        /// mode allows writing, it will be truncated to length 0.
        truncate: bool = true,

        /// Ensures that this open call creates the file, otherwise causes
        /// `error.PathAlreadyExists` to be returned.
        exclusive: bool = false,

        /// Open the file with an advisory lock to coordinate with other processes
        /// accessing it at the same time. An exclusive lock will prevent other
        /// processes from acquiring a lock. A shared lock will prevent other
        /// processes from acquiring a exclusive lock, but does not prevent
        /// other process from getting their own shared locks.
        ///
        /// The lock is advisory, except on Linux in very specific cirsumstances[1].
        /// This means that a process that does not respect the locking API can still get access
        /// to the file, despite the lock.
        ///
        /// On these operating systems, the lock is acquired atomically with
        /// opening the file:
        /// * Darwin
        /// * DragonFlyBSD
        /// * FreeBSD
        /// * Haiku
        /// * NetBSD
        /// * OpenBSD
        /// On these operating systems, the lock is acquired via a separate syscall
        /// after opening the file:
        /// * Linux
        /// * Windows
        ///
        /// [1]: https://www.kernel.org/doc/Documentation/filesystems/mandatory-locking.txt
        lock: Lock = .None,

        /// Sets whether or not to wait until the file is locked to return. If set to true,
        /// `error.WouldBlock` will be returned. Otherwise, the file will wait until the file
        /// is available to proceed.
        /// In async I/O mode, non-blocking at the OS level is
        /// determined by `intended_io_mode`, and `true` means `error.WouldBlock` is returned,
        /// and `false` means `error.WouldBlock` is handled by the event loop.
        lock_nonblocking: bool = false,

        /// For POSIX systems this is the file system mode the file will
        /// be created with.
        mode: Mode = default_mode,

        /// Setting this to `.blocking` prevents `O_NONBLOCK` from being passed even
        /// if `std.io.is_async`. It allows the use of `nosuspend` when calling functions
        /// related to opening the file, reading, writing, and locking.
        intended_io_mode: io.ModeOverride = io.default_mode,
    };

    /// Upon success, the stream is in an uninitialized state. To continue using it,
    /// you must use the open() function.
    pub fn close(self: File) void {
        if (is_windows) {
            windows.CloseHandle(self.handle);
        } else if (self.capable_io_mode != self.intended_io_mode) {
            std.event.Loop.instance.?.close(self.handle);
        } else {
            os.close(self.handle);
        }
    }

    /// Test whether the file refers to a terminal.
    /// See also `supportsAnsiEscapeCodes`.
    pub fn isTty(self: File) bool {
        return os.isatty(self.handle);
    }

    /// Test whether ANSI escape codes will be treated as such.
    pub fn supportsAnsiEscapeCodes(self: File) bool {
        if (builtin.os.tag == .windows) {
            return os.isCygwinPty(self.handle);
        }
        if (builtin.os.tag == .wasi) {
            // WASI sanitizes stdout when fd is a tty so ANSI escape codes
            // will not be interpreted as actual cursor commands, and
            // stderr is always sanitized.
            return false;
        }
        if (self.isTty()) {
            if (self.handle == os.STDOUT_FILENO or self.handle == os.STDERR_FILENO) {
                // Use getenvC to workaround https://github.com/ziglang/zig/issues/3511
                if (os.getenvZ("TERM")) |term| {
                    if (std.mem.eql(u8, term, "dumb"))
                        return false;
                }
            }
            return true;
        }
        return false;
    }

    pub const SetEndPosError = os.TruncateError;

    /// Shrinks or expands the file.
    /// The file offset after this call is left unchanged.
    pub fn setEndPos(self: File, length: u64) SetEndPosError!void {
        try os.ftruncate(self.handle, length);
    }

    pub const SeekError = os.SeekError;

    /// Repositions read/write file offset relative to the current offset.
    /// TODO: integrate with async I/O
    pub fn seekBy(self: File, offset: i64) SeekError!void {
        return os.lseek_CUR(self.handle, offset);
    }

    /// Repositions read/write file offset relative to the end.
    /// TODO: integrate with async I/O
    pub fn seekFromEnd(self: File, offset: i64) SeekError!void {
        return os.lseek_END(self.handle, offset);
    }

    /// Repositions read/write file offset relative to the beginning.
    /// TODO: integrate with async I/O
    pub fn seekTo(self: File, offset: u64) SeekError!void {
        return os.lseek_SET(self.handle, offset);
    }

    pub const GetSeekPosError = os.SeekError || os.FStatError;

    /// TODO: integrate with async I/O
    pub fn getPos(self: File) GetSeekPosError!u64 {
        return os.lseek_CUR_get(self.handle);
    }

    /// TODO: integrate with async I/O
    pub fn getEndPos(self: File) GetSeekPosError!u64 {
        if (builtin.os.tag == .windows) {
            return windows.GetFileSizeEx(self.handle);
        }
        return (try self.stat()).size;
    }

    pub const ModeError = os.FStatError;

    /// TODO: integrate with async I/O
    pub fn mode(self: File) ModeError!Mode {
        if (builtin.os.tag == .windows) {
            return 0;
        }
        return (try self.stat()).mode;
    }

    pub const Stat = struct {
        /// A number that the system uses to point to the file metadata. This number is not guaranteed to be
        /// unique across time, as some file systems may reuse an inode after its file has been deleted.
        /// Some systems may change the inode of a file over time.
        ///
        /// On Linux, the inode is a structure that stores the metadata, and the inode _number_ is what
        /// you see here: the index number of the inode.
        ///
        /// The FileIndex on Windows is similar. It is a number for a file that is unique to each filesystem.
        inode: INode,
        size: u64,
        mode: Mode,
        kind: Kind,

        /// Access time in nanoseconds, relative to UTC 1970-01-01.
        atime: i128,
        /// Last modification time in nanoseconds, relative to UTC 1970-01-01.
        mtime: i128,
        /// Creation time in nanoseconds, relative to UTC 1970-01-01.
        ctime: i128,
    };

    pub const StatError = os.FStatError;

    /// TODO: integrate with async I/O
    pub fn stat(self: File) StatError!Stat {
        if (builtin.os.tag == .windows) {
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            var info: windows.FILE_ALL_INFORMATION = undefined;
            const rc = windows.ntdll.NtQueryInformationFile(self.handle, &io_status_block, &info, @sizeOf(windows.FILE_ALL_INFORMATION), .FileAllInformation);
            switch (rc) {
                .SUCCESS => {},
                .BUFFER_OVERFLOW => {},
                .INVALID_PARAMETER => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                else => return windows.unexpectedStatus(rc),
            }
            return Stat{
                .inode = info.InternalInformation.IndexNumber,
                .size = @bitCast(u64, info.StandardInformation.EndOfFile),
                .mode = 0,
                .kind = if (info.StandardInformation.Directory == 0) .File else .Directory,
                .atime = windows.fromSysTime(info.BasicInformation.LastAccessTime),
                .mtime = windows.fromSysTime(info.BasicInformation.LastWriteTime),
                .ctime = windows.fromSysTime(info.BasicInformation.CreationTime),
            };
        }

        const st = try os.fstat(self.handle);
        const atime = st.atime();
        const mtime = st.mtime();
        const ctime = st.ctime();
        return Stat{
            .inode = st.ino,
            .size = @bitCast(u64, st.size),
            .mode = st.mode,
            .kind = switch (builtin.os.tag) {
                .wasi => switch (st.filetype) {
                    os.FILETYPE_BLOCK_DEVICE => Kind.BlockDevice,
                    os.FILETYPE_CHARACTER_DEVICE => Kind.CharacterDevice,
                    os.FILETYPE_DIRECTORY => Kind.Directory,
                    os.FILETYPE_SYMBOLIC_LINK => Kind.SymLink,
                    os.FILETYPE_REGULAR_FILE => Kind.File,
                    os.FILETYPE_SOCKET_STREAM, os.FILETYPE_SOCKET_DGRAM => Kind.UnixDomainSocket,
                    else => Kind.Unknown,
                },
                else => switch (st.mode & os.S_IFMT) {
                    os.S_IFBLK => Kind.BlockDevice,
                    os.S_IFCHR => Kind.CharacterDevice,
                    os.S_IFDIR => Kind.Directory,
                    os.S_IFIFO => Kind.NamedPipe,
                    os.S_IFLNK => Kind.SymLink,
                    os.S_IFREG => Kind.File,
                    os.S_IFSOCK => Kind.UnixDomainSocket,
                    else => Kind.Unknown,
                },
            },
            .atime = @as(i128, atime.tv_sec) * std.time.ns_per_s + atime.tv_nsec,
            .mtime = @as(i128, mtime.tv_sec) * std.time.ns_per_s + mtime.tv_nsec,
            .ctime = @as(i128, ctime.tv_sec) * std.time.ns_per_s + ctime.tv_nsec,
        };
    }

    pub const UpdateTimesError = os.FutimensError || windows.SetFileTimeError;

    /// The underlying file system may have a different granularity than nanoseconds,
    /// and therefore this function cannot guarantee any precision will be stored.
    /// Further, the maximum value is limited by the system ABI. When a value is provided
    /// that exceeds this range, the value is clamped to the maximum.
    /// TODO: integrate with async I/O
    pub fn updateTimes(
        self: File,
        /// access timestamp in nanoseconds
        atime: i128,
        /// last modification timestamp in nanoseconds
        mtime: i128,
    ) UpdateTimesError!void {
        if (builtin.os.tag == .windows) {
            const atime_ft = windows.nanoSecondsToFileTime(atime);
            const mtime_ft = windows.nanoSecondsToFileTime(mtime);
            return windows.SetFileTime(self.handle, null, &atime_ft, &mtime_ft);
        }
        const times = [2]os.timespec{
            os.timespec{
                .tv_sec = math.cast(isize, @divFloor(atime, std.time.ns_per_s)) catch maxInt(isize),
                .tv_nsec = math.cast(isize, @mod(atime, std.time.ns_per_s)) catch maxInt(isize),
            },
            os.timespec{
                .tv_sec = math.cast(isize, @divFloor(mtime, std.time.ns_per_s)) catch maxInt(isize),
                .tv_nsec = math.cast(isize, @mod(mtime, std.time.ns_per_s)) catch maxInt(isize),
            },
        };
        try os.futimens(self.handle, &times);
    }

    /// Reads all the bytes from the current position to the end of the file.
    /// On success, caller owns returned buffer.
    /// If the file is larger than `max_bytes`, returns `error.FileTooBig`.
    pub fn readToEndAlloc(self: File, allocator: *mem.Allocator, max_bytes: usize) ![]u8 {
        return self.readToEndAllocOptions(allocator, max_bytes, null, @alignOf(u8), null);
    }

    /// Reads all the bytes from the current position to the end of the file.
    /// On success, caller owns returned buffer.
    /// If the file is larger than `max_bytes`, returns `error.FileTooBig`.
    /// If `size_hint` is specified the initial buffer size is calculated using
    /// that value, otherwise an arbitrary value is used instead.
    /// Allows specifying alignment and a sentinel value.
    pub fn readToEndAllocOptions(
        self: File,
        allocator: *mem.Allocator,
        max_bytes: usize,
        size_hint: ?usize,
        comptime alignment: u29,
        comptime optional_sentinel: ?u8,
    ) !(if (optional_sentinel) |s| [:s]align(alignment) u8 else []align(alignment) u8) {
        // If no size hint is provided fall back to the size=0 code path
        const size = size_hint orelse 0;

        // The file size returned by stat is used as hint to set the buffer
        // size. If the reported size is zero, as it happens on Linux for files
        // in /proc, a small buffer is allocated instead.
        const initial_cap = (if (size > 0) size else 1024) + @boolToInt(optional_sentinel != null);
        var array_list = try std.ArrayListAligned(u8, alignment).initCapacity(allocator, initial_cap);
        defer array_list.deinit();

        self.reader().readAllArrayListAligned(alignment, &array_list, max_bytes) catch |err| switch (err) {
            error.StreamTooLong => return error.FileTooBig,
            else => |e| return e,
        };

        if (optional_sentinel) |sentinel| {
            try array_list.append(sentinel);
            const buf = array_list.toOwnedSlice();
            return buf[0 .. buf.len - 1 :sentinel];
        } else {
            return array_list.toOwnedSlice();
        }
    }

    pub const ReadError = os.ReadError;
    pub const PReadError = os.PReadError;

    pub fn read(self: File, buffer: []u8) ReadError!usize {
        if (is_windows) {
            return windows.ReadFile(self.handle, buffer, null, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.read(self.handle, buffer);
        } else {
            return std.event.Loop.instance.?.read(self.handle, buffer, self.capable_io_mode != self.intended_io_mode);
        }
    }

    /// Returns the number of bytes read. If the number read is smaller than `buffer.len`, it
    /// means the file reached the end. Reaching the end of a file is not an error condition.
    pub fn readAll(self: File, buffer: []u8) ReadError!usize {
        var index: usize = 0;
        while (index != buffer.len) {
            const amt = try self.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    pub fn pread(self: File, buffer: []u8, offset: u64) PReadError!usize {
        if (is_windows) {
            return windows.ReadFile(self.handle, buffer, offset, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.pread(self.handle, buffer, offset);
        } else {
            return std.event.Loop.instance.?.pread(self.handle, buffer, offset, self.capable_io_mode != self.intended_io_mode);
        }
    }

    /// Returns the number of bytes read. If the number read is smaller than `buffer.len`, it
    /// means the file reached the end. Reaching the end of a file is not an error condition.
    pub fn preadAll(self: File, buffer: []u8, offset: u64) PReadError!usize {
        var index: usize = 0;
        while (index != buffer.len) {
            const amt = try self.pread(buffer[index..], offset + index);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    /// See https://github.com/ziglang/zig/issues/7699
    pub fn readv(self: File, iovecs: []const os.iovec) ReadError!usize {
        if (is_windows) {
            // TODO improve this to use ReadFileScatter
            if (iovecs.len == 0) return @as(usize, 0);
            const first = iovecs[0];
            return windows.ReadFile(self.handle, first.iov_base[0..first.iov_len], null, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.readv(self.handle, iovecs);
        } else {
            return std.event.Loop.instance.?.readv(self.handle, iovecs, self.capable_io_mode != self.intended_io_mode);
        }
    }

    /// Returns the number of bytes read. If the number read is smaller than the total bytes
    /// from all the buffers, it means the file reached the end. Reaching the end of a file
    /// is not an error condition.
    /// The `iovecs` parameter is mutable because this function needs to mutate the fields in
    /// order to handle partial reads from the underlying OS layer.
    /// See https://github.com/ziglang/zig/issues/7699
    pub fn readvAll(self: File, iovecs: []os.iovec) ReadError!usize {
        if (iovecs.len == 0) return 0;

        var i: usize = 0;
        var off: usize = 0;
        while (true) {
            var amt = try self.readv(iovecs[i..]);
            var eof = amt == 0;
            off += amt;
            while (amt >= iovecs[i].iov_len) {
                amt -= iovecs[i].iov_len;
                i += 1;
                if (i >= iovecs.len) return off;
                eof = false;
            }
            if (eof) return off;
            iovecs[i].iov_base += amt;
            iovecs[i].iov_len -= amt;
        }
    }

    /// See https://github.com/ziglang/zig/issues/7699
    pub fn preadv(self: File, iovecs: []const os.iovec, offset: u64) PReadError!usize {
        if (is_windows) {
            // TODO improve this to use ReadFileScatter
            if (iovecs.len == 0) return @as(usize, 0);
            const first = iovecs[0];
            return windows.ReadFile(self.handle, first.iov_base[0..first.iov_len], offset, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.preadv(self.handle, iovecs, offset);
        } else {
            return std.event.Loop.instance.?.preadv(self.handle, iovecs, offset, self.capable_io_mode != self.intended_io_mode);
        }
    }

    /// Returns the number of bytes read. If the number read is smaller than the total bytes
    /// from all the buffers, it means the file reached the end. Reaching the end of a file
    /// is not an error condition.
    /// The `iovecs` parameter is mutable because this function needs to mutate the fields in
    /// order to handle partial reads from the underlying OS layer.
    /// See https://github.com/ziglang/zig/issues/7699
    pub fn preadvAll(self: File, iovecs: []os.iovec, offset: u64) PReadError!usize {
        if (iovecs.len == 0) return 0;

        var i: usize = 0;
        var off: usize = 0;
        while (true) {
            var amt = try self.preadv(iovecs[i..], offset + off);
            var eof = amt == 0;
            off += amt;
            while (amt >= iovecs[i].iov_len) {
                amt -= iovecs[i].iov_len;
                i += 1;
                if (i >= iovecs.len) return off;
                eof = false;
            }
            if (eof) return off;
            iovecs[i].iov_base += amt;
            iovecs[i].iov_len -= amt;
        }
    }

    pub const WriteError = os.WriteError;
    pub const PWriteError = os.PWriteError;

    pub fn write(self: File, bytes: []const u8) WriteError!usize {
        if (is_windows) {
            return windows.WriteFile(self.handle, bytes, null, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.write(self.handle, bytes);
        } else {
            return std.event.Loop.instance.?.write(self.handle, bytes, self.capable_io_mode != self.intended_io_mode);
        }
    }

    pub fn writeAll(self: File, bytes: []const u8) WriteError!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try self.write(bytes[index..]);
        }
    }

    pub fn pwrite(self: File, bytes: []const u8, offset: u64) PWriteError!usize {
        if (is_windows) {
            return windows.WriteFile(self.handle, bytes, offset, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.pwrite(self.handle, bytes, offset);
        } else {
            return std.event.Loop.instance.?.pwrite(self.handle, bytes, offset, self.capable_io_mode != self.intended_io_mode);
        }
    }

    pub fn pwriteAll(self: File, bytes: []const u8, offset: u64) PWriteError!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try self.pwrite(bytes[index..], offset + index);
        }
    }

    /// See https://github.com/ziglang/zig/issues/7699
    /// See equivalent function: `std.net.Stream.writev`.
    pub fn writev(self: File, iovecs: []const os.iovec_const) WriteError!usize {
        if (is_windows) {
            // TODO improve this to use WriteFileScatter
            if (iovecs.len == 0) return @as(usize, 0);
            const first = iovecs[0];
            return windows.WriteFile(self.handle, first.iov_base[0..first.iov_len], null, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.writev(self.handle, iovecs);
        } else {
            return std.event.Loop.instance.?.writev(self.handle, iovecs, self.capable_io_mode != self.intended_io_mode);
        }
    }

    /// The `iovecs` parameter is mutable because this function needs to mutate the fields in
    /// order to handle partial writes from the underlying OS layer.
    /// See https://github.com/ziglang/zig/issues/7699
    /// See equivalent function: `std.net.Stream.writevAll`.
    pub fn writevAll(self: File, iovecs: []os.iovec_const) WriteError!void {
        if (iovecs.len == 0) return;

        var i: usize = 0;
        while (true) {
            var amt = try self.writev(iovecs[i..]);
            while (amt >= iovecs[i].iov_len) {
                amt -= iovecs[i].iov_len;
                i += 1;
                if (i >= iovecs.len) return;
            }
            iovecs[i].iov_base += amt;
            iovecs[i].iov_len -= amt;
        }
    }

    /// See https://github.com/ziglang/zig/issues/7699
    pub fn pwritev(self: File, iovecs: []os.iovec_const, offset: u64) PWriteError!usize {
        if (is_windows) {
            // TODO improve this to use WriteFileScatter
            if (iovecs.len == 0) return @as(usize, 0);
            const first = iovecs[0];
            return windows.WriteFile(self.handle, first.iov_base[0..first.iov_len], offset, self.intended_io_mode);
        }

        if (self.intended_io_mode == .blocking) {
            return os.pwritev(self.handle, iovecs, offset);
        } else {
            return std.event.Loop.instance.?.pwritev(self.handle, iovecs, offset, self.capable_io_mode != self.intended_io_mode);
        }
    }

    /// The `iovecs` parameter is mutable because this function needs to mutate the fields in
    /// order to handle partial writes from the underlying OS layer.
    /// See https://github.com/ziglang/zig/issues/7699
    pub fn pwritevAll(self: File, iovecs: []os.iovec_const, offset: u64) PWriteError!void {
        if (iovecs.len == 0) return;

        var i: usize = 0;
        var off: u64 = 0;
        while (true) {
            var amt = try self.pwritev(iovecs[i..], offset + off);
            off += amt;
            while (amt >= iovecs[i].iov_len) {
                amt -= iovecs[i].iov_len;
                i += 1;
                if (i >= iovecs.len) return;
            }
            iovecs[i].iov_base += amt;
            iovecs[i].iov_len -= amt;
        }
    }

    pub const CopyRangeError = os.CopyFileRangeError;

    pub fn copyRange(in: File, in_offset: u64, out: File, out_offset: u64, len: u64) CopyRangeError!u64 {
        const adjusted_len = math.cast(usize, len) catch math.maxInt(usize);
        const result = try os.copy_file_range(in.handle, in_offset, out.handle, out_offset, adjusted_len, 0);
        return result;
    }

    /// Returns the number of bytes copied. If the number read is smaller than `buffer.len`, it
    /// means the in file reached the end. Reaching the end of a file is not an error condition.
    pub fn copyRangeAll(in: File, in_offset: u64, out: File, out_offset: u64, len: u64) CopyRangeError!u64 {
        var total_bytes_copied: u64 = 0;
        var in_off = in_offset;
        var out_off = out_offset;
        while (total_bytes_copied < len) {
            const amt_copied = try copyRange(in, in_off, out, out_off, len - total_bytes_copied);
            if (amt_copied == 0) return total_bytes_copied;
            total_bytes_copied += amt_copied;
            in_off += amt_copied;
            out_off += amt_copied;
        }
        return total_bytes_copied;
    }

    pub const WriteFileOptions = struct {
        in_offset: u64 = 0,

        /// `null` means the entire file. `0` means no bytes from the file.
        /// When this is `null`, trailers must be sent in a separate writev() call
        /// due to a flaw in the BSD sendfile API. Other operating systems, such as
        /// Linux, already do this anyway due to API limitations.
        /// If the size of the source file is known, passing the size here will save one syscall.
        in_len: ?u64 = null,

        headers_and_trailers: []os.iovec_const = &[0]os.iovec_const{},

        /// The trailer count is inferred from `headers_and_trailers.len - header_count`
        header_count: usize = 0,
    };

    pub const WriteFileError = ReadError || error{EndOfStream} || WriteError;

    pub fn writeFileAll(self: File, in_file: File, args: WriteFileOptions) WriteFileError!void {
        return self.writeFileAllSendfile(in_file, args) catch |err| switch (err) {
            error.Unseekable,
            error.FastOpenAlreadyInProgress,
            error.MessageTooBig,
            error.FileDescriptorNotASocket,
            error.NetworkUnreachable,
            error.NetworkSubsystemFailed,
            => return self.writeFileAllUnseekable(in_file, args),

            else => |e| return e,
        };
    }

    /// Does not try seeking in either of the File parameters.
    /// See `writeFileAll` as an alternative to calling this.
    pub fn writeFileAllUnseekable(self: File, in_file: File, args: WriteFileOptions) WriteFileError!void {
        const headers = args.headers_and_trailers[0..args.header_count];
        const trailers = args.headers_and_trailers[args.header_count..];

        try self.writevAll(headers);

        try in_file.reader().skipBytes(args.in_offset, .{ .buf_size = 4096 });

        var fifo = std.fifo.LinearFifo(u8, .{ .Static = 4096 }).init();
        if (args.in_len) |len| {
            var stream = std.io.limitedReader(in_file.reader(), len);
            try fifo.pump(stream.reader(), self.writer());
        } else {
            try fifo.pump(in_file.reader(), self.writer());
        }

        try self.writevAll(trailers);
    }

    /// Low level function which can fail for OS-specific reasons.
    /// See `writeFileAll` as an alternative to calling this.
    /// TODO integrate with async I/O
    fn writeFileAllSendfile(self: File, in_file: File, args: WriteFileOptions) os.SendFileError!void {
        const count = blk: {
            if (args.in_len) |l| {
                if (l == 0) {
                    return self.writevAll(args.headers_and_trailers);
                } else {
                    break :blk l;
                }
            } else {
                break :blk 0;
            }
        };
        const headers = args.headers_and_trailers[0..args.header_count];
        const trailers = args.headers_and_trailers[args.header_count..];
        const zero_iovec = &[0]os.iovec_const{};
        // When reading the whole file, we cannot put the trailers in the sendfile() syscall,
        // because we have no way to determine whether a partial write is past the end of the file or not.
        const trls = if (count == 0) zero_iovec else trailers;
        const offset = args.in_offset;
        const out_fd = self.handle;
        const in_fd = in_file.handle;
        const flags = 0;
        var amt: usize = 0;
        hdrs: {
            var i: usize = 0;
            while (i < headers.len) {
                amt = try os.sendfile(out_fd, in_fd, offset, count, headers[i..], trls, flags);
                while (amt >= headers[i].iov_len) {
                    amt -= headers[i].iov_len;
                    i += 1;
                    if (i >= headers.len) break :hdrs;
                }
                headers[i].iov_base += amt;
                headers[i].iov_len -= amt;
            }
        }
        if (count == 0) {
            var off: u64 = amt;
            while (true) {
                amt = try os.sendfile(out_fd, in_fd, offset + off, 0, zero_iovec, zero_iovec, flags);
                if (amt == 0) break;
                off += amt;
            }
        } else {
            var off: u64 = amt;
            while (off < count) {
                amt = try os.sendfile(out_fd, in_fd, offset + off, count - off, zero_iovec, trailers, flags);
                off += amt;
            }
            amt = @intCast(usize, off - count);
        }
        var i: usize = 0;
        while (i < trailers.len) {
            while (amt >= trailers[i].iov_len) {
                amt -= trailers[i].iov_len;
                i += 1;
                if (i >= trailers.len) return;
            }
            trailers[i].iov_base += amt;
            trailers[i].iov_len -= amt;
            amt = try os.writev(self.handle, trailers[i..]);
        }
    }

    pub const Reader = io.Reader(File, ReadError, read);

    pub fn reader(file: File) Reader {
        return .{ .context = file };
    }

    pub const Writer = io.Writer(File, WriteError, write);

    pub fn writer(file: File) Writer {
        return .{ .context = file };
    }

    pub const SeekableStream = io.SeekableStream(
        File,
        SeekError,
        GetSeekPosError,
        seekTo,
        seekBy,
        getPos,
        getEndPos,
    );

    pub fn seekableStream(file: File) SeekableStream {
        return .{ .context = file };
    }

    const range_off: windows.LARGE_INTEGER = 0;
    const range_len: windows.LARGE_INTEGER = 1;

    pub const LockError = error{
        SystemResources,
    } || os.UnexpectedError;

    /// Blocks when an incompatible lock is held by another process.
    /// A process may hold only one type of lock (shared or exclusive) on
    /// a file. When a process terminates in any way, the lock is released.
    ///
    /// Assumes the file is unlocked.
    ///
    /// TODO: integrate with async I/O
    pub fn lock(file: File, l: Lock) LockError!void {
        if (is_windows) {
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            const exclusive = switch (l) {
                .None => return,
                .Shared => false,
                .Exclusive => true,
            };
            return windows.LockFile(
                file.handle,
                null,
                null,
                null,
                &io_status_block,
                &range_off,
                &range_len,
                null,
                windows.FALSE, // non-blocking=false
                @boolToInt(exclusive),
            ) catch |err| switch (err) {
                error.WouldBlock => unreachable, // non-blocking=false
                else => |e| return e,
            };
        } else {
            return os.flock(file.handle, switch (l) {
                .None => os.LOCK_UN,
                .Shared => os.LOCK_SH,
                .Exclusive => os.LOCK_EX,
            }) catch |err| switch (err) {
                error.WouldBlock => unreachable, // non-blocking=false
                else => |e| return e,
            };
        }
    }

    /// Assumes the file is locked.
    pub fn unlock(file: File) void {
        if (is_windows) {
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            return windows.UnlockFile(
                file.handle,
                &io_status_block,
                &range_off,
                &range_len,
                null,
            ) catch |err| switch (err) {
                error.RangeNotLocked => unreachable, // Function assumes unlocked.
                error.Unexpected => unreachable, // Resource deallocation must succeed.
            };
        } else {
            return os.flock(file.handle, os.LOCK_UN) catch |err| switch (err) {
                error.WouldBlock => unreachable, // unlocking can't block
                error.SystemResources => unreachable, // We are deallocating resources.
                error.Unexpected => unreachable, // Resource deallocation must succeed.
            };
        }
    }

    /// Attempts to obtain a lock, returning `true` if the lock is
    /// obtained, and `false` if there was an existing incompatible lock held.
    /// A process may hold only one type of lock (shared or exclusive) on
    /// a file. When a process terminates in any way, the lock is released.
    ///
    /// Assumes the file is unlocked.
    ///
    /// TODO: integrate with async I/O
    pub fn tryLock(file: File, l: Lock) LockError!bool {
        if (is_windows) {
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            const exclusive = switch (l) {
                .None => return,
                .Shared => false,
                .Exclusive => true,
            };
            windows.LockFile(
                file.handle,
                null,
                null,
                null,
                &io_status_block,
                &range_off,
                &range_len,
                null,
                windows.TRUE, // non-blocking=true
                @boolToInt(exclusive),
            ) catch |err| switch (err) {
                error.WouldBlock => return false,
                else => |e| return e,
            };
        } else {
            os.flock(file.handle, switch (l) {
                .None => os.LOCK_UN,
                .Shared => os.LOCK_SH | os.LOCK_NB,
                .Exclusive => os.LOCK_EX | os.LOCK_NB,
            }) catch |err| switch (err) {
                error.WouldBlock => return false,
                else => |e| return e,
            };
        }
        return true;
    }

    /// Assumes the file is already locked in exclusive mode.
    /// Atomically modifies the lock to be in shared mode, without releasing it.
    ///
    /// TODO: integrate with async I/O
    pub fn downgradeLock(file: File) LockError!void {
        if (is_windows) {
            // On Windows it works like a semaphore + exclusivity flag. To implement this
            // function, we first obtain another lock in shared mode. This changes the
            // exclusivity flag, but increments the semaphore to 2. So we follow up with
            // an NtUnlockFile which decrements the semaphore but does not modify the
            // exclusivity flag.
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            windows.LockFile(
                file.handle,
                null,
                null,
                null,
                &io_status_block,
                &range_off,
                &range_len,
                null,
                windows.TRUE, // non-blocking=true
                windows.FALSE, // exclusive=false
            ) catch |err| switch (err) {
                error.WouldBlock => unreachable, // File was not locked in exclusive mode.
                else => |e| return e,
            };
            return windows.UnlockFile(
                file.handle,
                &io_status_block,
                &range_off,
                &range_len,
                null,
            ) catch |err| switch (err) {
                error.RangeNotLocked => unreachable, // File was not locked.
                error.Unexpected => unreachable, // Resource deallocation must succeed.
            };
        } else {
            return os.flock(file.handle, os.LOCK_SH | os.LOCK_NB) catch |err| switch (err) {
                error.WouldBlock => unreachable, // File was not locked in exclusive mode.
                else => |e| return e,
            };
        }
    }
};
