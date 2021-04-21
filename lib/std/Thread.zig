// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! This struct represents a kernel thread, and acts as a namespace for concurrency
//! primitives that operate on kernel threads. For concurrency primitives that support
//! both evented I/O and async I/O, see the respective names in the top level std namespace.

data: Data,

pub const AutoResetEvent = @import("Thread/AutoResetEvent.zig");
pub const Futex = @import("Thread/Futex.zig");
pub const ResetEvent = @import("Thread/ResetEvent.zig");
pub const StaticResetEvent = @import("Thread/StaticResetEvent.zig");
pub const Mutex = @import("Thread/Mutex.zig");
pub const Semaphore = @import("Thread/Semaphore.zig");
pub const Condition = @import("Thread/Condition.zig");

pub const use_pthreads = std.Target.current.os.tag != .windows and builtin.link_libc;

const Thread = @This();
const std = @import("std.zig");
const builtin = std.builtin;
const os = std.os;
const mem = std.mem;
const windows = std.os.windows;
const c = std.c;
const assert = std.debug.assert;

const bad_startfn_ret = "expected return type of startFn to be 'u8', 'noreturn', 'void', or '!void'";

/// Represents a kernel thread handle.
/// May be an integer or a pointer depending on the platform.
/// On Linux and POSIX, this is the same as Id.
pub const Handle = if (use_pthreads)
    c.pthread_t
else switch (std.Target.current.os.tag) {
    .linux => i32,
    .windows => windows.HANDLE,
    else => void,
};

/// Represents a unique ID per thread.
/// May be an integer or pointer depending on the platform.
/// On Linux and POSIX, this is the same as Handle.
pub const Id = switch (std.Target.current.os.tag) {
    .windows => windows.DWORD,
    else => Handle,
};

pub const Data = if (use_pthreads)
    struct {
        handle: Thread.Handle,
        memory: []u8,
    }
else switch (std.Target.current.os.tag) {
    .linux => struct {
        handle: Thread.Handle,
        memory: []align(mem.page_size) u8,
    },
    .windows => struct {
        handle: Thread.Handle,
        alloc_start: *c_void,
        heap_handle: windows.HANDLE,
    },
    else => struct {},
};

pub const spinLoopHint = @compileError("deprecated: use std.atomic.spinLoopHint");

pub const maxNameLen = switch (std.Target.current.os.tag) {
    .linux => 15,
    .windows => 31,
    .macos, .ios, .watchos, .tvos => 63,
    .netbsd => 31,
    .freebsd => 15,
    .openbsd => 31,
    else => 0,
};

pub fn setName(self: Thread, name: []const u8) !void {
    if (name.len > maxNameLen) return error.NameTooLong;

    const name_with_terminator = blk: {
        var name_buf: [maxNameLen:0]u8 = undefined;
        std.mem.copy(u8, &name_buf, name);
        name_buf[name.len] = 0;
        break :blk name_buf[0..name.len :0];
    };

    switch (std.Target.current.os.tag) {
        .linux => if (use_pthreads) {
            const err = c.pthread_setname_np(self.data.handle, name_with_terminator.ptr);
            return switch (err) {
                0 => {},
                os.ERANGE => unreachable,
                else => return os.unexpectedErrno(err),
            };
        } else if (self.data.handle == getCurrentId()) {
            const err = try os.prctl(.SET_NAME, .{@ptrToInt(name_with_terminator.ptr)});
            return switch (err) {
                0 => {},
                else => return os.unexpectedErrno(err),
            };
        } else {
            var buf: [32]u8 = undefined;
            const path = try std.fmt.bufPrint(&buf, "/proc/self/task/{d}/comm", .{self.data.handle});

            const file = try std.fs.cwd().openFile(path, .{ .write = true });
            defer file.close();

            try file.writer().writeAll(name);
        },
        .windows => if (std.Target.current.os.isAtLeast(.windows, .win10_rs1)) |res| {
            // SetThreadDescription is only available since version 1607, which is 10.0.14393.795
            // See https://en.wikipedia.org/wiki/Microsoft_Windows_SDK
            if (!res) {
                return error.Unsupported;
            }

            var name_buf_w: [maxNameLen:0]u16 = undefined;
            const length = try std.unicode.utf8ToUtf16Le(&name_buf_w, name);
            name_buf_w[length] = 0;

            try os.windows.SetThreadDescription(
                self.data.handle,
                @ptrCast(os.windows.LPWSTR, &name_buf_w),
            );
        } else {
            return error.Unsupported;
        },
        .macos, .ios, .watchos, .tvos => if (use_pthreads) {
            // There doesn't seem to be a way to set the name for an arbitrary thread, only the current one.
            if (self.data.handle != getCurrentId()) return error.Unsupported;

            const err = c.pthread_setname_np(name_with_terminator.ptr);
            return switch (err) {
                0 => {},
                else => return os.unexpectedErrno(err),
            };
        },
        .netbsd => if (use_pthreads) {
            const err = c.pthread_setname_np(self.data.handle, name_with_terminator.ptr, null);
            return switch (err) {
                0 => {},
                os.EINVAL => unreachable,
                os.ESRCH => unreachable,
                os.ENOMEM => unreachable,
                else => return os.unexpectedErrno(err),
            };
        },
        .freebsd, .openbsd => if (use_pthreads) {
            // Use pthread_set_name_np for FreeBSD because pthread_setname_np is FreeBSD 12.2+ only.
            // TODO maybe revisit this if depending on FreeBSD 12.2+ is acceptable because pthread_setname_np can return an error.

            c.pthread_set_name_np(self.data.handle, name_with_terminator.ptr);
        },
        else => return error.Unsupported,
    }
}

pub fn getName(self: Thread, allocator: *std.mem.Allocator) !?[]const u8 {
    switch (std.Target.current.os.tag) {
        .linux => if (use_pthreads and comptime std.Target.current.abi.isGnu()) {
            var buffer = try allocator.allocSentinel(u8, maxNameLen, 0);

            const err = c.pthread_getname_np(self.data.handle, buffer.ptr, maxNameLen + 1);
            return switch (err) {
                0 => std.mem.spanZ(buffer),
                os.ERANGE => unreachable,
                else => return os.unexpectedErrno(err),
            };
        } else if (self.data.handle == getCurrentId()) {
            var buffer = try allocator.allocSentinel(u8, maxNameLen, 0);

            const err = try os.prctl(.GET_NAME, .{@ptrToInt(buffer.ptr)});
            return switch (err) {
                0 => std.mem.spanZ(buffer),
                else => return os.unexpectedErrno(err),
            };
        } else if (!use_pthreads) {
            var buf: [32]u8 = undefined;
            const path = try std.fmt.bufPrint(&buf, "/proc/self/task/{d}/comm", .{self.data.handle});

            const file = try std.fs.cwd().openFile(path, .{});
            defer file.close();

            const data = try file.reader().readAllAlloc(allocator, maxNameLen + 1);
            return if (data.len >= 1) data[0 .. data.len - 1] else null;
        } else {
            // musl doesn't provide pthread_getname_np and there's no way to retrieve the thread id of an arbitrary thread.
            return error.Unsupported;
        },
        .windows => if (std.Target.current.os.isAtLeast(.windows, .win10_rs1)) |res| {
            // GetThreadDescription is only available since version 1607, which is 10.0.14393.795
            // See https://en.wikipedia.org/wiki/Microsoft_Windows_SDK
            if (!res) {
                return error.Unsupported;
            }

            var name_w: os.windows.LPWSTR = undefined;
            try windows.GetThreadDescription(self.data.handle, &name_w);
            defer windows.LocalFree(name_w);

            return try std.unicode.utf16leToUtf8Alloc(
                allocator,
                std.mem.spanZ(name_w),
            );
        } else {
            return error.Unsupported;
        },
        .macos, .ios, .watchos, .tvos => if (use_pthreads) {
            var buffer = try allocator.allocSentinel(u8, maxNameLen, 0);

            const err = c.pthread_getname_np(self.data.handle, buffer.ptr, maxNameLen + 1);
            return switch (err) {
                0 => std.mem.spanZ(buffer),
                os.ESRCH => unreachable,
                else => return os.unexpectedErrno(err),
            };
        },
        .netbsd => if (use_pthreads) {
            var buffer = try allocator.allocSentinel(u8, maxNameLen, 0);

            const err = c.pthread_getname_np(self.data.handle, buffer.ptr, maxNameLen + 1);
            return switch (err) {
                0 => std.mem.spanZ(buffer),
                os.EINVAL => unreachable,
                os.ESRCH => unreachable,
                else => return os.unexpectedErrno(err),
            };
        },
        .freebsd, .openbsd => if (use_pthreads) {
            var buffer = try allocator.allocSentinel(u8, maxNameLen, 0);

            // Use pthread_get_name_np for FreeBSD because pthread_getname_np is FreeBSD 12.2+ only.
            // TODO maybe revisit this if depending on FreeBSD 12.2+ is acceptable because pthread_getname_np can return an error.

            c.pthread_get_name_np(self.data.handle, buffer.ptr, maxNameLen + 1);
            return std.mem.spanZ(buffer);
        },
        else => return error.Unsupported,
    }
}

/// Returns the ID of the calling thread.
/// Makes a syscall every time the function is called.
/// On Linux and POSIX, this Id is the same as a Handle.
pub fn getCurrentId() Id {
    if (use_pthreads) {
        return c.pthread_self();
    } else return switch (std.Target.current.os.tag) {
        .linux => os.linux.gettid(),
        .windows => windows.kernel32.GetCurrentThreadId(),
        else => @compileError("Unsupported OS"),
    };
}

/// Returns the handle of this thread.
/// On Linux and POSIX, this is the same as Id.
/// On Linux, it is possible that the thread spawned with `spawn`
/// finishes executing entirely before the clone syscall completes. In this
/// case, this function will return 0 rather than the no-longer-existing thread's
/// pid.
pub fn handle(self: Thread) Handle {
    return self.data.handle;
}

pub fn wait(self: *Thread) void {
    if (use_pthreads) {
        const err = c.pthread_join(self.data.handle, null);
        switch (err) {
            0 => {},
            os.EINVAL => unreachable,
            os.ESRCH => unreachable,
            os.EDEADLK => unreachable,
            else => unreachable,
        }
        std.heap.c_allocator.free(self.data.memory);
        std.heap.c_allocator.destroy(self);
    } else switch (std.Target.current.os.tag) {
        .linux => {
            while (true) {
                const pid_value = @atomicLoad(i32, &self.data.handle, .SeqCst);
                if (pid_value == 0) break;
                const rc = os.linux.futex_wait(&self.data.handle, os.linux.FUTEX_WAIT, pid_value, null);
                switch (os.linux.getErrno(rc)) {
                    0 => continue,
                    os.EINTR => continue,
                    os.EAGAIN => continue,
                    else => unreachable,
                }
            }
            os.munmap(self.data.memory);
        },
        .windows => {
            windows.WaitForSingleObjectEx(self.data.handle, windows.INFINITE, false) catch unreachable;
            windows.CloseHandle(self.data.handle);
            windows.HeapFree(self.data.heap_handle, 0, self.data.alloc_start);
        },
        else => @compileError("Unsupported OS"),
    }
}

pub const SpawnError = error{
    /// A system-imposed limit on the number of threads was encountered.
    /// There are a number of limits that may trigger this error:
    /// *  the  RLIMIT_NPROC soft resource limit (set via setrlimit(2)),
    ///    which limits the number of processes and threads for  a  real
    ///    user ID, was reached;
    /// *  the kernel's system-wide limit on the number of processes and
    ///    threads,  /proc/sys/kernel/threads-max,  was   reached   (see
    ///    proc(5));
    /// *  the  maximum  number  of  PIDs, /proc/sys/kernel/pid_max, was
    ///    reached (see proc(5)); or
    /// *  the PID limit (pids.max) imposed by the cgroup "process  num‐
    ///    ber" (PIDs) controller was reached.
    ThreadQuotaExceeded,

    /// The kernel cannot allocate sufficient memory to allocate a task structure
    /// for the child, or to copy those parts of the caller's context that need to
    /// be copied.
    SystemResources,

    /// Not enough userland memory to spawn the thread.
    OutOfMemory,

    /// `mlockall` is enabled, and the memory needed to spawn the thread
    /// would exceed the limit.
    LockedMemoryLimitExceeded,

    Unexpected,
};

// Given `T`, the type of the thread startFn, extract the expected type for the
// context parameter.
fn SpawnContextType(comptime T: type) type {
    const TI = @typeInfo(T);
    if (TI != .Fn)
        @compileError("expected function type, found " ++ @typeName(T));

    if (TI.Fn.args.len != 1)
        @compileError("expected function with single argument, found " ++ @typeName(T));

    return TI.Fn.args[0].arg_type orelse
        @compileError("cannot use a generic function as thread startFn");
}

/// Spawns a new thread executing startFn, returning an handle for it.
/// Caller must call wait on the returned thread.
/// The `startFn` function must take a single argument of type T and return a
/// value of type u8, noreturn, void or !void.
/// The `context` parameter is of type T and is passed to the spawned thread.
pub fn spawn(comptime startFn: anytype, context: SpawnContextType(@TypeOf(startFn))) SpawnError!*Thread {
    if (builtin.single_threaded) @compileError("cannot spawn thread when building in single-threaded mode");
    // TODO compile-time call graph analysis to determine stack upper bound
    // https://github.com/ziglang/zig/issues/157
    const default_stack_size = 16 * 1024 * 1024;

    const Context = @TypeOf(context);

    if (std.Target.current.os.tag == .windows) {
        const WinThread = struct {
            const OuterContext = struct {
                thread: Thread,
                inner: Context,
            };
            fn threadMain(raw_arg: windows.LPVOID) callconv(.C) windows.DWORD {
                const arg = if (@sizeOf(Context) == 0) undefined //
                else @ptrCast(*Context, @alignCast(@alignOf(Context), raw_arg)).*;

                switch (@typeInfo(@typeInfo(@TypeOf(startFn)).Fn.return_type.?)) {
                    .NoReturn => {
                        startFn(arg);
                    },
                    .Void => {
                        startFn(arg);
                        return 0;
                    },
                    .Int => |info| {
                        if (info.bits != 8) {
                            @compileError(bad_startfn_ret);
                        }
                        return startFn(arg);
                    },
                    .ErrorUnion => |info| {
                        if (info.payload != void) {
                            @compileError(bad_startfn_ret);
                        }
                        startFn(arg) catch |err| {
                            std.debug.warn("error: {s}\n", .{@errorName(err)});
                            if (@errorReturnTrace()) |trace| {
                                std.debug.dumpStackTrace(trace.*);
                            }
                        };
                        return 0;
                    },
                    else => @compileError(bad_startfn_ret),
                }
            }
        };

        const heap_handle = windows.kernel32.GetProcessHeap() orelse return error.OutOfMemory;
        const byte_count = @alignOf(WinThread.OuterContext) + @sizeOf(WinThread.OuterContext);
        const bytes_ptr = windows.kernel32.HeapAlloc(heap_handle, 0, byte_count) orelse return error.OutOfMemory;
        errdefer assert(windows.kernel32.HeapFree(heap_handle, 0, bytes_ptr) != 0);
        const bytes = @ptrCast([*]u8, bytes_ptr)[0..byte_count];
        const outer_context = std.heap.FixedBufferAllocator.init(bytes).allocator.create(WinThread.OuterContext) catch unreachable;
        outer_context.* = WinThread.OuterContext{
            .thread = Thread{
                .data = Thread.Data{
                    .heap_handle = heap_handle,
                    .alloc_start = bytes_ptr,
                    .handle = undefined,
                },
            },
            .inner = context,
        };

        const parameter = if (@sizeOf(Context) == 0) null else @ptrCast(*c_void, &outer_context.inner);
        outer_context.thread.data.handle = windows.kernel32.CreateThread(null, default_stack_size, WinThread.threadMain, parameter, 0, null) orelse {
            switch (windows.kernel32.GetLastError()) {
                else => |err| return windows.unexpectedError(err),
            }
        };
        return &outer_context.thread;
    }

    const MainFuncs = struct {
        fn linuxThreadMain(ctx_addr: usize) callconv(.C) u8 {
            const arg = if (@sizeOf(Context) == 0) undefined //
            else @intToPtr(*Context, ctx_addr).*;

            switch (@typeInfo(@typeInfo(@TypeOf(startFn)).Fn.return_type.?)) {
                .NoReturn => {
                    startFn(arg);
                },
                .Void => {
                    startFn(arg);
                    return 0;
                },
                .Int => |info| {
                    if (info.bits != 8) {
                        @compileError(bad_startfn_ret);
                    }
                    return startFn(arg);
                },
                .ErrorUnion => |info| {
                    if (info.payload != void) {
                        @compileError(bad_startfn_ret);
                    }
                    startFn(arg) catch |err| {
                        std.debug.warn("error: {s}\n", .{@errorName(err)});
                        if (@errorReturnTrace()) |trace| {
                            std.debug.dumpStackTrace(trace.*);
                        }
                    };
                    return 0;
                },
                else => @compileError(bad_startfn_ret),
            }
        }
        fn posixThreadMain(ctx: ?*c_void) callconv(.C) ?*c_void {
            const arg = if (@sizeOf(Context) == 0) undefined //
            else @ptrCast(*Context, @alignCast(@alignOf(Context), ctx)).*;

            switch (@typeInfo(@typeInfo(@TypeOf(startFn)).Fn.return_type.?)) {
                .NoReturn => {
                    startFn(arg);
                },
                .Void => {
                    startFn(arg);
                    return null;
                },
                .Int => |info| {
                    if (info.bits != 8) {
                        @compileError(bad_startfn_ret);
                    }
                    // pthreads don't support exit status, ignore value
                    _ = startFn(arg);
                    return null;
                },
                .ErrorUnion => |info| {
                    if (info.payload != void) {
                        @compileError(bad_startfn_ret);
                    }
                    startFn(arg) catch |err| {
                        std.debug.warn("error: {s}\n", .{@errorName(err)});
                        if (@errorReturnTrace()) |trace| {
                            std.debug.dumpStackTrace(trace.*);
                        }
                    };
                    return null;
                },
                else => @compileError(bad_startfn_ret),
            }
        }
    };

    if (Thread.use_pthreads) {
        var attr: c.pthread_attr_t = undefined;
        if (c.pthread_attr_init(&attr) != 0) return error.SystemResources;
        defer assert(c.pthread_attr_destroy(&attr) == 0);

        const thread_obj = try std.heap.c_allocator.create(Thread);
        errdefer std.heap.c_allocator.destroy(thread_obj);
        if (@sizeOf(Context) > 0) {
            thread_obj.data.memory = try std.heap.c_allocator.allocAdvanced(
                u8,
                @alignOf(Context),
                @sizeOf(Context),
                .at_least,
            );
            errdefer std.heap.c_allocator.free(thread_obj.data.memory);
            mem.copy(u8, thread_obj.data.memory, mem.asBytes(&context));
        } else {
            thread_obj.data.memory = @as([*]u8, undefined)[0..0];
        }

        // Use the same set of parameters used by the libc-less impl.
        assert(c.pthread_attr_setstacksize(&attr, default_stack_size) == 0);
        assert(c.pthread_attr_setguardsize(&attr, mem.page_size) == 0);

        const err = c.pthread_create(
            &thread_obj.data.handle,
            &attr,
            MainFuncs.posixThreadMain,
            thread_obj.data.memory.ptr,
        );
        switch (err) {
            0 => return thread_obj,
            os.EAGAIN => return error.SystemResources,
            os.EPERM => unreachable,
            os.EINVAL => unreachable,
            else => return os.unexpectedErrno(err),
        }

        return thread_obj;
    }

    var guard_end_offset: usize = undefined;
    var stack_end_offset: usize = undefined;
    var thread_start_offset: usize = undefined;
    var context_start_offset: usize = undefined;
    var tls_start_offset: usize = undefined;
    const mmap_len = blk: {
        var l: usize = mem.page_size;
        // Allocate a guard page right after the end of the stack region
        guard_end_offset = l;
        // The stack itself, which grows downwards.
        l = mem.alignForward(l + default_stack_size, mem.page_size);
        stack_end_offset = l;
        // Above the stack, so that it can be in the same mmap call, put the Thread object.
        l = mem.alignForward(l, @alignOf(Thread));
        thread_start_offset = l;
        l += @sizeOf(Thread);
        // Next, the Context object.
        if (@sizeOf(Context) != 0) {
            l = mem.alignForward(l, @alignOf(Context));
            context_start_offset = l;
            l += @sizeOf(Context);
        }
        // Finally, the Thread Local Storage, if any.
        l = mem.alignForward(l, os.linux.tls.tls_image.alloc_align);
        tls_start_offset = l;
        l += os.linux.tls.tls_image.alloc_size;
        // Round the size to the page size.
        break :blk mem.alignForward(l, mem.page_size);
    };

    const mmap_slice = mem: {
        // Map the whole stack with no rw permissions to avoid
        // committing the whole region right away
        const mmap_slice = os.mmap(
            null,
            mmap_len,
            os.PROT_NONE,
            os.MAP_PRIVATE | os.MAP_ANONYMOUS,
            -1,
            0,
        ) catch |err| switch (err) {
            error.MemoryMappingNotSupported => unreachable,
            error.AccessDenied => unreachable,
            error.PermissionDenied => unreachable,
            else => |e| return e,
        };
        errdefer os.munmap(mmap_slice);

        // Map everything but the guard page as rw
        os.mprotect(
            mmap_slice[guard_end_offset..],
            os.PROT_READ | os.PROT_WRITE,
        ) catch |err| switch (err) {
            error.AccessDenied => unreachable,
            else => |e| return e,
        };

        break :mem mmap_slice;
    };

    const mmap_addr = @ptrToInt(mmap_slice.ptr);

    const thread_ptr = @alignCast(@alignOf(Thread), @intToPtr(*Thread, mmap_addr + thread_start_offset));
    thread_ptr.data.memory = mmap_slice;

    var arg: usize = undefined;
    if (@sizeOf(Context) != 0) {
        arg = mmap_addr + context_start_offset;
        const context_ptr = @alignCast(@alignOf(Context), @intToPtr(*Context, arg));
        context_ptr.* = context;
    }

    if (std.Target.current.os.tag == .linux) {
        const flags: u32 = os.CLONE_VM | os.CLONE_FS | os.CLONE_FILES |
            os.CLONE_SIGHAND | os.CLONE_THREAD | os.CLONE_SYSVSEM |
            os.CLONE_PARENT_SETTID | os.CLONE_CHILD_CLEARTID |
            os.CLONE_DETACHED | os.CLONE_SETTLS;
        // This structure is only needed when targeting i386
        var user_desc: if (std.Target.current.cpu.arch == .i386) os.linux.user_desc else void = undefined;

        const tls_area = mmap_slice[tls_start_offset..];
        const tp_value = os.linux.tls.prepareTLS(tls_area);

        const newtls = blk: {
            if (std.Target.current.cpu.arch == .i386) {
                user_desc = os.linux.user_desc{
                    .entry_number = os.linux.tls.tls_image.gdt_entry_number,
                    .base_addr = tp_value,
                    .limit = 0xfffff,
                    .seg_32bit = 1,
                    .contents = 0, // Data
                    .read_exec_only = 0,
                    .limit_in_pages = 1,
                    .seg_not_present = 0,
                    .useable = 1,
                };
                break :blk @ptrToInt(&user_desc);
            } else {
                break :blk tp_value;
            }
        };

        const rc = os.linux.clone(
            MainFuncs.linuxThreadMain,
            mmap_addr + stack_end_offset,
            flags,
            arg,
            &thread_ptr.data.handle,
            newtls,
            &thread_ptr.data.handle,
        );
        switch (os.errno(rc)) {
            0 => return thread_ptr,
            os.EAGAIN => return error.ThreadQuotaExceeded,
            os.EINVAL => unreachable,
            os.ENOMEM => return error.SystemResources,
            os.ENOSPC => unreachable,
            os.EPERM => unreachable,
            os.EUSERS => unreachable,
            else => |err| return os.unexpectedErrno(err),
        }
    } else {
        @compileError("Unsupported OS");
    }
}

pub const CpuCountError = error{
    PermissionDenied,
    SystemResources,
    Unexpected,
};

pub fn cpuCount() CpuCountError!usize {
    switch (std.Target.current.os.tag) {
        .linux => {
            const cpu_set = try os.sched_getaffinity(0);
            return @as(usize, os.CPU_COUNT(cpu_set)); // TODO should not need this usize cast
        },
        .windows => {
            return os.windows.peb().NumberOfProcessors;
        },
        .openbsd => {
            var count: c_int = undefined;
            var count_size: usize = @sizeOf(c_int);
            const mib = [_]c_int{ os.CTL_HW, os.HW_NCPUONLINE };
            os.sysctl(&mib, &count, &count_size, null, 0) catch |err| switch (err) {
                error.NameTooLong, error.UnknownName => unreachable,
                else => |e| return e,
            };
            return @intCast(usize, count);
        },
        .haiku => {
            var count: u32 = undefined;
            var system_info: os.system_info = undefined;
            const rc = os.system.get_system_info(&system_info);
            count = system_info.cpu_count;
            return @intCast(usize, count);
        },
        else => {
            var count: c_int = undefined;
            var count_len: usize = @sizeOf(c_int);
            const name = if (comptime std.Target.current.isDarwin()) "hw.logicalcpu" else "hw.ncpu";
            os.sysctlbynameZ(name, &count, &count_len, null, 0) catch |err| switch (err) {
                error.NameTooLong, error.UnknownName => unreachable,
                else => |e| return e,
            };
            return @intCast(usize, count);
        },
    }
}

pub fn getCurrentThreadId() u64 {
    switch (std.Target.current.os.tag) {
        .linux => {
            // Use the syscall directly as musl doesn't provide a wrapper.
            return @bitCast(u32, os.linux.gettid());
        },
        .windows => {
            return os.windows.kernel32.GetCurrentThreadId();
        },
        .macos, .ios, .watchos, .tvos => {
            var thread_id: u64 = undefined;
            // Pass thread=null to get the current thread ID.
            assert(c.pthread_threadid_np(null, &thread_id) == 0);
            return thread_id;
        },
        .dragonfly => {
            return @bitCast(u32, c.lwp_gettid());
        },
        .netbsd => {
            return @bitCast(u32, c._lwp_self());
        },
        .freebsd => {
            return @bitCast(u32, c.pthread_getthreadid_np());
        },
        .openbsd => {
            return @bitCast(u32, c.getthrid());
        },
        .haiku => {
            return @bitCast(u32, c.find_thread(null));
        },
        else => {
            @compileError("getCurrentThreadId not implemented for this platform");
        },
    }
}

fn testThreadName(thread: *Thread) !void {
    const testCases = &[_][]const u8{
        "mythread",
        "b" ** maxNameLen,
    };

    inline for (testCases) |tc| {
        try thread.setName(tc);

        const name = try thread.getName(std.testing.allocator);
        if (name) |value| {
            defer std.testing.allocator.free(value);
            try std.testing.expectEqualStrings(tc, value);
        }
    }
}

test "setName, getName" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const Context = struct {
        start_wait_event: ResetEvent = undefined,
        test_done_event: ResetEvent = undefined,

        done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),
        thread: *Thread = undefined,

        fn init(self: *@This()) !void {
            try self.start_wait_event.init();
            try self.test_done_event.init();
        }

        pub fn run(ctx: *@This()) !void {
            // Wait for the main thread to have set the thread field in the context.
            ctx.start_wait_event.wait();

            switch (std.Target.current.os.tag) {
                .windows => testThreadName(ctx.thread) catch |err| switch (err) {
                    error.Unsupported => return error.SkipZigTest,
                    else => return err,
                },
                else => try testThreadName(ctx.thread),
            }

            // Signal our test is done
            ctx.test_done_event.set();

            while (!ctx.done.load(.SeqCst)) {
                std.time.sleep(5 * std.time.ns_per_ms);
            }
        }
    };

    var context = Context{};
    try context.init();

    var thread = try spawn(Context.run, &context);
    context.thread = thread;
    context.start_wait_event.set();
    context.test_done_event.wait();

    switch (std.Target.current.os.tag) {
        .macos, .ios, .watchos, .tvos => {
            const res = thread.setName("foobar");
            try std.testing.expectError(error.Unsupported, res);
        },
        .windows => testThreadName(thread) catch |err| switch (err) {
            error.Unsupported => return error.SkipZigTest,
            else => return err,
        },
        else => |tag| if (tag == .linux and use_pthreads and comptime std.Target.current.abi.isMusl()) {
            try thread.setName("foobar");
            const res = thread.getName(std.testing.allocator);
            try std.testing.expectError(error.Unsupported, res);
        } else {
            try testThreadName(thread);
        },
    }

    context.done.store(true, .SeqCst);
    thread.wait();
}

test "std.Thread" {
    if (!builtin.single_threaded) {
        _ = AutoResetEvent;
        _ = Futex;
        _ = ResetEvent;
        _ = StaticResetEvent;
        _ = Mutex;
        _ = Semaphore;
        _ = Condition;
    }
}
