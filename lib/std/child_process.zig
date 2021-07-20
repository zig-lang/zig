// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std.zig");
const builtin = @import("builtin");
const cstr = std.cstr;
const unicode = std.unicode;
const io = std.io;
const fs = std.fs;
const os = std.os;
const process = std.process;
const File = std.fs.File;
const windows = os.windows;
const mem = std.mem;
const math = std.math;
const debug = std.debug;
const BufMap = std.BufMap;
const Os = std.builtin.Os;
const TailQueue = std.TailQueue;
const maxInt = std.math.maxInt;
const assert = std.debug.assert;

pub const ChildProcess = struct {
    pid: if (builtin.os.tag == .windows) void else i32,
    handle: if (builtin.os.tag == .windows) windows.HANDLE else void,
    thread_handle: if (builtin.os.tag == .windows) windows.HANDLE else void,

    allocator: *mem.Allocator,

    stdin: ?File,
    stdout: ?File,
    stderr: ?File,

    term: ?(SpawnError!Term),

    argv: []const []const u8,

    /// Leave as null to use the current env map using the supplied allocator.
    env_map: ?*const BufMap,

    stdin_behavior: StdIo,
    stdout_behavior: StdIo,
    stderr_behavior: StdIo,

    /// Set to change the user id when spawning the child process.
    uid: if (builtin.os.tag == .windows or builtin.os.tag == .wasi) void else ?os.uid_t,

    /// Set to change the group id when spawning the child process.
    gid: if (builtin.os.tag == .windows or builtin.os.tag == .wasi) void else ?os.gid_t,

    /// Set to change the current working directory when spawning the child process.
    cwd: ?[]const u8,
    /// Set to change the current working directory when spawning the child process.
    /// This is not yet implemented for Windows. See https://github.com/ziglang/zig/issues/5190
    /// Once that is done, `cwd` will be deprecated in favor of this field.
    cwd_dir: ?fs.Dir = null,

    err_pipe: if (builtin.os.tag == .windows) void else [2]os.fd_t,

    expand_arg0: Arg0Expand,

    pub const Arg0Expand = os.Arg0Expand;

    pub const SpawnError = error{
        OutOfMemory,

        /// POSIX-only. `StdIo.Ignore` was selected and opening `/dev/null` returned ENODEV.
        NoDevice,

        /// Windows-only. One of:
        /// * `cwd` was provided and it could not be re-encoded into UTF16LE, or
        /// * The `PATH` or `PATHEXT` environment variable contained invalid UTF-8.
        InvalidUtf8,

        /// Windows-only. `cwd` was provided, but the path did not exist when spawning the child process.
        CurrentWorkingDirectoryUnlinked,
    } || os.ExecveError || os.SetIdError || os.ChangeCurDirError || windows.CreateProcessError || windows.WaitForSingleObjectError;

    pub const Term = union(enum) {
        Exited: u8,
        Signal: u32,
        Stopped: u32,
        Unknown: u32,
    };

    pub const StdIo = enum {
        Inherit,
        Ignore,
        Pipe,
        Close,
    };

    /// First argument in argv is the executable.
    /// On success must call deinit.
    pub fn init(argv: []const []const u8, allocator: *mem.Allocator) !*ChildProcess {
        const child = try allocator.create(ChildProcess);
        child.* = ChildProcess{
            .allocator = allocator,
            .argv = argv,
            .pid = undefined,
            .handle = undefined,
            .thread_handle = undefined,
            .err_pipe = undefined,
            .term = null,
            .env_map = null,
            .cwd = null,
            .uid = if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {} else null,
            .gid = if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {} else null,
            .stdin = null,
            .stdout = null,
            .stderr = null,
            .stdin_behavior = StdIo.Inherit,
            .stdout_behavior = StdIo.Inherit,
            .stderr_behavior = StdIo.Inherit,
            .expand_arg0 = .no_expand,
        };
        errdefer allocator.destroy(child);
        return child;
    }

    pub fn setUserName(self: *ChildProcess, name: []const u8) !void {
        const user_info = try os.getUserInfo(name);
        self.uid = user_info.uid;
        self.gid = user_info.gid;
    }

    /// On success must call `kill` or `wait`.
    pub fn spawn(self: *ChildProcess) SpawnError!void {
        if (builtin.os.tag == .windows) {
            return self.spawnWindows();
        } else {
            return self.spawnPosix();
        }
    }

    pub fn spawnAndWait(self: *ChildProcess) SpawnError!Term {
        try self.spawn();
        return self.wait();
    }

    /// Forcibly terminates child process and then cleans up all resources.
    pub fn kill(self: *ChildProcess) !Term {
        if (builtin.os.tag == .windows) {
            return self.killWindows(1);
        } else {
            return self.killPosix();
        }
    }

    pub fn killWindows(self: *ChildProcess, exit_code: windows.UINT) !Term {
        if (self.term) |term| {
            self.cleanupStreams();
            return term;
        }

        try windows.TerminateProcess(self.handle, exit_code);
        try self.waitUnwrappedWindows();
        return self.term.?;
    }

    pub fn killPosix(self: *ChildProcess) !Term {
        if (self.term) |term| {
            self.cleanupStreams();
            return term;
        }
        try os.kill(self.pid, os.SIGTERM);
        self.waitUnwrapped();
        return self.term.?;
    }

    /// Blocks until child process terminates and then cleans up all resources.
    pub fn wait(self: *ChildProcess) !Term {
        if (builtin.os.tag == .windows) {
            return self.waitWindows();
        } else {
            return self.waitPosix();
        }
    }

    pub const ExecResult = struct {
        term: Term,
        stdout: []u8,
        stderr: []u8,
    };

    pub const exec2 = @compileError("deprecated: exec2 is renamed to exec");

    fn collectOutputPosix(
        child: *const ChildProcess,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
        max_output_bytes: usize,
    ) !void {
        var poll_fds = [_]os.pollfd{
            .{ .fd = child.stdout.?.handle, .events = os.POLLIN, .revents = undefined },
            .{ .fd = child.stderr.?.handle, .events = os.POLLIN, .revents = undefined },
        };

        var dead_fds: usize = 0;
        // We ask for ensureCapacity with this much extra space. This has more of an
        // effect on small reads because once the reads start to get larger the amount
        // of space an ArrayList will allocate grows exponentially.
        const bump_amt = 512;

        const err_mask = os.POLLERR | os.POLLNVAL | os.POLLHUP;

        while (dead_fds < poll_fds.len) {
            const events = try os.poll(&poll_fds, std.math.maxInt(i32));
            if (events == 0) continue;

            var remove_stdout = false;
            var remove_stderr = false;
            // Try reading whatever is available before checking the error
            // conditions.
            // It's still possible to read after a POLLHUP is received, always
            // check if there's some data waiting to be read first.
            if (poll_fds[0].revents & os.POLLIN != 0) {
                // stdout is ready.
                const new_capacity = std.math.min(stdout.items.len + bump_amt, max_output_bytes);
                try stdout.ensureCapacity(new_capacity);
                const buf = stdout.unusedCapacitySlice();
                if (buf.len == 0) return error.StdoutStreamTooLong;
                const nread = try os.read(poll_fds[0].fd, buf);
                stdout.items.len += nread;

                // Remove the fd when the EOF condition is met.
                remove_stdout = nread == 0;
            } else {
                remove_stdout = poll_fds[0].revents & err_mask != 0;
            }

            if (poll_fds[1].revents & os.POLLIN != 0) {
                // stderr is ready.
                const new_capacity = std.math.min(stderr.items.len + bump_amt, max_output_bytes);
                try stderr.ensureCapacity(new_capacity);
                const buf = stderr.unusedCapacitySlice();
                if (buf.len == 0) return error.StderrStreamTooLong;
                const nread = try os.read(poll_fds[1].fd, buf);
                stderr.items.len += nread;

                // Remove the fd when the EOF condition is met.
                remove_stderr = nread == 0;
            } else {
                remove_stderr = poll_fds[1].revents & err_mask != 0;
            }

            // Exclude the fds that signaled an error.
            if (remove_stdout) {
                poll_fds[0].fd = -1;
                dead_fds += 1;
            }
            if (remove_stderr) {
                poll_fds[1].fd = -1;
                dead_fds += 1;
            }
        }
    }

    fn collectOutputWindows(child: *const ChildProcess, outs: [2]*std.ArrayList(u8), max_output_bytes: usize) !void {
        const bump_amt = 512;
        const handles = [_]windows.HANDLE{
            child.stdout.?.handle,
            child.stderr.?.handle,
        };

        var overlapped = [_]windows.OVERLAPPED{
            mem.zeroes(windows.OVERLAPPED),
            mem.zeroes(windows.OVERLAPPED),
        };

        var wait_objects: [2]windows.HANDLE = undefined;
        var wait_object_count: u2 = 0;

        // we need to cancel all pending IO before returning so our OVERLAPPED values don't go out of scope
        defer for (wait_objects[0..wait_object_count]) |o| {
            _ = windows.kernel32.CancelIo(o);
        };

        // Windows Async IO requires an initial call to ReadFile before waiting on the handle
        for ([_]u1{ 0, 1 }) |i| {
            try outs[i].ensureCapacity(bump_amt);
            const buf = outs[i].unusedCapacitySlice();
            _ = windows.kernel32.ReadFile(handles[i], buf.ptr, math.cast(u32, buf.len) catch maxInt(u32), null, &overlapped[i]);
            wait_objects[wait_object_count] = handles[i];
            wait_object_count += 1;
        }

        while (true) {
            const status = windows.kernel32.WaitForMultipleObjects(wait_object_count, &wait_objects, 0, windows.INFINITE);
            if (status == windows.WAIT_FAILED) {
                switch (windows.kernel32.GetLastError()) {
                    else => |err| return windows.unexpectedError(err),
                }
            }
            if (status < windows.WAIT_OBJECT_0 or status > windows.WAIT_OBJECT_0 + wait_object_count - 1)
                unreachable;

            const wait_idx = status - windows.WAIT_OBJECT_0;

            // this extra `i` index is needed to map the wait handle back to the stdout or stderr
            // values since the wait_idx can change which handle it corresponds with
            const i: u1 = if (wait_objects[wait_idx] == handles[0]) 0 else 1;

            // remove completed event from the wait list
            wait_object_count -= 1;
            if (wait_idx == 0)
                wait_objects[0] = wait_objects[1];

            var read_bytes: u32 = undefined;
            if (windows.kernel32.GetOverlappedResult(handles[i], &overlapped[i], &read_bytes, 0) == 0) {
                switch (windows.kernel32.GetLastError()) {
                    .BROKEN_PIPE => {
                        if (wait_object_count == 0)
                            break;
                        continue;
                    },
                    else => |err| return windows.unexpectedError(err),
                }
            }

            outs[i].items.len += read_bytes;
            const new_capacity = std.math.min(outs[i].items.len + bump_amt, max_output_bytes);
            try outs[i].ensureCapacity(new_capacity);
            const buf = outs[i].unusedCapacitySlice();
            if (buf.len == 0) return if (i == 0) error.StdoutStreamTooLong else error.StderrStreamTooLong;
            _ = windows.kernel32.ReadFile(handles[i], buf.ptr, math.cast(u32, buf.len) catch maxInt(u32), null, &overlapped[i]);
            wait_objects[wait_object_count] = handles[i];
            wait_object_count += 1;
        }
    }

    /// Spawns a child process, waits for it, collecting stdout and stderr, and then returns.
    /// If it succeeds, the caller owns result.stdout and result.stderr memory.
    pub fn exec(args: struct {
        allocator: *mem.Allocator,
        argv: []const []const u8,
        cwd: ?[]const u8 = null,
        cwd_dir: ?fs.Dir = null,
        env_map: ?*const BufMap = null,
        max_output_bytes: usize = 50 * 1024,
        expand_arg0: Arg0Expand = .no_expand,
    }) !ExecResult {
        const child = try ChildProcess.init(args.argv, args.allocator);
        defer child.deinit();

        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.cwd = args.cwd;
        child.cwd_dir = args.cwd_dir;
        child.env_map = args.env_map;
        child.expand_arg0 = args.expand_arg0;

        try child.spawn();

        // TODO collect output in a deadlock-avoiding way on Windows.
        // https://github.com/ziglang/zig/issues/6343
        if (builtin.os.tag == .windows or builtin.os.tag == .haiku) {
            const stdout_in = child.stdout.?.reader();
            const stderr_in = child.stderr.?.reader();

            const stdout = try stdout_in.readAllAlloc(args.allocator, args.max_output_bytes);
            errdefer args.allocator.free(stdout);
            const stderr = try stderr_in.readAllAlloc(args.allocator, args.max_output_bytes);
            errdefer args.allocator.free(stderr);

            return ExecResult{
                .term = try child.wait(),
                .stdout = stdout,
                .stderr = stderr,
            };
        }

        var stdout = std.ArrayList(u8).init(args.allocator);
        var stderr = std.ArrayList(u8).init(args.allocator);
        errdefer {
            stdout.deinit();
            stderr.deinit();
        }

        if (builtin.os.tag == .windows) {
            try collectOutputWindows(child, [_]*std.ArrayList(u8){ &stdout, &stderr }, args.max_output_bytes);
        } else {
            try collectOutputPosix(child, &stdout, &stderr, args.max_output_bytes);
        }

        return ExecResult{
            .term = try child.wait(),
            .stdout = stdout.toOwnedSlice(),
            .stderr = stderr.toOwnedSlice(),
        };
    }

    fn waitWindows(self: *ChildProcess) !Term {
        if (self.term) |term| {
            self.cleanupStreams();
            return term;
        }

        try self.waitUnwrappedWindows();
        return self.term.?;
    }

    fn waitPosix(self: *ChildProcess) !Term {
        if (self.term) |term| {
            self.cleanupStreams();
            return term;
        }

        self.waitUnwrapped();
        return self.term.?;
    }

    pub fn deinit(self: *ChildProcess) void {
        self.allocator.destroy(self);
    }

    fn waitUnwrappedWindows(self: *ChildProcess) !void {
        const result = windows.WaitForSingleObjectEx(self.handle, windows.INFINITE, false);

        self.term = @as(SpawnError!Term, x: {
            var exit_code: windows.DWORD = undefined;
            if (windows.kernel32.GetExitCodeProcess(self.handle, &exit_code) == 0) {
                break :x Term{ .Unknown = 0 };
            } else {
                break :x Term{ .Exited = @truncate(u8, exit_code) };
            }
        });

        os.close(self.handle);
        os.close(self.thread_handle);
        self.cleanupStreams();
        return result;
    }

    fn waitUnwrapped(self: *ChildProcess) void {
        const status = os.waitpid(self.pid, 0).status;
        self.cleanupStreams();
        self.handleWaitResult(status);
    }

    fn handleWaitResult(self: *ChildProcess, status: u32) void {
        self.term = self.cleanupAfterWait(status);
    }

    fn cleanupStreams(self: *ChildProcess) void {
        if (self.stdin) |*stdin| {
            stdin.close();
            self.stdin = null;
        }
        if (self.stdout) |*stdout| {
            stdout.close();
            self.stdout = null;
        }
        if (self.stderr) |*stderr| {
            stderr.close();
            self.stderr = null;
        }
    }

    fn cleanupAfterWait(self: *ChildProcess, status: u32) !Term {
        defer destroyPipe(self.err_pipe);

        if (builtin.os.tag == .linux) {
            var fd = [1]std.os.pollfd{std.os.pollfd{
                .fd = self.err_pipe[0],
                .events = std.os.POLLIN,
                .revents = undefined,
            }};

            // Check if the eventfd buffer stores a non-zero value by polling
            // it, that's the error code returned by the child process.
            _ = std.os.poll(&fd, 0) catch unreachable;

            // According to eventfd(2) the descriptro is readable if the counter
            // has a value greater than 0
            if ((fd[0].revents & std.os.POLLIN) != 0) {
                const err_int = try readIntFd(self.err_pipe[0]);
                return @errSetCast(SpawnError, @intToError(err_int));
            }
        } else {
            // Write maxInt(ErrInt) to the write end of the err_pipe. This is after
            // waitpid, so this write is guaranteed to be after the child
            // pid potentially wrote an error. This way we can do a blocking
            // read on the error pipe and either get maxInt(ErrInt) (no error) or
            // an error code.
            try writeIntFd(self.err_pipe[1], maxInt(ErrInt));
            const err_int = try readIntFd(self.err_pipe[0]);
            // Here we potentially return the fork child's error from the parent
            // pid.
            if (err_int != maxInt(ErrInt)) {
                return @errSetCast(SpawnError, @intToError(err_int));
            }
        }

        return statusToTerm(status);
    }

    fn statusToTerm(status: u32) Term {
        return if (os.WIFEXITED(status))
            Term{ .Exited = os.WEXITSTATUS(status) }
        else if (os.WIFSIGNALED(status))
            Term{ .Signal = os.WTERMSIG(status) }
        else if (os.WIFSTOPPED(status))
            Term{ .Stopped = os.WSTOPSIG(status) }
        else
            Term{ .Unknown = status };
    }

    fn spawnPosix(self: *ChildProcess) SpawnError!void {
        const pipe_flags = if (io.is_async) os.O_NONBLOCK else 0;
        const stdin_pipe = if (self.stdin_behavior == StdIo.Pipe) try os.pipe2(pipe_flags) else undefined;
        errdefer if (self.stdin_behavior == StdIo.Pipe) {
            destroyPipe(stdin_pipe);
        };

        const stdout_pipe = if (self.stdout_behavior == StdIo.Pipe) try os.pipe2(pipe_flags) else undefined;
        errdefer if (self.stdout_behavior == StdIo.Pipe) {
            destroyPipe(stdout_pipe);
        };

        const stderr_pipe = if (self.stderr_behavior == StdIo.Pipe) try os.pipe2(pipe_flags) else undefined;
        errdefer if (self.stderr_behavior == StdIo.Pipe) {
            destroyPipe(stderr_pipe);
        };

        const any_ignore = (self.stdin_behavior == StdIo.Ignore or self.stdout_behavior == StdIo.Ignore or self.stderr_behavior == StdIo.Ignore);
        const dev_null_fd = if (any_ignore)
            os.openZ("/dev/null", os.O_RDWR, 0) catch |err| switch (err) {
                error.PathAlreadyExists => unreachable,
                error.NoSpaceLeft => unreachable,
                error.FileTooBig => unreachable,
                error.DeviceBusy => unreachable,
                error.FileLocksNotSupported => unreachable,
                error.BadPathName => unreachable, // Windows-only
                error.WouldBlock => unreachable,
                else => |e| return e,
            }
        else
            undefined;
        defer {
            if (any_ignore) os.close(dev_null_fd);
        }

        var arena_allocator = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_allocator.deinit();
        const arena = &arena_allocator.allocator;

        // The POSIX standard does not allow malloc() between fork() and execve(),
        // and `self.allocator` may be a libc allocator.
        // I have personally observed the child process deadlocking when it tries
        // to call malloc() due to a heap allocation between fork() and execve(),
        // in musl v1.1.24.
        // Additionally, we want to reduce the number of possible ways things
        // can fail between fork() and execve().
        // Therefore, we do all the allocation for the execve() before the fork().
        // This means we must do the null-termination of argv and env vars here.
        const argv_buf = try arena.allocSentinel(?[*:0]u8, self.argv.len, null);
        for (self.argv) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;

        const envp = m: {
            if (self.env_map) |env_map| {
                const envp_buf = try createNullDelimitedEnvMap(arena, env_map);
                break :m envp_buf.ptr;
            } else if (builtin.link_libc) {
                break :m std.c.environ;
            } else if (builtin.output_mode == .Exe) {
                // Then we have Zig start code and this works.
                // TODO type-safety for null-termination of `os.environ`.
                break :m @ptrCast([*:null]?[*:0]u8, os.environ.ptr);
            } else {
                // TODO come up with a solution for this.
                @compileError("missing std lib enhancement: ChildProcess implementation has no way to collect the environment variables to forward to the child process");
            }
        };

        // This pipe is used to communicate errors between the time of fork
        // and execve from the child process to the parent process.
        const err_pipe = blk: {
            if (builtin.os.tag == .linux) {
                const fd = try os.eventfd(0, os.EFD_CLOEXEC);
                // There's no distinction between the readable and the writeable
                // end with eventfd
                break :blk [2]os.fd_t{ fd, fd };
            } else {
                break :blk try os.pipe2(os.O_CLOEXEC);
            }
        };
        errdefer destroyPipe(err_pipe);

        const pid_result = try os.fork();
        if (pid_result == 0) {
            // we are the child
            setUpChildIo(self.stdin_behavior, stdin_pipe[0], os.STDIN_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);
            setUpChildIo(self.stdout_behavior, stdout_pipe[1], os.STDOUT_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);
            setUpChildIo(self.stderr_behavior, stderr_pipe[1], os.STDERR_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);

            if (self.stdin_behavior == .Pipe) {
                os.close(stdin_pipe[0]);
                os.close(stdin_pipe[1]);
            }
            if (self.stdout_behavior == .Pipe) {
                os.close(stdout_pipe[0]);
                os.close(stdout_pipe[1]);
            }
            if (self.stderr_behavior == .Pipe) {
                os.close(stderr_pipe[0]);
                os.close(stderr_pipe[1]);
            }

            if (self.cwd_dir) |cwd| {
                os.fchdir(cwd.fd) catch |err| forkChildErrReport(err_pipe[1], err);
            } else if (self.cwd) |cwd| {
                os.chdir(cwd) catch |err| forkChildErrReport(err_pipe[1], err);
            }

            if (self.gid) |gid| {
                os.setregid(gid, gid) catch |err| forkChildErrReport(err_pipe[1], err);
            }

            if (self.uid) |uid| {
                os.setreuid(uid, uid) catch |err| forkChildErrReport(err_pipe[1], err);
            }

            const err = switch (self.expand_arg0) {
                .expand => os.execvpeZ_expandArg0(.expand, argv_buf.ptr[0].?, argv_buf.ptr, envp),
                .no_expand => os.execvpeZ_expandArg0(.no_expand, argv_buf.ptr[0].?, argv_buf.ptr, envp),
            };
            forkChildErrReport(err_pipe[1], err);
        }

        // we are the parent
        const pid = @intCast(i32, pid_result);
        if (self.stdin_behavior == StdIo.Pipe) {
            self.stdin = File{ .handle = stdin_pipe[1] };
        } else {
            self.stdin = null;
        }
        if (self.stdout_behavior == StdIo.Pipe) {
            self.stdout = File{ .handle = stdout_pipe[0] };
        } else {
            self.stdout = null;
        }
        if (self.stderr_behavior == StdIo.Pipe) {
            self.stderr = File{ .handle = stderr_pipe[0] };
        } else {
            self.stderr = null;
        }

        self.pid = pid;
        self.err_pipe = err_pipe;
        self.term = null;

        if (self.stdin_behavior == StdIo.Pipe) {
            os.close(stdin_pipe[0]);
        }
        if (self.stdout_behavior == StdIo.Pipe) {
            os.close(stdout_pipe[1]);
        }
        if (self.stderr_behavior == StdIo.Pipe) {
            os.close(stderr_pipe[1]);
        }
    }

    fn spawnWindows(self: *ChildProcess) SpawnError!void {
        const saAttr = windows.SECURITY_ATTRIBUTES{
            .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
            .bInheritHandle = windows.TRUE,
            .lpSecurityDescriptor = null,
        };

        const any_ignore = (self.stdin_behavior == StdIo.Ignore or self.stdout_behavior == StdIo.Ignore or self.stderr_behavior == StdIo.Ignore);

        const nul_handle = if (any_ignore)
            // "\Device\Null" or "\??\NUL"
            windows.OpenFile(&[_]u16{ '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 'u', 'l', 'l' }, .{
                .access_mask = windows.GENERIC_READ | windows.SYNCHRONIZE,
                .share_access = windows.FILE_SHARE_READ,
                .creation = windows.OPEN_EXISTING,
                .io_mode = .blocking,
            }) catch |err| switch (err) {
                error.PathAlreadyExists => unreachable, // not possible for "NUL"
                error.PipeBusy => unreachable, // not possible for "NUL"
                error.FileNotFound => unreachable, // not possible for "NUL"
                error.AccessDenied => unreachable, // not possible for "NUL"
                error.NameTooLong => unreachable, // not possible for "NUL"
                error.WouldBlock => unreachable, // not possible for "NUL"
                else => |e| return e,
            }
        else
            undefined;
        defer {
            if (any_ignore) os.close(nul_handle);
        }
        if (any_ignore) {
            try windows.SetHandleInformation(nul_handle, windows.HANDLE_FLAG_INHERIT, 0);
        }

        var g_hChildStd_IN_Rd: ?windows.HANDLE = null;
        var g_hChildStd_IN_Wr: ?windows.HANDLE = null;
        switch (self.stdin_behavior) {
            StdIo.Pipe => {
                try windowsMakePipeIn(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr);
            },
            StdIo.Ignore => {
                g_hChildStd_IN_Rd = nul_handle;
            },
            StdIo.Inherit => {
                g_hChildStd_IN_Rd = windows.GetStdHandle(windows.STD_INPUT_HANDLE) catch null;
            },
            StdIo.Close => {
                g_hChildStd_IN_Rd = null;
            },
        }
        errdefer if (self.stdin_behavior == StdIo.Pipe) {
            windowsDestroyPipe(g_hChildStd_IN_Rd, g_hChildStd_IN_Wr);
        };

        var g_hChildStd_OUT_Rd: ?windows.HANDLE = null;
        var g_hChildStd_OUT_Wr: ?windows.HANDLE = null;
        switch (self.stdout_behavior) {
            StdIo.Pipe => {
                try windowsMakeAsyncPipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr);
            },
            StdIo.Ignore => {
                g_hChildStd_OUT_Wr = nul_handle;
            },
            StdIo.Inherit => {
                g_hChildStd_OUT_Wr = windows.GetStdHandle(windows.STD_OUTPUT_HANDLE) catch null;
            },
            StdIo.Close => {
                g_hChildStd_OUT_Wr = null;
            },
        }
        errdefer if (self.stdin_behavior == StdIo.Pipe) {
            windowsDestroyPipe(g_hChildStd_OUT_Rd, g_hChildStd_OUT_Wr);
        };

        var g_hChildStd_ERR_Rd: ?windows.HANDLE = null;
        var g_hChildStd_ERR_Wr: ?windows.HANDLE = null;
        switch (self.stderr_behavior) {
            StdIo.Pipe => {
                try windowsMakeAsyncPipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &saAttr);
            },
            StdIo.Ignore => {
                g_hChildStd_ERR_Wr = nul_handle;
            },
            StdIo.Inherit => {
                g_hChildStd_ERR_Wr = windows.GetStdHandle(windows.STD_ERROR_HANDLE) catch null;
            },
            StdIo.Close => {
                g_hChildStd_ERR_Wr = null;
            },
        }
        errdefer if (self.stdin_behavior == StdIo.Pipe) {
            windowsDestroyPipe(g_hChildStd_ERR_Rd, g_hChildStd_ERR_Wr);
        };

        const cmd_line = try windowsCreateCommandLine(self.allocator, self.argv);
        defer self.allocator.free(cmd_line);

        var siStartInfo = windows.STARTUPINFOW{
            .cb = @sizeOf(windows.STARTUPINFOW),
            .hStdError = g_hChildStd_ERR_Wr,
            .hStdOutput = g_hChildStd_OUT_Wr,
            .hStdInput = g_hChildStd_IN_Rd,
            .dwFlags = windows.STARTF_USESTDHANDLES,

            .lpReserved = null,
            .lpDesktop = null,
            .lpTitle = null,
            .dwX = 0,
            .dwY = 0,
            .dwXSize = 0,
            .dwYSize = 0,
            .dwXCountChars = 0,
            .dwYCountChars = 0,
            .dwFillAttribute = 0,
            .wShowWindow = 0,
            .cbReserved2 = 0,
            .lpReserved2 = null,
        };
        var piProcInfo: windows.PROCESS_INFORMATION = undefined;

        const cwd_w = if (self.cwd) |cwd| try unicode.utf8ToUtf16LeWithNull(self.allocator, cwd) else null;
        defer if (cwd_w) |cwd| self.allocator.free(cwd);
        const cwd_w_ptr = if (cwd_w) |cwd| cwd.ptr else null;

        const maybe_envp_buf = if (self.env_map) |env_map| try createWindowsEnvBlock(self.allocator, env_map) else null;
        defer if (maybe_envp_buf) |envp_buf| self.allocator.free(envp_buf);
        const envp_ptr = if (maybe_envp_buf) |envp_buf| envp_buf.ptr else null;

        // the cwd set in ChildProcess is in effect when choosing the executable path
        // to match posix semantics
        const app_path = x: {
            if (self.cwd) |cwd| {
                const resolved = try fs.path.resolve(self.allocator, &[_][]const u8{ cwd, self.argv[0] });
                defer self.allocator.free(resolved);
                break :x try cstr.addNullByte(self.allocator, resolved);
            } else {
                break :x try cstr.addNullByte(self.allocator, self.argv[0]);
            }
        };
        defer self.allocator.free(app_path);

        const app_path_w = try unicode.utf8ToUtf16LeWithNull(self.allocator, app_path);
        defer self.allocator.free(app_path_w);

        const cmd_line_w = try unicode.utf8ToUtf16LeWithNull(self.allocator, cmd_line);
        defer self.allocator.free(cmd_line_w);

        windowsCreateProcess(app_path_w.ptr, cmd_line_w.ptr, envp_ptr, cwd_w_ptr, &siStartInfo, &piProcInfo) catch |no_path_err| {
            if (no_path_err != error.FileNotFound) return no_path_err;

            var free_path = true;
            const PATH = process.getEnvVarOwned(self.allocator, "PATH") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => blk: {
                    free_path = false;
                    break :blk "";
                },
                else => |e| return e,
            };
            defer if (free_path) self.allocator.free(PATH);

            var free_path_ext = true;
            const PATHEXT = process.getEnvVarOwned(self.allocator, "PATHEXT") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => blk: {
                    free_path_ext = false;
                    break :blk "";
                },
                else => |e| return e,
            };
            defer if (free_path_ext) self.allocator.free(PATHEXT);

            const app_name = self.argv[0];

            var it = mem.tokenize(PATH, ";");
            retry: while (it.next()) |search_path| {
                const path_no_ext = try fs.path.join(self.allocator, &[_][]const u8{ search_path, app_name });
                defer self.allocator.free(path_no_ext);

                var ext_it = mem.tokenize(PATHEXT, ";");
                while (ext_it.next()) |app_ext| {
                    const joined_path = try mem.concat(self.allocator, u8, &[_][]const u8{ path_no_ext, app_ext });
                    defer self.allocator.free(joined_path);

                    const joined_path_w = try unicode.utf8ToUtf16LeWithNull(self.allocator, joined_path);
                    defer self.allocator.free(joined_path_w);

                    if (windowsCreateProcess(joined_path_w.ptr, cmd_line_w.ptr, envp_ptr, cwd_w_ptr, &siStartInfo, &piProcInfo)) |_| {
                        break :retry;
                    } else |err| switch (err) {
                        error.FileNotFound => continue,
                        error.AccessDenied => continue,
                        else => return err,
                    }
                }
            } else {
                return no_path_err; // return the original error
            }
        };

        if (g_hChildStd_IN_Wr) |h| {
            self.stdin = File{ .handle = h };
        } else {
            self.stdin = null;
        }
        if (g_hChildStd_OUT_Rd) |h| {
            self.stdout = File{ .handle = h };
        } else {
            self.stdout = null;
        }
        if (g_hChildStd_ERR_Rd) |h| {
            self.stderr = File{ .handle = h };
        } else {
            self.stderr = null;
        }

        self.handle = piProcInfo.hProcess;
        self.thread_handle = piProcInfo.hThread;
        self.term = null;

        if (self.stdin_behavior == StdIo.Pipe) {
            os.close(g_hChildStd_IN_Rd.?);
        }
        if (self.stderr_behavior == StdIo.Pipe) {
            os.close(g_hChildStd_ERR_Wr.?);
        }
        if (self.stdout_behavior == StdIo.Pipe) {
            os.close(g_hChildStd_OUT_Wr.?);
        }
    }

    fn setUpChildIo(stdio: StdIo, pipe_fd: i32, std_fileno: i32, dev_null_fd: i32) !void {
        switch (stdio) {
            .Pipe => try os.dup2(pipe_fd, std_fileno),
            .Close => os.close(std_fileno),
            .Inherit => {},
            .Ignore => try os.dup2(dev_null_fd, std_fileno),
        }
    }
};

fn windowsCreateProcess(app_name: [*:0]u16, cmd_line: [*:0]u16, envp_ptr: ?[*]u16, cwd_ptr: ?[*:0]u16, lpStartupInfo: *windows.STARTUPINFOW, lpProcessInformation: *windows.PROCESS_INFORMATION) !void {
    // TODO the docs for environment pointer say:
    // > A pointer to the environment block for the new process. If this parameter
    // > is NULL, the new process uses the environment of the calling process.
    // > ...
    // > An environment block can contain either Unicode or ANSI characters. If
    // > the environment block pointed to by lpEnvironment contains Unicode
    // > characters, be sure that dwCreationFlags includes CREATE_UNICODE_ENVIRONMENT.
    // > If this parameter is NULL and the environment block of the parent process
    // > contains Unicode characters, you must also ensure that dwCreationFlags
    // > includes CREATE_UNICODE_ENVIRONMENT.
    // This seems to imply that we have to somehow know whether our process parent passed
    // CREATE_UNICODE_ENVIRONMENT if we want to pass NULL for the environment parameter.
    // Since we do not know this information that would imply that we must not pass NULL
    // for the parameter.
    // However this would imply that programs compiled with -DUNICODE could not pass
    // environment variables to programs that were not, which seems unlikely.
    // More investigation is needed.
    return windows.CreateProcessW(
        app_name,
        cmd_line,
        null,
        null,
        windows.TRUE,
        windows.CREATE_UNICODE_ENVIRONMENT,
        @ptrCast(?*c_void, envp_ptr),
        cwd_ptr,
        lpStartupInfo,
        lpProcessInformation,
    );
}

/// Caller must dealloc.
fn windowsCreateCommandLine(allocator: *mem.Allocator, argv: []const []const u8) ![:0]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    for (argv) |arg, arg_i| {
        if (arg_i != 0) try buf.append(' ');
        if (mem.indexOfAny(u8, arg, " \t\n\"") == null) {
            try buf.appendSlice(arg);
            continue;
        }
        try buf.append('"');
        var backslash_count: usize = 0;
        for (arg) |byte| {
            switch (byte) {
                '\\' => backslash_count += 1,
                '"' => {
                    try buf.appendNTimes('\\', backslash_count * 2 + 1);
                    try buf.append('"');
                    backslash_count = 0;
                },
                else => {
                    try buf.appendNTimes('\\', backslash_count);
                    try buf.append(byte);
                    backslash_count = 0;
                },
            }
        }
        try buf.appendNTimes('\\', backslash_count * 2);
        try buf.append('"');
    }

    return buf.toOwnedSliceSentinel(0);
}

fn windowsDestroyPipe(rd: ?windows.HANDLE, wr: ?windows.HANDLE) void {
    if (rd) |h| os.close(h);
    if (wr) |h| os.close(h);
}

fn windowsMakePipeIn(rd: *?windows.HANDLE, wr: *?windows.HANDLE, sattr: *const windows.SECURITY_ATTRIBUTES) !void {
    var rd_h: windows.HANDLE = undefined;
    var wr_h: windows.HANDLE = undefined;
    try windows.CreatePipe(&rd_h, &wr_h, sattr);
    errdefer windowsDestroyPipe(rd_h, wr_h);
    try windows.SetHandleInformation(wr_h, windows.HANDLE_FLAG_INHERIT, 0);
    rd.* = rd_h;
    wr.* = wr_h;
}

var pipe_name_counter = std.atomic.Atomic(u32).init(1);

fn windowsMakeAsyncPipe(rd: *?windows.HANDLE, wr: *?windows.HANDLE, sattr: *const windows.SECURITY_ATTRIBUTES) !void {
    var tmp_bufw: [128]u16 = undefined;

    // We must make a named pipe on windows because anonymous pipes do not support async IO
    const pipe_path = blk: {
        var tmp_buf: [128]u8 = undefined;
        // Forge a random path for the pipe.
        const pipe_path = std.fmt.bufPrintZ(
            &tmp_buf,
            "\\\\.\\pipe\\zig-childprocess-{d}-{d}",
            .{ windows.kernel32.GetCurrentProcessId(), pipe_name_counter.fetchAdd(1, .Monotonic) },
        ) catch unreachable;
        const len = std.unicode.utf8ToUtf16Le(&tmp_bufw, pipe_path) catch unreachable;
        tmp_bufw[len] = 0;
        break :blk tmp_bufw[0..len :0];
    };

    // Create the read handle that can be used with overlapped IO ops.
    const read_handle = windows.kernel32.CreateNamedPipeW(
        pipe_path.ptr,
        windows.PIPE_ACCESS_INBOUND | windows.FILE_FLAG_OVERLAPPED,
        windows.PIPE_TYPE_BYTE,
        1,
        4096,
        4096,
        0,
        sattr,
    );
    if (read_handle == windows.INVALID_HANDLE_VALUE) {
        switch (windows.kernel32.GetLastError()) {
            else => |err| return windows.unexpectedError(err),
        }
    }
    errdefer os.close(read_handle);

    var sattr_copy = sattr.*;
    const write_handle = windows.kernel32.CreateFileW(
        pipe_path.ptr,
        windows.GENERIC_WRITE,
        0,
        &sattr_copy,
        windows.OPEN_EXISTING,
        windows.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (write_handle == windows.INVALID_HANDLE_VALUE) {
        switch (windows.kernel32.GetLastError()) {
            else => |err| return windows.unexpectedError(err),
        }
    }
    errdefer os.close(write_handle);

    try windows.SetHandleInformation(read_handle, windows.HANDLE_FLAG_INHERIT, 0);

    rd.* = read_handle;
    wr.* = write_handle;
}

fn destroyPipe(pipe: [2]os.fd_t) void {
    os.close(pipe[0]);
    if (pipe[0] != pipe[1]) os.close(pipe[1]);
}

// Child of fork calls this to report an error to the fork parent.
// Then the child exits.
fn forkChildErrReport(fd: i32, err: ChildProcess.SpawnError) noreturn {
    writeIntFd(fd, @as(ErrInt, @errorToInt(err))) catch {};
    // If we're linking libc, some naughty applications may have registered atexit handlers
    // which we really do not want to run in the fork child. I caught LLVM doing this and
    // it caused a deadlock instead of doing an exit syscall. In the words of Avril Lavigne,
    // "Why'd you have to go and make things so complicated?"
    if (builtin.link_libc) {
        // The _exit(2) function does nothing but make the exit syscall, unlike exit(3)
        std.c._exit(1);
    }
    os.exit(1);
}

const ErrInt = std.meta.Int(.unsigned, @sizeOf(anyerror) * 8);

fn writeIntFd(fd: i32, value: ErrInt) !void {
    const file = File{
        .handle = fd,
        .capable_io_mode = .blocking,
        .intended_io_mode = .blocking,
    };
    file.writer().writeIntNative(u64, @intCast(u64, value)) catch return error.SystemResources;
}

fn readIntFd(fd: i32) !ErrInt {
    const file = File{
        .handle = fd,
        .capable_io_mode = .blocking,
        .intended_io_mode = .blocking,
    };
    return @intCast(ErrInt, file.reader().readIntNative(u64) catch return error.SystemResources);
}

/// Caller must free result.
pub fn createWindowsEnvBlock(allocator: *mem.Allocator, env_map: *const BufMap) ![]u16 {
    // count bytes needed
    const max_chars_needed = x: {
        var max_chars_needed: usize = 4; // 4 for the final 4 null bytes
        var it = env_map.iterator();
        while (it.next()) |pair| {
            // +1 for '='
            // +1 for null byte
            max_chars_needed += pair.key_ptr.len + pair.value_ptr.len + 2;
        }
        break :x max_chars_needed;
    };
    const result = try allocator.alloc(u16, max_chars_needed);
    errdefer allocator.free(result);

    var it = env_map.iterator();
    var i: usize = 0;
    while (it.next()) |pair| {
        i += try unicode.utf8ToUtf16Le(result[i..], pair.key_ptr.*);
        result[i] = '=';
        i += 1;
        i += try unicode.utf8ToUtf16Le(result[i..], pair.value_ptr.*);
        result[i] = 0;
        i += 1;
    }
    result[i] = 0;
    i += 1;
    result[i] = 0;
    i += 1;
    result[i] = 0;
    i += 1;
    result[i] = 0;
    i += 1;
    return allocator.shrink(result, i);
}

pub fn createNullDelimitedEnvMap(arena: *mem.Allocator, env_map: *const std.BufMap) ![:null]?[*:0]u8 {
    const envp_count = env_map.count();
    const envp_buf = try arena.allocSentinel(?[*:0]u8, envp_count, null);
    {
        var it = env_map.iterator();
        var i: usize = 0;
        while (it.next()) |pair| : (i += 1) {
            const env_buf = try arena.allocSentinel(u8, pair.key_ptr.len + pair.value_ptr.len + 1, 0);
            mem.copy(u8, env_buf, pair.key_ptr.*);
            env_buf[pair.key_ptr.len] = '=';
            mem.copy(u8, env_buf[pair.key_ptr.len + 1 ..], pair.value_ptr.*);
            envp_buf[i] = env_buf.ptr;
        }
        assert(i == envp_count);
    }
    return envp_buf;
}

test "createNullDelimitedEnvMap" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var envmap = BufMap.init(allocator);
    defer envmap.deinit();

    try envmap.put("HOME", "/home/ifreund");
    try envmap.put("WAYLAND_DISPLAY", "wayland-1");
    try envmap.put("DISPLAY", ":1");
    try envmap.put("DEBUGINFOD_URLS", " ");
    try envmap.put("XCURSOR_SIZE", "24");

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const environ = try createNullDelimitedEnvMap(&arena.allocator, &envmap);

    try testing.expectEqual(@as(usize, 5), environ.len);

    inline for (.{
        "HOME=/home/ifreund",
        "WAYLAND_DISPLAY=wayland-1",
        "DISPLAY=:1",
        "DEBUGINFOD_URLS= ",
        "XCURSOR_SIZE=24",
    }) |target| {
        for (environ) |variable| {
            if (mem.eql(u8, mem.span(variable orelse continue), target)) break;
        } else {
            try testing.expect(false); // Environment variable not found
        }
    }
}
