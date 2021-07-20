// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const os = std.os;
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectError = testing.expectError;
const io = std.io;
const fs = std.fs;
const mem = std.mem;
const elf = std.elf;
const File = std.fs.File;
const Thread = std.Thread;

const a = std.testing.allocator;

const builtin = @import("builtin");
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const AtomicOrder = std.builtin.AtomicOrder;
const native_os = builtin.os.tag;
const tmpDir = std.testing.tmpDir;
const Dir = std.fs.Dir;
const ArenaAllocator = std.heap.ArenaAllocator;

test "chdir smoke test" {
    if (native_os == .wasi) return error.SkipZigTest;

    // Get current working directory path
    var old_cwd_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const old_cwd = try os.getcwd(old_cwd_buf[0..]);

    {
        // Firstly, changing to itself should have no effect
        try os.chdir(old_cwd);
        var new_cwd_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
        const new_cwd = try os.getcwd(new_cwd_buf[0..]);
        try expect(mem.eql(u8, old_cwd, new_cwd));
    }
    {
        // Next, change current working directory to one level above
        const parent = fs.path.dirname(old_cwd) orelse unreachable; // old_cwd should be absolute
        try os.chdir(parent);
        // Restore cwd because process may have other tests that do not tolerate chdir.
        defer os.chdir(old_cwd) catch unreachable;
        var new_cwd_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
        const new_cwd = try os.getcwd(new_cwd_buf[0..]);
        try expect(mem.eql(u8, parent, new_cwd));
    }
}

test "open smoke test" {
    if (native_os == .wasi) return error.SkipZigTest;

    // TODO verify file attributes using `fstat`

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // Get base abs path
    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const base_path = blk: {
        const relative_path = try fs.path.join(&arena.allocator, &[_][]const u8{ "zig-cache", "tmp", tmp.sub_path[0..] });
        break :blk try fs.realpathAlloc(&arena.allocator, relative_path);
    };

    var file_path: []u8 = undefined;
    var fd: os.fd_t = undefined;
    const mode: os.mode_t = if (native_os == .windows) 0 else 0o666;

    // Create some file using `open`.
    file_path = try fs.path.join(&arena.allocator, &[_][]const u8{ base_path, "some_file" });
    fd = try os.open(file_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, mode);
    os.close(fd);

    // Try this again with the same flags. This op should fail with error.PathAlreadyExists.
    file_path = try fs.path.join(&arena.allocator, &[_][]const u8{ base_path, "some_file" });
    try expectError(error.PathAlreadyExists, os.open(file_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, mode));

    // Try opening without `O_EXCL` flag.
    file_path = try fs.path.join(&arena.allocator, &[_][]const u8{ base_path, "some_file" });
    fd = try os.open(file_path, os.O_RDWR | os.O_CREAT, mode);
    os.close(fd);

    // Try opening as a directory which should fail.
    file_path = try fs.path.join(&arena.allocator, &[_][]const u8{ base_path, "some_file" });
    try expectError(error.NotDir, os.open(file_path, os.O_RDWR | os.O_DIRECTORY, mode));

    // Create some directory
    file_path = try fs.path.join(&arena.allocator, &[_][]const u8{ base_path, "some_dir" });
    try os.mkdir(file_path, mode);

    // Open dir using `open`
    file_path = try fs.path.join(&arena.allocator, &[_][]const u8{ base_path, "some_dir" });
    fd = try os.open(file_path, os.O_RDONLY | os.O_DIRECTORY, mode);
    os.close(fd);

    // Try opening as file which should fail.
    file_path = try fs.path.join(&arena.allocator, &[_][]const u8{ base_path, "some_dir" });
    try expectError(error.IsDir, os.open(file_path, os.O_RDWR, mode));
}

test "openat smoke test" {
    if (native_os == .wasi) return error.SkipZigTest;

    // TODO verify file attributes using `fstatat`

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var fd: os.fd_t = undefined;
    const mode: os.mode_t = if (native_os == .windows) 0 else 0o666;

    // Create some file using `openat`.
    fd = try os.openat(tmp.dir.fd, "some_file", os.O_RDWR | os.O_CREAT | os.O_EXCL, mode);
    os.close(fd);

    // Try this again with the same flags. This op should fail with error.PathAlreadyExists.
    try expectError(error.PathAlreadyExists, os.openat(tmp.dir.fd, "some_file", os.O_RDWR | os.O_CREAT | os.O_EXCL, mode));

    // Try opening without `O_EXCL` flag.
    fd = try os.openat(tmp.dir.fd, "some_file", os.O_RDWR | os.O_CREAT, mode);
    os.close(fd);

    // Try opening as a directory which should fail.
    try expectError(error.NotDir, os.openat(tmp.dir.fd, "some_file", os.O_RDWR | os.O_DIRECTORY, mode));

    // Create some directory
    try os.mkdirat(tmp.dir.fd, "some_dir", mode);

    // Open dir using `open`
    fd = try os.openat(tmp.dir.fd, "some_dir", os.O_RDONLY | os.O_DIRECTORY, mode);
    os.close(fd);

    // Try opening as file which should fail.
    try expectError(error.IsDir, os.openat(tmp.dir.fd, "some_dir", os.O_RDWR, mode));
}

test "symlink with relative paths" {
    if (native_os == .wasi) return error.SkipZigTest;

    const cwd = fs.cwd();
    cwd.deleteFile("file.txt") catch {};
    cwd.deleteFile("symlinked") catch {};

    // First, try relative paths in cwd
    try cwd.writeFile("file.txt", "nonsense");

    if (native_os == .windows) {
        os.windows.CreateSymbolicLink(
            cwd.fd,
            &[_]u16{ 's', 'y', 'm', 'l', 'i', 'n', 'k', 'e', 'd' },
            &[_]u16{ 'f', 'i', 'l', 'e', '.', 't', 'x', 't' },
            false,
        ) catch |err| switch (err) {
            // Symlink requires admin privileges on windows, so this test can legitimately fail.
            error.AccessDenied => {
                try cwd.deleteFile("file.txt");
                try cwd.deleteFile("symlinked");
                return error.SkipZigTest;
            },
            else => return err,
        };
    } else {
        try os.symlink("file.txt", "symlinked");
    }

    var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
    const given = try os.readlink("symlinked", buffer[0..]);
    try expect(mem.eql(u8, "file.txt", given));

    try cwd.deleteFile("file.txt");
    try cwd.deleteFile("symlinked");
}

test "readlink on Windows" {
    if (native_os != .windows) return error.SkipZigTest;

    try testReadlink("C:\\ProgramData", "C:\\Users\\All Users");
    try testReadlink("C:\\Users\\Default", "C:\\Users\\Default User");
    try testReadlink("C:\\Users", "C:\\Documents and Settings");
}

fn testReadlink(target_path: []const u8, symlink_path: []const u8) !void {
    var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
    const given = try os.readlink(symlink_path, buffer[0..]);
    try expect(mem.eql(u8, target_path, given));
}

test "link with relative paths" {
    if (native_os != .linux) return error.SkipZigTest;
    var cwd = fs.cwd();

    cwd.deleteFile("example.txt") catch {};
    cwd.deleteFile("new.txt") catch {};

    try cwd.writeFile("example.txt", "example");
    try os.link("example.txt", "new.txt", 0);

    const efd = try cwd.openFile("example.txt", .{});
    defer efd.close();

    const nfd = try cwd.openFile("new.txt", .{});
    defer nfd.close();

    {
        const estat = try os.fstat(efd.handle);
        const nstat = try os.fstat(nfd.handle);

        try testing.expectEqual(estat.ino, nstat.ino);
        try testing.expectEqual(@as(usize, 2), nstat.nlink);
    }

    try os.unlink("new.txt");

    {
        const estat = try os.fstat(efd.handle);
        try testing.expectEqual(@as(usize, 1), estat.nlink);
    }

    try cwd.deleteFile("example.txt");
}

test "linkat with different directories" {
    if (native_os != .linux) return error.SkipZigTest;
    var cwd = fs.cwd();
    var tmp = tmpDir(.{});

    cwd.deleteFile("example.txt") catch {};
    tmp.dir.deleteFile("new.txt") catch {};

    try cwd.writeFile("example.txt", "example");
    try os.linkat(cwd.fd, "example.txt", tmp.dir.fd, "new.txt", 0);

    const efd = try cwd.openFile("example.txt", .{});
    defer efd.close();

    const nfd = try tmp.dir.openFile("new.txt", .{});

    {
        defer nfd.close();
        const estat = try os.fstat(efd.handle);
        const nstat = try os.fstat(nfd.handle);

        try testing.expectEqual(estat.ino, nstat.ino);
        try testing.expectEqual(@as(usize, 2), nstat.nlink);
    }

    try os.unlinkat(tmp.dir.fd, "new.txt", 0);

    {
        const estat = try os.fstat(efd.handle);
        try testing.expectEqual(@as(usize, 1), estat.nlink);
    }

    try cwd.deleteFile("example.txt");
}

test "fstatat" {
    // enable when `fstat` and `fstatat` are implemented on Windows
    if (native_os == .windows) return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // create dummy file
    const contents = "nonsense";
    try tmp.dir.writeFile("file.txt", contents);

    // fetch file's info on the opened fd directly
    const file = try tmp.dir.openFile("file.txt", .{});
    const stat = try os.fstat(file.handle);
    defer file.close();

    // now repeat but using `fstatat` instead
    const flags = if (native_os == .wasi) 0x0 else os.AT_SYMLINK_NOFOLLOW;
    const statat = try os.fstatat(tmp.dir.fd, "file.txt", flags);
    try expectEqual(stat, statat);
}

test "readlinkat" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // create file
    try tmp.dir.writeFile("file.txt", "nonsense");

    // create a symbolic link
    if (native_os == .windows) {
        os.windows.CreateSymbolicLink(
            tmp.dir.fd,
            &[_]u16{ 'l', 'i', 'n', 'k' },
            &[_]u16{ 'f', 'i', 'l', 'e', '.', 't', 'x', 't' },
            false,
        ) catch |err| switch (err) {
            // Symlink requires admin privileges on windows, so this test can legitimately fail.
            error.AccessDenied => return error.SkipZigTest,
            else => return err,
        };
    } else {
        try os.symlinkat("file.txt", tmp.dir.fd, "link");
    }

    // read the link
    var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
    const read_link = try os.readlinkat(tmp.dir.fd, "link", buffer[0..]);
    try expect(mem.eql(u8, "file.txt", read_link));
}

fn testThreadIdFn(thread_id: *Thread.Id) void {
    thread_id.* = Thread.getCurrentId();
}

test "std.Thread.getCurrentId" {
    if (builtin.single_threaded) return error.SkipZigTest;

    var thread_current_id: Thread.Id = undefined;
    const thread = try Thread.spawn(.{}, testThreadIdFn, .{&thread_current_id});
    thread.join();
    try expect(Thread.getCurrentId() != thread_current_id);
}

test "spawn threads" {
    if (builtin.single_threaded) return error.SkipZigTest;

    var shared_ctx: i32 = 1;

    const thread1 = try Thread.spawn(.{}, start1, .{});
    const thread2 = try Thread.spawn(.{}, start2, .{&shared_ctx});
    const thread3 = try Thread.spawn(.{}, start2, .{&shared_ctx});
    const thread4 = try Thread.spawn(.{}, start2, .{&shared_ctx});

    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();

    try expect(shared_ctx == 4);
}

fn start1() u8 {
    return 0;
}

fn start2(ctx: *i32) u8 {
    _ = @atomicRmw(i32, ctx, AtomicRmwOp.Add, 1, AtomicOrder.SeqCst);
    return 0;
}

test "cpu count" {
    if (native_os == .wasi) return error.SkipZigTest;

    const cpu_count = try Thread.getCpuCount();
    try expect(cpu_count >= 1);
}

test "thread local storage" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const thread1 = try Thread.spawn(.{}, testTls, .{});
    const thread2 = try Thread.spawn(.{}, testTls, .{});
    try testTls();
    thread1.join();
    thread2.join();
}

threadlocal var x: i32 = 1234;
fn testTls() !void {
    if (x != 1234) return error.TlsBadStartValue;
    x += 1;
    if (x != 1235) return error.TlsBadEndValue;
}

test "getrandom" {
    var buf_a: [50]u8 = undefined;
    var buf_b: [50]u8 = undefined;
    try os.getrandom(&buf_a);
    try os.getrandom(&buf_b);
    // If this test fails the chance is significantly higher that there is a bug than
    // that two sets of 50 bytes were equal.
    try expect(!mem.eql(u8, &buf_a, &buf_b));
}

test "getcwd" {
    if (native_os == .wasi) return error.SkipZigTest;

    // at least call it so it gets compiled
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    _ = os.getcwd(&buf) catch undefined;
}

test "sigaltstack" {
    if (native_os == .windows or native_os == .wasi) return error.SkipZigTest;

    var st: os.stack_t = undefined;
    try os.sigaltstack(null, &st);
    // Setting a stack size less than MINSIGSTKSZ returns ENOMEM
    st.ss_flags = 0;
    st.ss_size = 1;
    try testing.expectError(error.SizeTooSmall, os.sigaltstack(&st, null));
}

// If the type is not available use void to avoid erroring out when `iter_fn` is
// analyzed
const dl_phdr_info = if (@hasDecl(os, "dl_phdr_info")) os.dl_phdr_info else c_void;

const IterFnError = error{
    MissingPtLoadSegment,
    MissingLoad,
    BadElfMagic,
    FailedConsistencyCheck,
};

fn iter_fn(info: *dl_phdr_info, size: usize, counter: *usize) IterFnError!void {
    _ = size;
    // Count how many libraries are loaded
    counter.* += @as(usize, 1);

    // The image should contain at least a PT_LOAD segment
    if (info.dlpi_phnum < 1) return error.MissingPtLoadSegment;

    // Quick & dirty validation of the phdr pointers, make sure we're not
    // pointing to some random gibberish
    var i: usize = 0;
    var found_load = false;
    while (i < info.dlpi_phnum) : (i += 1) {
        const phdr = info.dlpi_phdr[i];

        if (phdr.p_type != elf.PT_LOAD) continue;

        const reloc_addr = info.dlpi_addr + phdr.p_vaddr;
        // Find the ELF header
        const elf_header = @intToPtr(*elf.Ehdr, reloc_addr - phdr.p_offset);
        // Validate the magic
        if (!mem.eql(u8, elf_header.e_ident[0..4], "\x7fELF")) return error.BadElfMagic;
        // Consistency check
        if (elf_header.e_phnum != info.dlpi_phnum) return error.FailedConsistencyCheck;

        found_load = true;
        break;
    }

    if (!found_load) return error.MissingLoad;
}

test "dl_iterate_phdr" {
    if (native_os == .windows or native_os == .wasi or native_os == .macos)
        return error.SkipZigTest;

    var counter: usize = 0;
    try os.dl_iterate_phdr(&counter, IterFnError, iter_fn);
    try expect(counter != 0);
}

test "gethostname" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    var buf: [os.HOST_NAME_MAX]u8 = undefined;
    const hostname = try os.gethostname(&buf);
    try expect(hostname.len != 0);
}

test "pipe" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    var fds = try os.pipe();
    try expect((try os.write(fds[1], "hello")) == 5);
    var buf: [16]u8 = undefined;
    try expect((try os.read(fds[0], buf[0..])) == 5);
    try testing.expectEqualSlices(u8, buf[0..5], "hello");
    os.close(fds[1]);
    os.close(fds[0]);
}

test "argsAlloc" {
    var args = try std.process.argsAlloc(std.testing.allocator);
    std.process.argsFree(std.testing.allocator, args);
}

test "memfd_create" {
    // memfd_create is linux specific.
    if (native_os != .linux) return error.SkipZigTest;
    const fd = std.os.memfd_create("test", 0) catch |err| switch (err) {
        // Related: https://github.com/ziglang/zig/issues/4019
        error.SystemOutdated => return error.SkipZigTest,
        else => |e| return e,
    };
    defer std.os.close(fd);
    try expect((try std.os.write(fd, "test")) == 4);
    try std.os.lseek_SET(fd, 0);

    var buf: [10]u8 = undefined;
    const bytes_read = try std.os.read(fd, &buf);
    try expect(bytes_read == 4);
    try expect(mem.eql(u8, buf[0..4], "test"));
}

test "mmap" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    // Simple mmap() call with non page-aligned size
    {
        const data = try os.mmap(
            null,
            1234,
            os.PROT_READ | os.PROT_WRITE,
            os.MAP_ANONYMOUS | os.MAP_PRIVATE,
            -1,
            0,
        );
        defer os.munmap(data);

        try testing.expectEqual(@as(usize, 1234), data.len);

        // By definition the data returned by mmap is zero-filled
        try testing.expect(mem.eql(u8, data, &[_]u8{0x00} ** 1234));

        // Make sure the memory is writeable as requested
        std.mem.set(u8, data, 0x55);
        try testing.expect(mem.eql(u8, data, &[_]u8{0x55} ** 1234));
    }

    const test_out_file = "os_tmp_test";
    // Must be a multiple of 4096 so that the test works with mmap2
    const alloc_size = 8 * 4096;

    // Create a file used for testing mmap() calls with a file descriptor
    {
        const file = try tmp.dir.createFile(test_out_file, .{});
        defer file.close();

        const stream = file.writer();

        var i: u32 = 0;
        while (i < alloc_size / @sizeOf(u32)) : (i += 1) {
            try stream.writeIntNative(u32, i);
        }
    }

    // Map the whole file
    {
        const file = try tmp.dir.openFile(test_out_file, .{});
        defer file.close();

        const data = try os.mmap(
            null,
            alloc_size,
            os.PROT_READ,
            os.MAP_PRIVATE,
            file.handle,
            0,
        );
        defer os.munmap(data);

        var mem_stream = io.fixedBufferStream(data);
        const stream = mem_stream.reader();

        var i: u32 = 0;
        while (i < alloc_size / @sizeOf(u32)) : (i += 1) {
            try testing.expectEqual(i, try stream.readIntNative(u32));
        }
    }

    // Map the upper half of the file
    {
        const file = try tmp.dir.openFile(test_out_file, .{});
        defer file.close();

        const data = try os.mmap(
            null,
            alloc_size / 2,
            os.PROT_READ,
            os.MAP_PRIVATE,
            file.handle,
            alloc_size / 2,
        );
        defer os.munmap(data);

        var mem_stream = io.fixedBufferStream(data);
        const stream = mem_stream.reader();

        var i: u32 = alloc_size / 2 / @sizeOf(u32);
        while (i < alloc_size / @sizeOf(u32)) : (i += 1) {
            try testing.expectEqual(i, try stream.readIntNative(u32));
        }
    }

    try tmp.dir.deleteFile(test_out_file);
}

test "getenv" {
    if (native_os == .windows) {
        try expect(os.getenvW(&[_:0]u16{ 'B', 'O', 'G', 'U', 'S', 0x11, 0x22, 0x33, 0x44, 0x55 }) == null);
    } else {
        try expect(os.getenvZ("BOGUSDOESNOTEXISTENVVAR") == null);
    }
}

test "fcntl" {
    if (native_os == .windows or native_os == .wasi)
        return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const test_out_file = "os_tmp_test";

    const file = try tmp.dir.createFile(test_out_file, .{});
    defer {
        file.close();
        tmp.dir.deleteFile(test_out_file) catch {};
    }

    // Note: The test assumes createFile opens the file with O_CLOEXEC
    {
        const flags = try os.fcntl(file.handle, os.F_GETFD, 0);
        try expect((flags & os.FD_CLOEXEC) != 0);
    }
    {
        _ = try os.fcntl(file.handle, os.F_SETFD, 0);
        const flags = try os.fcntl(file.handle, os.F_GETFD, 0);
        try expect((flags & os.FD_CLOEXEC) == 0);
    }
    {
        _ = try os.fcntl(file.handle, os.F_SETFD, os.FD_CLOEXEC);
        const flags = try os.fcntl(file.handle, os.F_GETFD, 0);
        try expect((flags & os.FD_CLOEXEC) != 0);
    }
}

test "signalfd" {
    if (native_os != .linux)
        return error.SkipZigTest;
    _ = std.os.signalfd;
}

test "sync" {
    if (native_os != .linux)
        return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const test_out_file = "os_tmp_test";
    const file = try tmp.dir.createFile(test_out_file, .{});
    defer {
        file.close();
        tmp.dir.deleteFile(test_out_file) catch {};
    }

    os.sync();
    try os.syncfs(file.handle);
}

test "fsync" {
    if (native_os != .linux and native_os != .windows)
        return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const test_out_file = "os_tmp_test";
    const file = try tmp.dir.createFile(test_out_file, .{});
    defer {
        file.close();
        tmp.dir.deleteFile(test_out_file) catch {};
    }

    try os.fsync(file.handle);
    try os.fdatasync(file.handle);
}

test "getrlimit and setrlimit" {
    if (!@hasDecl(os, "rlimit")) {
        return error.SkipZigTest;
    }

    inline for (std.meta.fields(os.rlimit_resource)) |field| {
        const resource = @intToEnum(os.rlimit_resource, field.value);
        const limit = try os.getrlimit(resource);
        try os.setrlimit(resource, limit);
    }
}

test "shutdown socket" {
    if (native_os == .wasi)
        return error.SkipZigTest;
    if (native_os == .windows) {
        _ = try std.os.windows.WSAStartup(2, 2);
    }
    defer {
        if (native_os == .windows) {
            std.os.windows.WSACleanup() catch unreachable;
        }
    }
    const sock = try os.socket(os.AF_INET, os.SOCK_STREAM, 0);
    os.shutdown(sock, .both) catch |err| switch (err) {
        error.SocketNotConnected => {},
        else => |e| return e,
    };
    os.closeSocket(sock);
}

var signal_test_failed = true;

test "sigaction" {
    if (native_os == .wasi or native_os == .windows)
        return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/7427
    if (native_os == .linux and builtin.cpu.arch == .i386)
        return error.SkipZigTest;

    const S = struct {
        fn handler(sig: i32, info: *const os.siginfo_t, ctx_ptr: ?*const c_void) callconv(.C) void {
            _ = ctx_ptr;
            // Check that we received the correct signal.
            switch (native_os) {
                .netbsd => {
                    if (sig == os.SIGUSR1 and sig == info.info.signo)
                        signal_test_failed = false;
                },
                else => {
                    if (sig == os.SIGUSR1 and sig == info.signo)
                        signal_test_failed = false;
                },
            }
        }
    };

    var sa = os.Sigaction{
        .handler = .{ .sigaction = S.handler },
        .mask = os.empty_sigset,
        .flags = os.SA_SIGINFO | os.SA_RESETHAND,
    };
    var old_sa: os.Sigaction = undefined;
    // Install the new signal handler.
    os.sigaction(os.SIGUSR1, &sa, null);
    // Check that we can read it back correctly.
    os.sigaction(os.SIGUSR1, null, &old_sa);
    try testing.expectEqual(S.handler, old_sa.handler.sigaction.?);
    try testing.expect((old_sa.flags & os.SA_SIGINFO) != 0);
    // Invoke the handler.
    try os.raise(os.SIGUSR1);
    try testing.expect(signal_test_failed == false);
    // Check if the handler has been correctly reset to SIG_DFL
    os.sigaction(os.SIGUSR1, null, &old_sa);
    try testing.expectEqual(os.SIG_DFL, old_sa.handler.sigaction);
}

test "dup & dup2" {
    if (native_os != .linux) return error.SkipZigTest;

    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    {
        var file = try tmp.dir.createFile("os_dup_test", .{});
        defer file.close();

        var duped = std.fs.File{ .handle = try std.os.dup(file.handle) };
        defer duped.close();
        try duped.writeAll("dup");

        // Tests aren't run in parallel so using the next fd shouldn't be an issue.
        const new_fd = duped.handle + 1;
        try std.os.dup2(file.handle, new_fd);
        var dup2ed = std.fs.File{ .handle = new_fd };
        defer dup2ed.close();
        try dup2ed.writeAll("dup2");
    }

    var file = try tmp.dir.openFile("os_dup_test", .{});
    defer file.close();

    var buf: [7]u8 = undefined;
    try testing.expectEqualStrings("dupdup2", buf[0..try file.readAll(&buf)]);
}
