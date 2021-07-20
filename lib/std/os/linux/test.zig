// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const linux = std.os.linux;
const mem = std.mem;
const elf = std.elf;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const fs = std.fs;

test "fallocate" {
    const path = "test_fallocate";
    const file = try fs.cwd().createFile(path, .{ .truncate = true, .mode = 0o666 });
    defer file.close();
    defer fs.cwd().deleteFile(path) catch {};

    try expect((try file.stat()).size == 0);

    const len: i64 = 65536;
    switch (linux.getErrno(linux.fallocate(file.handle, 0, 0, len))) {
        0 => {},
        linux.ENOSYS => return error.SkipZigTest,
        linux.EOPNOTSUPP => return error.SkipZigTest,
        else => |errno| std.debug.panic("unhandled errno: {}", .{errno}),
    }

    try expect((try file.stat()).size == len);
}

test "getpid" {
    try expect(linux.getpid() != 0);
}

test "timer" {
    const epoll_fd = linux.epoll_create();
    var err: usize = linux.getErrno(epoll_fd);
    try expect(err == 0);

    const timer_fd = linux.timerfd_create(linux.CLOCK_MONOTONIC, 0);
    try expect(linux.getErrno(timer_fd) == 0);

    const time_interval = linux.timespec{
        .tv_sec = 0,
        .tv_nsec = 2000000,
    };

    const new_time = linux.itimerspec{
        .it_interval = time_interval,
        .it_value = time_interval,
    };

    err = linux.timerfd_settime(@intCast(i32, timer_fd), 0, &new_time, null);
    try expect(err == 0);

    var event = linux.epoll_event{
        .events = linux.EPOLLIN | linux.EPOLLOUT | linux.EPOLLET,
        .data = linux.epoll_data{ .ptr = 0 },
    };

    err = linux.epoll_ctl(@intCast(i32, epoll_fd), linux.EPOLL_CTL_ADD, @intCast(i32, timer_fd), &event);
    try expect(err == 0);

    const events_one: linux.epoll_event = undefined;
    var events = [_]linux.epoll_event{events_one} ** 8;

    // TODO implicit cast from *[N]T to [*]T
    err = linux.epoll_wait(@intCast(i32, epoll_fd), @ptrCast([*]linux.epoll_event, &events), 8, -1);
}

test "statx" {
    const tmp_file_name = "just_a_temporary_file.txt";
    var file = try fs.cwd().createFile(tmp_file_name, .{});
    defer {
        file.close();
        fs.cwd().deleteFile(tmp_file_name) catch {};
    }

    var statx_buf: linux.Statx = undefined;
    switch (linux.getErrno(linux.statx(file.handle, "", linux.AT_EMPTY_PATH, linux.STATX_BASIC_STATS, &statx_buf))) {
        0 => {},
        // The statx syscall was only introduced in linux 4.11
        linux.ENOSYS => return error.SkipZigTest,
        else => unreachable,
    }

    var stat_buf: linux.kernel_stat = undefined;
    switch (linux.getErrno(linux.fstatat(file.handle, "", &stat_buf, linux.AT_EMPTY_PATH))) {
        0 => {},
        else => unreachable,
    }

    try expect(stat_buf.mode == statx_buf.mode);
    try expect(@bitCast(u32, stat_buf.uid) == statx_buf.uid);
    try expect(@bitCast(u32, stat_buf.gid) == statx_buf.gid);
    try expect(@bitCast(u64, @as(i64, stat_buf.size)) == statx_buf.size);
    try expect(@bitCast(u64, @as(i64, stat_buf.blksize)) == statx_buf.blksize);
    try expect(@bitCast(u64, @as(i64, stat_buf.blocks)) == statx_buf.blocks);
}

test "user and group ids" {
    if (builtin.link_libc) return error.SkipZigTest;
    try expectEqual(linux.getauxval(elf.AT_UID), linux.getuid());
    try expectEqual(linux.getauxval(elf.AT_GID), linux.getgid());
    try expectEqual(linux.getauxval(elf.AT_EUID), linux.geteuid());
    try expectEqual(linux.getauxval(elf.AT_EGID), linux.getegid());
}

test "fadvise" {
    const tmp_file_name = "temp_posix_fadvise.txt";
    var file = try fs.cwd().createFile(tmp_file_name, .{});
    defer {
        file.close();
        fs.cwd().deleteFile(tmp_file_name) catch {};
    }

    var buf: [2048]u8 = undefined;
    try file.writeAll(&buf);

    const ret = linux.fadvise(
        file.handle,
        0,
        0,
        linux.POSIX_FADV_SEQUENTIAL,
    );
    try expectEqual(@as(usize, 0), ret);
}
