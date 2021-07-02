// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = std.builtin;
const io = std.io;
const testing = std.testing;

pub const CWriter = io.Writer(*std.c.FILE, std.fs.File.WriteError, cWriterWrite);

pub fn cWriter(c_file: *std.c.FILE) CWriter {
    return .{ .context = c_file };
}

fn cWriterWrite(c_file: *std.c.FILE, bytes: []const u8) std.fs.File.WriteError!usize {
    const amt_written = std.c.fwrite(bytes.ptr, 1, bytes.len, c_file);
    if (amt_written >= 0) return amt_written;
    switch (std.c._errno().*) {
        0 => unreachable,
        os.EINVAL => unreachable,
        os.EFAULT => unreachable,
        os.EAGAIN => unreachable, // this is a blocking API
        os.EBADF => unreachable, // always a race condition
        os.EDESTADDRREQ => unreachable, // connect was never called
        os.EDQUOT => return error.DiskQuota,
        os.EFBIG => return error.FileTooBig,
        os.EIO => return error.InputOutput,
        os.ENOSPC => return error.NoSpaceLeft,
        os.EPERM => return error.AccessDenied,
        os.EPIPE => return error.BrokenPipe,
        else => |err| return os.unexpectedErrno(err),
    }
}

test {
    if (!builtin.link_libc or builtin.os.tag == .wasi) return error.SkipZigTest;

    const filename = "tmp_io_test_file.txt";
    const out_file = std.c.fopen(filename, "w") orelse return error.UnableToOpenTestFile;
    defer {
        _ = std.c.fclose(out_file);
        std.fs.cwd().deleteFileZ(filename) catch {};
    }

    const writer = cWriter(out_file);
    try writer.print("hi: {}\n", .{@as(i32, 123)});
}
