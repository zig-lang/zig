// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const meta = std.meta;
const trait = std.trait;
const DefaultPrng = std.rand.DefaultPrng;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const mem = std.mem;
const fs = std.fs;
const File = std.fs.File;
const native_endian = builtin.cpu.arch.endian();

const tmpDir = std.testing.tmpDir;

test "write a file, read it, then delete it" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var data: [1024]u8 = undefined;
    var prng = DefaultPrng.init(1234);
    prng.random.bytes(data[0..]);
    const tmp_file_name = "temp_test_file.txt";
    {
        var file = try tmp.dir.createFile(tmp_file_name, .{});
        defer file.close();

        var buf_stream = io.bufferedWriter(file.writer());
        const st = buf_stream.writer();
        try st.print("begin", .{});
        try st.writeAll(data[0..]);
        try st.print("end", .{});
        try buf_stream.flush();
    }

    {
        // Make sure the exclusive flag is honored.
        try expectError(File.OpenError.PathAlreadyExists, tmp.dir.createFile(tmp_file_name, .{ .exclusive = true }));
    }

    {
        var file = try tmp.dir.openFile(tmp_file_name, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const expected_file_size: u64 = "begin".len + data.len + "end".len;
        try expectEqual(expected_file_size, file_size);

        var buf_stream = io.bufferedReader(file.reader());
        const st = buf_stream.reader();
        const contents = try st.readAllAlloc(std.testing.allocator, 2 * 1024);
        defer std.testing.allocator.free(contents);

        try expect(mem.eql(u8, contents[0.."begin".len], "begin"));
        try expect(mem.eql(u8, contents["begin".len .. contents.len - "end".len], &data));
        try expect(mem.eql(u8, contents[contents.len - "end".len ..], "end"));
    }
    try tmp.dir.deleteFile(tmp_file_name);
}

test "BitStreams with File Stream" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    {
        var file = try tmp.dir.createFile(tmp_file_name, .{});
        defer file.close();

        var bit_stream = io.bitWriter(native_endian, file.writer());

        try bit_stream.writeBits(@as(u2, 1), 1);
        try bit_stream.writeBits(@as(u5, 2), 2);
        try bit_stream.writeBits(@as(u128, 3), 3);
        try bit_stream.writeBits(@as(u8, 4), 4);
        try bit_stream.writeBits(@as(u9, 5), 5);
        try bit_stream.writeBits(@as(u1, 1), 1);
        try bit_stream.flushBits();
    }
    {
        var file = try tmp.dir.openFile(tmp_file_name, .{});
        defer file.close();

        var bit_stream = io.bitReader(native_endian, file.reader());

        var out_bits: usize = undefined;

        try expect(1 == try bit_stream.readBits(u2, 1, &out_bits));
        try expect(out_bits == 1);
        try expect(2 == try bit_stream.readBits(u5, 2, &out_bits));
        try expect(out_bits == 2);
        try expect(3 == try bit_stream.readBits(u128, 3, &out_bits));
        try expect(out_bits == 3);
        try expect(4 == try bit_stream.readBits(u8, 4, &out_bits));
        try expect(out_bits == 4);
        try expect(5 == try bit_stream.readBits(u9, 5, &out_bits));
        try expect(out_bits == 5);
        try expect(1 == try bit_stream.readBits(u1, 1, &out_bits));
        try expect(out_bits == 1);

        try expectError(error.EndOfStream, bit_stream.readBitsNoEof(u1, 1));
    }
    try tmp.dir.deleteFile(tmp_file_name);
}

test "File seek ops" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{});
    defer {
        file.close();
        tmp.dir.deleteFile(tmp_file_name) catch {};
    }

    try file.writeAll(&([_]u8{0x55} ** 8192));

    // Seek to the end
    try file.seekFromEnd(0);
    try expect((try file.getPos()) == try file.getEndPos());
    // Negative delta
    try file.seekBy(-4096);
    try expect((try file.getPos()) == 4096);
    // Positive delta
    try file.seekBy(10);
    try expect((try file.getPos()) == 4106);
    // Absolute position
    try file.seekTo(1234);
    try expect((try file.getPos()) == 1234);
}

test "setEndPos" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{});
    defer {
        file.close();
        tmp.dir.deleteFile(tmp_file_name) catch {};
    }

    // Verify that the file size changes and the file offset is not moved
    try std.testing.expect((try file.getEndPos()) == 0);
    try std.testing.expect((try file.getPos()) == 0);
    try file.setEndPos(8192);
    try std.testing.expect((try file.getEndPos()) == 8192);
    try std.testing.expect((try file.getPos()) == 0);
    try file.seekTo(100);
    try file.setEndPos(4096);
    try std.testing.expect((try file.getEndPos()) == 4096);
    try std.testing.expect((try file.getPos()) == 100);
    try file.setEndPos(0);
    try std.testing.expect((try file.getEndPos()) == 0);
    try std.testing.expect((try file.getPos()) == 100);
}

test "updateTimes" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "just_a_temporary_file.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{ .read = true });
    defer {
        file.close();
        tmp.dir.deleteFile(tmp_file_name) catch {};
    }
    var stat_old = try file.stat();
    // Set atime and mtime to 5s before
    try file.updateTimes(
        stat_old.atime - 5 * std.time.ns_per_s,
        stat_old.mtime - 5 * std.time.ns_per_s,
    );
    var stat_new = try file.stat();
    try expect(stat_new.atime < stat_old.atime);
    try expect(stat_new.mtime < stat_old.mtime);
}
