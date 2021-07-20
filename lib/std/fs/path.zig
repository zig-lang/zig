// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const builtin = @import("builtin");
const std = @import("../std.zig");
const debug = std.debug;
const assert = debug.assert;
const testing = std.testing;
const mem = std.mem;
const fmt = std.fmt;
const Allocator = mem.Allocator;
const math = std.math;
const windows = std.os.windows;
const fs = std.fs;
const process = std.process;
const native_os = builtin.os.tag;

pub const sep_windows = '\\';
pub const sep_posix = '/';
pub const sep = if (native_os == .windows) sep_windows else sep_posix;

pub const sep_str_windows = "\\";
pub const sep_str_posix = "/";
pub const sep_str = if (native_os == .windows) sep_str_windows else sep_str_posix;

pub const delimiter_windows = ';';
pub const delimiter_posix = ':';
pub const delimiter = if (native_os == .windows) delimiter_windows else delimiter_posix;

/// Returns if the given byte is a valid path separator
pub fn isSep(byte: u8) bool {
    if (native_os == .windows) {
        return byte == '/' or byte == '\\';
    } else {
        return byte == '/';
    }
}

/// This is different from mem.join in that the separator will not be repeated if
/// it is found at the end or beginning of a pair of consecutive paths.
fn joinSepMaybeZ(allocator: *Allocator, separator: u8, sepPredicate: fn (u8) bool, paths: []const []const u8, zero: bool) ![]u8 {
    if (paths.len == 0) return if (zero) try allocator.dupe(u8, &[1]u8{0}) else &[0]u8{};

    const total_len = blk: {
        var sum: usize = paths[0].len;
        var i: usize = 1;
        while (i < paths.len) : (i += 1) {
            const prev_path = paths[i - 1];
            const this_path = paths[i];
            const prev_sep = (prev_path.len != 0 and sepPredicate(prev_path[prev_path.len - 1]));
            const this_sep = (this_path.len != 0 and sepPredicate(this_path[0]));
            sum += @boolToInt(!prev_sep and !this_sep);
            sum += if (prev_sep and this_sep) this_path.len - 1 else this_path.len;
        }
        if (zero) sum += 1;
        break :blk sum;
    };

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    mem.copy(u8, buf, paths[0]);
    var buf_index: usize = paths[0].len;
    var i: usize = 1;
    while (i < paths.len) : (i += 1) {
        const prev_path = paths[i - 1];
        const this_path = paths[i];
        const prev_sep = (prev_path.len != 0 and sepPredicate(prev_path[prev_path.len - 1]));
        const this_sep = (this_path.len != 0 and sepPredicate(this_path[0]));
        if (!prev_sep and !this_sep) {
            buf[buf_index] = separator;
            buf_index += 1;
        }
        const adjusted_path = if (prev_sep and this_sep) this_path[1..] else this_path;
        mem.copy(u8, buf[buf_index..], adjusted_path);
        buf_index += adjusted_path.len;
    }

    if (zero) buf[buf.len - 1] = 0;

    // No need for shrink since buf is exactly the correct size.
    return buf;
}

/// Naively combines a series of paths with the native path seperator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn join(allocator: *Allocator, paths: []const []const u8) ![]u8 {
    return joinSepMaybeZ(allocator, sep, isSep, paths, false);
}

/// Naively combines a series of paths with the native path seperator and null terminator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn joinZ(allocator: *Allocator, paths: []const []const u8) ![:0]u8 {
    const out = try joinSepMaybeZ(allocator, sep, isSep, paths, true);
    return out[0 .. out.len - 1 :0];
}

fn testJoinMaybeZWindows(paths: []const []const u8, expected: []const u8, zero: bool) !void {
    const windowsIsSep = struct {
        fn isSep(byte: u8) bool {
            return byte == '/' or byte == '\\';
        }
    }.isSep;
    const actual = try joinSepMaybeZ(testing.allocator, sep_windows, windowsIsSep, paths, zero);
    defer testing.allocator.free(actual);
    try testing.expectEqualSlices(u8, expected, if (zero) actual[0 .. actual.len - 1 :0] else actual);
}

fn testJoinMaybeZPosix(paths: []const []const u8, expected: []const u8, zero: bool) !void {
    const posixIsSep = struct {
        fn isSep(byte: u8) bool {
            return byte == '/';
        }
    }.isSep;
    const actual = try joinSepMaybeZ(testing.allocator, sep_posix, posixIsSep, paths, zero);
    defer testing.allocator.free(actual);
    try testing.expectEqualSlices(u8, expected, if (zero) actual[0 .. actual.len - 1 :0] else actual);
}

test "join" {
    {
        const actual: []u8 = try join(testing.allocator, &[_][]const u8{});
        defer testing.allocator.free(actual);
        try testing.expectEqualSlices(u8, "", actual);
    }
    {
        const actual: [:0]u8 = try joinZ(testing.allocator, &[_][]const u8{});
        defer testing.allocator.free(actual);
        try testing.expectEqualSlices(u8, "", actual);
    }
    for (&[_]bool{ false, true }) |zero| {
        try testJoinMaybeZWindows(&[_][]const u8{}, "", zero);
        try testJoinMaybeZWindows(&[_][]const u8{ "c:\\a\\b", "c" }, "c:\\a\\b\\c", zero);
        try testJoinMaybeZWindows(&[_][]const u8{ "c:\\a\\b", "c" }, "c:\\a\\b\\c", zero);
        try testJoinMaybeZWindows(&[_][]const u8{ "c:\\a\\b\\", "c" }, "c:\\a\\b\\c", zero);

        try testJoinMaybeZWindows(&[_][]const u8{ "c:\\", "a", "b\\", "c" }, "c:\\a\\b\\c", zero);
        try testJoinMaybeZWindows(&[_][]const u8{ "c:\\a\\", "b\\", "c" }, "c:\\a\\b\\c", zero);

        try testJoinMaybeZWindows(
            &[_][]const u8{ "c:\\home\\andy\\dev\\zig\\build\\lib\\zig\\std", "io.zig" },
            "c:\\home\\andy\\dev\\zig\\build\\lib\\zig\\std\\io.zig",
            zero,
        );

        try testJoinMaybeZWindows(&[_][]const u8{ "c:\\", "a", "b/", "c" }, "c:\\a\\b/c", zero);
        try testJoinMaybeZWindows(&[_][]const u8{ "c:\\a/", "b\\", "/c" }, "c:\\a/b\\c", zero);

        try testJoinMaybeZPosix(&[_][]const u8{}, "", zero);
        try testJoinMaybeZPosix(&[_][]const u8{ "/a/b", "c" }, "/a/b/c", zero);
        try testJoinMaybeZPosix(&[_][]const u8{ "/a/b/", "c" }, "/a/b/c", zero);

        try testJoinMaybeZPosix(&[_][]const u8{ "/", "a", "b/", "c" }, "/a/b/c", zero);
        try testJoinMaybeZPosix(&[_][]const u8{ "/a/", "b/", "c" }, "/a/b/c", zero);

        try testJoinMaybeZPosix(
            &[_][]const u8{ "/home/andy/dev/zig/build/lib/zig/std", "io.zig" },
            "/home/andy/dev/zig/build/lib/zig/std/io.zig",
            zero,
        );

        try testJoinMaybeZPosix(&[_][]const u8{ "a", "/c" }, "a/c", zero);
        try testJoinMaybeZPosix(&[_][]const u8{ "a/", "/c" }, "a/c", zero);
    }
}

pub const isAbsoluteC = @compileError("deprecated: renamed to isAbsoluteZ");

pub fn isAbsoluteZ(path_c: [*:0]const u8) bool {
    if (native_os == .windows) {
        return isAbsoluteWindowsZ(path_c);
    } else {
        return isAbsolutePosixZ(path_c);
    }
}

pub fn isAbsolute(path: []const u8) bool {
    if (native_os == .windows) {
        return isAbsoluteWindows(path);
    } else {
        return isAbsolutePosix(path);
    }
}

fn isAbsoluteWindowsImpl(comptime T: type, path: []const T) bool {
    if (path.len < 1)
        return false;

    if (path[0] == '/')
        return true;

    if (path[0] == '\\')
        return true;

    if (path.len < 3)
        return false;

    if (path[1] == ':') {
        if (path[2] == '/')
            return true;
        if (path[2] == '\\')
            return true;
    }

    return false;
}

pub fn isAbsoluteWindows(path: []const u8) bool {
    return isAbsoluteWindowsImpl(u8, path);
}

pub fn isAbsoluteWindowsW(path_w: [*:0]const u16) bool {
    return isAbsoluteWindowsImpl(u16, mem.spanZ(path_w));
}

pub fn isAbsoluteWindowsWTF16(path: []const u16) bool {
    return isAbsoluteWindowsImpl(u16, path);
}

pub const isAbsoluteWindowsC = @compileError("deprecated: renamed to isAbsoluteWindowsZ");

pub fn isAbsoluteWindowsZ(path_c: [*:0]const u8) bool {
    return isAbsoluteWindowsImpl(u8, mem.spanZ(path_c));
}

pub fn isAbsolutePosix(path: []const u8) bool {
    return path.len > 0 and path[0] == sep_posix;
}

pub const isAbsolutePosixC = @compileError("deprecated: renamed to isAbsolutePosixZ");

pub fn isAbsolutePosixZ(path_c: [*:0]const u8) bool {
    return isAbsolutePosix(mem.spanZ(path_c));
}

test "isAbsoluteWindows" {
    try testIsAbsoluteWindows("", false);
    try testIsAbsoluteWindows("/", true);
    try testIsAbsoluteWindows("//", true);
    try testIsAbsoluteWindows("//server", true);
    try testIsAbsoluteWindows("//server/file", true);
    try testIsAbsoluteWindows("\\\\server\\file", true);
    try testIsAbsoluteWindows("\\\\server", true);
    try testIsAbsoluteWindows("\\\\", true);
    try testIsAbsoluteWindows("c", false);
    try testIsAbsoluteWindows("c:", false);
    try testIsAbsoluteWindows("c:\\", true);
    try testIsAbsoluteWindows("c:/", true);
    try testIsAbsoluteWindows("c://", true);
    try testIsAbsoluteWindows("C:/Users/", true);
    try testIsAbsoluteWindows("C:\\Users\\", true);
    try testIsAbsoluteWindows("C:cwd/another", false);
    try testIsAbsoluteWindows("C:cwd\\another", false);
    try testIsAbsoluteWindows("directory/directory", false);
    try testIsAbsoluteWindows("directory\\directory", false);
    try testIsAbsoluteWindows("/usr/local", true);
}

test "isAbsolutePosix" {
    try testIsAbsolutePosix("", false);
    try testIsAbsolutePosix("/home/foo", true);
    try testIsAbsolutePosix("/home/foo/..", true);
    try testIsAbsolutePosix("bar/", false);
    try testIsAbsolutePosix("./baz", false);
}

fn testIsAbsoluteWindows(path: []const u8, expected_result: bool) !void {
    try testing.expectEqual(expected_result, isAbsoluteWindows(path));
}

fn testIsAbsolutePosix(path: []const u8, expected_result: bool) !void {
    try testing.expectEqual(expected_result, isAbsolutePosix(path));
}

pub const WindowsPath = struct {
    is_abs: bool,
    kind: Kind,
    disk_designator: []const u8,

    pub const Kind = enum {
        None,
        Drive,
        NetworkShare,
    };
};

pub fn windowsParsePath(path: []const u8) WindowsPath {
    if (path.len >= 2 and path[1] == ':') {
        return WindowsPath{
            .is_abs = isAbsoluteWindows(path),
            .kind = WindowsPath.Kind.Drive,
            .disk_designator = path[0..2],
        };
    }
    if (path.len >= 1 and (path[0] == '/' or path[0] == '\\') and
        (path.len == 1 or (path[1] != '/' and path[1] != '\\')))
    {
        return WindowsPath{
            .is_abs = true,
            .kind = WindowsPath.Kind.None,
            .disk_designator = path[0..0],
        };
    }
    const relative_path = WindowsPath{
        .kind = WindowsPath.Kind.None,
        .disk_designator = &[_]u8{},
        .is_abs = false,
    };
    if (path.len < "//a/b".len) {
        return relative_path;
    }

    inline for ("/\\") |this_sep| {
        const two_sep = [_]u8{ this_sep, this_sep };
        if (mem.startsWith(u8, path, &two_sep)) {
            if (path[2] == this_sep) {
                return relative_path;
            }

            var it = mem.tokenize(path, &[_]u8{this_sep});
            _ = (it.next() orelse return relative_path);
            _ = (it.next() orelse return relative_path);
            return WindowsPath{
                .is_abs = isAbsoluteWindows(path),
                .kind = WindowsPath.Kind.NetworkShare,
                .disk_designator = path[0..it.index],
            };
        }
    }
    return relative_path;
}

test "windowsParsePath" {
    {
        const parsed = windowsParsePath("//a/b");
        try testing.expect(parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.NetworkShare);
        try testing.expect(mem.eql(u8, parsed.disk_designator, "//a/b"));
    }
    {
        const parsed = windowsParsePath("\\\\a\\b");
        try testing.expect(parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.NetworkShare);
        try testing.expect(mem.eql(u8, parsed.disk_designator, "\\\\a\\b"));
    }
    {
        const parsed = windowsParsePath("\\\\a\\");
        try testing.expect(!parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.None);
        try testing.expect(mem.eql(u8, parsed.disk_designator, ""));
    }
    {
        const parsed = windowsParsePath("/usr/local");
        try testing.expect(parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.None);
        try testing.expect(mem.eql(u8, parsed.disk_designator, ""));
    }
    {
        const parsed = windowsParsePath("c:../");
        try testing.expect(!parsed.is_abs);
        try testing.expect(parsed.kind == WindowsPath.Kind.Drive);
        try testing.expect(mem.eql(u8, parsed.disk_designator, "c:"));
    }
}

pub fn diskDesignator(path: []const u8) []const u8 {
    if (native_os == .windows) {
        return diskDesignatorWindows(path);
    } else {
        return "";
    }
}

pub fn diskDesignatorWindows(path: []const u8) []const u8 {
    return windowsParsePath(path).disk_designator;
}

fn networkShareServersEql(ns1: []const u8, ns2: []const u8) bool {
    const sep1 = ns1[0];
    const sep2 = ns2[0];

    var it1 = mem.tokenize(ns1, &[_]u8{sep1});
    var it2 = mem.tokenize(ns2, &[_]u8{sep2});

    // TODO ASCII is wrong, we actually need full unicode support to compare paths.
    return asciiEqlIgnoreCase(it1.next().?, it2.next().?);
}

fn compareDiskDesignators(kind: WindowsPath.Kind, p1: []const u8, p2: []const u8) bool {
    switch (kind) {
        WindowsPath.Kind.None => {
            assert(p1.len == 0);
            assert(p2.len == 0);
            return true;
        },
        WindowsPath.Kind.Drive => {
            return asciiUpper(p1[0]) == asciiUpper(p2[0]);
        },
        WindowsPath.Kind.NetworkShare => {
            const sep1 = p1[0];
            const sep2 = p2[0];

            var it1 = mem.tokenize(p1, &[_]u8{sep1});
            var it2 = mem.tokenize(p2, &[_]u8{sep2});

            // TODO ASCII is wrong, we actually need full unicode support to compare paths.
            return asciiEqlIgnoreCase(it1.next().?, it2.next().?) and asciiEqlIgnoreCase(it1.next().?, it2.next().?);
        },
    }
}

fn asciiUpper(byte: u8) u8 {
    return switch (byte) {
        'a'...'z' => 'A' + (byte - 'a'),
        else => byte,
    };
}

fn asciiEqlIgnoreCase(s1: []const u8, s2: []const u8) bool {
    if (s1.len != s2.len)
        return false;
    var i: usize = 0;
    while (i < s1.len) : (i += 1) {
        if (asciiUpper(s1[i]) != asciiUpper(s2[i]))
            return false;
    }
    return true;
}

/// On Windows, this calls `resolveWindows` and on POSIX it calls `resolvePosix`.
pub fn resolve(allocator: *Allocator, paths: []const []const u8) ![]u8 {
    if (native_os == .windows) {
        return resolveWindows(allocator, paths);
    } else {
        return resolvePosix(allocator, paths);
    }
}

/// This function is like a series of `cd` statements executed one after another.
/// It resolves "." and "..".
/// The result does not have a trailing path separator.
/// If all paths are relative it uses the current working directory as a starting point.
/// Each drive has its own current working directory.
/// Path separators are canonicalized to '\\' and drives are canonicalized to capital letters.
/// Note: all usage of this function should be audited due to the existence of symlinks.
/// Without performing actual syscalls, resolving `..` could be incorrect.
pub fn resolveWindows(allocator: *Allocator, paths: []const []const u8) ![]u8 {
    if (paths.len == 0) {
        assert(native_os == .windows); // resolveWindows called on non windows can't use getCwd
        return process.getCwdAlloc(allocator);
    }

    // determine which disk designator we will result with, if any
    var result_drive_buf = "_:".*;
    var result_disk_designator: []const u8 = "";
    var have_drive_kind = WindowsPath.Kind.None;
    var have_abs_path = false;
    var first_index: usize = 0;
    var max_size: usize = 0;
    for (paths) |p, i| {
        const parsed = windowsParsePath(p);
        if (parsed.is_abs) {
            have_abs_path = true;
            first_index = i;
            max_size = result_disk_designator.len;
        }
        switch (parsed.kind) {
            WindowsPath.Kind.Drive => {
                result_drive_buf[0] = asciiUpper(parsed.disk_designator[0]);
                result_disk_designator = result_drive_buf[0..];
                have_drive_kind = WindowsPath.Kind.Drive;
            },
            WindowsPath.Kind.NetworkShare => {
                result_disk_designator = parsed.disk_designator;
                have_drive_kind = WindowsPath.Kind.NetworkShare;
            },
            WindowsPath.Kind.None => {},
        }
        max_size += p.len + 1;
    }

    // if we will result with a disk designator, loop again to determine
    // which is the last time the disk designator is absolutely specified, if any
    // and count up the max bytes for paths related to this disk designator
    if (have_drive_kind != WindowsPath.Kind.None) {
        have_abs_path = false;
        first_index = 0;
        max_size = result_disk_designator.len;
        var correct_disk_designator = false;

        for (paths) |p, i| {
            const parsed = windowsParsePath(p);
            if (parsed.kind != WindowsPath.Kind.None) {
                if (parsed.kind == have_drive_kind) {
                    correct_disk_designator = compareDiskDesignators(have_drive_kind, result_disk_designator, parsed.disk_designator);
                } else {
                    continue;
                }
            }
            if (!correct_disk_designator) {
                continue;
            }
            if (parsed.is_abs) {
                first_index = i;
                max_size = result_disk_designator.len;
                have_abs_path = true;
            }
            max_size += p.len + 1;
        }
    }

    // Allocate result and fill in the disk designator, calling getCwd if we have to.
    var result: []u8 = undefined;
    var result_index: usize = 0;

    if (have_abs_path) {
        switch (have_drive_kind) {
            WindowsPath.Kind.Drive => {
                result = try allocator.alloc(u8, max_size);

                mem.copy(u8, result, result_disk_designator);
                result_index += result_disk_designator.len;
            },
            WindowsPath.Kind.NetworkShare => {
                result = try allocator.alloc(u8, max_size);
                var it = mem.tokenize(paths[first_index], "/\\");
                const server_name = it.next().?;
                const other_name = it.next().?;

                result[result_index] = '\\';
                result_index += 1;
                result[result_index] = '\\';
                result_index += 1;
                mem.copy(u8, result[result_index..], server_name);
                result_index += server_name.len;
                result[result_index] = '\\';
                result_index += 1;
                mem.copy(u8, result[result_index..], other_name);
                result_index += other_name.len;

                result_disk_designator = result[0..result_index];
            },
            WindowsPath.Kind.None => {
                assert(native_os == .windows); // resolveWindows called on non windows can't use getCwd
                const cwd = try process.getCwdAlloc(allocator);
                defer allocator.free(cwd);
                const parsed_cwd = windowsParsePath(cwd);
                result = try allocator.alloc(u8, max_size + parsed_cwd.disk_designator.len + 1);
                mem.copy(u8, result, parsed_cwd.disk_designator);
                result_index += parsed_cwd.disk_designator.len;
                result_disk_designator = result[0..parsed_cwd.disk_designator.len];
                if (parsed_cwd.kind == WindowsPath.Kind.Drive) {
                    result[0] = asciiUpper(result[0]);
                }
                have_drive_kind = parsed_cwd.kind;
            },
        }
    } else {
        assert(native_os == .windows); // resolveWindows called on non windows can't use getCwd
        // TODO call get cwd for the result_disk_designator instead of the global one
        const cwd = try process.getCwdAlloc(allocator);
        defer allocator.free(cwd);

        result = try allocator.alloc(u8, max_size + cwd.len + 1);

        mem.copy(u8, result, cwd);
        result_index += cwd.len;
        const parsed_cwd = windowsParsePath(result[0..result_index]);
        result_disk_designator = parsed_cwd.disk_designator;
        if (parsed_cwd.kind == WindowsPath.Kind.Drive) {
            result[0] = asciiUpper(result[0]);
        }
        have_drive_kind = parsed_cwd.kind;
    }
    errdefer allocator.free(result);

    // Now we know the disk designator to use, if any, and what kind it is. And our result
    // is big enough to append all the paths to.
    var correct_disk_designator = true;
    for (paths[first_index..]) |p| {
        const parsed = windowsParsePath(p);

        if (parsed.kind != WindowsPath.Kind.None) {
            if (parsed.kind == have_drive_kind) {
                correct_disk_designator = compareDiskDesignators(have_drive_kind, result_disk_designator, parsed.disk_designator);
            } else {
                continue;
            }
        }
        if (!correct_disk_designator) {
            continue;
        }
        var it = mem.tokenize(p[parsed.disk_designator.len..], "/\\");
        while (it.next()) |component| {
            if (mem.eql(u8, component, ".")) {
                continue;
            } else if (mem.eql(u8, component, "..")) {
                while (true) {
                    if (result_index == 0 or result_index == result_disk_designator.len)
                        break;
                    result_index -= 1;
                    if (result[result_index] == '\\' or result[result_index] == '/')
                        break;
                }
            } else {
                result[result_index] = sep_windows;
                result_index += 1;
                mem.copy(u8, result[result_index..], component);
                result_index += component.len;
            }
        }
    }

    if (result_index == result_disk_designator.len) {
        result[result_index] = '\\';
        result_index += 1;
    }

    return allocator.shrink(result, result_index);
}

/// This function is like a series of `cd` statements executed one after another.
/// It resolves "." and "..".
/// The result does not have a trailing path separator.
/// If all paths are relative it uses the current working directory as a starting point.
/// Note: all usage of this function should be audited due to the existence of symlinks.
/// Without performing actual syscalls, resolving `..` could be incorrect.
pub fn resolvePosix(allocator: *Allocator, paths: []const []const u8) ![]u8 {
    if (paths.len == 0) {
        assert(native_os != .windows); // resolvePosix called on windows can't use getCwd
        return process.getCwdAlloc(allocator);
    }

    var first_index: usize = 0;
    var have_abs = false;
    var max_size: usize = 0;
    for (paths) |p, i| {
        if (isAbsolutePosix(p)) {
            first_index = i;
            have_abs = true;
            max_size = 0;
        }
        max_size += p.len + 1;
    }

    var result: []u8 = undefined;
    var result_index: usize = 0;

    if (have_abs) {
        result = try allocator.alloc(u8, max_size);
    } else {
        assert(native_os != .windows); // resolvePosix called on windows can't use getCwd
        const cwd = try process.getCwdAlloc(allocator);
        defer allocator.free(cwd);
        result = try allocator.alloc(u8, max_size + cwd.len + 1);
        mem.copy(u8, result, cwd);
        result_index += cwd.len;
    }
    errdefer allocator.free(result);

    for (paths[first_index..]) |p| {
        var it = mem.tokenize(p, "/");
        while (it.next()) |component| {
            if (mem.eql(u8, component, ".")) {
                continue;
            } else if (mem.eql(u8, component, "..")) {
                while (true) {
                    if (result_index == 0)
                        break;
                    result_index -= 1;
                    if (result[result_index] == '/')
                        break;
                }
            } else {
                result[result_index] = '/';
                result_index += 1;
                mem.copy(u8, result[result_index..], component);
                result_index += component.len;
            }
        }
    }

    if (result_index == 0) {
        result[0] = '/';
        result_index += 1;
    }

    return allocator.shrink(result, result_index);
}

test "resolve" {
    if (native_os == .wasi) return error.SkipZigTest;

    const cwd = try process.getCwdAlloc(testing.allocator);
    defer testing.allocator.free(cwd);
    if (native_os == .windows) {
        if (windowsParsePath(cwd).kind == WindowsPath.Kind.Drive) {
            cwd[0] = asciiUpper(cwd[0]);
        }
        try testResolveWindows(&[_][]const u8{"."}, cwd);
    } else {
        try testResolvePosix(&[_][]const u8{ "a/b/c/", "../../.." }, cwd);
        try testResolvePosix(&[_][]const u8{"."}, cwd);
    }
}

test "resolveWindows" {
    if (builtin.cpu.arch == .aarch64) {
        // TODO https://github.com/ziglang/zig/issues/3288
        return error.SkipZigTest;
    }
    if (native_os == .wasi) return error.SkipZigTest;
    if (native_os == .windows) {
        const cwd = try process.getCwdAlloc(testing.allocator);
        defer testing.allocator.free(cwd);
        const parsed_cwd = windowsParsePath(cwd);
        {
            const expected = try join(testing.allocator, &[_][]const u8{
                parsed_cwd.disk_designator,
                "usr\\local\\lib\\zig\\std\\array_list.zig",
            });
            defer testing.allocator.free(expected);
            if (parsed_cwd.kind == WindowsPath.Kind.Drive) {
                expected[0] = asciiUpper(parsed_cwd.disk_designator[0]);
            }
            try testResolveWindows(&[_][]const u8{ "/usr/local", "lib\\zig\\std\\array_list.zig" }, expected);
        }
        {
            const expected = try join(testing.allocator, &[_][]const u8{
                cwd,
                "usr\\local\\lib\\zig",
            });
            defer testing.allocator.free(expected);
            if (parsed_cwd.kind == WindowsPath.Kind.Drive) {
                expected[0] = asciiUpper(parsed_cwd.disk_designator[0]);
            }
            try testResolveWindows(&[_][]const u8{ "usr/local", "lib\\zig" }, expected);
        }
    }

    try testResolveWindows(&[_][]const u8{ "c:\\a\\b\\c", "/hi", "ok" }, "C:\\hi\\ok");
    try testResolveWindows(&[_][]const u8{ "c:/blah\\blah", "d:/games", "c:../a" }, "C:\\blah\\a");
    try testResolveWindows(&[_][]const u8{ "c:/blah\\blah", "d:/games", "C:../a" }, "C:\\blah\\a");
    try testResolveWindows(&[_][]const u8{ "c:/ignore", "d:\\a/b\\c/d", "\\e.exe" }, "D:\\e.exe");
    try testResolveWindows(&[_][]const u8{ "c:/ignore", "c:/some/file" }, "C:\\some\\file");
    try testResolveWindows(&[_][]const u8{ "d:/ignore", "d:some/dir//" }, "D:\\ignore\\some\\dir");
    try testResolveWindows(&[_][]const u8{ "//server/share", "..", "relative\\" }, "\\\\server\\share\\relative");
    try testResolveWindows(&[_][]const u8{ "c:/", "//" }, "C:\\");
    try testResolveWindows(&[_][]const u8{ "c:/", "//dir" }, "C:\\dir");
    try testResolveWindows(&[_][]const u8{ "c:/", "//server/share" }, "\\\\server\\share\\");
    try testResolveWindows(&[_][]const u8{ "c:/", "//server//share" }, "\\\\server\\share\\");
    try testResolveWindows(&[_][]const u8{ "c:/", "///some//dir" }, "C:\\some\\dir");
    try testResolveWindows(&[_][]const u8{ "C:\\foo\\tmp.3\\", "..\\tmp.3\\cycles\\root.js" }, "C:\\foo\\tmp.3\\cycles\\root.js");
}

test "resolvePosix" {
    if (native_os == .wasi) return error.SkipZigTest;

    try testResolvePosix(&[_][]const u8{ "/a/b", "c" }, "/a/b/c");
    try testResolvePosix(&[_][]const u8{ "/a/b", "c", "//d", "e///" }, "/d/e");
    try testResolvePosix(&[_][]const u8{ "/a/b/c", "..", "../" }, "/a");
    try testResolvePosix(&[_][]const u8{ "/", "..", ".." }, "/");
    try testResolvePosix(&[_][]const u8{"/a/b/c/"}, "/a/b/c");

    try testResolvePosix(&[_][]const u8{ "/var/lib", "../", "file/" }, "/var/file");
    try testResolvePosix(&[_][]const u8{ "/var/lib", "/../", "file/" }, "/file");
    try testResolvePosix(&[_][]const u8{ "/some/dir", ".", "/absolute/" }, "/absolute");
    try testResolvePosix(&[_][]const u8{ "/foo/tmp.3/", "../tmp.3/cycles/root.js" }, "/foo/tmp.3/cycles/root.js");
}

fn testResolveWindows(paths: []const []const u8, expected: []const u8) !void {
    const actual = try resolveWindows(testing.allocator, paths);
    defer testing.allocator.free(actual);
    try testing.expect(mem.eql(u8, actual, expected));
}

fn testResolvePosix(paths: []const []const u8, expected: []const u8) !void {
    const actual = try resolvePosix(testing.allocator, paths);
    defer testing.allocator.free(actual);
    try testing.expect(mem.eql(u8, actual, expected));
}

/// Strip the last component from a file path.
///
/// If the path is a file in the current directory (no directory component)
/// then returns null.
///
/// If the path is the root directory, returns null.
pub fn dirname(path: []const u8) ?[]const u8 {
    if (native_os == .windows) {
        return dirnameWindows(path);
    } else {
        return dirnamePosix(path);
    }
}

pub fn dirnameWindows(path: []const u8) ?[]const u8 {
    if (path.len == 0)
        return null;

    const root_slice = diskDesignatorWindows(path);
    if (path.len == root_slice.len)
        return null;

    const have_root_slash = path.len > root_slice.len and (path[root_slice.len] == '/' or path[root_slice.len] == '\\');

    var end_index: usize = path.len - 1;

    while (path[end_index] == '/' or path[end_index] == '\\') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    while (path[end_index] != '/' and path[end_index] != '\\') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    if (have_root_slash and end_index == root_slice.len) {
        end_index += 1;
    }

    if (end_index == 0)
        return null;

    return path[0..end_index];
}

pub fn dirnamePosix(path: []const u8) ?[]const u8 {
    if (path.len == 0)
        return null;

    var end_index: usize = path.len - 1;
    while (path[end_index] == '/') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    while (path[end_index] != '/') {
        if (end_index == 0)
            return null;
        end_index -= 1;
    }

    if (end_index == 0 and path[0] == '/')
        return path[0..1];

    if (end_index == 0)
        return null;

    return path[0..end_index];
}

test "dirnamePosix" {
    try testDirnamePosix("/a/b/c", "/a/b");
    try testDirnamePosix("/a/b/c///", "/a/b");
    try testDirnamePosix("/a", "/");
    try testDirnamePosix("/", null);
    try testDirnamePosix("//", null);
    try testDirnamePosix("///", null);
    try testDirnamePosix("////", null);
    try testDirnamePosix("", null);
    try testDirnamePosix("a", null);
    try testDirnamePosix("a/", null);
    try testDirnamePosix("a//", null);
}

test "dirnameWindows" {
    try testDirnameWindows("c:\\", null);
    try testDirnameWindows("c:\\foo", "c:\\");
    try testDirnameWindows("c:\\foo\\", "c:\\");
    try testDirnameWindows("c:\\foo\\bar", "c:\\foo");
    try testDirnameWindows("c:\\foo\\bar\\", "c:\\foo");
    try testDirnameWindows("c:\\foo\\bar\\baz", "c:\\foo\\bar");
    try testDirnameWindows("\\", null);
    try testDirnameWindows("\\foo", "\\");
    try testDirnameWindows("\\foo\\", "\\");
    try testDirnameWindows("\\foo\\bar", "\\foo");
    try testDirnameWindows("\\foo\\bar\\", "\\foo");
    try testDirnameWindows("\\foo\\bar\\baz", "\\foo\\bar");
    try testDirnameWindows("c:", null);
    try testDirnameWindows("c:foo", null);
    try testDirnameWindows("c:foo\\", null);
    try testDirnameWindows("c:foo\\bar", "c:foo");
    try testDirnameWindows("c:foo\\bar\\", "c:foo");
    try testDirnameWindows("c:foo\\bar\\baz", "c:foo\\bar");
    try testDirnameWindows("file:stream", null);
    try testDirnameWindows("dir\\file:stream", "dir");
    try testDirnameWindows("\\\\unc\\share", null);
    try testDirnameWindows("\\\\unc\\share\\foo", "\\\\unc\\share\\");
    try testDirnameWindows("\\\\unc\\share\\foo\\", "\\\\unc\\share\\");
    try testDirnameWindows("\\\\unc\\share\\foo\\bar", "\\\\unc\\share\\foo");
    try testDirnameWindows("\\\\unc\\share\\foo\\bar\\", "\\\\unc\\share\\foo");
    try testDirnameWindows("\\\\unc\\share\\foo\\bar\\baz", "\\\\unc\\share\\foo\\bar");
    try testDirnameWindows("/a/b/", "/a");
    try testDirnameWindows("/a/b", "/a");
    try testDirnameWindows("/a", "/");
    try testDirnameWindows("", null);
    try testDirnameWindows("/", null);
    try testDirnameWindows("////", null);
    try testDirnameWindows("foo", null);
}

fn testDirnamePosix(input: []const u8, expected_output: ?[]const u8) !void {
    if (dirnamePosix(input)) |output| {
        try testing.expect(mem.eql(u8, output, expected_output.?));
    } else {
        try testing.expect(expected_output == null);
    }
}

fn testDirnameWindows(input: []const u8, expected_output: ?[]const u8) !void {
    if (dirnameWindows(input)) |output| {
        try testing.expect(mem.eql(u8, output, expected_output.?));
    } else {
        try testing.expect(expected_output == null);
    }
}

pub fn basename(path: []const u8) []const u8 {
    if (native_os == .windows) {
        return basenameWindows(path);
    } else {
        return basenamePosix(path);
    }
}

pub fn basenamePosix(path: []const u8) []const u8 {
    if (path.len == 0)
        return &[_]u8{};

    var end_index: usize = path.len - 1;
    while (path[end_index] == '/') {
        if (end_index == 0)
            return &[_]u8{};
        end_index -= 1;
    }
    var start_index: usize = end_index;
    end_index += 1;
    while (path[start_index] != '/') {
        if (start_index == 0)
            return path[0..end_index];
        start_index -= 1;
    }

    return path[start_index + 1 .. end_index];
}

pub fn basenameWindows(path: []const u8) []const u8 {
    if (path.len == 0)
        return &[_]u8{};

    var end_index: usize = path.len - 1;
    while (true) {
        const byte = path[end_index];
        if (byte == '/' or byte == '\\') {
            if (end_index == 0)
                return &[_]u8{};
            end_index -= 1;
            continue;
        }
        if (byte == ':' and end_index == 1) {
            return &[_]u8{};
        }
        break;
    }

    var start_index: usize = end_index;
    end_index += 1;
    while (path[start_index] != '/' and path[start_index] != '\\' and
        !(path[start_index] == ':' and start_index == 1))
    {
        if (start_index == 0)
            return path[0..end_index];
        start_index -= 1;
    }

    return path[start_index + 1 .. end_index];
}

test "basename" {
    try testBasename("", "");
    try testBasename("/", "");
    try testBasename("/dir/basename.ext", "basename.ext");
    try testBasename("/basename.ext", "basename.ext");
    try testBasename("basename.ext", "basename.ext");
    try testBasename("basename.ext/", "basename.ext");
    try testBasename("basename.ext//", "basename.ext");
    try testBasename("/aaa/bbb", "bbb");
    try testBasename("/aaa/", "aaa");
    try testBasename("/aaa/b", "b");
    try testBasename("/a/b", "b");
    try testBasename("//a", "a");

    try testBasenamePosix("\\dir\\basename.ext", "\\dir\\basename.ext");
    try testBasenamePosix("\\basename.ext", "\\basename.ext");
    try testBasenamePosix("basename.ext", "basename.ext");
    try testBasenamePosix("basename.ext\\", "basename.ext\\");
    try testBasenamePosix("basename.ext\\\\", "basename.ext\\\\");
    try testBasenamePosix("foo", "foo");

    try testBasenameWindows("\\dir\\basename.ext", "basename.ext");
    try testBasenameWindows("\\basename.ext", "basename.ext");
    try testBasenameWindows("basename.ext", "basename.ext");
    try testBasenameWindows("basename.ext\\", "basename.ext");
    try testBasenameWindows("basename.ext\\\\", "basename.ext");
    try testBasenameWindows("foo", "foo");
    try testBasenameWindows("C:", "");
    try testBasenameWindows("C:.", ".");
    try testBasenameWindows("C:\\", "");
    try testBasenameWindows("C:\\dir\\base.ext", "base.ext");
    try testBasenameWindows("C:\\basename.ext", "basename.ext");
    try testBasenameWindows("C:basename.ext", "basename.ext");
    try testBasenameWindows("C:basename.ext\\", "basename.ext");
    try testBasenameWindows("C:basename.ext\\\\", "basename.ext");
    try testBasenameWindows("C:foo", "foo");
    try testBasenameWindows("file:stream", "file:stream");
}

fn testBasename(input: []const u8, expected_output: []const u8) !void {
    try testing.expectEqualSlices(u8, expected_output, basename(input));
}

fn testBasenamePosix(input: []const u8, expected_output: []const u8) !void {
    try testing.expectEqualSlices(u8, expected_output, basenamePosix(input));
}

fn testBasenameWindows(input: []const u8, expected_output: []const u8) !void {
    try testing.expectEqualSlices(u8, expected_output, basenameWindows(input));
}

/// Returns the relative path from `from` to `to`. If `from` and `to` each
/// resolve to the same path (after calling `resolve` on each), a zero-length
/// string is returned.
/// On Windows this canonicalizes the drive to a capital letter and paths to `\\`.
pub fn relative(allocator: *Allocator, from: []const u8, to: []const u8) ![]u8 {
    if (native_os == .windows) {
        return relativeWindows(allocator, from, to);
    } else {
        return relativePosix(allocator, from, to);
    }
}

pub fn relativeWindows(allocator: *Allocator, from: []const u8, to: []const u8) ![]u8 {
    const resolved_from = try resolveWindows(allocator, &[_][]const u8{from});
    defer allocator.free(resolved_from);

    var clean_up_resolved_to = true;
    const resolved_to = try resolveWindows(allocator, &[_][]const u8{to});
    defer if (clean_up_resolved_to) allocator.free(resolved_to);

    const parsed_from = windowsParsePath(resolved_from);
    const parsed_to = windowsParsePath(resolved_to);
    const result_is_to = x: {
        if (parsed_from.kind != parsed_to.kind) {
            break :x true;
        } else switch (parsed_from.kind) {
            WindowsPath.Kind.NetworkShare => {
                break :x !networkShareServersEql(parsed_to.disk_designator, parsed_from.disk_designator);
            },
            WindowsPath.Kind.Drive => {
                break :x asciiUpper(parsed_from.disk_designator[0]) != asciiUpper(parsed_to.disk_designator[0]);
            },
            else => unreachable,
        }
    };

    if (result_is_to) {
        clean_up_resolved_to = false;
        return resolved_to;
    }

    var from_it = mem.tokenize(resolved_from, "/\\");
    var to_it = mem.tokenize(resolved_to, "/\\");
    while (true) {
        const from_component = from_it.next() orelse return allocator.dupe(u8, to_it.rest());
        const to_rest = to_it.rest();
        if (to_it.next()) |to_component| {
            // TODO ASCII is wrong, we actually need full unicode support to compare paths.
            if (asciiEqlIgnoreCase(from_component, to_component))
                continue;
        }
        var up_count: usize = 1;
        while (from_it.next()) |_| {
            up_count += 1;
        }
        const up_index_end = up_count * "..\\".len;
        const result = try allocator.alloc(u8, up_index_end + to_rest.len);
        errdefer allocator.free(result);

        var result_index: usize = 0;
        while (result_index < up_index_end) {
            result[result_index] = '.';
            result_index += 1;
            result[result_index] = '.';
            result_index += 1;
            result[result_index] = '\\';
            result_index += 1;
        }
        // shave off the trailing slash
        result_index -= 1;

        var rest_it = mem.tokenize(to_rest, "/\\");
        while (rest_it.next()) |to_component| {
            result[result_index] = '\\';
            result_index += 1;
            mem.copy(u8, result[result_index..], to_component);
            result_index += to_component.len;
        }

        return result[0..result_index];
    }

    return [_]u8{};
}

pub fn relativePosix(allocator: *Allocator, from: []const u8, to: []const u8) ![]u8 {
    const resolved_from = try resolvePosix(allocator, &[_][]const u8{from});
    defer allocator.free(resolved_from);

    const resolved_to = try resolvePosix(allocator, &[_][]const u8{to});
    defer allocator.free(resolved_to);

    var from_it = mem.tokenize(resolved_from, "/");
    var to_it = mem.tokenize(resolved_to, "/");
    while (true) {
        const from_component = from_it.next() orelse return allocator.dupe(u8, to_it.rest());
        const to_rest = to_it.rest();
        if (to_it.next()) |to_component| {
            if (mem.eql(u8, from_component, to_component))
                continue;
        }
        var up_count: usize = 1;
        while (from_it.next()) |_| {
            up_count += 1;
        }
        const up_index_end = up_count * "../".len;
        const result = try allocator.alloc(u8, up_index_end + to_rest.len);
        errdefer allocator.free(result);

        var result_index: usize = 0;
        while (result_index < up_index_end) {
            result[result_index] = '.';
            result_index += 1;
            result[result_index] = '.';
            result_index += 1;
            result[result_index] = '/';
            result_index += 1;
        }
        if (to_rest.len == 0) {
            // shave off the trailing slash
            return allocator.shrink(result, result_index - 1);
        }

        mem.copy(u8, result[result_index..], to_rest);
        return result;
    }

    return [_]u8{};
}

test "relative" {
    if (builtin.cpu.arch == .aarch64) {
        // TODO https://github.com/ziglang/zig/issues/3288
        return error.SkipZigTest;
    }
    if (native_os == .wasi) return error.SkipZigTest;

    try testRelativeWindows("c:/blah\\blah", "d:/games", "D:\\games");
    try testRelativeWindows("c:/aaaa/bbbb", "c:/aaaa", "..");
    try testRelativeWindows("c:/aaaa/bbbb", "c:/cccc", "..\\..\\cccc");
    try testRelativeWindows("c:/aaaa/bbbb", "c:/aaaa/bbbb", "");
    try testRelativeWindows("c:/aaaa/bbbb", "c:/aaaa/cccc", "..\\cccc");
    try testRelativeWindows("c:/aaaa/", "c:/aaaa/cccc", "cccc");
    try testRelativeWindows("c:/", "c:\\aaaa\\bbbb", "aaaa\\bbbb");
    try testRelativeWindows("c:/aaaa/bbbb", "d:\\", "D:\\");
    try testRelativeWindows("c:/AaAa/bbbb", "c:/aaaa/bbbb", "");
    try testRelativeWindows("c:/aaaaa/", "c:/aaaa/cccc", "..\\aaaa\\cccc");
    try testRelativeWindows("C:\\foo\\bar\\baz\\quux", "C:\\", "..\\..\\..\\..");
    try testRelativeWindows("C:\\foo\\test", "C:\\foo\\test\\bar\\package.json", "bar\\package.json");
    try testRelativeWindows("C:\\foo\\bar\\baz-quux", "C:\\foo\\bar\\baz", "..\\baz");
    try testRelativeWindows("C:\\foo\\bar\\baz", "C:\\foo\\bar\\baz-quux", "..\\baz-quux");
    try testRelativeWindows("\\\\foo\\bar", "\\\\foo\\bar\\baz", "baz");
    try testRelativeWindows("\\\\foo\\bar\\baz", "\\\\foo\\bar", "..");
    try testRelativeWindows("\\\\foo\\bar\\baz-quux", "\\\\foo\\bar\\baz", "..\\baz");
    try testRelativeWindows("\\\\foo\\bar\\baz", "\\\\foo\\bar\\baz-quux", "..\\baz-quux");
    try testRelativeWindows("C:\\baz-quux", "C:\\baz", "..\\baz");
    try testRelativeWindows("C:\\baz", "C:\\baz-quux", "..\\baz-quux");
    try testRelativeWindows("\\\\foo\\baz-quux", "\\\\foo\\baz", "..\\baz");
    try testRelativeWindows("\\\\foo\\baz", "\\\\foo\\baz-quux", "..\\baz-quux");
    try testRelativeWindows("C:\\baz", "\\\\foo\\bar\\baz", "\\\\foo\\bar\\baz");
    try testRelativeWindows("\\\\foo\\bar\\baz", "C:\\baz", "C:\\baz");

    try testRelativePosix("/var/lib", "/var", "..");
    try testRelativePosix("/var/lib", "/bin", "../../bin");
    try testRelativePosix("/var/lib", "/var/lib", "");
    try testRelativePosix("/var/lib", "/var/apache", "../apache");
    try testRelativePosix("/var/", "/var/lib", "lib");
    try testRelativePosix("/", "/var/lib", "var/lib");
    try testRelativePosix("/foo/test", "/foo/test/bar/package.json", "bar/package.json");
    try testRelativePosix("/Users/a/web/b/test/mails", "/Users/a/web/b", "../..");
    try testRelativePosix("/foo/bar/baz-quux", "/foo/bar/baz", "../baz");
    try testRelativePosix("/foo/bar/baz", "/foo/bar/baz-quux", "../baz-quux");
    try testRelativePosix("/baz-quux", "/baz", "../baz");
    try testRelativePosix("/baz", "/baz-quux", "../baz-quux");
}

fn testRelativePosix(from: []const u8, to: []const u8, expected_output: []const u8) !void {
    const result = try relativePosix(testing.allocator, from, to);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, expected_output, result);
}

fn testRelativeWindows(from: []const u8, to: []const u8, expected_output: []const u8) !void {
    const result = try relativeWindows(testing.allocator, from, to);
    defer testing.allocator.free(result);
    try testing.expectEqualSlices(u8, expected_output, result);
}

/// Returns the extension of the file name (if any).
/// This function will search for the file extension (separated by a `.`) and will return the text after the `.`.
/// Files that end with `.` are considered to have no extension, files that start with `.`
/// Examples:
/// - `"main.zig"`     ⇒ `".zig"`
/// - `"src/main.zig"` ⇒ `".zig"`
/// - `".gitignore"`   ⇒ `""`
/// - `"keep."`        ⇒ `"."`
/// - `"src.keep.me"`  ⇒ `".me"`
/// - `"/src/keep.me"`  ⇒ `".me"`
/// - `"/src/keep.me/"`  ⇒ `".me"`
/// The returned slice is guaranteed to have its pointer within the start and end
/// pointer address range of `path`, even if it is length zero.
pub fn extension(path: []const u8) []const u8 {
    const filename = basename(path);
    const index = mem.lastIndexOfScalar(u8, filename, '.') orelse return path[path.len..];
    if (index == 0) return path[path.len..];
    return filename[index..];
}

fn testExtension(path: []const u8, expected: []const u8) !void {
    try std.testing.expectEqualStrings(expected, extension(path));
}

test "extension" {
    try testExtension("", "");
    try testExtension(".", "");
    try testExtension("a.", ".");
    try testExtension("abc.", ".");
    try testExtension(".a", "");
    try testExtension(".file", "");
    try testExtension(".gitignore", "");
    try testExtension("file.ext", ".ext");
    try testExtension("file.ext.", ".");
    try testExtension("very-long-file.bruh", ".bruh");
    try testExtension("a.b.c", ".c");
    try testExtension("a.b.c/", ".c");

    try testExtension("/", "");
    try testExtension("/.", "");
    try testExtension("/a.", ".");
    try testExtension("/abc.", ".");
    try testExtension("/.a", "");
    try testExtension("/.file", "");
    try testExtension("/.gitignore", "");
    try testExtension("/file.ext", ".ext");
    try testExtension("/file.ext.", ".");
    try testExtension("/very-long-file.bruh", ".bruh");
    try testExtension("/a.b.c", ".c");
    try testExtension("/a.b.c/", ".c");

    try testExtension("/foo/bar/bam/", "");
    try testExtension("/foo/bar/bam/.", "");
    try testExtension("/foo/bar/bam/a.", ".");
    try testExtension("/foo/bar/bam/abc.", ".");
    try testExtension("/foo/bar/bam/.a", "");
    try testExtension("/foo/bar/bam/.file", "");
    try testExtension("/foo/bar/bam/.gitignore", "");
    try testExtension("/foo/bar/bam/file.ext", ".ext");
    try testExtension("/foo/bar/bam/file.ext.", ".");
    try testExtension("/foo/bar/bam/very-long-file.bruh", ".bruh");
    try testExtension("/foo/bar/bam/a.b.c", ".c");
    try testExtension("/foo/bar/bam/a.b.c/", ".c");
}
