// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const unicode = std.unicode;
const mem = std.mem;
const fs = std.fs;
const os = std.os;

pub const GetAppDataDirError = error{
    OutOfMemory,
    AppDataDirUnavailable,
};

/// Caller owns returned memory.
/// TODO determine if we can remove the allocator requirement
pub fn getAppDataDir(allocator: *mem.Allocator, appname: []const u8) GetAppDataDirError![]u8 {
    switch (builtin.os.tag) {
        .windows => {
            var dir_path_ptr: [*:0]u16 = undefined;
            switch (os.windows.shell32.SHGetKnownFolderPath(
                &os.windows.FOLDERID_LocalAppData,
                os.windows.KF_FLAG_CREATE,
                null,
                &dir_path_ptr,
            )) {
                os.windows.S_OK => {
                    defer os.windows.ole32.CoTaskMemFree(@ptrCast(*c_void, dir_path_ptr));
                    const global_dir = unicode.utf16leToUtf8Alloc(allocator, mem.spanZ(dir_path_ptr)) catch |err| switch (err) {
                        error.UnexpectedSecondSurrogateHalf => return error.AppDataDirUnavailable,
                        error.ExpectedSecondSurrogateHalf => return error.AppDataDirUnavailable,
                        error.DanglingSurrogateHalf => return error.AppDataDirUnavailable,
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    defer allocator.free(global_dir);
                    return fs.path.join(allocator, &[_][]const u8{ global_dir, appname });
                },
                os.windows.E_OUTOFMEMORY => return error.OutOfMemory,
                else => return error.AppDataDirUnavailable,
            }
        },
        .macos => {
            const home_dir = os.getenv("HOME") orelse {
                // TODO look in /etc/passwd
                return error.AppDataDirUnavailable;
            };
            return fs.path.join(allocator, &[_][]const u8{ home_dir, "Library", "Application Support", appname });
        },
        .linux, .freebsd, .netbsd, .dragonfly, .openbsd => {
            const home_dir = os.getenv("HOME") orelse {
                // TODO look in /etc/passwd
                return error.AppDataDirUnavailable;
            };
            return fs.path.join(allocator, &[_][]const u8{ home_dir, ".local", "share", appname });
        },
        .haiku => {
            var dir_path_ptr: [*:0]u8 = undefined;
            // TODO look into directory_which
            const be_user_settings = 0xbbe;
            const rc = os.system.find_directory(be_user_settings, -1, true, dir_path_ptr, 1);
            const settings_dir = try allocator.dupeZ(u8, mem.spanZ(dir_path_ptr));
            defer allocator.free(settings_dir);
            switch (rc) {
                0 => return fs.path.join(allocator, &[_][]const u8{ settings_dir, appname }),
                else => return error.AppDataDirUnavailable,
            }
        },
        else => @compileError("Unsupported OS"),
    }
}

test "getAppDataDir" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    // We can't actually validate the result
    const dir = getAppDataDir(std.testing.allocator, "zig") catch return;
    defer std.testing.allocator.free(dir);
}
