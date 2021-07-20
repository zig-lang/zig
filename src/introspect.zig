const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const fs = std.fs;
const Compilation = @import("Compilation.zig");

/// Returns the sub_path that worked, or `null` if none did.
/// The path of the returned Directory is relative to `base`.
/// The handle of the returned Directory is open.
fn testZigInstallPrefix(base_dir: fs.Dir) ?Compilation.Directory {
    const test_index_file = "std" ++ fs.path.sep_str ++ "std.zig";

    zig_dir: {
        // Try lib/zig/std/std.zig
        const lib_zig = "lib" ++ fs.path.sep_str ++ "zig";
        var test_zig_dir = base_dir.openDir(lib_zig, .{}) catch break :zig_dir;
        const file = test_zig_dir.openFile(test_index_file, .{}) catch {
            test_zig_dir.close();
            break :zig_dir;
        };
        file.close();
        return Compilation.Directory{ .handle = test_zig_dir, .path = lib_zig };
    }

    // Try lib/std/std.zig
    var test_zig_dir = base_dir.openDir("lib", .{}) catch return null;
    const file = test_zig_dir.openFile(test_index_file, .{}) catch {
        test_zig_dir.close();
        return null;
    };
    file.close();
    return Compilation.Directory{ .handle = test_zig_dir, .path = "lib" };
}

/// Both the directory handle and the path are newly allocated resources which the caller now owns.
pub fn findZigLibDir(gpa: *mem.Allocator) !Compilation.Directory {
    const self_exe_path = try fs.selfExePathAlloc(gpa);
    defer gpa.free(self_exe_path);

    return findZigLibDirFromSelfExe(gpa, self_exe_path);
}

/// Both the directory handle and the path are newly allocated resources which the caller now owns.
pub fn findZigLibDirFromSelfExe(
    allocator: *mem.Allocator,
    self_exe_path: []const u8,
) error{ OutOfMemory, FileNotFound }!Compilation.Directory {
    const cwd = fs.cwd();
    var cur_path: []const u8 = self_exe_path;
    while (fs.path.dirname(cur_path)) |dirname| : (cur_path = dirname) {
        var base_dir = cwd.openDir(dirname, .{}) catch continue;
        defer base_dir.close();

        const sub_directory = testZigInstallPrefix(base_dir) orelse continue;
        return Compilation.Directory{
            .handle = sub_directory.handle,
            .path = try fs.path.join(allocator, &[_][]const u8{ dirname, sub_directory.path.? }),
        };
    }
    return error.FileNotFound;
}

/// Caller owns returned memory.
pub fn resolveGlobalCacheDir(allocator: *mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "ZIG_GLOBAL_CACHE_DIR")) |value| {
        if (value.len > 0) {
            return value;
        } else {
            allocator.free(value);
        }
    } else |_| {}

    const appname = "zig";

    if (builtin.os.tag != .windows) {
        if (std.os.getenv("XDG_CACHE_HOME")) |cache_root| {
            return fs.path.join(allocator, &[_][]const u8{ cache_root, appname });
        } else if (std.os.getenv("HOME")) |home| {
            return fs.path.join(allocator, &[_][]const u8{ home, ".cache", appname });
        }
    }

    return fs.getAppDataDir(allocator, appname);
}
