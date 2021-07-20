const std = @import("std");
const builtin = @import("builtin");
const Target = std.Target;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const Batch = std.event.Batch;
const build_options = @import("build_options");

const is_darwin = builtin.target.isDarwin();
const is_windows = builtin.os.tag == .windows;
const is_haiku = builtin.os.tag == .haiku;

const log = std.log.scoped(.libc_installation);

usingnamespace @import("windows_sdk.zig");

/// See the render function implementation for documentation of the fields.
pub const LibCInstallation = struct {
    include_dir: ?[]const u8 = null,
    sys_include_dir: ?[]const u8 = null,
    crt_dir: ?[]const u8 = null,
    msvc_lib_dir: ?[]const u8 = null,
    kernel32_lib_dir: ?[]const u8 = null,
    gcc_dir: ?[]const u8 = null,

    pub const FindError = error{
        OutOfMemory,
        FileSystem,
        UnableToSpawnCCompiler,
        CCompilerExitCode,
        CCompilerCrashed,
        CCompilerCannotFindHeaders,
        LibCRuntimeNotFound,
        LibCStdLibHeaderNotFound,
        LibCKernel32LibNotFound,
        UnsupportedArchitecture,
        WindowsSdkNotFound,
        ZigIsTheCCompiler,
    };

    pub fn parse(
        allocator: *Allocator,
        libc_file: []const u8,
    ) !LibCInstallation {
        var self: LibCInstallation = .{};

        const fields = std.meta.fields(LibCInstallation);
        const FoundKey = struct {
            found: bool,
            allocated: ?[:0]u8,
        };
        var found_keys = [1]FoundKey{FoundKey{ .found = false, .allocated = null }} ** fields.len;
        errdefer {
            self = .{};
            for (found_keys) |found_key| {
                if (found_key.allocated) |s| allocator.free(s);
            }
        }

        const contents = try std.fs.cwd().readFileAlloc(allocator, libc_file, std.math.maxInt(usize));
        defer allocator.free(contents);

        var it = std.mem.tokenize(contents, "\n");
        while (it.next()) |line| {
            if (line.len == 0 or line[0] == '#') continue;
            var line_it = std.mem.split(line, "=");
            const name = line_it.next() orelse {
                log.err("missing equal sign after field name\n", .{});
                return error.ParseError;
            };
            const value = line_it.rest();
            inline for (fields) |field, i| {
                if (std.mem.eql(u8, name, field.name)) {
                    found_keys[i].found = true;
                    if (value.len == 0) {
                        @field(self, field.name) = null;
                    } else {
                        found_keys[i].allocated = try std.mem.dupeZ(allocator, u8, value);
                        @field(self, field.name) = found_keys[i].allocated;
                    }
                    break;
                }
            }
        }
        inline for (fields) |field, i| {
            if (!found_keys[i].found) {
                log.err("missing field: {s}\n", .{field.name});
                return error.ParseError;
            }
        }
        if (self.include_dir == null) {
            log.err("include_dir may not be empty\n", .{});
            return error.ParseError;
        }
        if (self.sys_include_dir == null) {
            log.err("sys_include_dir may not be empty\n", .{});
            return error.ParseError;
        }
        if (self.crt_dir == null and !is_darwin) {
            log.err("crt_dir may not be empty for {s}\n", .{@tagName(builtin.os.tag)});
            return error.ParseError;
        }
        if (self.msvc_lib_dir == null and is_windows) {
            log.err("msvc_lib_dir may not be empty for {s}-{s}\n", .{
                @tagName(builtin.os.tag),
                @tagName(builtin.abi),
            });
            return error.ParseError;
        }
        if (self.kernel32_lib_dir == null and is_windows) {
            log.err("kernel32_lib_dir may not be empty for {s}-{s}\n", .{
                @tagName(builtin.os.tag),
                @tagName(builtin.abi),
            });
            return error.ParseError;
        }
        if (self.gcc_dir == null and is_haiku) {
            log.err("gcc_dir may not be empty for {s}\n", .{@tagName(builtin.os.tag)});
            return error.ParseError;
        }

        return self;
    }

    pub fn render(self: LibCInstallation, out: anytype) !void {
        @setEvalBranchQuota(4000);
        const include_dir = self.include_dir orelse "";
        const sys_include_dir = self.sys_include_dir orelse "";
        const crt_dir = self.crt_dir orelse "";
        const msvc_lib_dir = self.msvc_lib_dir orelse "";
        const kernel32_lib_dir = self.kernel32_lib_dir orelse "";
        const gcc_dir = self.gcc_dir orelse "";

        try out.print(
            \\# The directory that contains `stdlib.h`.
            \\# On POSIX-like systems, include directories be found with: `cc -E -Wp,-v -xc /dev/null`
            \\include_dir={s}
            \\
            \\# The system-specific include directory. May be the same as `include_dir`.
            \\# On Windows it's the directory that includes `vcruntime.h`.
            \\# On POSIX it's the directory that includes `sys/errno.h`.
            \\sys_include_dir={s}
            \\
            \\# The directory that contains `crt1.o` or `crt2.o`.
            \\# On POSIX, can be found with `cc -print-file-name=crt1.o`.
            \\# Not needed when targeting MacOS.
            \\crt_dir={s}
            \\
            \\# The directory that contains `vcruntime.lib`.
            \\# Only needed when targeting MSVC on Windows.
            \\msvc_lib_dir={s}
            \\
            \\# The directory that contains `kernel32.lib`.
            \\# Only needed when targeting MSVC on Windows.
            \\kernel32_lib_dir={s}
            \\
            \\# The directory that contains `crtbeginS.o` and `crtendS.o`
            \\# Only needed when targeting Haiku.
            \\gcc_dir={s}
            \\
        , .{
            include_dir,
            sys_include_dir,
            crt_dir,
            msvc_lib_dir,
            kernel32_lib_dir,
            gcc_dir,
        });
    }

    pub const FindNativeOptions = struct {
        allocator: *Allocator,

        /// If enabled, will print human-friendly errors to stderr.
        verbose: bool = false,
    };

    /// Finds the default, native libc.
    pub fn findNative(args: FindNativeOptions) FindError!LibCInstallation {
        var self: LibCInstallation = .{};

        if (is_windows) {
            if (!build_options.have_llvm)
                return error.WindowsSdkNotFound;
            var sdk: *ZigWindowsSDK = undefined;
            switch (zig_find_windows_sdk(&sdk)) {
                .None => {
                    defer zig_free_windows_sdk(sdk);

                    var batch = Batch(FindError!void, 5, .auto_async).init();
                    batch.add(&async self.findNativeMsvcIncludeDir(args, sdk));
                    batch.add(&async self.findNativeMsvcLibDir(args, sdk));
                    batch.add(&async self.findNativeKernel32LibDir(args, sdk));
                    batch.add(&async self.findNativeIncludeDirWindows(args, sdk));
                    batch.add(&async self.findNativeCrtDirWindows(args, sdk));
                    try batch.wait();
                },
                .OutOfMemory => return error.OutOfMemory,
                .NotFound => return error.WindowsSdkNotFound,
                .PathTooLong => return error.WindowsSdkNotFound,
            }
        } else if (is_haiku) {
            try blk: {
                var batch = Batch(FindError!void, 2, .auto_async).init();
                errdefer batch.wait() catch {};
                batch.add(&async self.findNativeIncludeDirPosix(args));
                batch.add(&async self.findNativeCrtBeginDirHaiku(args));
                self.crt_dir = try std.mem.dupeZ(args.allocator, u8, "/system/develop/lib");
                break :blk batch.wait();
            };
        } else {
            try blk: {
                var batch = Batch(FindError!void, 2, .auto_async).init();
                errdefer batch.wait() catch {};
                batch.add(&async self.findNativeIncludeDirPosix(args));
                switch (builtin.os.tag) {
                    .freebsd, .netbsd, .openbsd, .dragonfly => self.crt_dir = try std.mem.dupeZ(args.allocator, u8, "/usr/lib"),
                    .linux => batch.add(&async self.findNativeCrtDirPosix(args)),
                    else => {},
                }
                break :blk batch.wait();
            };
        }
        return self;
    }

    /// Must be the same allocator passed to `parse` or `findNative`.
    pub fn deinit(self: *LibCInstallation, allocator: *Allocator) void {
        const fields = std.meta.fields(LibCInstallation);
        inline for (fields) |field| {
            if (@field(self, field.name)) |payload| {
                allocator.free(payload);
            }
        }
        self.* = undefined;
    }

    fn findNativeIncludeDirPosix(self: *LibCInstallation, args: FindNativeOptions) FindError!void {
        const allocator = args.allocator;

        // Detect infinite loops.
        var env_map = try std.process.getEnvMap(allocator);
        defer env_map.deinit();
        const skip_cc_env_var = if (env_map.get(inf_loop_env_key)) |phase| blk: {
            if (std.mem.eql(u8, phase, "1")) {
                try env_map.put(inf_loop_env_key, "2");
                break :blk true;
            } else {
                return error.ZigIsTheCCompiler;
            }
        } else blk: {
            try env_map.put(inf_loop_env_key, "1");
            break :blk false;
        };

        const dev_null = if (is_windows) "nul" else "/dev/null";

        var argv = std.ArrayList([]const u8).init(allocator);
        defer argv.deinit();

        try appendCcExe(&argv, skip_cc_env_var);
        try argv.appendSlice(&.{
            "-E",
            "-Wp,-v",
            "-xc",
            dev_null,
        });

        const exec_res = std.ChildProcess.exec(.{
            .allocator = allocator,
            .argv = argv.items,
            .max_output_bytes = 1024 * 1024,
            .env_map = &env_map,
            // Some C compilers, such as Clang, are known to rely on argv[0] to find the path
            // to their own executable, without even bothering to resolve PATH. This results in the message:
            // error: unable to execute command: Executable "" doesn't exist!
            // So we use the expandArg0 variant of ChildProcess to give them a helping hand.
            .expand_arg0 = .expand,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                printVerboseInvocation(argv.items, null, args.verbose, null);
                return error.UnableToSpawnCCompiler;
            },
        };
        defer {
            allocator.free(exec_res.stdout);
            allocator.free(exec_res.stderr);
        }
        switch (exec_res.term) {
            .Exited => |code| if (code != 0) {
                printVerboseInvocation(argv.items, null, args.verbose, exec_res.stderr);
                return error.CCompilerExitCode;
            },
            else => {
                printVerboseInvocation(argv.items, null, args.verbose, exec_res.stderr);
                return error.CCompilerCrashed;
            },
        }

        var it = std.mem.tokenize(exec_res.stderr, "\n\r");
        var search_paths = std.ArrayList([]const u8).init(allocator);
        defer search_paths.deinit();
        while (it.next()) |line| {
            if (line.len != 0 and line[0] == ' ') {
                try search_paths.append(line);
            }
        }
        if (search_paths.items.len == 0) {
            return error.CCompilerCannotFindHeaders;
        }

        const include_dir_example_file = if (is_haiku) "posix/stdlib.h" else "stdlib.h";
        const sys_include_dir_example_file = if (is_windows)
            "sys\\types.h"
        else if (is_haiku)
            "posix/errno.h"
        else
            "sys/errno.h";

        var path_i: usize = 0;
        while (path_i < search_paths.items.len) : (path_i += 1) {
            // search in reverse order
            const search_path_untrimmed = search_paths.items[search_paths.items.len - path_i - 1];
            const search_path = std.mem.trimLeft(u8, search_path_untrimmed, " ");
            var search_dir = fs.cwd().openDir(search_path, .{}) catch |err| switch (err) {
                error.FileNotFound,
                error.NotDir,
                error.NoDevice,
                => continue,

                else => return error.FileSystem,
            };
            defer search_dir.close();

            if (self.include_dir == null) {
                if (search_dir.accessZ(include_dir_example_file, .{})) |_| {
                    self.include_dir = try std.mem.dupeZ(allocator, u8, search_path);
                } else |err| switch (err) {
                    error.FileNotFound => {},
                    else => return error.FileSystem,
                }
            }

            if (self.sys_include_dir == null) {
                if (search_dir.accessZ(sys_include_dir_example_file, .{})) |_| {
                    self.sys_include_dir = try std.mem.dupeZ(allocator, u8, search_path);
                } else |err| switch (err) {
                    error.FileNotFound => {},
                    else => return error.FileSystem,
                }
            }

            if (self.include_dir != null and self.sys_include_dir != null) {
                // Success.
                return;
            }
        }

        return error.LibCStdLibHeaderNotFound;
    }

    fn findNativeIncludeDirWindows(
        self: *LibCInstallation,
        args: FindNativeOptions,
        sdk: *ZigWindowsSDK,
    ) FindError!void {
        const allocator = args.allocator;

        var search_buf: [2]Search = undefined;
        const searches = fillSearch(&search_buf, sdk);

        var result_buf = std.ArrayList(u8).init(allocator);
        defer result_buf.deinit();

        for (searches) |search| {
            result_buf.shrinkAndFree(0);
            try result_buf.writer().print("{s}\\Include\\{s}\\ucrt", .{ search.path, search.version });

            var dir = fs.cwd().openDir(result_buf.items, .{}) catch |err| switch (err) {
                error.FileNotFound,
                error.NotDir,
                error.NoDevice,
                => continue,

                else => return error.FileSystem,
            };
            defer dir.close();

            dir.accessZ("stdlib.h", .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return error.FileSystem,
            };

            self.include_dir = result_buf.toOwnedSlice();
            return;
        }

        return error.LibCStdLibHeaderNotFound;
    }

    fn findNativeCrtDirWindows(
        self: *LibCInstallation,
        args: FindNativeOptions,
        sdk: *ZigWindowsSDK,
    ) FindError!void {
        const allocator = args.allocator;

        var search_buf: [2]Search = undefined;
        const searches = fillSearch(&search_buf, sdk);

        var result_buf = std.ArrayList(u8).init(allocator);
        defer result_buf.deinit();

        const arch_sub_dir = switch (builtin.cpu.arch) {
            .i386 => "x86",
            .x86_64 => "x64",
            .arm, .armeb => "arm",
            else => return error.UnsupportedArchitecture,
        };

        for (searches) |search| {
            result_buf.shrinkAndFree(0);
            try result_buf.writer().print("{s}\\Lib\\{s}\\ucrt\\{s}", .{ search.path, search.version, arch_sub_dir });

            var dir = fs.cwd().openDir(result_buf.items, .{}) catch |err| switch (err) {
                error.FileNotFound,
                error.NotDir,
                error.NoDevice,
                => continue,

                else => return error.FileSystem,
            };
            defer dir.close();

            dir.accessZ("ucrt.lib", .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return error.FileSystem,
            };

            self.crt_dir = result_buf.toOwnedSlice();
            return;
        }
        return error.LibCRuntimeNotFound;
    }

    fn findNativeCrtDirPosix(self: *LibCInstallation, args: FindNativeOptions) FindError!void {
        self.crt_dir = try ccPrintFileName(.{
            .allocator = args.allocator,
            .search_basename = "crt1.o",
            .want_dirname = .only_dir,
            .verbose = args.verbose,
        });
    }

    fn findNativeCrtBeginDirHaiku(self: *LibCInstallation, args: FindNativeOptions) FindError!void {
        self.gcc_dir = try ccPrintFileName(.{
            .allocator = args.allocator,
            .search_basename = "crtbeginS.o",
            .want_dirname = .only_dir,
            .verbose = args.verbose,
        });
    }

    fn findNativeKernel32LibDir(
        self: *LibCInstallation,
        args: FindNativeOptions,
        sdk: *ZigWindowsSDK,
    ) FindError!void {
        const allocator = args.allocator;

        var search_buf: [2]Search = undefined;
        const searches = fillSearch(&search_buf, sdk);

        var result_buf = std.ArrayList(u8).init(allocator);
        defer result_buf.deinit();

        const arch_sub_dir = switch (builtin.cpu.arch) {
            .i386 => "x86",
            .x86_64 => "x64",
            .arm, .armeb => "arm",
            else => return error.UnsupportedArchitecture,
        };

        for (searches) |search| {
            result_buf.shrinkAndFree(0);
            const stream = result_buf.writer();
            try stream.print("{s}\\Lib\\{s}\\um\\{s}", .{ search.path, search.version, arch_sub_dir });

            var dir = fs.cwd().openDir(result_buf.items, .{}) catch |err| switch (err) {
                error.FileNotFound,
                error.NotDir,
                error.NoDevice,
                => continue,

                else => return error.FileSystem,
            };
            defer dir.close();

            dir.accessZ("kernel32.lib", .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return error.FileSystem,
            };

            self.kernel32_lib_dir = result_buf.toOwnedSlice();
            return;
        }
        return error.LibCKernel32LibNotFound;
    }

    fn findNativeMsvcIncludeDir(
        self: *LibCInstallation,
        args: FindNativeOptions,
        sdk: *ZigWindowsSDK,
    ) FindError!void {
        const allocator = args.allocator;

        const msvc_lib_dir_ptr = sdk.msvc_lib_dir_ptr orelse return error.LibCStdLibHeaderNotFound;
        const msvc_lib_dir = msvc_lib_dir_ptr[0..sdk.msvc_lib_dir_len];
        const up1 = fs.path.dirname(msvc_lib_dir) orelse return error.LibCStdLibHeaderNotFound;
        const up2 = fs.path.dirname(up1) orelse return error.LibCStdLibHeaderNotFound;

        const dir_path = try fs.path.join(allocator, &[_][]const u8{ up2, "include" });
        errdefer allocator.free(dir_path);

        var dir = fs.cwd().openDir(dir_path, .{}) catch |err| switch (err) {
            error.FileNotFound,
            error.NotDir,
            error.NoDevice,
            => return error.LibCStdLibHeaderNotFound,

            else => return error.FileSystem,
        };
        defer dir.close();

        dir.accessZ("vcruntime.h", .{}) catch |err| switch (err) {
            error.FileNotFound => return error.LibCStdLibHeaderNotFound,
            else => return error.FileSystem,
        };

        self.sys_include_dir = dir_path;
    }

    fn findNativeMsvcLibDir(
        self: *LibCInstallation,
        args: FindNativeOptions,
        sdk: *ZigWindowsSDK,
    ) FindError!void {
        const allocator = args.allocator;
        const msvc_lib_dir_ptr = sdk.msvc_lib_dir_ptr orelse return error.LibCRuntimeNotFound;
        self.msvc_lib_dir = try std.mem.dupeZ(allocator, u8, msvc_lib_dir_ptr[0..sdk.msvc_lib_dir_len]);
    }
};

pub const CCPrintFileNameOptions = struct {
    allocator: *Allocator,
    search_basename: []const u8,
    want_dirname: enum { full_path, only_dir },
    verbose: bool = false,
};

/// caller owns returned memory
fn ccPrintFileName(args: CCPrintFileNameOptions) ![:0]u8 {
    const allocator = args.allocator;

    // Detect infinite loops.
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    const skip_cc_env_var = if (env_map.get(inf_loop_env_key)) |phase| blk: {
        if (std.mem.eql(u8, phase, "1")) {
            try env_map.put(inf_loop_env_key, "2");
            break :blk true;
        } else {
            return error.ZigIsTheCCompiler;
        }
    } else blk: {
        try env_map.put(inf_loop_env_key, "1");
        break :blk false;
    };

    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();

    const arg1 = try std.fmt.allocPrint(allocator, "-print-file-name={s}", .{args.search_basename});
    defer allocator.free(arg1);

    try appendCcExe(&argv, skip_cc_env_var);
    try argv.append(arg1);

    const exec_res = std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = argv.items,
        .max_output_bytes = 1024 * 1024,
        .env_map = &env_map,
        // Some C compilers, such as Clang, are known to rely on argv[0] to find the path
        // to their own executable, without even bothering to resolve PATH. This results in the message:
        // error: unable to execute command: Executable "" doesn't exist!
        // So we use the expandArg0 variant of ChildProcess to give them a helping hand.
        .expand_arg0 = .expand,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.UnableToSpawnCCompiler,
    };
    defer {
        allocator.free(exec_res.stdout);
        allocator.free(exec_res.stderr);
    }
    switch (exec_res.term) {
        .Exited => |code| if (code != 0) {
            printVerboseInvocation(argv.items, args.search_basename, args.verbose, exec_res.stderr);
            return error.CCompilerExitCode;
        },
        else => {
            printVerboseInvocation(argv.items, args.search_basename, args.verbose, exec_res.stderr);
            return error.CCompilerCrashed;
        },
    }

    var it = std.mem.tokenize(exec_res.stdout, "\n\r");
    const line = it.next() orelse return error.LibCRuntimeNotFound;
    // When this command fails, it returns exit code 0 and duplicates the input file name.
    // So we detect failure by checking if the output matches exactly the input.
    if (std.mem.eql(u8, line, args.search_basename)) return error.LibCRuntimeNotFound;
    switch (args.want_dirname) {
        .full_path => return std.mem.dupeZ(allocator, u8, line),
        .only_dir => {
            const dirname = fs.path.dirname(line) orelse return error.LibCRuntimeNotFound;
            return std.mem.dupeZ(allocator, u8, dirname);
        },
    }
}

fn printVerboseInvocation(
    argv: []const []const u8,
    search_basename: ?[]const u8,
    verbose: bool,
    stderr: ?[]const u8,
) void {
    if (!verbose) return;

    if (search_basename) |s| {
        std.debug.warn("Zig attempted to find the file '{s}' by executing this command:\n", .{s});
    } else {
        std.debug.warn("Zig attempted to find the path to native system libc headers by executing this command:\n", .{});
    }
    for (argv) |arg, i| {
        if (i != 0) std.debug.warn(" ", .{});
        std.debug.warn("{s}", .{arg});
    }
    std.debug.warn("\n", .{});
    if (stderr) |s| {
        std.debug.warn("Output:\n==========\n{s}\n==========\n", .{s});
    }
}

const Search = struct {
    path: []const u8,
    version: []const u8,
};

fn fillSearch(search_buf: *[2]Search, sdk: *ZigWindowsSDK) []Search {
    var search_end: usize = 0;
    if (sdk.path10_ptr) |path10_ptr| {
        if (sdk.version10_ptr) |version10_ptr| {
            search_buf[search_end] = Search{
                .path = path10_ptr[0..sdk.path10_len],
                .version = version10_ptr[0..sdk.version10_len],
            };
            search_end += 1;
        }
    }
    if (sdk.path81_ptr) |path81_ptr| {
        if (sdk.version81_ptr) |version81_ptr| {
            search_buf[search_end] = Search{
                .path = path81_ptr[0..sdk.path81_len],
                .version = version81_ptr[0..sdk.version81_len],
            };
            search_end += 1;
        }
    }
    return search_buf[0..search_end];
}

const inf_loop_env_key = "ZIG_IS_DETECTING_LIBC_PATHS";

fn appendCcExe(args: *std.ArrayList([]const u8), skip_cc_env_var: bool) !void {
    const default_cc_exe = if (is_windows) "cc.exe" else "cc";
    try args.ensureUnusedCapacity(1);
    if (skip_cc_env_var) {
        args.appendAssumeCapacity(default_cc_exe);
        return;
    }
    const cc_env_var = std.os.getenvZ("CC") orelse {
        args.appendAssumeCapacity(default_cc_exe);
        return;
    };
    // Respect space-separated flags to the C compiler.
    var it = std.mem.tokenize(cc_env_var, " ");
    while (it.next()) |arg| {
        try args.append(arg);
    }
}
