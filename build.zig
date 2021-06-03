const std = @import("std");
const builtin = std.builtin;
const Builder = std.build.Builder;
const tests = @import("test/tests.zig");
const BufMap = std.BufMap;
const warn = std.debug.warn;
const mem = std.mem;
const ArrayList = std.ArrayList;
const io = std.io;
const fs = std.fs;
const InstallDirectoryOptions = std.build.InstallDirectoryOptions;
const assert = std.debug.assert;

const zig_version = std.builtin.Version{ .major = 0, .minor = 8, .patch = 0 };

pub fn build(b: *Builder) !void {
    b.setPreferredReleaseMode(.ReleaseFast);
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});
    const single_threaded = b.option(bool, "single-threaded", "Build artifacts that run in single threaded mode") orelse false;

    var docgen_exe = b.addExecutable("docgen", "doc/docgen.zig");
    docgen_exe.single_threaded = single_threaded;

    const rel_zig_exe = try fs.path.relative(b.allocator, b.build_root, b.zig_exe);
    const langref_out_path = fs.path.join(
        b.allocator,
        &[_][]const u8{ b.cache_root, "langref.html" },
    ) catch unreachable;
    var docgen_cmd = docgen_exe.run();
    docgen_cmd.addArgs(&[_][]const u8{
        rel_zig_exe,
        "doc" ++ fs.path.sep_str ++ "langref.html.in",
        langref_out_path,
    });
    docgen_cmd.step.dependOn(&docgen_exe.step);

    const docs_step = b.step("docs", "Build documentation");
    docs_step.dependOn(&docgen_cmd.step);

    const toolchain_step = b.step("test-toolchain", "Run the tests for the toolchain");

    var test_stage2 = b.addTest("src/test.zig");
    test_stage2.setBuildMode(mode);
    test_stage2.addPackagePath("stage2_tests", "test/stage2/test.zig");
    test_stage2.single_threaded = single_threaded;

    const fmt_build_zig = b.addFmt(&[_][]const u8{"build.zig"});

    const skip_debug = b.option(bool, "skip-debug", "Main test suite skips debug builds") orelse false;
    const skip_release = b.option(bool, "skip-release", "Main test suite skips release builds") orelse false;
    const skip_release_small = b.option(bool, "skip-release-small", "Main test suite skips release-small builds") orelse skip_release;
    const skip_release_fast = b.option(bool, "skip-release-fast", "Main test suite skips release-fast builds") orelse skip_release;
    const skip_release_safe = b.option(bool, "skip-release-safe", "Main test suite skips release-safe builds") orelse skip_release;
    const skip_non_native = b.option(bool, "skip-non-native", "Main test suite skips non-native builds") orelse false;
    const skip_libc = b.option(bool, "skip-libc", "Main test suite skips tests that link libc") orelse false;
    const skip_compile_errors = b.option(bool, "skip-compile-errors", "Main test suite skips compile error tests") orelse false;
    const skip_run_translated_c = b.option(bool, "skip-run-translated-c", "Main test suite skips run-translated-c tests") orelse false;
    const skip_stage2_tests = b.option(bool, "skip-stage2-tests", "Main test suite skips self-hosted compiler tests") orelse false;
    const skip_install_lib_files = b.option(bool, "skip-install-lib-files", "Do not copy lib/ files to installation prefix") orelse false;

    const only_install_lib_files = b.option(bool, "lib-files-only", "Only install library files") orelse false;
    const is_stage1 = b.option(bool, "stage1", "Build the stage1 compiler, put stage2 behind a feature flag") orelse false;
    const omit_stage2 = b.option(bool, "omit-stage2", "Do not include stage2 behind a feature flag inside stage1") orelse false;
    const static_llvm = b.option(bool, "static-llvm", "Disable integration with system-installed LLVM, Clang, LLD, and libc++") orelse false;
    const enable_llvm = b.option(bool, "enable-llvm", "Build self-hosted compiler with LLVM backend enabled") orelse (is_stage1 or static_llvm);
    const config_h_path_option = b.option([]const u8, "config_h", "Path to the generated config.h");

    if (!skip_install_lib_files) {
        b.installDirectory(InstallDirectoryOptions{
            .source_dir = "lib",
            .install_dir = .Lib,
            .install_subdir = "zig",
            .exclude_extensions = &[_][]const u8{
                "README.md",
                ".z.0",
                ".z.9",
                ".gz",
                "rfc1951.txt",
            },
            .blank_extensions = &[_][]const u8{
                "test.zig",
            },
        });
    }

    if (only_install_lib_files)
        return;

    const tracy = b.option([]const u8, "tracy", "Enable Tracy integration. Supply path to Tracy source");
    const link_libc = b.option(bool, "force-link-libc", "Force self-hosted compiler to link libc") orelse enable_llvm;
    const strip = b.option(bool, "strip", "Omit debug information") orelse false;

    const mem_leak_frames: u32 = b.option(u32, "mem-leak-frames", "How many stack frames to print when a memory leak occurs. Tests get 2x this amount.") orelse blk: {
        if (strip) break :blk @as(u32, 0);
        if (mode != .Debug) break :blk 0;
        break :blk 4;
    };

    const main_file = if (is_stage1) "src/stage1.zig" else "src/main.zig";

    var exe = b.addExecutable("zig", main_file);
    exe.strip = strip;
    exe.install();
    exe.setBuildMode(mode);
    exe.setTarget(target);
    toolchain_step.dependOn(&exe.step);
    b.default_step.dependOn(&exe.step);
    exe.single_threaded = single_threaded;

    exe.addBuildOption(u32, "mem_leak_frames", mem_leak_frames);
    exe.addBuildOption(bool, "skip_non_native", skip_non_native);
    exe.addBuildOption(bool, "have_llvm", enable_llvm);
    if (enable_llvm) {
        const cmake_cfg = if (static_llvm) null else findAndParseConfigH(b, config_h_path_option);

        if (is_stage1) {
            exe.addIncludeDir("src");
            exe.addIncludeDir("deps/SoftFloat-3e/source/include");
            // This is intentionally a dummy path. stage1.zig tries to @import("compiler_rt") in case
            // of being built by cmake. But when built by zig it's gonna get a compiler_rt so that
            // is pointless.
            exe.addPackagePath("compiler_rt", "src/empty.zig");
            exe.defineCMacro("ZIG_LINK_MODE=Static");

            const softfloat = b.addStaticLibrary("softfloat", null);
            softfloat.setBuildMode(.ReleaseFast);
            softfloat.setTarget(target);
            softfloat.addIncludeDir("deps/SoftFloat-3e-prebuilt");
            softfloat.addIncludeDir("deps/SoftFloat-3e/source/8086");
            softfloat.addIncludeDir("deps/SoftFloat-3e/source/include");
            softfloat.addCSourceFiles(&softfloat_sources, &[_][]const u8{ "-std=c99", "-O3" });
            softfloat.single_threaded = single_threaded;
            exe.linkLibrary(softfloat);

            exe.addCSourceFiles(&stage1_sources, &exe_cflags);
            exe.addCSourceFiles(&optimized_c_sources, &[_][]const u8{ "-std=c99", "-O3" });
        }
        if (cmake_cfg) |cfg| {
            // Inside this code path, we have to coordinate with system packaged LLVM, Clang, and LLD.
            // That means we also have to rely on stage1 compiled c++ files. We parse config.h to find
            // the information passed on to us from cmake.
            if (cfg.cmake_prefix_path.len > 0) {
                b.addSearchPrefix(cfg.cmake_prefix_path);
            }

            try addCmakeCfgOptionsToExe(b, cfg, tracy, exe);
            try addCmakeCfgOptionsToExe(b, cfg, tracy, test_stage2);
        } else {
            // Here we are -Denable-llvm but no cmake integration.
            try addStaticLlvmOptionsToExe(exe);
            try addStaticLlvmOptionsToExe(test_stage2);
        }
    }
    if (link_libc) {
        exe.linkLibC();
        test_stage2.linkLibC();
    }

    const enable_logging = b.option(bool, "log", "Whether to enable logging") orelse false;

    const opt_version_string = b.option([]const u8, "version-string", "Override Zig version string. Default is to find out with git.");
    const version = if (opt_version_string) |version| version else v: {
        const version_string = b.fmt("{d}.{d}.{d}", .{ zig_version.major, zig_version.minor, zig_version.patch });

        var code: u8 = undefined;
        const git_describe_untrimmed = b.execAllowFail(&[_][]const u8{
            "git", "-C", b.build_root, "describe", "--match", "*.*.*", "--tags",
        }, &code, .Ignore) catch {
            break :v version_string;
        };
        const git_describe = mem.trim(u8, git_describe_untrimmed, " \n\r");

        switch (mem.count(u8, git_describe, "-")) {
            0 => {
                // Tagged release version (e.g. 0.7.0).
                if (!mem.eql(u8, git_describe, version_string)) {
                    std.debug.print("Zig version '{s}' does not match Git tag '{s}'\n", .{ version_string, git_describe });
                    std.process.exit(1);
                }
                break :v version_string;
            },
            2 => {
                // Untagged development build (e.g. 0.7.0-684-gbbe2cca1a).
                var it = mem.split(git_describe, "-");
                const tagged_ancestor = it.next() orelse unreachable;
                const commit_height = it.next() orelse unreachable;
                const commit_id = it.next() orelse unreachable;

                const ancestor_ver = try std.builtin.Version.parse(tagged_ancestor);
                if (zig_version.order(ancestor_ver) != .gt) {
                    std.debug.print("Zig version '{}' must be greater than tagged ancestor '{}'\n", .{ zig_version, ancestor_ver });
                    std.process.exit(1);
                }

                // Check that the commit hash is prefixed with a 'g' (a Git convention).
                if (commit_id.len < 1 or commit_id[0] != 'g') {
                    std.debug.print("Unexpected `git describe` output: {s}\n", .{git_describe});
                    break :v version_string;
                }

                // The version is reformatted in accordance with the https://semver.org specification.
                break :v b.fmt("{s}-dev.{s}+{s}", .{ version_string, commit_height, commit_id[1..] });
            },
            else => {
                std.debug.print("Unexpected `git describe` output: {s}\n", .{git_describe});
                break :v version_string;
            },
        }
    };
    exe.addBuildOption([:0]const u8, "version", try b.allocator.dupeZ(u8, version));

    const semver = try std.SemanticVersion.parse(version);
    exe.addBuildOption(std.SemanticVersion, "semver", semver);

    exe.addBuildOption(bool, "enable_logging", enable_logging);
    exe.addBuildOption(bool, "enable_tracy", tracy != null);
    exe.addBuildOption(bool, "is_stage1", is_stage1);
    exe.addBuildOption(bool, "omit_stage2", omit_stage2);
    if (tracy) |tracy_path| {
        const client_cpp = fs.path.join(
            b.allocator,
            &[_][]const u8{ tracy_path, "TracyClient.cpp" },
        ) catch unreachable;
        exe.addIncludeDir(tracy_path);
        exe.addCSourceFile(client_cpp, &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined" });
        if (!enable_llvm) {
            exe.linkSystemLibraryName("c++");
        }
        exe.linkLibC();
    }

    const test_filter = b.option([]const u8, "test-filter", "Skip tests that do not match filter");

    const is_wine_enabled = b.option(bool, "enable-wine", "Use Wine to run cross compiled Windows tests") orelse false;
    const is_qemu_enabled = b.option(bool, "enable-qemu", "Use QEMU to run cross compiled foreign architecture tests") orelse false;
    const is_wasmtime_enabled = b.option(bool, "enable-wasmtime", "Use Wasmtime to enable and run WASI libstd tests") orelse false;
    const is_darling_enabled = b.option(bool, "enable-darling", "[Experimental] Use Darling to run cross compiled macOS tests") orelse false;
    const glibc_multi_dir = b.option([]const u8, "enable-foreign-glibc", "Provide directory with glibc installations to run cross compiled tests that link glibc");

    test_stage2.addBuildOption(bool, "skip_non_native", skip_non_native);
    test_stage2.addBuildOption(bool, "is_stage1", is_stage1);
    test_stage2.addBuildOption(bool, "omit_stage2", omit_stage2);
    test_stage2.addBuildOption(bool, "have_llvm", enable_llvm);
    test_stage2.addBuildOption(bool, "enable_qemu", is_qemu_enabled);
    test_stage2.addBuildOption(bool, "enable_wine", is_wine_enabled);
    test_stage2.addBuildOption(bool, "enable_wasmtime", is_wasmtime_enabled);
    test_stage2.addBuildOption(u32, "mem_leak_frames", mem_leak_frames * 2);
    test_stage2.addBuildOption(bool, "enable_darling", is_darling_enabled);
    test_stage2.addBuildOption(?[]const u8, "glibc_multi_install_dir", glibc_multi_dir);
    test_stage2.addBuildOption([]const u8, "version", version);

    const test_stage2_step = b.step("test-stage2", "Run the stage2 compiler tests");
    test_stage2_step.dependOn(&test_stage2.step);
    if (!skip_stage2_tests) {
        toolchain_step.dependOn(test_stage2_step);
    }

    var chosen_modes: [4]builtin.Mode = undefined;
    var chosen_mode_index: usize = 0;
    if (!skip_debug) {
        chosen_modes[chosen_mode_index] = builtin.Mode.Debug;
        chosen_mode_index += 1;
    }
    if (!skip_release_safe) {
        chosen_modes[chosen_mode_index] = builtin.Mode.ReleaseSafe;
        chosen_mode_index += 1;
    }
    if (!skip_release_fast) {
        chosen_modes[chosen_mode_index] = builtin.Mode.ReleaseFast;
        chosen_mode_index += 1;
    }
    if (!skip_release_small) {
        chosen_modes[chosen_mode_index] = builtin.Mode.ReleaseSmall;
        chosen_mode_index += 1;
    }
    const modes = chosen_modes[0..chosen_mode_index];

    // run stage1 `zig fmt` on this build.zig file just to make sure it works
    toolchain_step.dependOn(&fmt_build_zig.step);
    const fmt_step = b.step("test-fmt", "Run zig fmt against build.zig to make sure it works");
    fmt_step.dependOn(&fmt_build_zig.step);

    toolchain_step.dependOn(tests.addPkgTests(
        b,
        test_filter,
        "test/behavior.zig",
        "behavior",
        "Run the behavior tests",
        modes,
        false, // skip_single_threaded
        skip_non_native,
        skip_libc,
        is_wine_enabled,
        is_qemu_enabled,
        is_wasmtime_enabled,
        is_darling_enabled,
        glibc_multi_dir,
    ));

    toolchain_step.dependOn(tests.addPkgTests(
        b,
        test_filter,
        "lib/std/special/compiler_rt.zig",
        "compiler-rt",
        "Run the compiler_rt tests",
        modes,
        true, // skip_single_threaded
        skip_non_native,
        true, // skip_libc
        is_wine_enabled,
        is_qemu_enabled,
        is_wasmtime_enabled,
        is_darling_enabled,
        glibc_multi_dir,
    ));

    toolchain_step.dependOn(tests.addPkgTests(
        b,
        test_filter,
        "lib/std/special/c.zig",
        "minilibc",
        "Run the mini libc tests",
        modes,
        true, // skip_single_threaded
        skip_non_native,
        true, // skip_libc
        is_wine_enabled,
        is_qemu_enabled,
        is_wasmtime_enabled,
        is_darling_enabled,
        glibc_multi_dir,
    ));

    toolchain_step.dependOn(tests.addCompareOutputTests(b, test_filter, modes));
    toolchain_step.dependOn(tests.addStandaloneTests(b, test_filter, modes, skip_non_native, target));
    toolchain_step.dependOn(tests.addStackTraceTests(b, test_filter, modes));
    toolchain_step.dependOn(tests.addCliTests(b, test_filter, modes));
    toolchain_step.dependOn(tests.addAssembleAndLinkTests(b, test_filter, modes));
    toolchain_step.dependOn(tests.addRuntimeSafetyTests(b, test_filter, modes));
    toolchain_step.dependOn(tests.addTranslateCTests(b, test_filter));
    if (!skip_run_translated_c) {
        toolchain_step.dependOn(tests.addRunTranslatedCTests(b, test_filter, target));
    }
    // tests for this feature are disabled until we have the self-hosted compiler available
    // toolchain_step.dependOn(tests.addGenHTests(b, test_filter));
    if (!skip_compile_errors) {
        toolchain_step.dependOn(tests.addCompileErrorTests(b, test_filter, modes));
    }

    const std_step = tests.addPkgTests(
        b,
        test_filter,
        "lib/std/std.zig",
        "std",
        "Run the standard library tests",
        modes,
        false,
        skip_non_native,
        skip_libc,
        is_wine_enabled,
        is_qemu_enabled,
        is_wasmtime_enabled,
        is_darling_enabled,
        glibc_multi_dir,
    );

    const test_step = b.step("test", "Run all the tests");
    test_step.dependOn(toolchain_step);
    test_step.dependOn(std_step);
    test_step.dependOn(docs_step);
}

const exe_cflags = [_][]const u8{
    "-std=c++14",
    "-D__STDC_CONSTANT_MACROS",
    "-D__STDC_FORMAT_MACROS",
    "-D__STDC_LIMIT_MACROS",
    "-D_GNU_SOURCE",
    "-fvisibility-inlines-hidden",
    "-fno-exceptions",
    "-fno-rtti",
    "-Werror=type-limits",
    "-Wno-missing-braces",
    "-Wno-comment",
};

fn addCmakeCfgOptionsToExe(
    b: *Builder,
    cfg: CMakeConfig,
    tracy: ?[]const u8,
    exe: *std.build.LibExeObjStep,
) !void {
    exe.addObjectFile(fs.path.join(b.allocator, &[_][]const u8{
        cfg.cmake_binary_dir,
        "zigcpp",
        b.fmt("{s}{s}{s}", .{ exe.target.libPrefix(), "zigcpp", exe.target.staticLibSuffix() }),
    }) catch unreachable);
    assert(cfg.lld_include_dir.len != 0);
    exe.addIncludeDir(cfg.lld_include_dir);
    addCMakeLibraryList(exe, cfg.clang_libraries);
    addCMakeLibraryList(exe, cfg.lld_libraries);
    addCMakeLibraryList(exe, cfg.llvm_libraries);

    const need_cpp_includes = tracy != null;

    // System -lc++ must be used because in this code path we are attempting to link
    // against system-provided LLVM, Clang, LLD.
    if (exe.target.getOsTag() == .linux) {
        // First we try to static link against gcc libstdc++. If that doesn't work,
        // we fall back to -lc++ and cross our fingers.
        addCxxKnownPath(b, cfg, exe, "libstdc++.a", "", need_cpp_includes) catch |err| switch (err) {
            error.RequiredLibraryNotFound => {
                exe.linkSystemLibrary("c++");
            },
            else => |e| return e,
        };
        exe.linkSystemLibrary("unwind");
    } else if (exe.target.isFreeBSD()) {
        try addCxxKnownPath(b, cfg, exe, "libc++.a", null, need_cpp_includes);
        exe.linkSystemLibrary("pthread");
    } else if (exe.target.getOsTag() == .openbsd) {
        try addCxxKnownPath(b, cfg, exe, "libc++.a", null, need_cpp_includes);
        try addCxxKnownPath(b, cfg, exe, "libc++abi.a", null, need_cpp_includes);
    } else if (exe.target.isDarwin()) {
        exe.linkSystemLibrary("c++");
    }

    if (cfg.dia_guids_lib.len != 0) {
        exe.addObjectFile(cfg.dia_guids_lib);
    }
}

fn addStaticLlvmOptionsToExe(
    exe: *std.build.LibExeObjStep,
) !void {
    // Adds the Zig C++ sources which both stage1 and stage2 need.
    //
    // We need this because otherwise zig_clang_cc1_main.cpp ends up pulling
    // in a dependency on llvm::cfg::Update<llvm::BasicBlock*>::dump() which is
    // unavailable when LLVM is compiled in Release mode.
    const zig_cpp_cflags = exe_cflags ++ [_][]const u8{"-DNDEBUG=1"};
    exe.addCSourceFiles(&zig_cpp_sources, &zig_cpp_cflags);

    for (clang_libs) |lib_name| {
        exe.linkSystemLibrary(lib_name);
    }

    for (lld_libs) |lib_name| {
        exe.linkSystemLibrary(lib_name);
    }

    for (llvm_libs) |lib_name| {
        exe.linkSystemLibrary(lib_name);
    }

    // This means we rely on clang-or-zig-built LLVM, Clang, LLD libraries.
    exe.linkSystemLibrary("c++");

    if (exe.target.getOs().tag == .windows) {
        exe.linkSystemLibrary("version");
        exe.linkSystemLibrary("uuid");
    }
}

fn addCxxKnownPath(
    b: *Builder,
    ctx: CMakeConfig,
    exe: *std.build.LibExeObjStep,
    objname: []const u8,
    errtxt: ?[]const u8,
    need_cpp_includes: bool,
) !void {
    const path_padded = try b.exec(&[_][]const u8{
        ctx.cxx_compiler,
        b.fmt("-print-file-name={s}", .{objname}),
    });
    const path_unpadded = mem.tokenize(path_padded, "\r\n").next().?;
    if (mem.eql(u8, path_unpadded, objname)) {
        if (errtxt) |msg| {
            warn("{s}", .{msg});
        } else {
            warn("Unable to determine path to {s}\n", .{objname});
        }
        return error.RequiredLibraryNotFound;
    }
    exe.addObjectFile(path_unpadded);

    // TODO a way to integrate with system c++ include files here
    // cc -E -Wp,-v -xc++ /dev/null
    if (need_cpp_includes) {
        // I used these temporarily for testing something but we obviously need a
        // more general purpose solution here.
        //exe.addIncludeDir("/nix/store/b3zsk4ihlpiimv3vff86bb5bxghgdzb9-gcc-9.2.0/lib/gcc/x86_64-unknown-linux-gnu/9.2.0/../../../../include/c++/9.2.0");
        //exe.addIncludeDir("/nix/store/b3zsk4ihlpiimv3vff86bb5bxghgdzb9-gcc-9.2.0/lib/gcc/x86_64-unknown-linux-gnu/9.2.0/../../../../include/c++/9.2.0/x86_64-unknown-linux-gnu");
        //exe.addIncludeDir("/nix/store/b3zsk4ihlpiimv3vff86bb5bxghgdzb9-gcc-9.2.0/lib/gcc/x86_64-unknown-linux-gnu/9.2.0/../../../../include/c++/9.2.0/backward");
    }
}

fn addCMakeLibraryList(exe: *std.build.LibExeObjStep, list: []const u8) void {
    var it = mem.tokenize(list, ";");
    while (it.next()) |lib| {
        if (mem.startsWith(u8, lib, "-l")) {
            exe.linkSystemLibrary(lib["-l".len..]);
        } else {
            exe.addObjectFile(lib);
        }
    }
}

const CMakeConfig = struct {
    cmake_binary_dir: []const u8,
    cmake_prefix_path: []const u8,
    cxx_compiler: []const u8,
    lld_include_dir: []const u8,
    lld_libraries: []const u8,
    clang_libraries: []const u8,
    llvm_libraries: []const u8,
    dia_guids_lib: []const u8,
};

const max_config_h_bytes = 1 * 1024 * 1024;

fn findAndParseConfigH(b: *Builder, config_h_path_option: ?[]const u8) ?CMakeConfig {
    const config_h_text: []const u8 = if (config_h_path_option) |config_h_path| blk: {
        break :blk fs.cwd().readFileAlloc(b.allocator, config_h_path, max_config_h_bytes) catch unreachable;
    } else blk: {
        // TODO this should stop looking for config.h once it detects we hit the
        // zig source root directory.
        var check_dir = fs.path.dirname(b.zig_exe).?;
        while (true) {
            var dir = fs.cwd().openDir(check_dir, .{}) catch unreachable;
            defer dir.close();

            break :blk dir.readFileAlloc(b.allocator, "config.h", max_config_h_bytes) catch |err| switch (err) {
                error.FileNotFound => {
                    const new_check_dir = fs.path.dirname(check_dir);
                    if (new_check_dir == null or mem.eql(u8, new_check_dir.?, check_dir)) {
                        return null;
                    }
                    check_dir = new_check_dir.?;
                    continue;
                },
                else => unreachable,
            };
        } else unreachable; // TODO should not need `else unreachable`.
    };

    var ctx: CMakeConfig = .{
        .cmake_binary_dir = undefined,
        .cmake_prefix_path = undefined,
        .cxx_compiler = undefined,
        .lld_include_dir = undefined,
        .lld_libraries = undefined,
        .clang_libraries = undefined,
        .llvm_libraries = undefined,
        .dia_guids_lib = undefined,
    };

    const mappings = [_]struct { prefix: []const u8, field: []const u8 }{
        .{
            .prefix = "#define ZIG_CMAKE_BINARY_DIR ",
            .field = "cmake_binary_dir",
        },
        .{
            .prefix = "#define ZIG_CMAKE_PREFIX_PATH ",
            .field = "cmake_prefix_path",
        },
        .{
            .prefix = "#define ZIG_CXX_COMPILER ",
            .field = "cxx_compiler",
        },
        .{
            .prefix = "#define ZIG_LLD_INCLUDE_PATH ",
            .field = "lld_include_dir",
        },
        .{
            .prefix = "#define ZIG_LLD_LIBRARIES ",
            .field = "lld_libraries",
        },
        .{
            .prefix = "#define ZIG_CLANG_LIBRARIES ",
            .field = "clang_libraries",
        },
        .{
            .prefix = "#define ZIG_LLVM_LIBRARIES ",
            .field = "llvm_libraries",
        },
        .{
            .prefix = "#define ZIG_DIA_GUIDS_LIB ",
            .field = "dia_guids_lib",
        },
    };

    var lines_it = mem.tokenize(config_h_text, "\r\n");
    while (lines_it.next()) |line| {
        inline for (mappings) |mapping| {
            if (mem.startsWith(u8, line, mapping.prefix)) {
                var it = mem.split(line, "\"");
                _ = it.next().?; // skip the stuff before the quote
                const quoted = it.next().?; // the stuff inside the quote
                @field(ctx, mapping.field) = toNativePathSep(b, quoted);
            }
        }
    }
    return ctx;
}

fn toNativePathSep(b: *Builder, s: []const u8) []u8 {
    const duplicated = mem.dupe(b.allocator, u8, s) catch unreachable;
    for (duplicated) |*byte| switch (byte.*) {
        '/' => byte.* = fs.path.sep,
        else => {},
    };
    return duplicated;
}

const softfloat_sources = [_][]const u8{
    "deps/SoftFloat-3e/source/8086/f128M_isSignalingNaN.c",
    "deps/SoftFloat-3e/source/8086/s_commonNaNToF128M.c",
    "deps/SoftFloat-3e/source/8086/s_commonNaNToF16UI.c",
    "deps/SoftFloat-3e/source/8086/s_commonNaNToF32UI.c",
    "deps/SoftFloat-3e/source/8086/s_commonNaNToF64UI.c",
    "deps/SoftFloat-3e/source/8086/s_f128MToCommonNaN.c",
    "deps/SoftFloat-3e/source/8086/s_f16UIToCommonNaN.c",
    "deps/SoftFloat-3e/source/8086/s_f32UIToCommonNaN.c",
    "deps/SoftFloat-3e/source/8086/s_f64UIToCommonNaN.c",
    "deps/SoftFloat-3e/source/8086/s_propagateNaNF128M.c",
    "deps/SoftFloat-3e/source/8086/s_propagateNaNF16UI.c",
    "deps/SoftFloat-3e/source/8086/softfloat_raiseFlags.c",
    "deps/SoftFloat-3e/source/f128M_add.c",
    "deps/SoftFloat-3e/source/f128M_div.c",
    "deps/SoftFloat-3e/source/f128M_eq.c",
    "deps/SoftFloat-3e/source/f128M_eq_signaling.c",
    "deps/SoftFloat-3e/source/f128M_le.c",
    "deps/SoftFloat-3e/source/f128M_le_quiet.c",
    "deps/SoftFloat-3e/source/f128M_lt.c",
    "deps/SoftFloat-3e/source/f128M_lt_quiet.c",
    "deps/SoftFloat-3e/source/f128M_mul.c",
    "deps/SoftFloat-3e/source/f128M_mulAdd.c",
    "deps/SoftFloat-3e/source/f128M_rem.c",
    "deps/SoftFloat-3e/source/f128M_roundToInt.c",
    "deps/SoftFloat-3e/source/f128M_sqrt.c",
    "deps/SoftFloat-3e/source/f128M_sub.c",
    "deps/SoftFloat-3e/source/f128M_to_f16.c",
    "deps/SoftFloat-3e/source/f128M_to_f32.c",
    "deps/SoftFloat-3e/source/f128M_to_f64.c",
    "deps/SoftFloat-3e/source/f128M_to_i32.c",
    "deps/SoftFloat-3e/source/f128M_to_i32_r_minMag.c",
    "deps/SoftFloat-3e/source/f128M_to_i64.c",
    "deps/SoftFloat-3e/source/f128M_to_i64_r_minMag.c",
    "deps/SoftFloat-3e/source/f128M_to_ui32.c",
    "deps/SoftFloat-3e/source/f128M_to_ui32_r_minMag.c",
    "deps/SoftFloat-3e/source/f128M_to_ui64.c",
    "deps/SoftFloat-3e/source/f128M_to_ui64_r_minMag.c",
    "deps/SoftFloat-3e/source/f16_add.c",
    "deps/SoftFloat-3e/source/f16_div.c",
    "deps/SoftFloat-3e/source/f16_eq.c",
    "deps/SoftFloat-3e/source/f16_isSignalingNaN.c",
    "deps/SoftFloat-3e/source/f16_lt.c",
    "deps/SoftFloat-3e/source/f16_mul.c",
    "deps/SoftFloat-3e/source/f16_mulAdd.c",
    "deps/SoftFloat-3e/source/f16_rem.c",
    "deps/SoftFloat-3e/source/f16_roundToInt.c",
    "deps/SoftFloat-3e/source/f16_sqrt.c",
    "deps/SoftFloat-3e/source/f16_sub.c",
    "deps/SoftFloat-3e/source/f16_to_f128M.c",
    "deps/SoftFloat-3e/source/f16_to_f64.c",
    "deps/SoftFloat-3e/source/f32_to_f128M.c",
    "deps/SoftFloat-3e/source/f64_to_f128M.c",
    "deps/SoftFloat-3e/source/f64_to_f16.c",
    "deps/SoftFloat-3e/source/i32_to_f128M.c",
    "deps/SoftFloat-3e/source/s_add256M.c",
    "deps/SoftFloat-3e/source/s_addCarryM.c",
    "deps/SoftFloat-3e/source/s_addComplCarryM.c",
    "deps/SoftFloat-3e/source/s_addF128M.c",
    "deps/SoftFloat-3e/source/s_addM.c",
    "deps/SoftFloat-3e/source/s_addMagsF16.c",
    "deps/SoftFloat-3e/source/s_addMagsF32.c",
    "deps/SoftFloat-3e/source/s_addMagsF64.c",
    "deps/SoftFloat-3e/source/s_approxRecip32_1.c",
    "deps/SoftFloat-3e/source/s_approxRecipSqrt32_1.c",
    "deps/SoftFloat-3e/source/s_approxRecipSqrt_1Ks.c",
    "deps/SoftFloat-3e/source/s_approxRecip_1Ks.c",
    "deps/SoftFloat-3e/source/s_compare128M.c",
    "deps/SoftFloat-3e/source/s_compare96M.c",
    "deps/SoftFloat-3e/source/s_countLeadingZeros16.c",
    "deps/SoftFloat-3e/source/s_countLeadingZeros32.c",
    "deps/SoftFloat-3e/source/s_countLeadingZeros64.c",
    "deps/SoftFloat-3e/source/s_countLeadingZeros8.c",
    "deps/SoftFloat-3e/source/s_eq128.c",
    "deps/SoftFloat-3e/source/s_invalidF128M.c",
    "deps/SoftFloat-3e/source/s_isNaNF128M.c",
    "deps/SoftFloat-3e/source/s_le128.c",
    "deps/SoftFloat-3e/source/s_lt128.c",
    "deps/SoftFloat-3e/source/s_mul128MTo256M.c",
    "deps/SoftFloat-3e/source/s_mul64To128M.c",
    "deps/SoftFloat-3e/source/s_mulAddF128M.c",
    "deps/SoftFloat-3e/source/s_mulAddF16.c",
    "deps/SoftFloat-3e/source/s_mulAddF32.c",
    "deps/SoftFloat-3e/source/s_mulAddF64.c",
    "deps/SoftFloat-3e/source/s_negXM.c",
    "deps/SoftFloat-3e/source/s_normRoundPackMToF128M.c",
    "deps/SoftFloat-3e/source/s_normRoundPackToF16.c",
    "deps/SoftFloat-3e/source/s_normRoundPackToF32.c",
    "deps/SoftFloat-3e/source/s_normRoundPackToF64.c",
    "deps/SoftFloat-3e/source/s_normSubnormalF128SigM.c",
    "deps/SoftFloat-3e/source/s_normSubnormalF16Sig.c",
    "deps/SoftFloat-3e/source/s_normSubnormalF32Sig.c",
    "deps/SoftFloat-3e/source/s_normSubnormalF64Sig.c",
    "deps/SoftFloat-3e/source/s_remStepMBy32.c",
    "deps/SoftFloat-3e/source/s_roundMToI64.c",
    "deps/SoftFloat-3e/source/s_roundMToUI64.c",
    "deps/SoftFloat-3e/source/s_roundPackMToF128M.c",
    "deps/SoftFloat-3e/source/s_roundPackToF16.c",
    "deps/SoftFloat-3e/source/s_roundPackToF32.c",
    "deps/SoftFloat-3e/source/s_roundPackToF64.c",
    "deps/SoftFloat-3e/source/s_roundToI32.c",
    "deps/SoftFloat-3e/source/s_roundToI64.c",
    "deps/SoftFloat-3e/source/s_roundToUI32.c",
    "deps/SoftFloat-3e/source/s_roundToUI64.c",
    "deps/SoftFloat-3e/source/s_shiftLeftM.c",
    "deps/SoftFloat-3e/source/s_shiftNormSigF128M.c",
    "deps/SoftFloat-3e/source/s_shiftRightJam256M.c",
    "deps/SoftFloat-3e/source/s_shiftRightJam32.c",
    "deps/SoftFloat-3e/source/s_shiftRightJam64.c",
    "deps/SoftFloat-3e/source/s_shiftRightJamM.c",
    "deps/SoftFloat-3e/source/s_shiftRightM.c",
    "deps/SoftFloat-3e/source/s_shortShiftLeft64To96M.c",
    "deps/SoftFloat-3e/source/s_shortShiftLeftM.c",
    "deps/SoftFloat-3e/source/s_shortShiftRightExtendM.c",
    "deps/SoftFloat-3e/source/s_shortShiftRightJam64.c",
    "deps/SoftFloat-3e/source/s_shortShiftRightJamM.c",
    "deps/SoftFloat-3e/source/s_shortShiftRightM.c",
    "deps/SoftFloat-3e/source/s_sub1XM.c",
    "deps/SoftFloat-3e/source/s_sub256M.c",
    "deps/SoftFloat-3e/source/s_subM.c",
    "deps/SoftFloat-3e/source/s_subMagsF16.c",
    "deps/SoftFloat-3e/source/s_subMagsF32.c",
    "deps/SoftFloat-3e/source/s_subMagsF64.c",
    "deps/SoftFloat-3e/source/s_tryPropagateNaNF128M.c",
    "deps/SoftFloat-3e/source/softfloat_state.c",
    "deps/SoftFloat-3e/source/ui32_to_f128M.c",
    "deps/SoftFloat-3e/source/ui64_to_f128M.c",
};

const stage1_sources = [_][]const u8{
    "src/stage1/analyze.cpp",
    "src/stage1/astgen.cpp",
    "src/stage1/bigfloat.cpp",
    "src/stage1/bigint.cpp",
    "src/stage1/buffer.cpp",
    "src/stage1/codegen.cpp",
    "src/stage1/dump_analysis.cpp",
    "src/stage1/errmsg.cpp",
    "src/stage1/error.cpp",
    "src/stage1/heap.cpp",
    "src/stage1/ir.cpp",
    "src/stage1/ir_print.cpp",
    "src/stage1/mem.cpp",
    "src/stage1/os.cpp",
    "src/stage1/parser.cpp",
    "src/stage1/range_set.cpp",
    "src/stage1/stage1.cpp",
    "src/stage1/target.cpp",
    "src/stage1/tokenizer.cpp",
    "src/stage1/util.cpp",
    "src/stage1/softfloat_ext.cpp",
};
const optimized_c_sources = [_][]const u8{
    "src/stage1/parse_f128.c",
};
const zig_cpp_sources = [_][]const u8{
    // These are planned to stay even when we are self-hosted.
    "src/zig_llvm.cpp",
    "src/zig_clang.cpp",
    "src/zig_clang_driver.cpp",
    "src/zig_clang_cc1_main.cpp",
    "src/zig_clang_cc1as_main.cpp",
    // https://github.com/ziglang/zig/issues/6363
    "src/windows_sdk.cpp",
};

const clang_libs = [_][]const u8{
    "clangFrontendTool",
    "clangCodeGen",
    "clangFrontend",
    "clangDriver",
    "clangSerialization",
    "clangSema",
    "clangStaticAnalyzerFrontend",
    "clangStaticAnalyzerCheckers",
    "clangStaticAnalyzerCore",
    "clangAnalysis",
    "clangASTMatchers",
    "clangAST",
    "clangParse",
    "clangSema",
    "clangBasic",
    "clangEdit",
    "clangLex",
    "clangARCMigrate",
    "clangRewriteFrontend",
    "clangRewrite",
    "clangCrossTU",
    "clangIndex",
    "clangToolingCore",
};
const lld_libs = [_][]const u8{
    "lldDriver",
    "lldMinGW",
    "lldELF",
    "lldCOFF",
    "lldMachO",
    "lldWasm",
    "lldReaderWriter",
    "lldCore",
    "lldYAML",
    "lldCommon",
};
// This list can be re-generated with `llvm-config --libfiles` and then
// reformatting using your favorite text editor. Note we do not execute
// `llvm-config` here because we are cross compiling. Also omit LLVMTableGen
// from these libs.
const llvm_libs = [_][]const u8{
    "LLVMWindowsManifest",
    "LLVMXRay",
    "LLVMLibDriver",
    "LLVMDlltoolDriver",
    "LLVMCoverage",
    "LLVMLineEditor",
    "LLVMXCoreDisassembler",
    "LLVMXCoreCodeGen",
    "LLVMXCoreDesc",
    "LLVMXCoreInfo",
    "LLVMX86Disassembler",
    "LLVMX86AsmParser",
    "LLVMX86CodeGen",
    "LLVMX86Desc",
    "LLVMX86Info",
    "LLVMWebAssemblyDisassembler",
    "LLVMWebAssemblyAsmParser",
    "LLVMWebAssemblyCodeGen",
    "LLVMWebAssemblyDesc",
    "LLVMWebAssemblyInfo",
    "LLVMSystemZDisassembler",
    "LLVMSystemZAsmParser",
    "LLVMSystemZCodeGen",
    "LLVMSystemZDesc",
    "LLVMSystemZInfo",
    "LLVMSparcDisassembler",
    "LLVMSparcAsmParser",
    "LLVMSparcCodeGen",
    "LLVMSparcDesc",
    "LLVMSparcInfo",
    "LLVMRISCVDisassembler",
    "LLVMRISCVAsmParser",
    "LLVMRISCVCodeGen",
    "LLVMRISCVDesc",
    "LLVMRISCVInfo",
    "LLVMPowerPCDisassembler",
    "LLVMPowerPCAsmParser",
    "LLVMPowerPCCodeGen",
    "LLVMPowerPCDesc",
    "LLVMPowerPCInfo",
    "LLVMNVPTXCodeGen",
    "LLVMNVPTXDesc",
    "LLVMNVPTXInfo",
    "LLVMMSP430Disassembler",
    "LLVMMSP430AsmParser",
    "LLVMMSP430CodeGen",
    "LLVMMSP430Desc",
    "LLVMMSP430Info",
    "LLVMMipsDisassembler",
    "LLVMMipsAsmParser",
    "LLVMMipsCodeGen",
    "LLVMMipsDesc",
    "LLVMMipsInfo",
    "LLVMLanaiDisassembler",
    "LLVMLanaiCodeGen",
    "LLVMLanaiAsmParser",
    "LLVMLanaiDesc",
    "LLVMLanaiInfo",
    "LLVMHexagonDisassembler",
    "LLVMHexagonCodeGen",
    "LLVMHexagonAsmParser",
    "LLVMHexagonDesc",
    "LLVMHexagonInfo",
    "LLVMBPFDisassembler",
    "LLVMBPFAsmParser",
    "LLVMBPFCodeGen",
    "LLVMBPFDesc",
    "LLVMBPFInfo",
    "LLVMAVRDisassembler",
    "LLVMAVRAsmParser",
    "LLVMAVRCodeGen",
    "LLVMAVRDesc",
    "LLVMAVRInfo",
    "LLVMARMDisassembler",
    "LLVMARMAsmParser",
    "LLVMARMCodeGen",
    "LLVMARMDesc",
    "LLVMARMUtils",
    "LLVMARMInfo",
    "LLVMAMDGPUDisassembler",
    "LLVMAMDGPUAsmParser",
    "LLVMAMDGPUCodeGen",
    "LLVMAMDGPUDesc",
    "LLVMAMDGPUUtils",
    "LLVMAMDGPUInfo",
    "LLVMAArch64Disassembler",
    "LLVMAArch64AsmParser",
    "LLVMAArch64CodeGen",
    "LLVMAArch64Desc",
    "LLVMAArch64Utils",
    "LLVMAArch64Info",
    "LLVMOrcJIT",
    "LLVMMCJIT",
    "LLVMJITLink",
    "LLVMOrcTargetProcess",
    "LLVMOrcShared",
    "LLVMInterpreter",
    "LLVMExecutionEngine",
    "LLVMRuntimeDyld",
    "LLVMSymbolize",
    "LLVMDebugInfoPDB",
    "LLVMDebugInfoGSYM",
    "LLVMOption",
    "LLVMObjectYAML",
    "LLVMMCA",
    "LLVMMCDisassembler",
    "LLVMLTO",
    "LLVMPasses",
    "LLVMCFGuard",
    "LLVMCoroutines",
    "LLVMObjCARCOpts",
    "LLVMHelloNew",
    "LLVMipo",
    "LLVMVectorize",
    "LLVMLinker",
    "LLVMInstrumentation",
    "LLVMFrontendOpenMP",
    "LLVMFrontendOpenACC",
    "LLVMExtensions",
    "LLVMDWARFLinker",
    "LLVMGlobalISel",
    "LLVMMIRParser",
    "LLVMAsmPrinter",
    "LLVMDebugInfoDWARF",
    "LLVMSelectionDAG",
    "LLVMCodeGen",
    "LLVMIRReader",
    "LLVMAsmParser",
    "LLVMInterfaceStub",
    "LLVMFileCheck",
    "LLVMFuzzMutate",
    "LLVMTarget",
    "LLVMScalarOpts",
    "LLVMInstCombine",
    "LLVMAggressiveInstCombine",
    "LLVMTransformUtils",
    "LLVMBitWriter",
    "LLVMAnalysis",
    "LLVMProfileData",
    "LLVMObject",
    "LLVMTextAPI",
    "LLVMMCParser",
    "LLVMMC",
    "LLVMDebugInfoCodeView",
    "LLVMDebugInfoMSF",
    "LLVMBitReader",
    "LLVMCore",
    "LLVMRemarks",
    "LLVMBitstreamReader",
    "LLVMBinaryFormat",
    "LLVMSupport",
    "LLVMDemangle",
};
