const std = @import("std");
const builtin = std.builtin;
const debug = std.debug;
const warn = debug.warn;
const build = std.build;
const CrossTarget = std.zig.CrossTarget;
const io = std.io;
const fs = std.fs;
const mem = std.mem;
const fmt = std.fmt;
const ArrayList = std.ArrayList;
const Mode = builtin.Mode;
const LibExeObjStep = build.LibExeObjStep;

// Cases
const compare_output = @import("compare_output.zig");
const standalone = @import("standalone.zig");
const stack_traces = @import("stack_traces.zig");
const compile_errors = @import("compile_errors.zig");
const assemble_and_link = @import("assemble_and_link.zig");
const runtime_safety = @import("runtime_safety.zig");
const translate_c = @import("translate_c.zig");
const run_translated_c = @import("run_translated_c.zig");
const gen_h = @import("gen_h.zig");

// Implementations
pub const TranslateCContext = @import("src/translate_c.zig").TranslateCContext;
pub const RunTranslatedCContext = @import("src/run_translated_c.zig").RunTranslatedCContext;
pub const CompareOutputContext = @import("src/compare_output.zig").CompareOutputContext;

const TestTarget = struct {
    target: CrossTarget = @as(CrossTarget, .{}),
    mode: builtin.Mode = .Debug,
    link_libc: bool = false,
    single_threaded: bool = false,
    disable_native: bool = false,
};

const test_targets = blk: {
    // getBaselineCpuFeatures calls populateDependencies which has a O(N ^ 2) algorithm
    // (where N is roughly 160, which technically makes it O(1), but it adds up to a
    // lot of branches)
    @setEvalBranchQuota(50000);
    break :blk [_]TestTarget{
        TestTarget{},
        TestTarget{
            .link_libc = true,
        },
        TestTarget{
            .single_threaded = true,
        },

        TestTarget{
            .target = .{
                .cpu_arch = .wasm32,
                .os_tag = .wasi,
            },
            .link_libc = false,
            .single_threaded = true,
        },
        TestTarget{
            .target = .{
                .cpu_arch = .wasm32,
                .os_tag = .wasi,
            },
            .link_libc = true,
            .single_threaded = true,
        },

        TestTarget{
            .target = .{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
                .abi = .none,
            },
        },
        TestTarget{
            .target = .{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
                .abi = .gnu,
            },
            .link_libc = true,
        },
        TestTarget{
            .target = .{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
                .abi = .musl,
            },
            .link_libc = true,
        },

        TestTarget{
            .target = .{
                .cpu_arch = .i386,
                .os_tag = .linux,
                .abi = .none,
            },
        },
        TestTarget{
            .target = .{
                .cpu_arch = .i386,
                .os_tag = .linux,
                .abi = .musl,
            },
            .link_libc = true,
        },
        TestTarget{
            .target = .{
                .cpu_arch = .i386,
                .os_tag = .linux,
                .abi = .gnu,
            },
            .link_libc = true,
        },

        TestTarget{
            .target = .{
                .cpu_arch = .aarch64,
                .os_tag = .linux,
                .abi = .none,
            },
        },
        TestTarget{
            .target = .{
                .cpu_arch = .aarch64,
                .os_tag = .linux,
                .abi = .musl,
            },
            .link_libc = true,
        },
        TestTarget{
            .target = .{
                .cpu_arch = .aarch64,
                .os_tag = .linux,
                .abi = .gnu,
            },
            .link_libc = true,
        },

        TestTarget{
            .target = CrossTarget.parse(.{
                .arch_os_abi = "arm-linux-none",
                .cpu_features = "generic+v8a",
            }) catch unreachable,
        },
        TestTarget{
            .target = CrossTarget.parse(.{
                .arch_os_abi = "arm-linux-musleabihf",
                .cpu_features = "generic+v8a",
            }) catch unreachable,
            .link_libc = true,
        },
        // https://github.com/ziglang/zig/issues/3287
        //TestTarget{
        //    .target = CrossTarget.parse(.{
        //        .arch_os_abi = "arm-linux-gnueabihf",
        //        .cpu_features = "generic+v8a",
        //    }) catch unreachable,
        //    .link_libc = true,
        //},

        // https://github.com/ziglang/zig/issues/8155
        //TestTarget{
        //    .target = .{
        //        .cpu_arch = .mips,
        //        .os_tag = .linux,
        //        .abi = .none,
        //    },
        //},

        // https://github.com/ziglang/zig/issues/8155
        //TestTarget{
        //    .target = .{
        //        .cpu_arch = .mips,
        //        .os_tag = .linux,
        //        .abi = .musl,
        //    },
        //    .link_libc = true,
        //},

        // https://github.com/ziglang/zig/issues/4927
        //TestTarget{
        //    .target = .{
        //        .cpu_arch = .mips,
        //        .os_tag = .linux,
        //        .abi = .gnu,
        //    },
        //    .link_libc = true,
        //},

        // https://github.com/ziglang/zig/issues/8155
        //TestTarget{
        //    .target = .{
        //        .cpu_arch = .mipsel,
        //        .os_tag = .linux,
        //        .abi = .none,
        //    },
        //},

        // https://github.com/ziglang/zig/issues/8155
        //TestTarget{
        //    .target = .{
        //        .cpu_arch = .mipsel,
        //        .os_tag = .linux,
        //        .abi = .musl,
        //    },
        //    .link_libc = true,
        //},

        // https://github.com/ziglang/zig/issues/4927
        //TestTarget{
        //    .target = .{
        //        .cpu_arch = .mipsel,
        //        .os_tag = .linux,
        //        .abi = .gnu,
        //    },
        //    .link_libc = true,
        //},

        TestTarget{
            .target = .{
                .cpu_arch = .powerpc,
                .os_tag = .linux,
                .abi = .none,
            },
        },
        TestTarget{
            .target = .{
                .cpu_arch = .powerpc,
                .os_tag = .linux,
                .abi = .musl,
            },
            .link_libc = true,
        },

        TestTarget{
            .target = .{
                .cpu_arch = .riscv64,
                .os_tag = .linux,
                .abi = .none,
            },
        },

        TestTarget{
            .target = .{
                .cpu_arch = .riscv64,
                .os_tag = .linux,
                .abi = .musl,
            },
            .link_libc = true,
        },

        // https://github.com/ziglang/zig/issues/3340
        //TestTarget{
        //    .target = .{
        //        .cpu_arch = .riscv64,
        //        .os = .linux,
        //        .abi = .gnu,
        //    },
        //    .link_libc = true,
        //},

        TestTarget{
            .target = .{
                .cpu_arch = .x86_64,
                .os_tag = .macos,
                .abi = .gnu,
            },
            // https://github.com/ziglang/zig/issues/3295
            .disable_native = true,
        },

        TestTarget{
            .target = .{
                .cpu_arch = .i386,
                .os_tag = .windows,
                .abi = .msvc,
            },
        },

        TestTarget{
            .target = .{
                .cpu_arch = .x86_64,
                .os_tag = .windows,
                .abi = .msvc,
            },
        },

        TestTarget{
            .target = .{
                .cpu_arch = .i386,
                .os_tag = .windows,
                .abi = .gnu,
            },
            .link_libc = true,
        },

        TestTarget{
            .target = .{
                .cpu_arch = .x86_64,
                .os_tag = .windows,
                .abi = .gnu,
            },
            .link_libc = true,
        },

        // Do the release tests last because they take a long time
        TestTarget{
            .mode = .ReleaseFast,
        },
        TestTarget{
            .link_libc = true,
            .mode = .ReleaseFast,
        },
        TestTarget{
            .mode = .ReleaseFast,
            .single_threaded = true,
        },

        TestTarget{
            .mode = .ReleaseSafe,
        },
        TestTarget{
            .link_libc = true,
            .mode = .ReleaseSafe,
        },
        TestTarget{
            .mode = .ReleaseSafe,
            .single_threaded = true,
        },

        TestTarget{
            .mode = .ReleaseSmall,
        },
        TestTarget{
            .link_libc = true,
            .mode = .ReleaseSmall,
        },
        TestTarget{
            .mode = .ReleaseSmall,
            .single_threaded = true,
        },
    };
};

const max_stdout_size = 1 * 1024 * 1024; // 1 MB

pub fn addCompareOutputTests(b: *build.Builder, test_filter: ?[]const u8, modes: []const Mode) *build.Step {
    const cases = b.allocator.create(CompareOutputContext) catch unreachable;
    cases.* = CompareOutputContext{
        .b = b,
        .step = b.step("test-compare-output", "Run the compare output tests"),
        .test_index = 0,
        .test_filter = test_filter,
        .modes = modes,
    };

    compare_output.addCases(cases);

    return cases.step;
}

pub fn addStackTraceTests(b: *build.Builder, test_filter: ?[]const u8, modes: []const Mode) *build.Step {
    const cases = b.allocator.create(StackTracesContext) catch unreachable;
    cases.* = StackTracesContext{
        .b = b,
        .step = b.step("test-stack-traces", "Run the stack trace tests"),
        .test_index = 0,
        .test_filter = test_filter,
        .modes = modes,
    };

    stack_traces.addCases(cases);

    return cases.step;
}

pub fn addRuntimeSafetyTests(b: *build.Builder, test_filter: ?[]const u8, modes: []const Mode) *build.Step {
    const cases = b.allocator.create(CompareOutputContext) catch unreachable;
    cases.* = CompareOutputContext{
        .b = b,
        .step = b.step("test-runtime-safety", "Run the runtime safety tests"),
        .test_index = 0,
        .test_filter = test_filter,
        .modes = modes,
    };

    runtime_safety.addCases(cases);

    return cases.step;
}

pub fn addCompileErrorTests(b: *build.Builder, test_filter: ?[]const u8, modes: []const Mode) *build.Step {
    const cases = b.allocator.create(CompileErrorContext) catch unreachable;
    cases.* = CompileErrorContext{
        .b = b,
        .step = b.step("test-compile-errors", "Run the compile error tests"),
        .test_index = 0,
        .test_filter = test_filter,
        .modes = modes,
    };

    compile_errors.addCases(cases);

    return cases.step;
}

pub fn addStandaloneTests(b: *build.Builder, test_filter: ?[]const u8, modes: []const Mode, skip_non_native: bool, target: std.zig.CrossTarget) *build.Step {
    const cases = b.allocator.create(StandaloneContext) catch unreachable;
    cases.* = StandaloneContext{
        .b = b,
        .step = b.step("test-standalone", "Run the standalone tests"),
        .test_index = 0,
        .test_filter = test_filter,
        .modes = modes,
        .skip_non_native = skip_non_native,
        .target = target,
    };

    standalone.addCases(cases);

    return cases.step;
}

pub fn addCliTests(b: *build.Builder, test_filter: ?[]const u8, modes: []const Mode) *build.Step {
    _ = test_filter;
    _ = modes;
    const step = b.step("test-cli", "Test the command line interface");

    const exe = b.addExecutable("test-cli", "test/cli.zig");
    const run_cmd = exe.run();
    run_cmd.addArgs(&[_][]const u8{
        fs.realpathAlloc(b.allocator, b.zig_exe) catch unreachable,
        b.pathFromRoot(b.cache_root),
    });

    step.dependOn(&run_cmd.step);
    return step;
}

pub fn addAssembleAndLinkTests(b: *build.Builder, test_filter: ?[]const u8, modes: []const Mode) *build.Step {
    const cases = b.allocator.create(CompareOutputContext) catch unreachable;
    cases.* = CompareOutputContext{
        .b = b,
        .step = b.step("test-asm-link", "Run the assemble and link tests"),
        .test_index = 0,
        .test_filter = test_filter,
        .modes = modes,
    };

    assemble_and_link.addCases(cases);

    return cases.step;
}

pub fn addTranslateCTests(b: *build.Builder, test_filter: ?[]const u8) *build.Step {
    const cases = b.allocator.create(TranslateCContext) catch unreachable;
    cases.* = TranslateCContext{
        .b = b,
        .step = b.step("test-translate-c", "Run the C transation tests"),
        .test_index = 0,
        .test_filter = test_filter,
    };

    translate_c.addCases(cases);

    return cases.step;
}

pub fn addRunTranslatedCTests(
    b: *build.Builder,
    test_filter: ?[]const u8,
    target: std.zig.CrossTarget,
) *build.Step {
    const cases = b.allocator.create(RunTranslatedCContext) catch unreachable;
    cases.* = .{
        .b = b,
        .step = b.step("test-run-translated-c", "Run the Run-Translated-C tests"),
        .test_index = 0,
        .test_filter = test_filter,
        .target = target,
    };

    run_translated_c.addCases(cases);

    return cases.step;
}

pub fn addGenHTests(b: *build.Builder, test_filter: ?[]const u8) *build.Step {
    const cases = b.allocator.create(GenHContext) catch unreachable;
    cases.* = GenHContext{
        .b = b,
        .step = b.step("test-gen-h", "Run the C header file generation tests"),
        .test_index = 0,
        .test_filter = test_filter,
    };

    gen_h.addCases(cases);

    return cases.step;
}

pub fn addPkgTests(
    b: *build.Builder,
    test_filter: ?[]const u8,
    root_src: []const u8,
    name: []const u8,
    desc: []const u8,
    modes: []const Mode,
    skip_single_threaded: bool,
    skip_non_native: bool,
    skip_libc: bool,
    is_wine_enabled: bool,
    is_qemu_enabled: bool,
    is_wasmtime_enabled: bool,
    is_darling_enabled: bool,
    glibc_dir: ?[]const u8,
) *build.Step {
    const step = b.step(b.fmt("test-{s}", .{name}), desc);

    for (test_targets) |test_target| {
        if (skip_non_native and !test_target.target.isNative())
            continue;

        if (skip_libc and test_target.link_libc)
            continue;

        if (test_target.link_libc and test_target.target.getOs().requiresLibC()) {
            // This would be a redundant test.
            continue;
        }

        if (skip_single_threaded and test_target.single_threaded)
            continue;

        if (test_target.disable_native and
            test_target.target.getOsTag() == std.Target.current.os.tag and
            test_target.target.getCpuArch() == std.Target.current.cpu.arch)
        {
            continue;
        }

        const want_this_mode = for (modes) |m| {
            if (m == test_target.mode) break true;
        } else false;
        if (!want_this_mode) continue;

        const libc_prefix = if (test_target.target.getOs().requiresLibC())
            ""
        else if (test_target.link_libc)
            "c"
        else
            "bare";

        const triple_prefix = test_target.target.zigTriple(b.allocator) catch unreachable;

        const these_tests = b.addTest(root_src);
        const single_threaded_txt = if (test_target.single_threaded) "single" else "multi";
        these_tests.setNamePrefix(b.fmt("{s}-{s}-{s}-{s}-{s} ", .{
            name,
            triple_prefix,
            @tagName(test_target.mode),
            libc_prefix,
            single_threaded_txt,
        }));
        these_tests.single_threaded = test_target.single_threaded;
        these_tests.setFilter(test_filter);
        these_tests.setBuildMode(test_target.mode);
        these_tests.setTarget(test_target.target);
        if (test_target.link_libc) {
            these_tests.linkSystemLibrary("c");
        }
        these_tests.overrideZigLibDir("lib");
        these_tests.enable_wine = is_wine_enabled;
        these_tests.enable_qemu = is_qemu_enabled;
        these_tests.enable_wasmtime = is_wasmtime_enabled;
        these_tests.enable_darling = is_darling_enabled;
        these_tests.glibc_multi_install_dir = glibc_dir;
        these_tests.addIncludeDir("test");

        step.dependOn(&these_tests.step);
    }
    return step;
}

pub const StackTracesContext = struct {
    b: *build.Builder,
    step: *build.Step,
    test_index: usize,
    test_filter: ?[]const u8,
    modes: []const Mode,

    const Expect = [@typeInfo(Mode).Enum.fields.len][]const u8;

    pub fn addCase(self: *StackTracesContext, config: anytype) void {
        if (@hasField(@TypeOf(config), "exclude")) {
            if (config.exclude.exclude()) return;
        }
        if (@hasField(@TypeOf(config), "exclude_arch")) {
            const exclude_arch: []const std.Target.Cpu.Arch = &config.exclude_arch;
            for (exclude_arch) |arch| if (arch == builtin.cpu.arch) return;
        }
        if (@hasField(@TypeOf(config), "exclude_os")) {
            const exclude_os: []const std.Target.Os.Tag = &config.exclude_os;
            for (exclude_os) |os| if (os == builtin.os.tag) return;
        }
        for (self.modes) |mode| {
            switch (mode) {
                .Debug => {
                    if (@hasField(@TypeOf(config), "Debug")) {
                        self.addExpect(config.name, config.source, mode, config.Debug);
                    }
                },
                .ReleaseSafe => {
                    if (@hasField(@TypeOf(config), "ReleaseSafe")) {
                        self.addExpect(config.name, config.source, mode, config.ReleaseSafe);
                    }
                },
                .ReleaseFast => {
                    if (@hasField(@TypeOf(config), "ReleaseFast")) {
                        self.addExpect(config.name, config.source, mode, config.ReleaseFast);
                    }
                },
                .ReleaseSmall => {
                    if (@hasField(@TypeOf(config), "ReleaseSmall")) {
                        self.addExpect(config.name, config.source, mode, config.ReleaseSmall);
                    }
                },
            }
        }
    }

    fn addExpect(
        self: *StackTracesContext,
        name: []const u8,
        source: []const u8,
        mode: Mode,
        mode_config: anytype,
    ) void {
        if (@hasField(@TypeOf(mode_config), "exclude")) {
            if (mode_config.exclude.exclude()) return;
        }
        if (@hasField(@TypeOf(mode_config), "exclude_arch")) {
            const exclude_arch: []const std.Target.Cpu.Arch = &mode_config.exclude_arch;
            for (exclude_arch) |arch| if (arch == builtin.cpu.arch) return;
        }
        if (@hasField(@TypeOf(mode_config), "exclude_os")) {
            const exclude_os: []const std.Target.Os.Tag = &mode_config.exclude_os;
            for (exclude_os) |os| if (os == builtin.os.tag) return;
        }

        const annotated_case_name = fmt.allocPrint(self.b.allocator, "{s} {s} ({s})", .{
            "stack-trace",
            name,
            @tagName(mode),
        }) catch unreachable;
        if (self.test_filter) |filter| {
            if (mem.indexOf(u8, annotated_case_name, filter) == null) return;
        }

        const b = self.b;
        const src_basename = "source.zig";
        const write_src = b.addWriteFile(src_basename, source);
        const exe = b.addExecutableSource("test", write_src.getFileSource(src_basename).?);
        exe.setBuildMode(mode);

        const run_and_compare = RunAndCompareStep.create(
            self,
            exe,
            annotated_case_name,
            mode,
            mode_config.expect,
        );

        self.step.dependOn(&run_and_compare.step);
    }

    const RunAndCompareStep = struct {
        pub const base_id = .custom;

        step: build.Step,
        context: *StackTracesContext,
        exe: *LibExeObjStep,
        name: []const u8,
        mode: Mode,
        expect_output: []const u8,
        test_index: usize,

        pub fn create(
            context: *StackTracesContext,
            exe: *LibExeObjStep,
            name: []const u8,
            mode: Mode,
            expect_output: []const u8,
        ) *RunAndCompareStep {
            const allocator = context.b.allocator;
            const ptr = allocator.create(RunAndCompareStep) catch unreachable;
            ptr.* = RunAndCompareStep{
                .step = build.Step.init(.custom, "StackTraceCompareOutputStep", allocator, make),
                .context = context,
                .exe = exe,
                .name = name,
                .mode = mode,
                .expect_output = expect_output,
                .test_index = context.test_index,
            };
            ptr.step.dependOn(&exe.step);
            context.test_index += 1;
            return ptr;
        }

        fn make(step: *build.Step) !void {
            const self = @fieldParentPtr(RunAndCompareStep, "step", step);
            const b = self.context.b;

            const full_exe_path = self.exe.getOutputSource().getPath(b);
            var args = ArrayList([]const u8).init(b.allocator);
            defer args.deinit();
            args.append(full_exe_path) catch unreachable;

            warn("Test {d}/{d} {s}...", .{ self.test_index + 1, self.context.test_index, self.name });

            const child = std.ChildProcess.init(args.items, b.allocator) catch unreachable;
            defer child.deinit();

            child.stdin_behavior = .Ignore;
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Pipe;
            child.env_map = b.env_map;

            if (b.verbose) {
                printInvocation(args.items);
            }
            child.spawn() catch |err| debug.panic("Unable to spawn {s}: {s}\n", .{ full_exe_path, @errorName(err) });

            const stdout = child.stdout.?.reader().readAllAlloc(b.allocator, max_stdout_size) catch unreachable;
            defer b.allocator.free(stdout);
            const stderrFull = child.stderr.?.reader().readAllAlloc(b.allocator, max_stdout_size) catch unreachable;
            defer b.allocator.free(stderrFull);
            var stderr = stderrFull;

            const term = child.wait() catch |err| {
                debug.panic("Unable to spawn {s}: {s}\n", .{ full_exe_path, @errorName(err) });
            };

            switch (term) {
                .Exited => |code| {
                    const expect_code: u32 = 1;
                    if (code != expect_code) {
                        warn("Process {s} exited with error code {d} but expected code {d}\n", .{
                            full_exe_path,
                            code,
                            expect_code,
                        });
                        printInvocation(args.items);
                        return error.TestFailed;
                    }
                },
                .Signal => |signum| {
                    warn("Process {s} terminated on signal {d}\n", .{ full_exe_path, signum });
                    printInvocation(args.items);
                    return error.TestFailed;
                },
                .Stopped => |signum| {
                    warn("Process {s} stopped on signal {d}\n", .{ full_exe_path, signum });
                    printInvocation(args.items);
                    return error.TestFailed;
                },
                .Unknown => |code| {
                    warn("Process {s} terminated unexpectedly with error code {d}\n", .{ full_exe_path, code });
                    printInvocation(args.items);
                    return error.TestFailed;
                },
            }

            // process result
            // - keep only basename of source file path
            // - replace address with symbolic string
            // - replace function name with symbolic string when mode != .Debug
            // - skip empty lines
            const got: []const u8 = got_result: {
                var buf = ArrayList(u8).init(b.allocator);
                defer buf.deinit();
                if (stderr.len != 0 and stderr[stderr.len - 1] == '\n') stderr = stderr[0 .. stderr.len - 1];
                var it = mem.split(stderr, "\n");
                process_lines: while (it.next()) |line| {
                    if (line.len == 0) continue;

                    // offset search past `[drive]:` on windows
                    var pos: usize = if (std.Target.current.os.tag == .windows) 2 else 0;
                    // locate delims/anchor
                    const delims = [_][]const u8{ ":", ":", ":", " in ", "(", ")" };
                    var marks = [_]usize{0} ** delims.len;
                    for (delims) |delim, i| {
                        marks[i] = mem.indexOfPos(u8, line, pos, delim) orelse {
                            // unexpected pattern: emit raw line and cont
                            try buf.appendSlice(line);
                            try buf.appendSlice("\n");
                            continue :process_lines;
                        };
                        pos = marks[i] + delim.len;
                    }
                    // locate source basename
                    pos = mem.lastIndexOfScalar(u8, line[0..marks[0]], fs.path.sep) orelse {
                        // unexpected pattern: emit raw line and cont
                        try buf.appendSlice(line);
                        try buf.appendSlice("\n");
                        continue :process_lines;
                    };
                    // end processing if source basename changes
                    if (!mem.eql(u8, "source.zig", line[pos + 1 .. marks[0]])) break;
                    // emit substituted line
                    try buf.appendSlice(line[pos + 1 .. marks[2] + delims[2].len]);
                    try buf.appendSlice(" [address]");
                    if (self.mode == .Debug) {
                        if (mem.lastIndexOfScalar(u8, line[marks[4]..marks[5]], '.')) |idot| {
                            // On certain platforms (windows) or possibly depending on how we choose to link main
                            // the object file extension may be present so we simply strip any extension.
                            try buf.appendSlice(line[marks[3] .. marks[4] + idot]);
                            try buf.appendSlice(line[marks[5]..]);
                        } else {
                            try buf.appendSlice(line[marks[3]..]);
                        }
                    } else {
                        try buf.appendSlice(line[marks[3] .. marks[3] + delims[3].len]);
                        try buf.appendSlice("[function]");
                    }
                    try buf.appendSlice("\n");
                }
                break :got_result buf.toOwnedSlice();
            };

            if (!mem.eql(u8, self.expect_output, got)) {
                warn(
                    \\
                    \\========= Expected this output: =========
                    \\{s}
                    \\================================================
                    \\{s}
                    \\
                , .{ self.expect_output, got });
                return error.TestFailed;
            }
            warn("OK\n", .{});
        }
    };
};

pub const CompileErrorContext = struct {
    b: *build.Builder,
    step: *build.Step,
    test_index: usize,
    test_filter: ?[]const u8,
    modes: []const Mode,

    const TestCase = struct {
        name: []const u8,
        sources: ArrayList(SourceFile),
        expected_errors: ArrayList([]const u8),
        expect_exact: bool,
        link_libc: bool,
        is_exe: bool,
        is_test: bool,
        target: CrossTarget = CrossTarget{},

        const SourceFile = struct {
            filename: []const u8,
            source: []const u8,
        };

        pub fn addSourceFile(self: *TestCase, filename: []const u8, source: []const u8) void {
            self.sources.append(SourceFile{
                .filename = filename,
                .source = source,
            }) catch unreachable;
        }

        pub fn addExpectedError(self: *TestCase, text: []const u8) void {
            self.expected_errors.append(text) catch unreachable;
        }
    };

    const CompileCmpOutputStep = struct {
        pub const base_id = .custom;

        step: build.Step,
        context: *CompileErrorContext,
        name: []const u8,
        test_index: usize,
        case: *const TestCase,
        build_mode: Mode,
        write_src: *build.WriteFileStep,

        const ErrLineIter = struct {
            lines: mem.SplitIterator,

            const source_file = "tmp.zig";

            fn init(input: []const u8) ErrLineIter {
                return ErrLineIter{ .lines = mem.split(input, "\n") };
            }

            fn next(self: *ErrLineIter) ?[]const u8 {
                while (self.lines.next()) |line| {
                    if (mem.indexOf(u8, line, source_file) != null)
                        return line;
                }
                return null;
            }
        };

        pub fn create(
            context: *CompileErrorContext,
            name: []const u8,
            case: *const TestCase,
            build_mode: Mode,
            write_src: *build.WriteFileStep,
        ) *CompileCmpOutputStep {
            const allocator = context.b.allocator;
            const ptr = allocator.create(CompileCmpOutputStep) catch unreachable;
            ptr.* = CompileCmpOutputStep{
                .step = build.Step.init(.custom, "CompileCmpOutput", allocator, make),
                .context = context,
                .name = name,
                .test_index = context.test_index,
                .case = case,
                .build_mode = build_mode,
                .write_src = write_src,
            };

            context.test_index += 1;
            return ptr;
        }

        fn make(step: *build.Step) !void {
            const self = @fieldParentPtr(CompileCmpOutputStep, "step", step);
            const b = self.context.b;

            var zig_args = ArrayList([]const u8).init(b.allocator);
            zig_args.append(b.zig_exe) catch unreachable;

            if (self.case.is_exe) {
                try zig_args.append("build-exe");
            } else if (self.case.is_test) {
                try zig_args.append("test");
            } else {
                try zig_args.append("build-obj");
            }
            const root_src_basename = self.case.sources.items[0].filename;
            try zig_args.append(self.write_src.getFileSource(root_src_basename).?.getPath(b));

            zig_args.append("--name") catch unreachable;
            zig_args.append("test") catch unreachable;

            if (!self.case.target.isNative()) {
                try zig_args.append("-target");
                try zig_args.append(try self.case.target.zigTriple(b.allocator));
            }

            zig_args.append("-O") catch unreachable;
            zig_args.append(@tagName(self.build_mode)) catch unreachable;

            warn("Test {d}/{d} {s}...", .{ self.test_index + 1, self.context.test_index, self.name });

            if (b.verbose) {
                printInvocation(zig_args.items);
            }

            const child = std.ChildProcess.init(zig_args.items, b.allocator) catch unreachable;
            defer child.deinit();

            child.env_map = b.env_map;
            child.stdin_behavior = .Ignore;
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Pipe;

            child.spawn() catch |err| debug.panic("Unable to spawn {s}: {s}\n", .{ zig_args.items[0], @errorName(err) });

            var stdout_buf = ArrayList(u8).init(b.allocator);
            var stderr_buf = ArrayList(u8).init(b.allocator);

            child.stdout.?.reader().readAllArrayList(&stdout_buf, max_stdout_size) catch unreachable;
            child.stderr.?.reader().readAllArrayList(&stderr_buf, max_stdout_size) catch unreachable;

            const term = child.wait() catch |err| {
                debug.panic("Unable to spawn {s}: {s}\n", .{ zig_args.items[0], @errorName(err) });
            };
            switch (term) {
                .Exited => |code| {
                    if (code == 0) {
                        printInvocation(zig_args.items);
                        return error.CompilationIncorrectlySucceeded;
                    }
                },
                else => {
                    warn("Process {s} terminated unexpectedly\n", .{b.zig_exe});
                    printInvocation(zig_args.items);
                    return error.TestFailed;
                },
            }

            const stdout = stdout_buf.items;
            const stderr = stderr_buf.items;

            if (stdout.len != 0) {
                warn(
                    \\
                    \\Expected empty stdout, instead found:
                    \\================================================
                    \\{s}
                    \\================================================
                    \\
                , .{stdout});
                return error.TestFailed;
            }

            var ok = true;
            if (self.case.expect_exact) {
                var err_iter = ErrLineIter.init(stderr);
                var i: usize = 0;
                ok = while (err_iter.next()) |line| : (i += 1) {
                    if (i >= self.case.expected_errors.items.len) break false;
                    const expected = self.case.expected_errors.items[i];
                    if (mem.indexOf(u8, line, expected) == null) break false;
                    continue;
                } else true;

                ok = ok and i == self.case.expected_errors.items.len;

                if (!ok) {
                    warn("\n======== Expected these compile errors: ========\n", .{});
                    for (self.case.expected_errors.items) |expected| {
                        warn("{s}\n", .{expected});
                    }
                }
            } else {
                for (self.case.expected_errors.items) |expected| {
                    if (mem.indexOf(u8, stderr, expected) == null) {
                        warn(
                            \\
                            \\=========== Expected compile error: ============
                            \\{s}
                            \\
                        , .{expected});
                        ok = false;
                        break;
                    }
                }
            }

            if (!ok) {
                warn(
                    \\================= Full output: =================
                    \\{s}
                    \\
                , .{stderr});
                return error.TestFailed;
            }

            warn("OK\n", .{});
        }
    };

    pub fn create(
        self: *CompileErrorContext,
        name: []const u8,
        source: []const u8,
        expected_lines: []const []const u8,
    ) *TestCase {
        const tc = self.b.allocator.create(TestCase) catch unreachable;
        tc.* = TestCase{
            .name = name,
            .sources = ArrayList(TestCase.SourceFile).init(self.b.allocator),
            .expected_errors = ArrayList([]const u8).init(self.b.allocator),
            .expect_exact = false,
            .link_libc = false,
            .is_exe = false,
            .is_test = false,
        };

        tc.addSourceFile("tmp.zig", source);
        var arg_i: usize = 0;
        while (arg_i < expected_lines.len) : (arg_i += 1) {
            tc.addExpectedError(expected_lines[arg_i]);
        }
        return tc;
    }

    pub fn addC(self: *CompileErrorContext, name: []const u8, source: []const u8, expected_lines: []const []const u8) void {
        var tc = self.create(name, source, expected_lines);
        tc.link_libc = true;
        self.addCase(tc);
    }

    pub fn addExe(
        self: *CompileErrorContext,
        name: []const u8,
        source: []const u8,
        expected_lines: []const []const u8,
    ) void {
        var tc = self.create(name, source, expected_lines);
        tc.is_exe = true;
        self.addCase(tc);
    }

    pub fn add(
        self: *CompileErrorContext,
        name: []const u8,
        source: []const u8,
        expected_lines: []const []const u8,
    ) void {
        const tc = self.create(name, source, expected_lines);
        self.addCase(tc);
    }

    pub fn addTest(
        self: *CompileErrorContext,
        name: []const u8,
        source: []const u8,
        expected_lines: []const []const u8,
    ) void {
        const tc = self.create(name, source, expected_lines);
        tc.is_test = true;
        self.addCase(tc);
    }

    pub fn addCase(self: *CompileErrorContext, case: *const TestCase) void {
        const b = self.b;

        const annotated_case_name = fmt.allocPrint(self.b.allocator, "compile-error {s}", .{
            case.name,
        }) catch unreachable;
        if (self.test_filter) |filter| {
            if (mem.indexOf(u8, annotated_case_name, filter) == null) return;
        }
        const write_src = b.addWriteFiles();
        for (case.sources.items) |src_file| {
            write_src.add(src_file.filename, src_file.source);
        }

        const compile_and_cmp_errors = CompileCmpOutputStep.create(self, annotated_case_name, case, .Debug, write_src);
        compile_and_cmp_errors.step.dependOn(&write_src.step);
        self.step.dependOn(&compile_and_cmp_errors.step);
    }
};

pub const StandaloneContext = struct {
    b: *build.Builder,
    step: *build.Step,
    test_index: usize,
    test_filter: ?[]const u8,
    modes: []const Mode,
    skip_non_native: bool,
    target: std.zig.CrossTarget,

    pub fn addC(self: *StandaloneContext, root_src: []const u8) void {
        self.addAllArgs(root_src, true);
    }

    pub fn add(self: *StandaloneContext, root_src: []const u8) void {
        self.addAllArgs(root_src, false);
    }

    pub fn addBuildFile(self: *StandaloneContext, build_file: []const u8, features: struct { build_modes: bool = false, cross_targets: bool = false }) void {
        const b = self.b;

        const annotated_case_name = b.fmt("build {s}", .{build_file});
        if (self.test_filter) |filter| {
            if (mem.indexOf(u8, annotated_case_name, filter) == null) return;
        }

        var zig_args = ArrayList([]const u8).init(b.allocator);
        const rel_zig_exe = fs.path.relative(b.allocator, b.build_root, b.zig_exe) catch unreachable;
        zig_args.append(rel_zig_exe) catch unreachable;
        zig_args.append("build") catch unreachable;

        zig_args.append("--build-file") catch unreachable;
        zig_args.append(b.pathFromRoot(build_file)) catch unreachable;

        zig_args.append("test") catch unreachable;

        if (b.verbose) {
            zig_args.append("--verbose") catch unreachable;
        }

        if (features.cross_targets and !self.target.isNative()) {
            const target_arg = fmt.allocPrint(b.allocator, "-Dtarget={s}", .{self.target.zigTriple(b.allocator) catch unreachable}) catch unreachable;
            zig_args.append(target_arg) catch unreachable;
        }

        const modes = if (features.build_modes) self.modes else &[1]Mode{.Debug};
        for (modes) |mode| {
            const arg = switch (mode) {
                .Debug => "",
                .ReleaseFast => "-Drelease-fast",
                .ReleaseSafe => "-Drelease-safe",
                .ReleaseSmall => "-Drelease-small",
            };
            const zig_args_base_len = zig_args.items.len;
            if (arg.len > 0)
                zig_args.append(arg) catch unreachable;
            defer zig_args.resize(zig_args_base_len) catch unreachable;

            const run_cmd = b.addSystemCommand(zig_args.items);
            const log_step = b.addLog("PASS {s} ({s})\n", .{ annotated_case_name, @tagName(mode) });
            log_step.step.dependOn(&run_cmd.step);

            self.step.dependOn(&log_step.step);
        }
    }

    pub fn addAllArgs(self: *StandaloneContext, root_src: []const u8, link_libc: bool) void {
        const b = self.b;

        for (self.modes) |mode| {
            const annotated_case_name = fmt.allocPrint(self.b.allocator, "build {s} ({s})", .{
                root_src,
                @tagName(mode),
            }) catch unreachable;
            if (self.test_filter) |filter| {
                if (mem.indexOf(u8, annotated_case_name, filter) == null) continue;
            }

            const exe = b.addExecutable("test", root_src);
            exe.setBuildMode(mode);
            if (link_libc) {
                exe.linkSystemLibrary("c");
            }

            const log_step = b.addLog("PASS {s}\n", .{annotated_case_name});
            log_step.step.dependOn(&exe.step);

            self.step.dependOn(&log_step.step);
        }
    }
};

pub const GenHContext = struct {
    b: *build.Builder,
    step: *build.Step,
    test_index: usize,
    test_filter: ?[]const u8,

    const TestCase = struct {
        name: []const u8,
        sources: ArrayList(SourceFile),
        expected_lines: ArrayList([]const u8),

        const SourceFile = struct {
            filename: []const u8,
            source: []const u8,
        };

        pub fn addSourceFile(self: *TestCase, filename: []const u8, source: []const u8) void {
            self.sources.append(SourceFile{
                .filename = filename,
                .source = source,
            }) catch unreachable;
        }

        pub fn addExpectedLine(self: *TestCase, text: []const u8) void {
            self.expected_lines.append(text) catch unreachable;
        }
    };

    const GenHCmpOutputStep = struct {
        step: build.Step,
        context: *GenHContext,
        obj: *LibExeObjStep,
        name: []const u8,
        test_index: usize,
        case: *const TestCase,

        pub fn create(
            context: *GenHContext,
            obj: *LibExeObjStep,
            name: []const u8,
            case: *const TestCase,
        ) *GenHCmpOutputStep {
            const allocator = context.b.allocator;
            const ptr = allocator.create(GenHCmpOutputStep) catch unreachable;
            ptr.* = GenHCmpOutputStep{
                .step = build.Step.init(.Custom, "ParseCCmpOutput", allocator, make),
                .context = context,
                .obj = obj,
                .name = name,
                .test_index = context.test_index,
                .case = case,
            };
            ptr.step.dependOn(&obj.step);
            context.test_index += 1;
            return ptr;
        }

        fn make(step: *build.Step) !void {
            const self = @fieldParentPtr(GenHCmpOutputStep, "step", step);
            const b = self.context.b;

            warn("Test {d}/{d} {s}...", .{ self.test_index + 1, self.context.test_index, self.name });

            const full_h_path = self.obj.getOutputHPath();
            const actual_h = try io.readFileAlloc(b.allocator, full_h_path);

            for (self.case.expected_lines.items) |expected_line| {
                if (mem.indexOf(u8, actual_h, expected_line) == null) {
                    warn(
                        \\
                        \\========= Expected this output: ================
                        \\{s}
                        \\========= But found: ===========================
                        \\{s}
                        \\
                    , .{ expected_line, actual_h });
                    return error.TestFailed;
                }
            }
            warn("OK\n", .{});
        }
    };

    fn printInvocation(args: []const []const u8) void {
        for (args) |arg| {
            warn("{s} ", .{arg});
        }
        warn("\n", .{});
    }

    pub fn create(
        self: *GenHContext,
        filename: []const u8,
        name: []const u8,
        source: []const u8,
        expected_lines: []const []const u8,
    ) *TestCase {
        const tc = self.b.allocator.create(TestCase) catch unreachable;
        tc.* = TestCase{
            .name = name,
            .sources = ArrayList(TestCase.SourceFile).init(self.b.allocator),
            .expected_lines = ArrayList([]const u8).init(self.b.allocator),
        };

        tc.addSourceFile(filename, source);
        var arg_i: usize = 0;
        while (arg_i < expected_lines.len) : (arg_i += 1) {
            tc.addExpectedLine(expected_lines[arg_i]);
        }
        return tc;
    }

    pub fn add(self: *GenHContext, name: []const u8, source: []const u8, expected_lines: []const []const u8) void {
        const tc = self.create("test.zig", name, source, expected_lines);
        self.addCase(tc);
    }

    pub fn addCase(self: *GenHContext, case: *const TestCase) void {
        const b = self.b;

        const mode = builtin.Mode.Debug;
        const annotated_case_name = fmt.allocPrint(self.b.allocator, "gen-h {s} ({s})", .{ case.name, @tagName(mode) }) catch unreachable;
        if (self.test_filter) |filter| {
            if (mem.indexOf(u8, annotated_case_name, filter) == null) return;
        }

        const write_src = b.addWriteFiles();
        for (case.sources.items) |src_file| {
            write_src.add(src_file.filename, src_file.source);
        }

        const obj = b.addObjectFromWriteFileStep("test", write_src, case.sources.items[0].filename);
        obj.setBuildMode(mode);

        const cmp_h = GenHCmpOutputStep.create(self, obj, annotated_case_name, case);

        self.step.dependOn(&cmp_h.step);
    }
};

fn printInvocation(args: []const []const u8) void {
    for (args) |arg| {
        warn("{s} ", .{arg});
    }
    warn("\n", .{});
}
