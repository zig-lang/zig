const std = @import("std");
const builtin = @import("builtin");
const fs = std.fs;
const mem = std.mem;
const json = std.json;
const assert = std.debug.assert;

// All references to other features are based on "zig name" as the key.

const FeatureOverride = struct {
    llvm_name: []const u8,
    /// If true, completely omit the feature; as if it does not exist.
    omit: bool = false,
    /// If true, omit the feature, but all the dependencies of the feature
    /// are added in its place.
    flatten: bool = false,
    zig_name: ?[]const u8 = null,
    desc: ?[]const u8 = null,
    extra_deps: []const []const u8 = &.{},
};

const Cpu = struct {
    llvm_name: ?[]const u8,
    zig_name: []const u8,
    features: []const []const u8,
};

const Feature = struct {
    llvm_name: ?[]const u8 = null,
    zig_name: []const u8,
    desc: []const u8,
    deps: []const []const u8,
    flatten: bool = false,
};

const LlvmTarget = struct {
    zig_name: []const u8,
    llvm_name: []const u8,
    td_name: []const u8,
    feature_overrides: []const FeatureOverride = &.{},
    extra_cpus: []const Cpu = &.{},
    extra_features: []const Feature = &.{},
    branch_quota: ?usize = null,
};

const llvm_targets = [_]LlvmTarget{
    .{
        .zig_name = "aarch64",
        .llvm_name = "AArch64",
        .td_name = "AArch64.td",
        .branch_quota = 2000,
        .feature_overrides = &.{
            .{
                .llvm_name = "CONTEXTIDREL2",
                .zig_name = "contextidr_el2",
                .desc = "Enable RW operand Context ID Register (EL2)",
            },
            .{
                .llvm_name = "neoversee1",
                .zig_name = "neoverse_e1",
            },
            .{
                .llvm_name = "neoversen1",
                .zig_name = "neoverse_n1",
            },
            .{
                .llvm_name = "neoversen2",
                .zig_name = "neoverse_n2",
            },
            .{
                .llvm_name = "neoversev1",
                .zig_name = "neoverse_v1",
            },
            .{
                .llvm_name = "exynosm3",
                .zig_name = "exynos_m3",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "exynosm4",
                .zig_name = "exynos_m4",
            },
            .{
                .llvm_name = "v8.1a",
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "a35",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "a53",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "a55",
                .flatten = true,
            },
            .{
                .llvm_name = "a57",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "a64fx",
                .flatten = true,
            },
            .{
                .llvm_name = "a72",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "a73",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "a75",
                .flatten = true,
            },
            .{
                .llvm_name = "a77",
                .flatten = true,
            },
            .{
                .llvm_name = "apple-a10",
                .flatten = true,
            },
            .{
                .llvm_name = "apple-a11",
                .flatten = true,
            },
            .{
                .llvm_name = "apple-a14",
                .flatten = true,
            },
            .{
                .llvm_name = "carmel",
                .flatten = true,
            },
            .{
                .llvm_name = "cortex-a78",
                .flatten = true,
            },
            .{
                .llvm_name = "cortex-x1",
                .flatten = true,
            },
            .{
                .llvm_name = "falkor",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "kryo",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "saphira",
                .flatten = true,
            },
            .{
                .llvm_name = "thunderx",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "thunderx2t99",
                .flatten = true,
            },
            .{
                .llvm_name = "thunderx3t110",
                .flatten = true,
            },
            .{
                .llvm_name = "thunderxt81",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "thunderxt83",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "thunderxt88",
                .flatten = true,
                .extra_deps = &.{"v8a"},
            },
            .{
                .llvm_name = "tsv110",
                .flatten = true,
            },
        },
        .extra_features = &.{
            .{
                .zig_name = "v8a",
                .desc = "Support ARM v8a instructions",
                .deps = &.{ "fp_armv8", "neon" },
            },
        },
        .extra_cpus = &.{
            .{
                .llvm_name = null,
                .zig_name = "exynos_m1",
                .features = &.{
                    "crc",
                    "crypto",
                    "exynos_cheap_as_move",
                    "force_32bit_jump_tables",
                    "fuse_aes",
                    "perfmon",
                    "slow_misaligned_128store",
                    "slow_paired_128",
                    "use_postra_scheduler",
                    "use_reciprocal_square_root",
                    "v8a",
                    "zcz_fp",
                },
            },
            .{
                .llvm_name = null,
                .zig_name = "exynos_m2",
                .features = &.{
                    "crc",
                    "crypto",
                    "exynos_cheap_as_move",
                    "force_32bit_jump_tables",
                    "fuse_aes",
                    "perfmon",
                    "slow_misaligned_128store",
                    "slow_paired_128",
                    "use_postra_scheduler",
                    "v8a",
                    "zcz_fp",
                },
            },
            .{
                .llvm_name = null,
                .zig_name = "xgene1",
                .features = &.{
                    "fp_armv8",
                    "neon",
                    "perfmon",
                    "v8a",
                },
            },
            .{
                .llvm_name = null,
                .zig_name = "emag",
                .features = &.{
                    "crc",
                    "crypto",
                    "fp_armv8",
                    "neon",
                    "perfmon",
                    "v8a",
                },
            },
        },
    },
    .{
        .zig_name = "amdgpu",
        .llvm_name = "AMDGPU",
        .td_name = "AMDGPU.td",
        .feature_overrides = &.{
            .{
                .llvm_name = "DumpCode",
                .omit = true,
            },
            .{
                .llvm_name = "dumpcode",
                .omit = true,
            },
        },
    },
    .{
        .zig_name = "arc",
        .llvm_name = "ARC",
        .td_name = "ARC.td",
    },
    .{
        .zig_name = "arm",
        .llvm_name = "ARM",
        .td_name = "ARM.td",
        .branch_quota = 10000,
        .extra_cpus = &.{
            .{
                .llvm_name = "generic",
                .zig_name = "baseline",
                .features = &.{"v7a"},
            },
            .{
                .llvm_name = null,
                .zig_name = "exynos_m1",
                .features = &.{ "v8a", "exynos" },
            },
            .{
                .llvm_name = null,
                .zig_name = "exynos_m2",
                .features = &.{ "v8a", "exynos" },
            },
        },
        .feature_overrides = &.{
            .{
                .llvm_name = "cortex-a78",
                .flatten = true,
            },
            .{
                .llvm_name = "r5",
                .flatten = true,
            },
            .{
                .llvm_name = "r52",
                .flatten = true,
            },
            .{
                .llvm_name = "r7",
                .flatten = true,
            },
            .{
                .llvm_name = "m7",
                .flatten = true,
            },
            .{
                .llvm_name = "krait",
                .flatten = true,
            },
            .{
                .llvm_name = "kryo",
                .flatten = true,
            },
            .{
                .llvm_name = "cortex-x1",
                .flatten = true,
            },
            .{
                .llvm_name = "neoverse-v1",
                .flatten = true,
            },
            .{
                .llvm_name = "a5",
                .flatten = true,
            },
            .{
                .llvm_name = "a7",
                .flatten = true,
            },
            .{
                .llvm_name = "a8",
                .flatten = true,
            },
            .{
                .llvm_name = "a9",
                .flatten = true,
            },
            .{
                .llvm_name = "a12",
                .flatten = true,
            },
            .{
                .llvm_name = "a15",
                .flatten = true,
            },
            .{
                .llvm_name = "a17",
                .flatten = true,
            },
            .{
                .llvm_name = "a32",
                .flatten = true,
            },
            .{
                .llvm_name = "a35",
                .flatten = true,
            },
            .{
                .llvm_name = "a53",
                .flatten = true,
            },
            .{
                .llvm_name = "a55",
                .flatten = true,
            },
            .{
                .llvm_name = "a57",
                .flatten = true,
            },
            .{
                .llvm_name = "a72",
                .flatten = true,
            },
            .{
                .llvm_name = "a73",
                .flatten = true,
            },
            .{
                .llvm_name = "a75",
                .flatten = true,
            },
            .{
                .llvm_name = "a77",
                .flatten = true,
            },
            .{
                .llvm_name = "a78c",
                .flatten = true,
            },
            .{
                .llvm_name = "armv2",
                .zig_name = "v2",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv2a",
                .zig_name = "v2a",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv3",
                .zig_name = "v3",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv3m",
                .zig_name = "v3m",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv4",
                .zig_name = "v4",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv4t",
                .zig_name = "v4t",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv5t",
                .zig_name = "v5t",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv5te",
                .zig_name = "v5te",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv5tej",
                .zig_name = "v5tej",
                .extra_deps = &.{"strict_align"},
            },
            .{
                .llvm_name = "armv6",
                .zig_name = "v6",
            },
            .{
                .llvm_name = "armv6-m",
                .zig_name = "v6m",
            },
            .{
                .llvm_name = "armv6j",
                .zig_name = "v6j",
            },
            .{
                .llvm_name = "armv6k",
                .zig_name = "v6k",
            },
            .{
                .llvm_name = "armv6kz",
                .zig_name = "v6kz",
            },
            .{
                .llvm_name = "armv6s-m",
                .zig_name = "v6sm",
            },
            .{
                .llvm_name = "armv6t2",
                .zig_name = "v6t2",
            },
            .{
                .llvm_name = "armv7-a",
                .zig_name = "v7a",
            },
            .{
                .llvm_name = "armv7-m",
                .zig_name = "v7m",
            },
            .{
                .llvm_name = "armv7-r",
                .zig_name = "v7r",
            },
            .{
                .llvm_name = "armv7e-m",
                .zig_name = "v7em",
            },
            .{
                .llvm_name = "armv7k",
                .zig_name = "v7k",
            },
            .{
                .llvm_name = "armv7s",
                .zig_name = "v7s",
            },
            .{
                .llvm_name = "armv7ve",
                .zig_name = "v7ve",
            },
            .{
                .llvm_name = "armv8.1-a",
                .zig_name = "v8_1a",
            },
            .{
                .llvm_name = "armv8.1-m.main",
                .zig_name = "v8_1m_main",
            },
            .{
                .llvm_name = "armv8.2-a",
                .zig_name = "v8_2a",
            },
            .{
                .llvm_name = "armv8.3-a",
                .zig_name = "v8_3a",
            },
            .{
                .llvm_name = "armv8.4-a",
                .zig_name = "v8_4a",
            },
            .{
                .llvm_name = "armv8.5-a",
                .zig_name = "v8_5a",
            },
            .{
                .llvm_name = "armv8.6-a",
                .zig_name = "v8_6a",
            },
            .{
                .llvm_name = "armv8.7-a",
                .zig_name = "v8_7a",
            },
            .{
                .llvm_name = "armv8-a",
                .zig_name = "v8a",
            },
            .{
                .llvm_name = "armv8-m.base",
                .zig_name = "v8m",
            },
            .{
                .llvm_name = "armv8-m.main",
                .zig_name = "v8m_main",
            },
            .{
                .llvm_name = "armv8-r",
                .zig_name = "v8r",
            },
            .{
                .llvm_name = "v4t",
                .zig_name = "has_v4t",
            },
            .{
                .llvm_name = "v5t",
                .zig_name = "has_v5t",
            },
            .{
                .llvm_name = "v5te",
                .zig_name = "has_v5te",
            },
            .{
                .llvm_name = "v6",
                .zig_name = "has_v6",
            },
            .{
                .llvm_name = "v6k",
                .zig_name = "has_v6k",
            },
            .{
                .llvm_name = "v6m",
                .zig_name = "has_v6m",
            },
            .{
                .llvm_name = "v6t2",
                .zig_name = "has_v6t2",
            },
            .{
                .llvm_name = "v7",
                .zig_name = "has_v7",
            },
            .{
                .llvm_name = "v7clrex",
                .zig_name = "has_v7clrex",
            },
            .{
                .llvm_name = "v8",
                .zig_name = "has_v8",
            },
            .{
                .llvm_name = "v8m",
                .zig_name = "has_v8m",
            },
            .{
                .llvm_name = "v8m.main",
                .zig_name = "has_v8m_main",
            },
            .{
                .llvm_name = "v8.1a",
                .zig_name = "has_v8_1a",
            },
            .{
                .llvm_name = "v8.1m.main",
                .zig_name = "has_v8_1m_main",
            },
            .{
                .llvm_name = "v8.2a",
                .zig_name = "has_v8_2a",
            },
            .{
                .llvm_name = "v8.3a",
                .zig_name = "has_v8_3a",
            },
            .{
                .llvm_name = "v8.4a",
                .zig_name = "has_v8_4a",
            },
            .{
                .llvm_name = "v8.5a",
                .zig_name = "has_v8_5a",
            },
            .{
                .llvm_name = "v8.6a",
                .zig_name = "has_v8_6a",
            },
            .{
                .llvm_name = "v8.7a",
                .zig_name = "has_v8_7a",
            },
        },
    },
    .{
        .zig_name = "avr",
        .llvm_name = "AVR",
        .td_name = "AVR.td",
    },
    .{
        .zig_name = "bpf",
        .llvm_name = "BPF",
        .td_name = "BPF.td",
    },
    .{
        .zig_name = "csky",
        .llvm_name = "CSKY",
        .td_name = "CSKY.td",
    },
    .{
        .zig_name = "hexagon",
        .llvm_name = "Hexagon",
        .td_name = "Hexagon.td",
    },
    .{
        .zig_name = "lanai",
        .llvm_name = "Lanai",
        .td_name = "Lanai.td",
    },
    .{
        .zig_name = "msp430",
        .llvm_name = "MSP430",
        .td_name = "MSP430.td",
    },
    .{
        .zig_name = "mips",
        .llvm_name = "Mips",
        .td_name = "Mips.td",
    },
    .{
        .zig_name = "nvptx",
        .llvm_name = "NVPTX",
        .td_name = "NVPTX.td",
    },
    .{
        .zig_name = "powerpc",
        .llvm_name = "PowerPC",
        .td_name = "PPC.td",
        .feature_overrides = &.{
            .{
                .llvm_name = "ppc32",
                .omit = true,
            },
        },
    },
    .{
        .zig_name = "riscv",
        .llvm_name = "RISCV",
        .td_name = "RISCV.td",
        .extra_cpus = &.{
            .{
                .llvm_name = null,
                .zig_name = "baseline_rv32",
                .features = &.{ "a", "c", "d", "f", "m" },
            },
            .{
                .llvm_name = null,
                .zig_name = "baseline_rv64",
                .features = &.{ "64bit", "a", "c", "d", "f", "m" },
            },
        },
    },
    .{
        .zig_name = "sparc",
        .llvm_name = "Sparc",
        .td_name = "Sparc.td",
    },
    .{
        .zig_name = "systemz",
        .llvm_name = "SystemZ",
        .td_name = "SystemZ.td",
    },
    .{
        .zig_name = "ve",
        .llvm_name = "VE",
        .td_name = "VE.td",
    },
    .{
        .zig_name = "wasm",
        .llvm_name = "WebAssembly",
        .td_name = "WebAssembly.td",
    },
    .{
        .zig_name = "x86",
        .llvm_name = "X86",
        .td_name = "X86.td",
        .feature_overrides = &.{
            .{
                .llvm_name = "64bit-mode",
                .omit = true,
            },
            .{
                .llvm_name = "i386",
                .zig_name = "_i386",
            },
            .{
                .llvm_name = "i486",
                .zig_name = "_i486",
            },
            .{
                .llvm_name = "i586",
                .zig_name = "_i586",
            },
            .{
                .llvm_name = "i686",
                .zig_name = "_i686",
            },
            .{
                .llvm_name = "lakemont",
                .extra_deps = &.{"soft_float"},
            },
        },
    },
    .{
        .zig_name = "xcore",
        .llvm_name = "XCore",
        .td_name = "XCore.td",
    },
};

pub fn main() anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = &arena_state.allocator;

    const args = try std.process.argsAlloc(arena);
    if (args.len <= 1) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }
    if (std.mem.eql(u8, args[1], "--help")) {
        usageAndExit(std.io.getStdOut(), args[0], 0);
    }
    if (args.len < 4) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }

    const llvm_tblgen_exe = args[1];
    if (std.mem.startsWith(u8, llvm_tblgen_exe, "-")) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }

    const llvm_src_root = args[2];
    if (std.mem.startsWith(u8, llvm_src_root, "-")) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }

    const zig_src_root = args[3];
    if (std.mem.startsWith(u8, zig_src_root, "-")) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }

    var zig_src_dir = try fs.cwd().openDir(zig_src_root, .{});
    defer zig_src_dir.close();

    var progress = std.Progress{};
    const root_progress = try progress.start("", llvm_targets.len);
    defer root_progress.end();

    if (builtin.single_threaded) {
        for (llvm_targets) |llvm_target| {
            try processOneTarget(Job{
                .llvm_tblgen_exe = llvm_tblgen_exe,
                .llvm_src_root = llvm_src_root,
                .zig_src_dir = zig_src_dir,
                .root_progress = root_progress,
                .llvm_target = llvm_target,
            });
        }
    } else {
        var threads = try arena.alloc(std.Thread, llvm_targets.len);
        for (llvm_targets) |llvm_target, i| {
            threads[i] = try std.Thread.spawn(.{}, processOneTarget, .{
                Job{
                    .llvm_tblgen_exe = llvm_tblgen_exe,
                    .llvm_src_root = llvm_src_root,
                    .zig_src_dir = zig_src_dir,
                    .root_progress = root_progress,
                    .llvm_target = llvm_target,
                },
            });
        }
        for (threads) |thread| {
            thread.join();
        }
    }
}

const Job = struct {
    llvm_tblgen_exe: []const u8,
    llvm_src_root: []const u8,
    zig_src_dir: std.fs.Dir,
    root_progress: *std.Progress.Node,
    llvm_target: LlvmTarget,
};

fn processOneTarget(job: Job) anyerror!void {
    const llvm_target = job.llvm_target;

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = &arena_state.allocator;

    var progress_node = job.root_progress.start(llvm_target.zig_name, 3);
    progress_node.activate();
    defer progress_node.end();

    var tblgen_progress = progress_node.start("invoke llvm-tblgen", 0);
    tblgen_progress.activate();

    const child_args = [_][]const u8{
        job.llvm_tblgen_exe,
        "--dump-json",
        try std.fmt.allocPrint(arena, "{s}/llvm/lib/Target/{s}/{s}", .{
            job.llvm_src_root,
            llvm_target.llvm_name,
            llvm_target.td_name,
        }),
        try std.fmt.allocPrint(arena, "-I={s}/llvm/include", .{job.llvm_src_root}),
        try std.fmt.allocPrint(arena, "-I={s}/llvm/lib/Target/{s}", .{
            job.llvm_src_root, llvm_target.llvm_name,
        }),
    };

    const child_result = try std.ChildProcess.exec(.{
        .allocator = arena,
        .argv = &child_args,
        .max_output_bytes = 200 * 1024 * 1024,
    });
    tblgen_progress.end();
    if (child_result.stderr.len != 0) {
        std.debug.warn("{s}\n", .{child_result.stderr});
    }

    const json_text = switch (child_result.term) {
        .Exited => |code| if (code == 0) child_result.stdout else {
            std.debug.warn("llvm-tblgen exited with code {d}\n", .{code});
            std.process.exit(1);
        },
        else => {
            std.debug.warn("llvm-tblgen crashed\n", .{});
            std.process.exit(1);
        },
    };

    var json_parse_progress = progress_node.start("parse JSON", 0);
    json_parse_progress.activate();

    var parser = json.Parser.init(arena, false);
    const tree = try parser.parse(json_text);
    json_parse_progress.end();

    var render_progress = progress_node.start("render zig code", 0);
    render_progress.activate();

    const root_map = &tree.root.Object;
    var features_table = std.StringHashMap(Feature).init(arena);
    var all_features = std.ArrayList(Feature).init(arena);
    var all_cpus = std.ArrayList(Cpu).init(arena);
    {
        var it = root_map.iterator();
        root_it: while (it.next()) |kv| {
            if (kv.key_ptr.len == 0) continue;
            if (kv.key_ptr.*[0] == '!') continue;
            if (kv.value_ptr.* != .Object) continue;
            if (hasSuperclass(&kv.value_ptr.Object, "SubtargetFeature")) {
                const llvm_name = kv.value_ptr.Object.get("Name").?.String;
                if (llvm_name.len == 0) continue;

                var zig_name = try llvmNameToZigName(arena, llvm_name);
                var desc = kv.value_ptr.Object.get("Desc").?.String;
                var deps = std.ArrayList([]const u8).init(arena);
                var omit = false;
                var flatten = false;
                const implies = kv.value_ptr.Object.get("Implies").?.Array;
                for (implies.items) |imply| {
                    const other_key = imply.Object.get("def").?.String;
                    const other_obj = &root_map.getPtr(other_key).?.Object;
                    const other_llvm_name = other_obj.get("Name").?.String;
                    const other_zig_name = (try llvmNameToZigNameOmit(
                        arena,
                        llvm_target,
                        other_llvm_name,
                    )) orelse continue;
                    try deps.append(other_zig_name);
                }
                for (llvm_target.feature_overrides) |feature_override| {
                    if (mem.eql(u8, llvm_name, feature_override.llvm_name)) {
                        if (feature_override.omit) {
                            // Still put the feature into the table so that we can
                            // expand dependencies for the feature overrides marked `flatten`.
                            omit = true;
                        }
                        if (feature_override.flatten) {
                            flatten = true;
                        }
                        if (feature_override.zig_name) |override_name| {
                            zig_name = override_name;
                        }
                        if (feature_override.desc) |override_desc| {
                            desc = override_desc;
                        }
                        for (feature_override.extra_deps) |extra_dep| {
                            try deps.append(extra_dep);
                        }
                        break;
                    }
                }
                const feature: Feature = .{
                    .llvm_name = llvm_name,
                    .zig_name = zig_name,
                    .desc = desc,
                    .deps = deps.items,
                    .flatten = flatten,
                };
                try features_table.put(zig_name, feature);
                if (!omit and !flatten) {
                    try all_features.append(feature);
                }
            }
            if (hasSuperclass(&kv.value_ptr.Object, "Processor")) {
                const llvm_name = kv.value_ptr.Object.get("Name").?.String;
                if (llvm_name.len == 0) continue;

                var zig_name = try llvmNameToZigName(arena, llvm_name);
                var deps = std.ArrayList([]const u8).init(arena);
                const features = kv.value_ptr.Object.get("Features").?.Array;
                for (features.items) |feature| {
                    const feature_key = feature.Object.get("def").?.String;
                    const feature_obj = &root_map.getPtr(feature_key).?.Object;
                    const feature_llvm_name = feature_obj.get("Name").?.String;
                    if (feature_llvm_name.len == 0) continue;
                    const feature_zig_name = (try llvmNameToZigNameOmit(
                        arena,
                        llvm_target,
                        feature_llvm_name,
                    )) orelse continue;
                    try deps.append(feature_zig_name);
                }
                const tune_features = kv.value_ptr.Object.get("TuneFeatures").?.Array;
                for (tune_features.items) |feature| {
                    const feature_key = feature.Object.get("def").?.String;
                    const feature_obj = &root_map.getPtr(feature_key).?.Object;
                    const feature_llvm_name = feature_obj.get("Name").?.String;
                    if (feature_llvm_name.len == 0) continue;
                    const feature_zig_name = (try llvmNameToZigNameOmit(
                        arena,
                        llvm_target,
                        feature_llvm_name,
                    )) orelse continue;
                    try deps.append(feature_zig_name);
                }
                for (llvm_target.feature_overrides) |feature_override| {
                    if (mem.eql(u8, llvm_name, feature_override.llvm_name)) {
                        if (feature_override.omit) {
                            continue :root_it;
                        }
                        if (feature_override.zig_name) |override_name| {
                            zig_name = override_name;
                        }
                        for (feature_override.extra_deps) |extra_dep| {
                            try deps.append(extra_dep);
                        }
                        break;
                    }
                }
                try all_cpus.append(.{
                    .llvm_name = llvm_name,
                    .zig_name = zig_name,
                    .features = deps.items,
                });
            }
        }
    }
    for (llvm_target.extra_features) |extra_feature| {
        try features_table.put(extra_feature.zig_name, extra_feature);
        try all_features.append(extra_feature);
    }
    for (llvm_target.extra_cpus) |extra_cpu| {
        try all_cpus.append(extra_cpu);
    }
    std.sort.sort(Feature, all_features.items, {}, featureLessThan);
    std.sort.sort(Cpu, all_cpus.items, {}, cpuLessThan);

    const target_sub_path = try fs.path.join(arena, &.{ "lib", "std", "target" });
    var target_dir = try job.zig_src_dir.makeOpenPath(target_sub_path, .{});
    defer target_dir.close();

    const zig_code_basename = try std.fmt.allocPrint(arena, "{s}.zig", .{llvm_target.zig_name});

    if (all_features.items.len == 0) {
        // We represent this with an empty file.
        try target_dir.deleteTree(zig_code_basename);
        return;
    }

    var zig_code_file = try target_dir.createFile(zig_code_basename, .{});
    defer zig_code_file.close();

    var bw = std.io.bufferedWriter(zig_code_file.writer());
    const w = bw.writer();

    try w.writeAll(
        \\//! This file is auto-generated by tools/update_cpu_features.zig.
        \\
        \\const std = @import("../std.zig");
        \\const CpuFeature = std.Target.Cpu.Feature;
        \\const CpuModel = std.Target.Cpu.Model;
        \\
        \\pub const Feature = enum {
        \\
    );

    for (all_features.items) |feature| {
        try w.print("    {},\n", .{std.zig.fmtId(feature.zig_name)});
    }

    try w.writeAll(
        \\};
        \\
        \\pub usingnamespace CpuFeature.feature_set_fns(Feature);
        \\
        \\pub const all_features = blk: {
        \\
    );
    if (llvm_target.branch_quota) |branch_quota| {
        try w.print("    @setEvalBranchQuota({d});\n", .{branch_quota});
    }
    try w.writeAll(
        \\    const len = @typeInfo(Feature).Enum.fields.len;
        \\    std.debug.assert(len <= CpuFeature.Set.needed_bit_count);
        \\    var result: [len]CpuFeature = undefined;
        \\
    );

    for (all_features.items) |feature| {
        if (feature.llvm_name) |llvm_name| {
            try w.print(
                \\    result[@enumToInt(Feature.{})] = .{{
                \\        .llvm_name = "{}",
                \\        .description = "{}",
                \\        .dependencies = featureSet(&[_]Feature{{
            ,
                .{
                    std.zig.fmtId(feature.zig_name),
                    std.zig.fmtEscapes(llvm_name),
                    std.zig.fmtEscapes(feature.desc),
                },
            );
        } else {
            try w.print(
                \\    result[@enumToInt(Feature.{})] = .{{
                \\        .llvm_name = null,
                \\        .description = "{}",
                \\        .dependencies = featureSet(&[_]Feature{{
            ,
                .{
                    std.zig.fmtId(feature.zig_name),
                    std.zig.fmtEscapes(feature.desc),
                },
            );
        }
        var deps_set = std.StringHashMap(void).init(arena);
        for (feature.deps) |dep| {
            try putDep(&deps_set, features_table, dep);
        }
        try pruneFeatures(arena, features_table, &deps_set);
        var dependencies = std.ArrayList([]const u8).init(arena);
        {
            var it = deps_set.keyIterator();
            while (it.next()) |key| {
                try dependencies.append(key.*);
            }
        }
        std.sort.sort([]const u8, dependencies.items, {}, asciiLessThan);

        if (dependencies.items.len == 0) {
            try w.writeAll(
                \\}),
                \\    };
                \\
            );
        } else {
            try w.writeAll("\n");
            for (dependencies.items) |dep| {
                try w.print("            .{},\n", .{std.zig.fmtId(dep)});
            }
            try w.writeAll(
                \\        }),
                \\    };
                \\
            );
        }
    }
    try w.writeAll(
        \\    const ti = @typeInfo(Feature);
        \\    for (result) |*elem, i| {
        \\        elem.index = i;
        \\        elem.name = ti.Enum.fields[i].name;
        \\    }
        \\    break :blk result;
        \\};
        \\
        \\pub const cpu = struct {
        \\
    );
    for (all_cpus.items) |cpu| {
        var deps_set = std.StringHashMap(void).init(arena);
        for (cpu.features) |feature_zig_name| {
            try putDep(&deps_set, features_table, feature_zig_name);
        }
        try pruneFeatures(arena, features_table, &deps_set);
        var cpu_features = std.ArrayList([]const u8).init(arena);
        {
            var it = deps_set.keyIterator();
            while (it.next()) |key| {
                try cpu_features.append(key.*);
            }
        }
        std.sort.sort([]const u8, cpu_features.items, {}, asciiLessThan);
        if (cpu.llvm_name) |llvm_name| {
            try w.print(
                \\    pub const {} = CpuModel{{
                \\        .name = "{}",
                \\        .llvm_name = "{}",
                \\        .features = featureSet(&[_]Feature{{
            , .{
                std.zig.fmtId(cpu.zig_name),
                std.zig.fmtEscapes(cpu.zig_name),
                std.zig.fmtEscapes(llvm_name),
            });
        } else {
            try w.print(
                \\    pub const {} = CpuModel{{
                \\        .name = "{}",
                \\        .llvm_name = null,
                \\        .features = featureSet(&[_]Feature{{
            , .{
                std.zig.fmtId(cpu.zig_name),
                std.zig.fmtEscapes(cpu.zig_name),
            });
        }
        if (cpu_features.items.len == 0) {
            try w.writeAll(
                \\}),
                \\    };
                \\
            );
        } else {
            try w.writeAll("\n");
            for (cpu_features.items) |feature_zig_name| {
                try w.print("            .{},\n", .{std.zig.fmtId(feature_zig_name)});
            }
            try w.writeAll(
                \\        }),
                \\    };
                \\
            );
        }
    }

    try w.writeAll(
        \\};
        \\
    );
    try bw.flush();

    render_progress.end();
}

fn usageAndExit(file: fs.File, arg0: []const u8, code: u8) noreturn {
    file.writer().print(
        \\Usage: {s} /path/to/llvm-tblgen /path/git/llvm-project /path/git/zig
        \\
        \\Updates lib/std/target/<target>.zig from llvm/lib/Target/<Target>/<Target>.td .
        \\
        \\On a less beefy system, or when debugging, compile with --single-threaded.
        \\
    , .{arg0}) catch std.process.exit(1);
    std.process.exit(code);
}

fn featureLessThan(context: void, a: Feature, b: Feature) bool {
    _ = context;
    return std.ascii.lessThanIgnoreCase(a.zig_name, b.zig_name);
}

fn cpuLessThan(context: void, a: Cpu, b: Cpu) bool {
    _ = context;
    return std.ascii.lessThanIgnoreCase(a.zig_name, b.zig_name);
}

fn asciiLessThan(context: void, a: []const u8, b: []const u8) bool {
    _ = context;
    return std.ascii.lessThanIgnoreCase(a, b);
}

fn llvmNameToZigName(arena: *mem.Allocator, llvm_name: []const u8) ![]const u8 {
    const duped = try arena.dupe(u8, llvm_name);
    for (duped) |*byte| switch (byte.*) {
        '-', '.' => byte.* = '_',
        else => continue,
    };
    return duped;
}

fn llvmNameToZigNameOmit(
    arena: *mem.Allocator,
    llvm_target: LlvmTarget,
    llvm_name: []const u8,
) !?[]const u8 {
    for (llvm_target.feature_overrides) |feature_override| {
        if (mem.eql(u8, feature_override.llvm_name, llvm_name)) {
            if (feature_override.omit) return null;
            return feature_override.zig_name orelse break;
        }
    }
    return try llvmNameToZigName(arena, llvm_name);
}

fn hasSuperclass(obj: *json.ObjectMap, class_name: []const u8) bool {
    const superclasses_json = obj.get("!superclasses") orelse return false;
    for (superclasses_json.Array.items) |superclass_json| {
        const superclass = superclass_json.String;
        if (std.mem.eql(u8, superclass, class_name)) {
            return true;
        }
    }
    return false;
}

fn pruneFeatures(
    arena: *mem.Allocator,
    features_table: std.StringHashMap(Feature),
    deps_set: *std.StringHashMap(void),
) !void {
    // For each element, recursively iterate over the dependencies and add
    // everything we find to a "deletion set".
    // Then, iterate over the deletion set and delete all that stuff from `deps_set`.
    var deletion_set = std.StringHashMap(void).init(arena);
    {
        var it = deps_set.keyIterator();
        while (it.next()) |key| {
            const feature = features_table.get(key.*).?;
            try walkFeatures(features_table, &deletion_set, feature);
        }
    }
    {
        var it = deletion_set.keyIterator();
        while (it.next()) |key| {
            _ = deps_set.remove(key.*);
        }
    }
}

fn walkFeatures(
    features_table: std.StringHashMap(Feature),
    deletion_set: *std.StringHashMap(void),
    feature: Feature,
) error{OutOfMemory}!void {
    for (feature.deps) |dep| {
        try deletion_set.put(dep, {});
        const other_feature = features_table.get(dep).?;
        try walkFeatures(features_table, deletion_set, other_feature);
    }
}

fn putDep(
    deps_set: *std.StringHashMap(void),
    features_table: std.StringHashMap(Feature),
    zig_feature_name: []const u8,
) error{OutOfMemory}!void {
    const feature = features_table.get(zig_feature_name).?;
    if (feature.flatten) {
        for (feature.deps) |dep| {
            try putDep(deps_set, features_table, dep);
        }
    } else {
        try deps_set.put(zig_feature_name, {});
    }
}
