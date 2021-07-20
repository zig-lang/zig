const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const io = std.io;
const fs = std.fs;
const fmt = std.fmt;
const testing = std.testing;

const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;

const assert = std.debug.assert;

const SparcCpuinfoImpl = struct {
    model: ?*const Target.Cpu.Model = null,
    is_64bit: bool = false,

    const cpu_names = .{
        .{ "SuperSparc", &Target.sparc.cpu.supersparc },
        .{ "HyperSparc", &Target.sparc.cpu.hypersparc },
        .{ "SpitFire", &Target.sparc.cpu.ultrasparc },
        .{ "BlackBird", &Target.sparc.cpu.ultrasparc },
        .{ "Sabre", &Target.sparc.cpu.ultrasparc },
        .{ "Hummingbird", &Target.sparc.cpu.ultrasparc },
        .{ "Cheetah", &Target.sparc.cpu.ultrasparc3 },
        .{ "Jalapeno", &Target.sparc.cpu.ultrasparc3 },
        .{ "Jaguar", &Target.sparc.cpu.ultrasparc3 },
        .{ "Panther", &Target.sparc.cpu.ultrasparc3 },
        .{ "Serrano", &Target.sparc.cpu.ultrasparc3 },
        .{ "UltraSparc T1", &Target.sparc.cpu.niagara },
        .{ "UltraSparc T2", &Target.sparc.cpu.niagara2 },
        .{ "UltraSparc T3", &Target.sparc.cpu.niagara3 },
        .{ "UltraSparc T4", &Target.sparc.cpu.niagara4 },
        .{ "UltraSparc T5", &Target.sparc.cpu.niagara4 },
        .{ "LEON", &Target.sparc.cpu.leon3 },
    };

    fn line_hook(self: *SparcCpuinfoImpl, key: []const u8, value: []const u8) !bool {
        if (mem.eql(u8, key, "cpu")) {
            inline for (cpu_names) |pair| {
                if (mem.indexOfPos(u8, value, 0, pair[0]) != null) {
                    self.model = pair[1];
                    break;
                }
            }
        } else if (mem.eql(u8, key, "type")) {
            self.is_64bit = mem.eql(u8, value, "sun4u") or mem.eql(u8, value, "sun4v");
        }

        return true;
    }

    fn finalize(self: *const SparcCpuinfoImpl, arch: Target.Cpu.Arch) ?Target.Cpu {
        // At the moment we only support 64bit SPARC systems.
        assert(self.is_64bit);

        const model = self.model orelse return null;
        return Target.Cpu{
            .arch = arch,
            .model = model,
            .features = model.features,
        };
    }
};

const SparcCpuinfoParser = CpuinfoParser(SparcCpuinfoImpl);

test "cpuinfo: SPARC" {
    try testParser(SparcCpuinfoParser, .sparcv9, &Target.sparc.cpu.niagara2,
        \\cpu             : UltraSparc T2 (Niagara2)
        \\fpu             : UltraSparc T2 integrated FPU
        \\pmu             : niagara2
        \\type            : sun4v
    );
}

const PowerpcCpuinfoImpl = struct {
    model: ?*const Target.Cpu.Model = null,

    const cpu_names = .{
        .{ "604e", &Target.powerpc.cpu.@"604e" },
        .{ "604", &Target.powerpc.cpu.@"604" },
        .{ "7400", &Target.powerpc.cpu.@"7400" },
        .{ "7410", &Target.powerpc.cpu.@"7400" },
        .{ "7447", &Target.powerpc.cpu.@"7400" },
        .{ "7455", &Target.powerpc.cpu.@"7450" },
        .{ "G4", &Target.powerpc.cpu.@"g4" },
        .{ "POWER4", &Target.powerpc.cpu.@"970" },
        .{ "PPC970FX", &Target.powerpc.cpu.@"970" },
        .{ "PPC970MP", &Target.powerpc.cpu.@"970" },
        .{ "G5", &Target.powerpc.cpu.@"g5" },
        .{ "POWER5", &Target.powerpc.cpu.@"g5" },
        .{ "A2", &Target.powerpc.cpu.@"a2" },
        .{ "POWER6", &Target.powerpc.cpu.@"pwr6" },
        .{ "POWER7", &Target.powerpc.cpu.@"pwr7" },
        .{ "POWER8", &Target.powerpc.cpu.@"pwr8" },
        .{ "POWER8E", &Target.powerpc.cpu.@"pwr8" },
        .{ "POWER8NVL", &Target.powerpc.cpu.@"pwr8" },
        .{ "POWER9", &Target.powerpc.cpu.@"pwr9" },
        .{ "POWER10", &Target.powerpc.cpu.@"pwr10" },
    };

    fn line_hook(self: *PowerpcCpuinfoImpl, key: []const u8, value: []const u8) !bool {
        if (mem.eql(u8, key, "cpu")) {
            // The model name is often followed by a comma or space and extra
            // info.
            inline for (cpu_names) |pair| {
                const end_index = mem.indexOfAny(u8, value, ", ") orelse value.len;
                if (mem.eql(u8, value[0..end_index], pair[0])) {
                    self.model = pair[1];
                    break;
                }
            }

            // Stop the detection once we've seen the first core.
            return false;
        }

        return true;
    }

    fn finalize(self: *const PowerpcCpuinfoImpl, arch: Target.Cpu.Arch) ?Target.Cpu {
        const model = self.model orelse return null;
        return Target.Cpu{
            .arch = arch,
            .model = model,
            .features = model.features,
        };
    }
};

const PowerpcCpuinfoParser = CpuinfoParser(PowerpcCpuinfoImpl);

test "cpuinfo: PowerPC" {
    try testParser(PowerpcCpuinfoParser, .powerpc, &Target.powerpc.cpu.@"970",
        \\processor	: 0
        \\cpu		: PPC970MP, altivec supported
        \\clock		: 1250.000000MHz
        \\revision	: 1.1 (pvr 0044 0101)
    );
    try testParser(PowerpcCpuinfoParser, .powerpc64le, &Target.powerpc.cpu.pwr8,
        \\processor	: 0
        \\cpu		: POWER8 (raw), altivec supported
        \\clock		: 2926.000000MHz
        \\revision	: 2.0 (pvr 004d 0200)
    );
}

const ArmCpuinfoImpl = struct {
    cores: [4]CoreInfo = undefined,
    core_no: usize = 0,
    have_fields: usize = 0,

    const CoreInfo = struct {
        architecture: u8 = 0,
        implementer: u8 = 0,
        variant: u8 = 0,
        part: u16 = 0,
        is_really_v6: bool = false,
    };

    const cpu_models = struct {
        // Shorthands to simplify the tables below.
        const A32 = Target.arm.cpu;
        const A64 = Target.aarch64.cpu;

        const E = struct {
            part: u16,
            variant: ?u8 = null, // null if matches any variant
            m32: ?*const Target.Cpu.Model = null,
            m64: ?*const Target.Cpu.Model = null,
        };

        // implementer = 0x41
        const ARM = [_]E{
            E{ .part = 0x926, .m32 = &A32.arm926ej_s, .m64 = null },
            E{ .part = 0xb02, .m32 = &A32.mpcore, .m64 = null },
            E{ .part = 0xb36, .m32 = &A32.arm1136j_s, .m64 = null },
            E{ .part = 0xb56, .m32 = &A32.arm1156t2_s, .m64 = null },
            E{ .part = 0xb76, .m32 = &A32.arm1176jz_s, .m64 = null },
            E{ .part = 0xc05, .m32 = &A32.cortex_a5, .m64 = null },
            E{ .part = 0xc07, .m32 = &A32.cortex_a7, .m64 = null },
            E{ .part = 0xc08, .m32 = &A32.cortex_a8, .m64 = null },
            E{ .part = 0xc09, .m32 = &A32.cortex_a9, .m64 = null },
            E{ .part = 0xc0d, .m32 = &A32.cortex_a17, .m64 = null },
            E{ .part = 0xc0f, .m32 = &A32.cortex_a15, .m64 = null },
            E{ .part = 0xc0e, .m32 = &A32.cortex_a17, .m64 = null },
            E{ .part = 0xc14, .m32 = &A32.cortex_r4, .m64 = null },
            E{ .part = 0xc15, .m32 = &A32.cortex_r5, .m64 = null },
            E{ .part = 0xc17, .m32 = &A32.cortex_r7, .m64 = null },
            E{ .part = 0xc18, .m32 = &A32.cortex_r8, .m64 = null },
            E{ .part = 0xc20, .m32 = &A32.cortex_m0, .m64 = null },
            E{ .part = 0xc21, .m32 = &A32.cortex_m1, .m64 = null },
            E{ .part = 0xc23, .m32 = &A32.cortex_m3, .m64 = null },
            E{ .part = 0xc24, .m32 = &A32.cortex_m4, .m64 = null },
            E{ .part = 0xc27, .m32 = &A32.cortex_m7, .m64 = null },
            E{ .part = 0xc60, .m32 = &A32.cortex_m0plus, .m64 = null },
            E{ .part = 0xd01, .m32 = &A32.cortex_a32, .m64 = null },
            E{ .part = 0xd03, .m32 = &A32.cortex_a53, .m64 = &A64.cortex_a53 },
            E{ .part = 0xd04, .m32 = &A32.cortex_a35, .m64 = &A64.cortex_a35 },
            E{ .part = 0xd05, .m32 = &A32.cortex_a55, .m64 = &A64.cortex_a55 },
            E{ .part = 0xd07, .m32 = &A32.cortex_a57, .m64 = &A64.cortex_a57 },
            E{ .part = 0xd08, .m32 = &A32.cortex_a72, .m64 = &A64.cortex_a72 },
            E{ .part = 0xd09, .m32 = &A32.cortex_a73, .m64 = &A64.cortex_a73 },
            E{ .part = 0xd0a, .m32 = &A32.cortex_a75, .m64 = &A64.cortex_a75 },
            E{ .part = 0xd0b, .m32 = &A32.cortex_a76, .m64 = &A64.cortex_a76 },
            E{ .part = 0xd0c, .m32 = &A32.neoverse_n1, .m64 = null },
            E{ .part = 0xd0d, .m32 = &A32.cortex_a77, .m64 = &A64.cortex_a77 },
            E{ .part = 0xd13, .m32 = &A32.cortex_r52, .m64 = null },
            E{ .part = 0xd20, .m32 = &A32.cortex_m23, .m64 = null },
            E{ .part = 0xd21, .m32 = &A32.cortex_m33, .m64 = null },
            E{ .part = 0xd41, .m32 = &A32.cortex_a78, .m64 = &A64.cortex_a78 },
            E{ .part = 0xd4b, .m32 = &A32.cortex_a78c, .m64 = &A64.cortex_a78c },
            E{ .part = 0xd44, .m32 = &A32.cortex_x1, .m64 = &A64.cortex_x1 },
            E{ .part = 0xd02, .m64 = &A64.cortex_a34 },
            E{ .part = 0xd06, .m64 = &A64.cortex_a65 },
            E{ .part = 0xd43, .m64 = &A64.cortex_a65ae },
        };
        // implementer = 0x42
        const Broadcom = [_]E{
            E{ .part = 0x516, .m64 = &A64.thunderx2t99 },
        };
        // implementer = 0x43
        const Cavium = [_]E{
            E{ .part = 0x0a0, .m64 = &A64.thunderx },
            E{ .part = 0x0a2, .m64 = &A64.thunderxt81 },
            E{ .part = 0x0a3, .m64 = &A64.thunderxt83 },
            E{ .part = 0x0a1, .m64 = &A64.thunderxt88 },
            E{ .part = 0x0af, .m64 = &A64.thunderx2t99 },
        };
        // implementer = 0x46
        const Fujitsu = [_]E{
            E{ .part = 0x001, .m64 = &A64.a64fx },
        };
        // implementer = 0x48
        const HiSilicon = [_]E{
            E{ .part = 0xd01, .m64 = &A64.tsv110 },
        };
        // implementer = 0x4e
        const Nvidia = [_]E{
            E{ .part = 0x004, .m64 = &A64.carmel },
        };
        // implementer = 0x50
        const Ampere = [_]E{
            E{ .part = 0x000, .variant = 3, .m64 = &A64.emag },
            E{ .part = 0x000, .m64 = &A64.xgene1 },
        };
        // implementer = 0x51
        const Qualcomm = [_]E{
            E{ .part = 0x06f, .m32 = &A32.krait },
            E{ .part = 0x201, .m64 = &A64.kryo, .m32 = &A64.kryo },
            E{ .part = 0x205, .m64 = &A64.kryo, .m32 = &A64.kryo },
            E{ .part = 0x211, .m64 = &A64.kryo, .m32 = &A64.kryo },
            E{ .part = 0x800, .m64 = &A64.cortex_a73, .m32 = &A64.cortex_a73 },
            E{ .part = 0x801, .m64 = &A64.cortex_a73, .m32 = &A64.cortex_a73 },
            E{ .part = 0x802, .m64 = &A64.cortex_a75, .m32 = &A64.cortex_a75 },
            E{ .part = 0x803, .m64 = &A64.cortex_a75, .m32 = &A64.cortex_a75 },
            E{ .part = 0x804, .m64 = &A64.cortex_a76, .m32 = &A64.cortex_a76 },
            E{ .part = 0x805, .m64 = &A64.cortex_a76, .m32 = &A64.cortex_a76 },
            E{ .part = 0xc00, .m64 = &A64.falkor },
            E{ .part = 0xc01, .m64 = &A64.saphira },
        };

        fn isKnown(core: CoreInfo, is_64bit: bool) ?*const Target.Cpu.Model {
            const models = switch (core.implementer) {
                0x41 => &ARM,
                0x42 => &Broadcom,
                0x43 => &Cavium,
                0x46 => &Fujitsu,
                0x48 => &HiSilicon,
                0x50 => &Ampere,
                0x51 => &Qualcomm,
                else => return null,
            };

            for (models) |model| {
                if (model.part == core.part and
                    (model.variant == null or model.variant.? == core.variant))
                    return if (is_64bit) model.m64 else model.m32;
            }

            return null;
        }
    };

    fn addOne(self: *ArmCpuinfoImpl) void {
        if (self.have_fields == 4 and self.core_no < self.cores.len) {
            if (self.core_no > 0) {
                // Deduplicate the core info.
                for (self.cores[0..self.core_no]) |it| {
                    if (std.meta.eql(it, self.cores[self.core_no]))
                        return;
                }
            }
            self.core_no += 1;
        }
    }

    fn line_hook(self: *ArmCpuinfoImpl, key: []const u8, value: []const u8) !bool {
        const info = &self.cores[self.core_no];

        if (mem.eql(u8, key, "processor")) {
            // Handle both old-style and new-style cpuinfo formats.
            // The former prints a sequence of "processor: N" lines for each
            // core and then the info for the core that's executing this code(!)
            // while the latter prints the infos for each core right after the
            // "processor" key.
            self.have_fields = 0;
            self.cores[self.core_no] = .{};
        } else if (mem.eql(u8, key, "CPU implementer")) {
            info.implementer = try fmt.parseInt(u8, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "CPU architecture")) {
            // "AArch64" on older kernels.
            info.architecture = if (mem.startsWith(u8, value, "AArch64"))
                8
            else
                try fmt.parseInt(u8, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "CPU variant")) {
            info.variant = try fmt.parseInt(u8, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "CPU part")) {
            info.part = try fmt.parseInt(u16, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "model name")) {
            // ARMv6 cores report "CPU architecture" equal to 7.
            if (mem.indexOf(u8, value, "(v6l)")) |_| {
                info.is_really_v6 = true;
            }
        } else if (mem.eql(u8, key, "CPU revision")) {
            // This field is always the last one for each CPU section.
            _ = self.addOne();
        }

        return true;
    }

    fn finalize(self: *ArmCpuinfoImpl, arch: Target.Cpu.Arch) ?Target.Cpu {
        if (self.core_no == 0) return null;

        const is_64bit = switch (arch) {
            .aarch64, .aarch64_be, .aarch64_32 => true,
            else => false,
        };

        var known_models: [self.cores.len]?*const Target.Cpu.Model = undefined;
        for (self.cores[0..self.core_no]) |core, i| {
            known_models[i] = cpu_models.isKnown(core, is_64bit);
        }

        // XXX We pick the first core on big.LITTLE systems, hopefully the
        // LITTLE one.
        const model = known_models[0] orelse return null;
        return Target.Cpu{
            .arch = arch,
            .model = model,
            .features = model.features,
        };
    }
};

const ArmCpuinfoParser = CpuinfoParser(ArmCpuinfoImpl);

test "cpuinfo: ARM" {
    try testParser(ArmCpuinfoParser, .arm, &Target.arm.cpu.arm1176jz_s,
        \\processor       : 0
        \\model name      : ARMv6-compatible processor rev 7 (v6l)
        \\BogoMIPS        : 997.08
        \\Features        : half thumb fastmult vfp edsp java tls
        \\CPU implementer : 0x41
        \\CPU architecture: 7
        \\CPU variant     : 0x0
        \\CPU part        : 0xb76
        \\CPU revision    : 7
    );
    try testParser(ArmCpuinfoParser, .arm, &Target.arm.cpu.cortex_a7,
        \\processor	: 0
        \\model name	: ARMv7 Processor rev 3 (v7l)
        \\BogoMIPS	: 18.00
        \\Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae
        \\CPU implementer	: 0x41
        \\CPU architecture: 7
        \\CPU variant	: 0x0
        \\CPU part	: 0xc07
        \\CPU revision	: 3
        \\
        \\processor	: 4
        \\model name	: ARMv7 Processor rev 3 (v7l)
        \\BogoMIPS	: 90.00
        \\Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae
        \\CPU implementer	: 0x41
        \\CPU architecture: 7
        \\CPU variant	: 0x2
        \\CPU part	: 0xc0f
        \\CPU revision	: 3
    );
    try testParser(ArmCpuinfoParser, .aarch64, &Target.aarch64.cpu.cortex_a72,
        \\processor       : 0
        \\BogoMIPS        : 108.00
        \\Features        : fp asimd evtstrm crc32 cpuid
        \\CPU implementer : 0x41
        \\CPU architecture: 8
        \\CPU variant     : 0x0
        \\CPU part        : 0xd08
        \\CPU revision    : 3
    );
}

fn testParser(
    parser: anytype,
    arch: Target.Cpu.Arch,
    expected_model: *const Target.Cpu.Model,
    input: []const u8,
) !void {
    var fbs = io.fixedBufferStream(input);
    const result = try parser.parse(arch, fbs.reader());
    try testing.expectEqual(expected_model, result.?.model);
    try testing.expect(expected_model.features.eql(result.?.features));
}

// The generic implementation of a /proc/cpuinfo parser.
// For every line it invokes the line_hook method with the key and value strings
// as first and second parameters. Returning false from the hook function stops
// the iteration without raising an error.
// When all the lines have been analyzed the finalize method is called.
fn CpuinfoParser(comptime impl: anytype) type {
    return struct {
        fn parse(arch: Target.Cpu.Arch, reader: anytype) anyerror!?Target.Cpu {
            var line_buf: [1024]u8 = undefined;
            var obj: impl = .{};

            while (true) {
                const line = (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) orelse break;
                const colon_pos = mem.indexOfScalar(u8, line, ':') orelse continue;
                const key = mem.trimRight(u8, line[0..colon_pos], " \t");
                const value = mem.trimLeft(u8, line[colon_pos + 1 ..], " \t");

                if (!try obj.line_hook(key, value))
                    break;
            }

            return obj.finalize(arch);
        }
    };
}

pub fn detectNativeCpuAndFeatures() ?Target.Cpu {
    var f = fs.openFileAbsolute("/proc/cpuinfo", .{ .intended_io_mode = .blocking }) catch |err| switch (err) {
        else => return null,
    };
    defer f.close();

    const current_arch = builtin.cpu.arch;
    switch (current_arch) {
        .arm, .armeb, .thumb, .thumbeb, .aarch64, .aarch64_be, .aarch64_32 => {
            return ArmCpuinfoParser.parse(current_arch, f.reader()) catch null;
        },
        .sparcv9 => {
            return SparcCpuinfoParser.parse(current_arch, f.reader()) catch null;
        },
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => {
            return PowerpcCpuinfoParser.parse(current_arch, f.reader()) catch null;
        },
        else => {},
    }

    return null;
}
