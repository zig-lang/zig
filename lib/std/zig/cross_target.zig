// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Target = std.Target;
const mem = std.mem;

/// Contains all the same data as `Target`, additionally introducing the concept of "the native target".
/// The purpose of this abstraction is to provide meaningful and unsurprising defaults.
/// This struct does reference any resources and it is copyable.
pub const CrossTarget = struct {
    /// `null` means native.
    cpu_arch: ?Target.Cpu.Arch = null,

    cpu_model: CpuModel = CpuModel.determined_by_cpu_arch,

    /// Sparse set of CPU features to add to the set from `cpu_model`.
    cpu_features_add: Target.Cpu.Feature.Set = Target.Cpu.Feature.Set.empty,

    /// Sparse set of CPU features to remove from the set from `cpu_model`.
    cpu_features_sub: Target.Cpu.Feature.Set = Target.Cpu.Feature.Set.empty,

    /// `null` means native.
    os_tag: ?Target.Os.Tag = null,

    /// `null` means the default version range for `os_tag`. If `os_tag` is `null` (native)
    /// then `null` for this field means native.
    os_version_min: ?OsVersion = null,

    /// When cross compiling, `null` means default (latest known OS version).
    /// When `os_tag` is native, `null` means equal to the native OS version.
    os_version_max: ?OsVersion = null,

    /// `null` means default when cross compiling, or native when os_tag is native.
    /// If `isGnuLibC()` is `false`, this must be `null` and is ignored.
    glibc_version: ?SemVer = null,

    /// `null` means the native C ABI, if `os_tag` is native, otherwise it means the default C ABI.
    abi: ?Target.Abi = null,

    /// When `os_tag` is `null`, then `null` means native. Otherwise it means the standard path
    /// based on the `os_tag`.
    dynamic_linker: DynamicLinker = DynamicLinker{},

    pub const CpuModel = union(enum) {
        /// Always native
        native,

        /// Always baseline
        baseline,

        /// If CPU Architecture is native, then the CPU model will be native. Otherwise,
        /// it will be baseline.
        determined_by_cpu_arch,

        explicit: *const Target.Cpu.Model,
    };

    pub const OsVersion = union(enum) {
        none: void,
        semver: SemVer,
        windows: Target.Os.WindowsVersion,
    };

    pub const SemVer = std.builtin.Version;

    pub const DynamicLinker = Target.DynamicLinker;

    pub fn fromTarget(target: Target) CrossTarget {
        var result: CrossTarget = .{
            .cpu_arch = target.cpu.arch,
            .cpu_model = .{ .explicit = target.cpu.model },
            .os_tag = target.os.tag,
            .os_version_min = undefined,
            .os_version_max = undefined,
            .abi = target.abi,
            .glibc_version = if (target.isGnuLibC())
                target.os.version_range.linux.glibc
            else
                null,
        };
        result.updateOsVersionRange(target.os);

        const all_features = target.cpu.arch.allFeaturesList();
        var cpu_model_set = target.cpu.model.features;
        cpu_model_set.populateDependencies(all_features);
        {
            // The "add" set is the full set with the CPU Model set removed.
            const add_set = &result.cpu_features_add;
            add_set.* = target.cpu.features;
            add_set.removeFeatureSet(cpu_model_set);
        }
        {
            // The "sub" set is the features that are on in CPU Model set and off in the full set.
            const sub_set = &result.cpu_features_sub;
            sub_set.* = cpu_model_set;
            sub_set.removeFeatureSet(target.cpu.features);
        }
        return result;
    }

    fn updateOsVersionRange(self: *CrossTarget, os: Target.Os) void {
        switch (os.tag) {
            .freestanding,
            .ananas,
            .cloudabi,
            .fuchsia,
            .kfreebsd,
            .lv2,
            .solaris,
            .zos,
            .haiku,
            .minix,
            .rtems,
            .nacl,
            .aix,
            .cuda,
            .nvcl,
            .amdhsa,
            .ps4,
            .elfiamcu,
            .mesa3d,
            .contiki,
            .amdpal,
            .hermit,
            .hurd,
            .wasi,
            .emscripten,
            .uefi,
            .opencl,
            .glsl450,
            .vulkan,
            .plan9,
            .other,
            => {
                self.os_version_min = .{ .none = {} };
                self.os_version_max = .{ .none = {} };
            },

            .freebsd,
            .macos,
            .ios,
            .tvos,
            .watchos,
            .netbsd,
            .openbsd,
            .dragonfly,
            => {
                self.os_version_min = .{ .semver = os.version_range.semver.min };
                self.os_version_max = .{ .semver = os.version_range.semver.max };
            },

            .linux => {
                self.os_version_min = .{ .semver = os.version_range.linux.range.min };
                self.os_version_max = .{ .semver = os.version_range.linux.range.max };
            },

            .windows => {
                self.os_version_min = .{ .windows = os.version_range.windows.min };
                self.os_version_max = .{ .windows = os.version_range.windows.max };
            },
        }
    }

    /// TODO deprecated, use `std.zig.system.NativeTargetInfo.detect`.
    pub fn toTarget(self: CrossTarget) Target {
        return .{
            .cpu = self.getCpu(),
            .os = self.getOs(),
            .abi = self.getAbi(),
        };
    }

    pub const ParseOptions = struct {
        /// This is sometimes called a "triple". It looks roughly like this:
        ///     riscv64-linux-musl
        /// The fields are, respectively:
        /// * CPU Architecture
        /// * Operating System (and optional version range)
        /// * C ABI (optional, with optional glibc version)
        /// The string "native" can be used for CPU architecture as well as Operating System.
        /// If the CPU Architecture is specified as "native", then the Operating System and C ABI may be omitted.
        arch_os_abi: []const u8 = "native",

        /// Looks like "name+a+b-c-d+e", where "name" is a CPU Model name, "a", "b", and "e"
        /// are examples of CPU features to add to the set, and "c" and "d" are examples of CPU features
        /// to remove from the set.
        /// The following special strings are recognized for CPU Model name:
        /// * "baseline" - The "default" set of CPU features for cross-compiling. A conservative set
        ///                of features that is expected to be supported on most available hardware.
        /// * "native"   - The native CPU model is to be detected when compiling.
        /// If this field is not provided (`null`), then the value will depend on the
        /// parsed CPU Architecture. If native, then this will be "native". Otherwise, it will be "baseline".
        cpu_features: ?[]const u8 = null,

        /// Absolute path to dynamic linker, to override the default, which is either a natively
        /// detected path, or a standard path.
        dynamic_linker: ?[]const u8 = null,

        /// If this is provided, the function will populate some information about parsing failures,
        /// so that user-friendly error messages can be delivered.
        diagnostics: ?*Diagnostics = null,

        pub const Diagnostics = struct {
            /// If the architecture was determined, this will be populated.
            arch: ?Target.Cpu.Arch = null,

            /// If the OS name was determined, this will be populated.
            os_name: ?[]const u8 = null,

            /// If the OS tag was determined, this will be populated.
            os_tag: ?Target.Os.Tag = null,

            /// If the ABI was determined, this will be populated.
            abi: ?Target.Abi = null,

            /// If the CPU name was determined, this will be populated.
            cpu_name: ?[]const u8 = null,

            /// If error.UnknownCpuFeature is returned, this will be populated.
            unknown_feature_name: ?[]const u8 = null,
        };
    };

    pub fn parse(args: ParseOptions) !CrossTarget {
        var dummy_diags: ParseOptions.Diagnostics = undefined;
        const diags = args.diagnostics orelse &dummy_diags;

        var result: CrossTarget = .{
            .dynamic_linker = DynamicLinker.init(args.dynamic_linker),
        };

        var it = mem.split(args.arch_os_abi, "-");
        const arch_name = it.next().?;
        const arch_is_native = mem.eql(u8, arch_name, "native");
        if (!arch_is_native) {
            result.cpu_arch = std.meta.stringToEnum(Target.Cpu.Arch, arch_name) orelse
                return error.UnknownArchitecture;
        }
        const arch = result.getCpuArch();
        diags.arch = arch;

        if (it.next()) |os_text| {
            try parseOs(&result, diags, os_text);
        } else if (!arch_is_native) {
            return error.MissingOperatingSystem;
        }

        const opt_abi_text = it.next();
        if (opt_abi_text) |abi_text| {
            var abi_it = mem.split(abi_text, ".");
            const abi = std.meta.stringToEnum(Target.Abi, abi_it.next().?) orelse
                return error.UnknownApplicationBinaryInterface;
            result.abi = abi;
            diags.abi = abi;

            const abi_ver_text = abi_it.rest();
            if (abi_it.next() != null) {
                if (result.isGnuLibC()) {
                    result.glibc_version = SemVer.parse(abi_ver_text) catch |err| switch (err) {
                        error.Overflow => return error.InvalidAbiVersion,
                        error.InvalidCharacter => return error.InvalidAbiVersion,
                        error.InvalidVersion => return error.InvalidAbiVersion,
                    };
                } else {
                    return error.InvalidAbiVersion;
                }
            }
        }

        if (it.next() != null) return error.UnexpectedExtraField;

        if (args.cpu_features) |cpu_features| {
            const all_features = arch.allFeaturesList();
            var index: usize = 0;
            while (index < cpu_features.len and
                cpu_features[index] != '+' and
                cpu_features[index] != '-')
            {
                index += 1;
            }
            const cpu_name = cpu_features[0..index];
            diags.cpu_name = cpu_name;

            const add_set = &result.cpu_features_add;
            const sub_set = &result.cpu_features_sub;
            if (mem.eql(u8, cpu_name, "native")) {
                result.cpu_model = .native;
            } else if (mem.eql(u8, cpu_name, "baseline")) {
                result.cpu_model = .baseline;
            } else {
                result.cpu_model = .{ .explicit = try arch.parseCpuModel(cpu_name) };
            }

            while (index < cpu_features.len) {
                const op = cpu_features[index];
                const set = switch (op) {
                    '+' => add_set,
                    '-' => sub_set,
                    else => unreachable,
                };
                index += 1;
                const start = index;
                while (index < cpu_features.len and
                    cpu_features[index] != '+' and
                    cpu_features[index] != '-')
                {
                    index += 1;
                }
                const feature_name = cpu_features[start..index];
                for (all_features) |feature, feat_index_usize| {
                    const feat_index = @intCast(Target.Cpu.Feature.Set.Index, feat_index_usize);
                    if (mem.eql(u8, feature_name, feature.name)) {
                        set.addFeature(feat_index);
                        break;
                    }
                } else {
                    diags.unknown_feature_name = feature_name;
                    return error.UnknownCpuFeature;
                }
            }
        }

        return result;
    }

    /// TODO deprecated, use `std.zig.system.NativeTargetInfo.detect`.
    pub fn getCpu(self: CrossTarget) Target.Cpu {
        switch (self.cpu_model) {
            .native => {
                // This works when doing `zig build` because Zig generates a build executable using
                // native CPU model & features. However this will not be accurate otherwise, and
                // will need to be integrated with `std.zig.system.NativeTargetInfo.detect`.
                return builtin.cpu;
            },
            .baseline => {
                var adjusted_baseline = Target.Cpu.baseline(self.getCpuArch());
                self.updateCpuFeatures(&adjusted_baseline.features);
                return adjusted_baseline;
            },
            .determined_by_cpu_arch => if (self.cpu_arch == null) {
                // This works when doing `zig build` because Zig generates a build executable using
                // native CPU model & features. However this will not be accurate otherwise, and
                // will need to be integrated with `std.zig.system.NativeTargetInfo.detect`.
                return builtin.cpu;
            } else {
                var adjusted_baseline = Target.Cpu.baseline(self.getCpuArch());
                self.updateCpuFeatures(&adjusted_baseline.features);
                return adjusted_baseline;
            },
            .explicit => |model| {
                var adjusted_model = model.toCpu(self.getCpuArch());
                self.updateCpuFeatures(&adjusted_model.features);
                return adjusted_model;
            },
        }
    }

    pub fn getCpuArch(self: CrossTarget) Target.Cpu.Arch {
        return self.cpu_arch orelse builtin.cpu.arch;
    }

    pub fn getCpuModel(self: CrossTarget) *const Target.Cpu.Model {
        return switch (self.cpu_model) {
            .explicit => |cpu_model| cpu_model,
            else => self.getCpu().model,
        };
    }

    pub fn getCpuFeatures(self: CrossTarget) Target.Cpu.Feature.Set {
        return self.getCpu().features;
    }

    /// TODO deprecated, use `std.zig.system.NativeTargetInfo.detect`.
    pub fn getOs(self: CrossTarget) Target.Os {
        // `builtin.os` works when doing `zig build` because Zig generates a build executable using
        // native OS version range. However this will not be accurate otherwise, and
        // will need to be integrated with `std.zig.system.NativeTargetInfo.detect`.
        var adjusted_os = if (self.os_tag) |os_tag| os_tag.defaultVersionRange() else builtin.os;

        if (self.os_version_min) |min| switch (min) {
            .none => {},
            .semver => |semver| switch (self.getOsTag()) {
                .linux => adjusted_os.version_range.linux.range.min = semver,
                else => adjusted_os.version_range.semver.min = semver,
            },
            .windows => |win_ver| adjusted_os.version_range.windows.min = win_ver,
        };

        if (self.os_version_max) |max| switch (max) {
            .none => {},
            .semver => |semver| switch (self.getOsTag()) {
                .linux => adjusted_os.version_range.linux.range.max = semver,
                else => adjusted_os.version_range.semver.max = semver,
            },
            .windows => |win_ver| adjusted_os.version_range.windows.max = win_ver,
        };

        if (self.glibc_version) |glibc| {
            assert(self.isGnuLibC());
            adjusted_os.version_range.linux.glibc = glibc;
        }

        return adjusted_os;
    }

    pub fn getOsTag(self: CrossTarget) Target.Os.Tag {
        return self.os_tag orelse builtin.os.tag;
    }

    /// TODO deprecated, use `std.zig.system.NativeTargetInfo.detect`.
    pub fn getOsVersionMin(self: CrossTarget) OsVersion {
        if (self.os_version_min) |version_min| return version_min;
        var tmp: CrossTarget = undefined;
        tmp.updateOsVersionRange(self.getOs());
        return tmp.os_version_min.?;
    }

    /// TODO deprecated, use `std.zig.system.NativeTargetInfo.detect`.
    pub fn getOsVersionMax(self: CrossTarget) OsVersion {
        if (self.os_version_max) |version_max| return version_max;
        var tmp: CrossTarget = undefined;
        tmp.updateOsVersionRange(self.getOs());
        return tmp.os_version_max.?;
    }

    /// TODO deprecated, use `std.zig.system.NativeTargetInfo.detect`.
    pub fn getAbi(self: CrossTarget) Target.Abi {
        if (self.abi) |abi| return abi;

        if (self.os_tag == null) {
            // This works when doing `zig build` because Zig generates a build executable using
            // native CPU model & features. However this will not be accurate otherwise, and
            // will need to be integrated with `std.zig.system.NativeTargetInfo.detect`.
            return builtin.abi;
        }

        return Target.Abi.default(self.getCpuArch(), self.getOs());
    }

    pub fn isFreeBSD(self: CrossTarget) bool {
        return self.getOsTag() == .freebsd;
    }

    pub fn isDarwin(self: CrossTarget) bool {
        return self.getOsTag().isDarwin();
    }

    pub fn isNetBSD(self: CrossTarget) bool {
        return self.getOsTag() == .netbsd;
    }

    pub fn isOpenBSD(self: CrossTarget) bool {
        return self.getOsTag() == .openbsd;
    }

    pub fn isUefi(self: CrossTarget) bool {
        return self.getOsTag() == .uefi;
    }

    pub fn isDragonFlyBSD(self: CrossTarget) bool {
        return self.getOsTag() == .dragonfly;
    }

    pub fn isLinux(self: CrossTarget) bool {
        return self.getOsTag() == .linux;
    }

    pub fn isWindows(self: CrossTarget) bool {
        return self.getOsTag() == .windows;
    }

    pub fn oFileExt(self: CrossTarget) [:0]const u8 {
        return Target.oFileExt_os_abi(self.getOsTag(), self.getAbi());
    }

    pub fn exeFileExt(self: CrossTarget) [:0]const u8 {
        return Target.exeFileExtSimple(self.getCpuArch(), self.getOsTag());
    }

    pub fn staticLibSuffix(self: CrossTarget) [:0]const u8 {
        return Target.staticLibSuffix_os_abi(self.getOsTag(), self.getAbi());
    }

    pub fn dynamicLibSuffix(self: CrossTarget) [:0]const u8 {
        return self.getOsTag().dynamicLibSuffix();
    }

    pub fn libPrefix(self: CrossTarget) [:0]const u8 {
        return Target.libPrefix_os_abi(self.getOsTag(), self.getAbi());
    }

    pub fn isNativeCpu(self: CrossTarget) bool {
        return self.cpu_arch == null and
            (self.cpu_model == .native or self.cpu_model == .determined_by_cpu_arch) and
            self.cpu_features_sub.isEmpty() and self.cpu_features_add.isEmpty();
    }

    pub fn isNativeOs(self: CrossTarget) bool {
        return self.os_tag == null and self.os_version_min == null and self.os_version_max == null and
            self.dynamic_linker.get() == null and self.glibc_version == null;
    }

    pub fn isNativeAbi(self: CrossTarget) bool {
        return self.os_tag == null and self.abi == null;
    }

    pub fn isNative(self: CrossTarget) bool {
        return self.isNativeCpu() and self.isNativeOs() and self.isNativeAbi();
    }

    pub fn zigTriple(self: CrossTarget, allocator: *mem.Allocator) error{OutOfMemory}![]u8 {
        if (self.isNative()) {
            return allocator.dupe(u8, "native");
        }

        const arch_name = if (self.cpu_arch) |arch| @tagName(arch) else "native";
        const os_name = if (self.os_tag) |os_tag| @tagName(os_tag) else "native";

        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();

        try result.writer().print("{s}-{s}", .{ arch_name, os_name });

        // The zig target syntax does not allow specifying a max os version with no min, so
        // if either are present, we need the min.
        if (self.os_version_min != null or self.os_version_max != null) {
            switch (self.getOsVersionMin()) {
                .none => {},
                .semver => |v| try result.writer().print(".{}", .{v}),
                .windows => |v| try result.writer().print("{s}", .{v}),
            }
        }
        if (self.os_version_max) |max| {
            switch (max) {
                .none => {},
                .semver => |v| try result.writer().print("...{}", .{v}),
                .windows => |v| try result.writer().print("..{s}", .{v}),
            }
        }

        if (self.glibc_version) |v| {
            try result.writer().print("-{s}.{}", .{ @tagName(self.getAbi()), v });
        } else if (self.abi) |abi| {
            try result.writer().print("-{s}", .{@tagName(abi)});
        }

        return result.toOwnedSlice();
    }

    pub fn allocDescription(self: CrossTarget, allocator: *mem.Allocator) ![]u8 {
        // TODO is there anything else worthy of the description that is not
        // already captured in the triple?
        return self.zigTriple(allocator);
    }

    pub fn linuxTriple(self: CrossTarget, allocator: *mem.Allocator) ![]u8 {
        return Target.linuxTripleSimple(allocator, self.getCpuArch(), self.getOsTag(), self.getAbi());
    }

    pub fn wantSharedLibSymLinks(self: CrossTarget) bool {
        return self.getOsTag() != .windows;
    }

    pub const VcpkgLinkage = std.builtin.LinkMode;

    /// Returned slice must be freed by the caller.
    pub fn vcpkgTriplet(self: CrossTarget, allocator: *mem.Allocator, linkage: VcpkgLinkage) ![]u8 {
        const arch = switch (self.getCpuArch()) {
            .i386 => "x86",
            .x86_64 => "x64",

            .arm,
            .armeb,
            .thumb,
            .thumbeb,
            .aarch64_32,
            => "arm",

            .aarch64,
            .aarch64_be,
            => "arm64",

            else => return error.UnsupportedVcpkgArchitecture,
        };

        const os = switch (self.getOsTag()) {
            .windows => "windows",
            .linux => "linux",
            .macos => "macos",
            else => return error.UnsupportedVcpkgOperatingSystem,
        };

        const static_suffix = switch (linkage) {
            .Static => "-static",
            .Dynamic => "",
        };

        return std.fmt.allocPrint(allocator, "{s}-{s}{s}", .{ arch, os, static_suffix });
    }

    pub const Executor = union(enum) {
        native,
        qemu: []const u8,
        wine: []const u8,
        wasmtime: []const u8,
        darling: []const u8,
        unavailable,
    };

    /// Note that even a `CrossTarget` which returns `false` for `isNative` could still be natively executed.
    /// For example `-target arm-native` running on an aarch64 host.
    pub fn getExternalExecutor(self: CrossTarget) Executor {
        const cpu_arch = self.getCpuArch();
        const os_tag = self.getOsTag();
        const os_match = os_tag == builtin.os.tag;

        // If the OS and CPU arch match, the binary can be considered native.
        // TODO additionally match the CPU features. This `getExternalExecutor` function should
        // be moved to std.Target and match any chosen target against the native target.
        if (os_match and cpu_arch == builtin.cpu.arch) {
            // However, we also need to verify that the dynamic linker path is valid.
            if (self.os_tag == null) {
                return .native;
            }
            // TODO here we call toTarget, a deprecated function, because of the above TODO about moving
            // this code to std.Target.
            const opt_dl = self.dynamic_linker.get() orelse self.toTarget().standardDynamicLinkerPath().get();
            if (opt_dl) |dl| blk: {
                std.fs.cwd().access(dl, .{}) catch break :blk;
                return .native;
            }
        }

        // If the OS matches, we can use QEMU to emulate a foreign architecture.
        if (os_match) {
            return switch (cpu_arch) {
                .aarch64 => Executor{ .qemu = "qemu-aarch64" },
                .aarch64_be => Executor{ .qemu = "qemu-aarch64_be" },
                .arm => Executor{ .qemu = "qemu-arm" },
                .armeb => Executor{ .qemu = "qemu-armeb" },
                .i386 => Executor{ .qemu = "qemu-i386" },
                .mips => Executor{ .qemu = "qemu-mips" },
                .mipsel => Executor{ .qemu = "qemu-mipsel" },
                .mips64 => Executor{ .qemu = "qemu-mips64" },
                .mips64el => Executor{ .qemu = "qemu-mips64el" },
                .powerpc => Executor{ .qemu = "qemu-ppc" },
                .powerpc64 => Executor{ .qemu = "qemu-ppc64" },
                .powerpc64le => Executor{ .qemu = "qemu-ppc64le" },
                .riscv32 => Executor{ .qemu = "qemu-riscv32" },
                .riscv64 => Executor{ .qemu = "qemu-riscv64" },
                .s390x => Executor{ .qemu = "qemu-s390x" },
                .sparc => Executor{ .qemu = "qemu-sparc" },
                .x86_64 => Executor{ .qemu = "qemu-x86_64" },
                else => return .unavailable,
            };
        }

        switch (os_tag) {
            .windows => switch (cpu_arch.ptrBitWidth()) {
                32 => return Executor{ .wine = "wine" },
                64 => return Executor{ .wine = "wine64" },
                else => return .unavailable,
            },
            .wasi => switch (cpu_arch.ptrBitWidth()) {
                32 => return Executor{ .wasmtime = "wasmtime" },
                else => return .unavailable,
            },
            .macos => {
                // TODO loosen this check once upstream adds QEMU-based emulation
                // layer for non-host architectures:
                // https://github.com/darlinghq/darling/issues/863
                if (cpu_arch != builtin.cpu.arch) {
                    return .unavailable;
                }
                return Executor{ .darling = "darling" };
            },
            else => return .unavailable,
        }
    }

    pub fn isGnuLibC(self: CrossTarget) bool {
        return Target.isGnuLibC_os_tag_abi(self.getOsTag(), self.getAbi());
    }

    pub fn setGnuLibCVersion(self: *CrossTarget, major: u32, minor: u32, patch: u32) void {
        assert(self.isGnuLibC());
        self.glibc_version = SemVer{ .major = major, .minor = minor, .patch = patch };
    }

    pub fn getObjectFormat(self: CrossTarget) Target.ObjectFormat {
        return Target.getObjectFormatSimple(self.getOsTag(), self.getCpuArch());
    }

    pub fn updateCpuFeatures(self: CrossTarget, set: *Target.Cpu.Feature.Set) void {
        set.removeFeatureSet(self.cpu_features_sub);
        set.addFeatureSet(self.cpu_features_add);
        set.populateDependencies(self.getCpuArch().allFeaturesList());
        set.removeFeatureSet(self.cpu_features_sub);
    }

    fn parseOs(result: *CrossTarget, diags: *ParseOptions.Diagnostics, text: []const u8) !void {
        var it = mem.split(text, ".");
        const os_name = it.next().?;
        diags.os_name = os_name;
        const os_is_native = mem.eql(u8, os_name, "native");
        if (!os_is_native) {
            result.os_tag = std.meta.stringToEnum(Target.Os.Tag, os_name) orelse
                return error.UnknownOperatingSystem;
        }
        const tag = result.getOsTag();
        diags.os_tag = tag;

        const version_text = it.rest();
        if (it.next() == null) return;

        switch (tag) {
            .freestanding,
            .ananas,
            .cloudabi,
            .fuchsia,
            .kfreebsd,
            .lv2,
            .solaris,
            .zos,
            .haiku,
            .minix,
            .rtems,
            .nacl,
            .aix,
            .cuda,
            .nvcl,
            .amdhsa,
            .ps4,
            .elfiamcu,
            .mesa3d,
            .contiki,
            .amdpal,
            .hermit,
            .hurd,
            .wasi,
            .emscripten,
            .uefi,
            .opencl,
            .glsl450,
            .vulkan,
            .plan9,
            .other,
            => return error.InvalidOperatingSystemVersion,

            .freebsd,
            .macos,
            .ios,
            .tvos,
            .watchos,
            .netbsd,
            .openbsd,
            .linux,
            .dragonfly,
            => {
                var range_it = mem.split(version_text, "...");

                const min_text = range_it.next().?;
                const min_ver = SemVer.parse(min_text) catch |err| switch (err) {
                    error.Overflow => return error.InvalidOperatingSystemVersion,
                    error.InvalidCharacter => return error.InvalidOperatingSystemVersion,
                    error.InvalidVersion => return error.InvalidOperatingSystemVersion,
                };
                result.os_version_min = .{ .semver = min_ver };

                const max_text = range_it.next() orelse return;
                const max_ver = SemVer.parse(max_text) catch |err| switch (err) {
                    error.Overflow => return error.InvalidOperatingSystemVersion,
                    error.InvalidCharacter => return error.InvalidOperatingSystemVersion,
                    error.InvalidVersion => return error.InvalidOperatingSystemVersion,
                };
                result.os_version_max = .{ .semver = max_ver };
            },

            .windows => {
                var range_it = mem.split(version_text, "...");

                const min_text = range_it.next().?;
                const min_ver = std.meta.stringToEnum(Target.Os.WindowsVersion, min_text) orelse
                    return error.InvalidOperatingSystemVersion;
                result.os_version_min = .{ .windows = min_ver };

                const max_text = range_it.next() orelse return;
                const max_ver = std.meta.stringToEnum(Target.Os.WindowsVersion, max_text) orelse
                    return error.InvalidOperatingSystemVersion;
                result.os_version_max = .{ .windows = max_ver };
            },
        }
    }
};

test "CrossTarget.parse" {
    if (builtin.target.isGnuLibC()) {
        var cross_target = try CrossTarget.parse(.{});
        cross_target.setGnuLibCVersion(2, 1, 1);

        const text = try cross_target.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);

        var buf: [256]u8 = undefined;
        const triple = std.fmt.bufPrint(
            buf[0..],
            "native-native-{s}.2.1.1",
            .{@tagName(builtin.abi)},
        ) catch unreachable;

        try std.testing.expectEqualSlices(u8, triple, text);
    }
    {
        const cross_target = try CrossTarget.parse(.{
            .arch_os_abi = "aarch64-linux",
            .cpu_features = "native",
        });

        try std.testing.expect(cross_target.cpu_arch.? == .aarch64);
        try std.testing.expect(cross_target.cpu_model == .native);
    }
    {
        const cross_target = try CrossTarget.parse(.{ .arch_os_abi = "native" });

        try std.testing.expect(cross_target.cpu_arch == null);
        try std.testing.expect(cross_target.isNative());

        const text = try cross_target.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "native", text);
    }
    {
        const cross_target = try CrossTarget.parse(.{
            .arch_os_abi = "x86_64-linux-gnu",
            .cpu_features = "x86_64-sse-sse2-avx-cx8",
        });
        const target = cross_target.toTarget();

        try std.testing.expect(target.os.tag == .linux);
        try std.testing.expect(target.abi == .gnu);
        try std.testing.expect(target.cpu.arch == .x86_64);
        try std.testing.expect(!Target.x86.featureSetHas(target.cpu.features, .sse));
        try std.testing.expect(!Target.x86.featureSetHas(target.cpu.features, .avx));
        try std.testing.expect(!Target.x86.featureSetHas(target.cpu.features, .cx8));
        try std.testing.expect(Target.x86.featureSetHas(target.cpu.features, .cmov));
        try std.testing.expect(Target.x86.featureSetHas(target.cpu.features, .fxsr));

        try std.testing.expect(Target.x86.featureSetHasAny(target.cpu.features, .{ .sse, .avx, .cmov }));
        try std.testing.expect(!Target.x86.featureSetHasAny(target.cpu.features, .{ .sse, .avx }));
        try std.testing.expect(Target.x86.featureSetHasAll(target.cpu.features, .{ .mmx, .x87 }));
        try std.testing.expect(!Target.x86.featureSetHasAll(target.cpu.features, .{ .mmx, .x87, .sse }));

        const text = try cross_target.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "x86_64-linux-gnu", text);
    }
    {
        const cross_target = try CrossTarget.parse(.{
            .arch_os_abi = "arm-linux-musleabihf",
            .cpu_features = "generic+v8a",
        });
        const target = cross_target.toTarget();

        try std.testing.expect(target.os.tag == .linux);
        try std.testing.expect(target.abi == .musleabihf);
        try std.testing.expect(target.cpu.arch == .arm);
        try std.testing.expect(target.cpu.model == &Target.arm.cpu.generic);
        try std.testing.expect(Target.arm.featureSetHas(target.cpu.features, .v8a));

        const text = try cross_target.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "arm-linux-musleabihf", text);
    }
    {
        const cross_target = try CrossTarget.parse(.{
            .arch_os_abi = "aarch64-linux.3.10...4.4.1-gnu.2.27",
            .cpu_features = "generic+v8a",
        });
        const target = cross_target.toTarget();

        try std.testing.expect(target.cpu.arch == .aarch64);
        try std.testing.expect(target.os.tag == .linux);
        try std.testing.expect(target.os.version_range.linux.range.min.major == 3);
        try std.testing.expect(target.os.version_range.linux.range.min.minor == 10);
        try std.testing.expect(target.os.version_range.linux.range.min.patch == 0);
        try std.testing.expect(target.os.version_range.linux.range.max.major == 4);
        try std.testing.expect(target.os.version_range.linux.range.max.minor == 4);
        try std.testing.expect(target.os.version_range.linux.range.max.patch == 1);
        try std.testing.expect(target.os.version_range.linux.glibc.major == 2);
        try std.testing.expect(target.os.version_range.linux.glibc.minor == 27);
        try std.testing.expect(target.os.version_range.linux.glibc.patch == 0);
        try std.testing.expect(target.abi == .gnu);

        const text = try cross_target.zigTriple(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualSlices(u8, "aarch64-linux.3.10...4.4.1-gnu.2.27", text);
    }
}
