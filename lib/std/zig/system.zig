// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const elf = std.elf;
const mem = std.mem;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const assert = std.debug.assert;
const process = std.process;
const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;
const macos = @import("system/macos.zig");
const native_endian = builtin.cpu.arch.endian();
const linux = @import("system/linux.zig");
pub const windows = @import("system/windows.zig");

pub const getSDKPath = macos.getSDKPath;

pub const NativePaths = struct {
    include_dirs: ArrayList([:0]u8),
    lib_dirs: ArrayList([:0]u8),
    framework_dirs: ArrayList([:0]u8),
    rpaths: ArrayList([:0]u8),
    warnings: ArrayList([:0]u8),

    pub fn detect(allocator: *Allocator, native_info: NativeTargetInfo) !NativePaths {
        const native_target = native_info.target;

        var self: NativePaths = .{
            .include_dirs = ArrayList([:0]u8).init(allocator),
            .lib_dirs = ArrayList([:0]u8).init(allocator),
            .framework_dirs = ArrayList([:0]u8).init(allocator),
            .rpaths = ArrayList([:0]u8).init(allocator),
            .warnings = ArrayList([:0]u8).init(allocator),
        };
        errdefer self.deinit();

        var is_nix = false;
        if (process.getEnvVarOwned(allocator, "NIX_CFLAGS_COMPILE")) |nix_cflags_compile| {
            defer allocator.free(nix_cflags_compile);

            is_nix = true;
            var it = mem.tokenize(nix_cflags_compile, " ");
            while (true) {
                const word = it.next() orelse break;
                if (mem.eql(u8, word, "-isystem")) {
                    const include_path = it.next() orelse {
                        try self.addWarning("Expected argument after -isystem in NIX_CFLAGS_COMPILE");
                        break;
                    };
                    try self.addIncludeDir(include_path);
                } else {
                    if (mem.startsWith(u8, word, "-frandom-seed=")) {
                        continue;
                    }
                    try self.addWarningFmt("Unrecognized C flag from NIX_CFLAGS_COMPILE: {s}", .{word});
                }
            }
        } else |err| switch (err) {
            error.InvalidUtf8 => {},
            error.EnvironmentVariableNotFound => {},
            error.OutOfMemory => |e| return e,
        }
        if (process.getEnvVarOwned(allocator, "NIX_LDFLAGS")) |nix_ldflags| {
            defer allocator.free(nix_ldflags);

            is_nix = true;
            var it = mem.tokenize(nix_ldflags, " ");
            while (true) {
                const word = it.next() orelse break;
                if (mem.eql(u8, word, "-rpath")) {
                    const rpath = it.next() orelse {
                        try self.addWarning("Expected argument after -rpath in NIX_LDFLAGS");
                        break;
                    };
                    try self.addRPath(rpath);
                } else if (word.len > 2 and word[0] == '-' and word[1] == 'L') {
                    const lib_path = word[2..];
                    try self.addLibDir(lib_path);
                } else {
                    try self.addWarningFmt("Unrecognized C flag from NIX_LDFLAGS: {s}", .{word});
                    break;
                }
            }
        } else |err| switch (err) {
            error.InvalidUtf8 => {},
            error.EnvironmentVariableNotFound => {},
            error.OutOfMemory => |e| return e,
        }
        if (is_nix) {
            return self;
        }

        if (comptime builtin.target.isDarwin()) {
            try self.addIncludeDir("/usr/include");
            try self.addIncludeDir("/usr/local/include");

            try self.addLibDir("/usr/lib");
            try self.addLibDir("/usr/local/lib");

            try self.addFrameworkDir("/Library/Frameworks");
            try self.addFrameworkDir("/System/Library/Frameworks");

            return self;
        }

        if (native_target.os.tag != .windows) {
            const triple = try native_target.linuxTriple(allocator);
            const qual = native_target.cpu.arch.ptrBitWidth();

            // TODO: $ ld --verbose | grep SEARCH_DIR
            // the output contains some paths that end with lib64, maybe include them too?
            // TODO: what is the best possible order of things?
            // TODO: some of these are suspect and should only be added on some systems. audit needed.

            try self.addIncludeDir("/usr/local/include");
            try self.addLibDirFmt("/usr/local/lib{d}", .{qual});
            try self.addLibDir("/usr/local/lib");

            try self.addIncludeDirFmt("/usr/include/{s}", .{triple});
            try self.addLibDirFmt("/usr/lib/{s}", .{triple});

            try self.addIncludeDir("/usr/include");
            try self.addLibDirFmt("/lib{d}", .{qual});
            try self.addLibDir("/lib");
            try self.addLibDirFmt("/usr/lib{d}", .{qual});
            try self.addLibDir("/usr/lib");

            // example: on a 64-bit debian-based linux distro, with zlib installed from apt:
            // zlib.h is in /usr/include (added above)
            // libz.so.1 is in /lib/x86_64-linux-gnu (added here)
            try self.addLibDirFmt("/lib/{s}", .{triple});
        }

        return self;
    }

    pub fn deinit(self: *NativePaths) void {
        deinitArray(&self.include_dirs);
        deinitArray(&self.lib_dirs);
        deinitArray(&self.framework_dirs);
        deinitArray(&self.rpaths);
        deinitArray(&self.warnings);
        self.* = undefined;
    }

    fn deinitArray(array: *ArrayList([:0]u8)) void {
        for (array.items) |item| {
            array.allocator.free(item);
        }
        array.deinit();
    }

    pub fn addIncludeDir(self: *NativePaths, s: []const u8) !void {
        return self.appendArray(&self.include_dirs, s);
    }

    pub fn addIncludeDirFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
        const item = try std.fmt.allocPrint0(self.include_dirs.allocator, fmt, args);
        errdefer self.include_dirs.allocator.free(item);
        try self.include_dirs.append(item);
    }

    pub fn addLibDir(self: *NativePaths, s: []const u8) !void {
        return self.appendArray(&self.lib_dirs, s);
    }

    pub fn addLibDirFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
        const item = try std.fmt.allocPrint0(self.lib_dirs.allocator, fmt, args);
        errdefer self.lib_dirs.allocator.free(item);
        try self.lib_dirs.append(item);
    }

    pub fn addWarning(self: *NativePaths, s: []const u8) !void {
        return self.appendArray(&self.warnings, s);
    }

    pub fn addFrameworkDir(self: *NativePaths, s: []const u8) !void {
        return self.appendArray(&self.framework_dirs, s);
    }

    pub fn addFrameworkDirFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
        const item = try std.fmt.allocPrint0(self.framework_dirs.allocator, fmt, args);
        errdefer self.framework_dirs.allocator.free(item);
        try self.framework_dirs.append(item);
    }

    pub fn addWarningFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
        const item = try std.fmt.allocPrint0(self.warnings.allocator, fmt, args);
        errdefer self.warnings.allocator.free(item);
        try self.warnings.append(item);
    }

    pub fn addRPath(self: *NativePaths, s: []const u8) !void {
        return self.appendArray(&self.rpaths, s);
    }

    fn appendArray(self: *NativePaths, array: *ArrayList([:0]u8), s: []const u8) !void {
        _ = self;
        const item = try array.allocator.dupeZ(u8, s);
        errdefer array.allocator.free(item);
        try array.append(item);
    }
};

pub const NativeTargetInfo = struct {
    target: Target,

    dynamic_linker: DynamicLinker = DynamicLinker{},

    pub const DynamicLinker = Target.DynamicLinker;

    pub const DetectError = error{
        OutOfMemory,
        FileSystem,
        SystemResources,
        SymLinkLoop,
        ProcessFdQuotaExceeded,
        SystemFdQuotaExceeded,
        DeviceBusy,
        OSVersionDetectionFail,
    };

    /// Given a `CrossTarget`, which specifies in detail which parts of the target should be detected
    /// natively, which should be standard or default, and which are provided explicitly, this function
    /// resolves the native components by detecting the native system, and then resolves standard/default parts
    /// relative to that.
    /// Any resources this function allocates are released before returning, and so there is no
    /// deinitialization method.
    /// TODO Remove the Allocator requirement from this function.
    pub fn detect(allocator: *Allocator, cross_target: CrossTarget) DetectError!NativeTargetInfo {
        var os = cross_target.getOsTag().defaultVersionRange();
        if (cross_target.os_tag == null) {
            switch (builtin.os.tag) {
                .linux => {
                    const uts = std.os.uname();
                    const release = mem.spanZ(&uts.release);
                    // The release field sometimes has a weird format,
                    // `Version.parse` will attempt to find some meaningful interpretation.
                    if (std.builtin.Version.parse(release)) |ver| {
                        os.version_range.linux.range.min = ver;
                        os.version_range.linux.range.max = ver;
                    } else |err| switch (err) {
                        error.Overflow => {},
                        error.InvalidCharacter => {},
                        error.InvalidVersion => {},
                    }
                },
                .windows => {
                    const detected_version = windows.detectRuntimeVersion();
                    os.version_range.windows.min = detected_version;
                    os.version_range.windows.max = detected_version;
                },
                .macos => try macos.detect(&os),
                .freebsd, .netbsd, .dragonfly => {
                    const key = switch (builtin.os.tag) {
                        .freebsd => "kern.osreldate",
                        .netbsd, .dragonfly => "kern.osrevision",
                        else => unreachable,
                    };
                    var value: u32 = undefined;
                    var len: usize = @sizeOf(@TypeOf(value));

                    std.os.sysctlbynameZ(key, &value, &len, null, 0) catch |err| switch (err) {
                        error.NameTooLong => unreachable, // constant, known good value
                        error.PermissionDenied => unreachable, // only when setting values,
                        error.SystemResources => unreachable, // memory already on the stack
                        error.UnknownName => unreachable, // constant, known good value
                        error.Unexpected => return error.OSVersionDetectionFail,
                    };

                    switch (builtin.os.tag) {
                        .freebsd => {
                            // https://www.freebsd.org/doc/en_US.ISO8859-1/books/porters-handbook/versions.html
                            // Major * 100,000 has been convention since FreeBSD 2.2 (1997)
                            // Minor * 1(0),000 summed has been convention since FreeBSD 2.2 (1997)
                            // e.g. 492101 = 4.11-STABLE = 4.(9+2)
                            const major = value / 100_000;
                            const minor1 = value % 100_000 / 10_000; // usually 0 since 5.1
                            const minor2 = value % 10_000 / 1_000; // 0 before 5.1, minor version since
                            const patch = value % 1_000;
                            os.version_range.semver.min = .{ .major = major, .minor = minor1 + minor2, .patch = patch };
                            os.version_range.semver.max = os.version_range.semver.min;
                        },
                        .netbsd => {
                            // #define __NetBSD_Version__ MMmmrrpp00
                            //
                            // M = major version
                            // m = minor version; a minor number of 99 indicates current.
                            // r = 0 (*)
                            // p = patchlevel
                            const major = value / 100_000_000;
                            const minor = value % 100_000_000 / 1_000_000;
                            const patch = value % 10_000 / 100;
                            os.version_range.semver.min = .{ .major = major, .minor = minor, .patch = patch };
                            os.version_range.semver.max = os.version_range.semver.min;
                        },
                        .dragonfly => {
                            // https://github.com/DragonFlyBSD/DragonFlyBSD/blob/cb2cde83771754aeef9bb3251ee48959138dec87/Makefile.inc1#L15-L17
                            // flat base10 format: Mmmmpp
                            //   M = major
                            //   m = minor; odd-numbers indicate current dev branch
                            //   p = patch
                            const major = value / 100_000;
                            const minor = value % 100_000 / 100;
                            const patch = value % 100;
                            os.version_range.semver.min = .{ .major = major, .minor = minor, .patch = patch };
                            os.version_range.semver.max = os.version_range.semver.min;
                        },
                        else => unreachable,
                    }
                },
                .openbsd => {
                    const mib: [2]c_int = [_]c_int{
                        std.os.CTL_KERN,
                        std.os.KERN_OSRELEASE,
                    };
                    var buf: [64]u8 = undefined;
                    var len: usize = buf.len;

                    std.os.sysctl(&mib, &buf, &len, null, 0) catch |err| switch (err) {
                        error.NameTooLong => unreachable, // constant, known good value
                        error.PermissionDenied => unreachable, // only when setting values,
                        error.SystemResources => unreachable, // memory already on the stack
                        error.UnknownName => unreachable, // constant, known good value
                        error.Unexpected => return error.OSVersionDetectionFail,
                    };

                    if (std.builtin.Version.parse(buf[0 .. len - 1])) |ver| {
                        os.version_range.semver.min = ver;
                        os.version_range.semver.max = ver;
                    } else |_| {
                        return error.OSVersionDetectionFail;
                    }
                },
                else => {
                    // Unimplemented, fall back to default version range.
                },
            }
        }

        if (cross_target.os_version_min) |min| switch (min) {
            .none => {},
            .semver => |semver| switch (cross_target.getOsTag()) {
                .linux => os.version_range.linux.range.min = semver,
                else => os.version_range.semver.min = semver,
            },
            .windows => |win_ver| os.version_range.windows.min = win_ver,
        };

        if (cross_target.os_version_max) |max| switch (max) {
            .none => {},
            .semver => |semver| switch (cross_target.getOsTag()) {
                .linux => os.version_range.linux.range.max = semver,
                else => os.version_range.semver.max = semver,
            },
            .windows => |win_ver| os.version_range.windows.max = win_ver,
        };

        if (cross_target.glibc_version) |glibc| {
            assert(cross_target.isGnuLibC());
            os.version_range.linux.glibc = glibc;
        }

        // Until https://github.com/ziglang/zig/issues/4592 is implemented (support detecting the
        // native CPU architecture as being different than the current target), we use this:
        const cpu_arch = cross_target.getCpuArch();

        var cpu = switch (cross_target.cpu_model) {
            .native => detectNativeCpuAndFeatures(cpu_arch, os, cross_target),
            .baseline => Target.Cpu.baseline(cpu_arch),
            .determined_by_cpu_arch => if (cross_target.cpu_arch == null)
                detectNativeCpuAndFeatures(cpu_arch, os, cross_target)
            else
                Target.Cpu.baseline(cpu_arch),
            .explicit => |model| model.toCpu(cpu_arch),
        } orelse backup_cpu_detection: {
            break :backup_cpu_detection Target.Cpu.baseline(cpu_arch);
        };
        var result = try detectAbiAndDynamicLinker(allocator, cpu, os, cross_target);
        // For x86, we need to populate some CPU feature flags depending on architecture
        // and mode:
        //  * 16bit_mode => if the abi is code16
        //  * 32bit_mode => if the arch is i386
        // However, the "mode" flags can be used as overrides, so if the user explicitly
        // sets one of them, that takes precedence.
        switch (cpu_arch) {
            .i386 => {
                if (!std.Target.x86.featureSetHasAny(cross_target.cpu_features_add, .{
                    .@"16bit_mode", .@"32bit_mode",
                })) {
                    switch (result.target.abi) {
                        .code16 => result.target.cpu.features.addFeature(
                            @enumToInt(std.Target.x86.Feature.@"16bit_mode"),
                        ),
                        else => result.target.cpu.features.addFeature(
                            @enumToInt(std.Target.x86.Feature.@"32bit_mode"),
                        ),
                    }
                }
            },
            .arm, .armeb => {
                // XXX What do we do if the target has the noarm feature?
                //     What do we do if the user specifies +thumb_mode?
            },
            .thumb, .thumbeb => {
                result.target.cpu.features.addFeature(
                    @enumToInt(std.Target.arm.Feature.thumb_mode),
                );
            },
            else => {},
        }
        cross_target.updateCpuFeatures(&result.target.cpu.features);
        return result;
    }

    /// First we attempt to use the executable's own binary. If it is dynamically
    /// linked, then it should answer both the C ABI question and the dynamic linker question.
    /// If it is statically linked, then we try /usr/bin/env. If that does not provide the answer, then
    /// we fall back to the defaults.
    /// TODO Remove the Allocator requirement from this function.
    fn detectAbiAndDynamicLinker(
        allocator: *Allocator,
        cpu: Target.Cpu,
        os: Target.Os,
        cross_target: CrossTarget,
    ) DetectError!NativeTargetInfo {
        const native_target_has_ld = comptime builtin.target.hasDynamicLinker();
        const is_linux = builtin.os.tag == .linux;
        const have_all_info = cross_target.dynamic_linker.get() != null and
            cross_target.abi != null and (!is_linux or cross_target.abi.?.isGnu());
        const os_is_non_native = cross_target.os_tag != null;
        if (!native_target_has_ld or have_all_info or os_is_non_native) {
            return defaultAbiAndDynamicLinker(cpu, os, cross_target);
        }
        if (cross_target.abi) |abi| {
            if (abi.isMusl()) {
                // musl implies static linking.
                return defaultAbiAndDynamicLinker(cpu, os, cross_target);
            }
        }
        // The current target's ABI cannot be relied on for this. For example, we may build the zig
        // compiler for target riscv64-linux-musl and provide a tarball for users to download.
        // A user could then run that zig compiler on riscv64-linux-gnu. This use case is well-defined
        // and supported by Zig. But that means that we must detect the system ABI here rather than
        // relying on `builtin.target`.
        const all_abis = comptime blk: {
            assert(@enumToInt(Target.Abi.none) == 0);
            const fields = std.meta.fields(Target.Abi)[1..];
            var array: [fields.len]Target.Abi = undefined;
            inline for (fields) |field, i| {
                array[i] = @field(Target.Abi, field.name);
            }
            break :blk array;
        };
        var ld_info_list_buffer: [all_abis.len]LdInfo = undefined;
        var ld_info_list_len: usize = 0;

        for (all_abis) |abi| {
            // This may be a nonsensical parameter. We detect this with error.UnknownDynamicLinkerPath and
            // skip adding it to `ld_info_list`.
            const target: Target = .{
                .cpu = cpu,
                .os = os,
                .abi = abi,
            };
            const ld = target.standardDynamicLinkerPath();
            if (ld.get() == null) continue;

            ld_info_list_buffer[ld_info_list_len] = .{
                .ld = ld,
                .abi = abi,
            };
            ld_info_list_len += 1;
        }
        const ld_info_list = ld_info_list_buffer[0..ld_info_list_len];

        // Best case scenario: the executable is dynamically linked, and we can iterate
        // over our own shared objects and find a dynamic linker.
        self_exe: {
            const lib_paths = try std.process.getSelfExeSharedLibPaths(allocator);
            defer {
                for (lib_paths) |lib_path| {
                    allocator.free(lib_path);
                }
                allocator.free(lib_paths);
            }

            var found_ld_info: LdInfo = undefined;
            var found_ld_path: [:0]const u8 = undefined;

            // Look for dynamic linker.
            // This is O(N^M) but typical case here is N=2 and M=10.
            find_ld: for (lib_paths) |lib_path| {
                for (ld_info_list) |ld_info| {
                    const standard_ld_basename = fs.path.basename(ld_info.ld.get().?);
                    if (std.mem.endsWith(u8, lib_path, standard_ld_basename)) {
                        found_ld_info = ld_info;
                        found_ld_path = lib_path;
                        break :find_ld;
                    }
                }
            } else break :self_exe;

            // Look for glibc version.
            var os_adjusted = os;
            if (builtin.os.tag == .linux and found_ld_info.abi.isGnu() and
                cross_target.glibc_version == null)
            {
                for (lib_paths) |lib_path| {
                    if (std.mem.endsWith(u8, lib_path, glibc_so_basename)) {
                        os_adjusted.version_range.linux.glibc = glibcVerFromSO(lib_path) catch |err| switch (err) {
                            error.UnrecognizedGnuLibCFileName => continue,
                            error.InvalidGnuLibCVersion => continue,
                            error.GnuLibCVersionUnavailable => continue,
                            else => |e| return e,
                        };
                        break;
                    }
                }
            }

            var result: NativeTargetInfo = .{
                .target = .{
                    .cpu = cpu,
                    .os = os_adjusted,
                    .abi = cross_target.abi orelse found_ld_info.abi,
                },
                .dynamic_linker = if (cross_target.dynamic_linker.get() == null)
                    DynamicLinker.init(found_ld_path)
                else
                    cross_target.dynamic_linker,
            };
            return result;
        }

        const env_file = std.fs.openFileAbsoluteZ("/usr/bin/env", .{}) catch |err| switch (err) {
            error.NoSpaceLeft => unreachable,
            error.NameTooLong => unreachable,
            error.PathAlreadyExists => unreachable,
            error.SharingViolation => unreachable,
            error.InvalidUtf8 => unreachable,
            error.BadPathName => unreachable,
            error.PipeBusy => unreachable,
            error.FileLocksNotSupported => unreachable,
            error.WouldBlock => unreachable,

            error.IsDir,
            error.NotDir,
            error.AccessDenied,
            error.NoDevice,
            error.FileNotFound,
            error.FileTooBig,
            error.Unexpected,
            => return defaultAbiAndDynamicLinker(cpu, os, cross_target),

            else => |e| return e,
        };
        defer env_file.close();

        // If Zig is statically linked, such as via distributed binary static builds, the above
        // trick won't work. The next thing we fall back to is the same thing, but for /usr/bin/env.
        // Since that path is hard-coded into the shebang line of many portable scripts, it's a
        // reasonably reliable path to check for.
        return abiAndDynamicLinkerFromFile(env_file, cpu, os, ld_info_list, cross_target) catch |err| switch (err) {
            error.FileSystem,
            error.SystemResources,
            error.SymLinkLoop,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            => |e| return e,

            error.UnableToReadElfFile,
            error.InvalidElfClass,
            error.InvalidElfVersion,
            error.InvalidElfEndian,
            error.InvalidElfFile,
            error.InvalidElfMagic,
            error.Unexpected,
            error.UnexpectedEndOfFile,
            error.NameTooLong,
            // Finally, we fall back on the standard path.
            => defaultAbiAndDynamicLinker(cpu, os, cross_target),
        };
    }

    const glibc_so_basename = "libc.so.6";

    fn glibcVerFromSO(so_path: [:0]const u8) !std.builtin.Version {
        var link_buf: [std.os.PATH_MAX]u8 = undefined;
        const link_name = std.os.readlinkZ(so_path.ptr, &link_buf) catch |err| switch (err) {
            error.AccessDenied => return error.GnuLibCVersionUnavailable,
            error.FileSystem => return error.FileSystem,
            error.SymLinkLoop => return error.SymLinkLoop,
            error.NameTooLong => unreachable,
            error.FileNotFound => return error.GnuLibCVersionUnavailable,
            error.SystemResources => return error.SystemResources,
            error.NotDir => return error.GnuLibCVersionUnavailable,
            error.Unexpected => return error.GnuLibCVersionUnavailable,
            error.InvalidUtf8 => unreachable, // Windows only
            error.BadPathName => unreachable, // Windows only
            error.UnsupportedReparsePointType => unreachable, // Windows only
        };
        return glibcVerFromLinkName(link_name);
    }

    fn glibcVerFromLinkName(link_name: []const u8) !std.builtin.Version {
        // example: "libc-2.3.4.so"
        // example: "libc-2.27.so"
        const prefix = "libc-";
        const suffix = ".so";
        if (!mem.startsWith(u8, link_name, prefix) or !mem.endsWith(u8, link_name, suffix)) {
            return error.UnrecognizedGnuLibCFileName;
        }
        // chop off "libc-" and ".so"
        const link_name_chopped = link_name[prefix.len .. link_name.len - suffix.len];
        return std.builtin.Version.parse(link_name_chopped) catch |err| switch (err) {
            error.Overflow => return error.InvalidGnuLibCVersion,
            error.InvalidCharacter => return error.InvalidGnuLibCVersion,
            error.InvalidVersion => return error.InvalidGnuLibCVersion,
        };
    }

    pub const AbiAndDynamicLinkerFromFileError = error{
        FileSystem,
        SystemResources,
        SymLinkLoop,
        ProcessFdQuotaExceeded,
        SystemFdQuotaExceeded,
        UnableToReadElfFile,
        InvalidElfClass,
        InvalidElfVersion,
        InvalidElfEndian,
        InvalidElfFile,
        InvalidElfMagic,
        Unexpected,
        UnexpectedEndOfFile,
        NameTooLong,
    };

    pub fn abiAndDynamicLinkerFromFile(
        file: fs.File,
        cpu: Target.Cpu,
        os: Target.Os,
        ld_info_list: []const LdInfo,
        cross_target: CrossTarget,
    ) AbiAndDynamicLinkerFromFileError!NativeTargetInfo {
        var hdr_buf: [@sizeOf(elf.Elf64_Ehdr)]u8 align(@alignOf(elf.Elf64_Ehdr)) = undefined;
        _ = try preadMin(file, &hdr_buf, 0, hdr_buf.len);
        const hdr32 = @ptrCast(*elf.Elf32_Ehdr, &hdr_buf);
        const hdr64 = @ptrCast(*elf.Elf64_Ehdr, &hdr_buf);
        if (!mem.eql(u8, hdr32.e_ident[0..4], "\x7fELF")) return error.InvalidElfMagic;
        const elf_endian: std.builtin.Endian = switch (hdr32.e_ident[elf.EI_DATA]) {
            elf.ELFDATA2LSB => .Little,
            elf.ELFDATA2MSB => .Big,
            else => return error.InvalidElfEndian,
        };
        const need_bswap = elf_endian != native_endian;
        if (hdr32.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

        const is_64 = switch (hdr32.e_ident[elf.EI_CLASS]) {
            elf.ELFCLASS32 => false,
            elf.ELFCLASS64 => true,
            else => return error.InvalidElfClass,
        };
        var phoff = elfInt(is_64, need_bswap, hdr32.e_phoff, hdr64.e_phoff);
        const phentsize = elfInt(is_64, need_bswap, hdr32.e_phentsize, hdr64.e_phentsize);
        const phnum = elfInt(is_64, need_bswap, hdr32.e_phnum, hdr64.e_phnum);

        var result: NativeTargetInfo = .{
            .target = .{
                .cpu = cpu,
                .os = os,
                .abi = cross_target.abi orelse Target.Abi.default(cpu.arch, os),
            },
            .dynamic_linker = cross_target.dynamic_linker,
        };
        var rpath_offset: ?u64 = null; // Found inside PT_DYNAMIC
        const look_for_ld = cross_target.dynamic_linker.get() == null;

        var ph_buf: [16 * @sizeOf(elf.Elf64_Phdr)]u8 align(@alignOf(elf.Elf64_Phdr)) = undefined;
        if (phentsize > @sizeOf(elf.Elf64_Phdr)) return error.InvalidElfFile;

        var ph_i: u16 = 0;
        while (ph_i < phnum) {
            // Reserve some bytes so that we can deref the 64-bit struct fields
            // even when the ELF file is 32-bits.
            const ph_reserve: usize = @sizeOf(elf.Elf64_Phdr) - @sizeOf(elf.Elf32_Phdr);
            const ph_read_byte_len = try preadMin(file, ph_buf[0 .. ph_buf.len - ph_reserve], phoff, phentsize);
            var ph_buf_i: usize = 0;
            while (ph_buf_i < ph_read_byte_len and ph_i < phnum) : ({
                ph_i += 1;
                phoff += phentsize;
                ph_buf_i += phentsize;
            }) {
                const ph32 = @ptrCast(*elf.Elf32_Phdr, @alignCast(@alignOf(elf.Elf32_Phdr), &ph_buf[ph_buf_i]));
                const ph64 = @ptrCast(*elf.Elf64_Phdr, @alignCast(@alignOf(elf.Elf64_Phdr), &ph_buf[ph_buf_i]));
                const p_type = elfInt(is_64, need_bswap, ph32.p_type, ph64.p_type);
                switch (p_type) {
                    elf.PT_INTERP => if (look_for_ld) {
                        const p_offset = elfInt(is_64, need_bswap, ph32.p_offset, ph64.p_offset);
                        const p_filesz = elfInt(is_64, need_bswap, ph32.p_filesz, ph64.p_filesz);
                        if (p_filesz > result.dynamic_linker.buffer.len) return error.NameTooLong;
                        const filesz = @intCast(usize, p_filesz);
                        _ = try preadMin(file, result.dynamic_linker.buffer[0..filesz], p_offset, filesz);
                        // PT_INTERP includes a null byte in filesz.
                        const len = filesz - 1;
                        // dynamic_linker.max_byte is "max", not "len".
                        // We know it will fit in u8 because we check against dynamic_linker.buffer.len above.
                        result.dynamic_linker.max_byte = @intCast(u8, len - 1);

                        // Use it to determine ABI.
                        const full_ld_path = result.dynamic_linker.buffer[0..len];
                        for (ld_info_list) |ld_info| {
                            const standard_ld_basename = fs.path.basename(ld_info.ld.get().?);
                            if (std.mem.endsWith(u8, full_ld_path, standard_ld_basename)) {
                                result.target.abi = ld_info.abi;
                                break;
                            }
                        }
                    },
                    // We only need this for detecting glibc version.
                    elf.PT_DYNAMIC => if (builtin.os.tag == .linux and result.target.isGnuLibC() and
                        cross_target.glibc_version == null)
                    {
                        var dyn_off = elfInt(is_64, need_bswap, ph32.p_offset, ph64.p_offset);
                        const p_filesz = elfInt(is_64, need_bswap, ph32.p_filesz, ph64.p_filesz);
                        const dyn_size: usize = if (is_64) @sizeOf(elf.Elf64_Dyn) else @sizeOf(elf.Elf32_Dyn);
                        const dyn_num = p_filesz / dyn_size;
                        var dyn_buf: [16 * @sizeOf(elf.Elf64_Dyn)]u8 align(@alignOf(elf.Elf64_Dyn)) = undefined;
                        var dyn_i: usize = 0;
                        dyn: while (dyn_i < dyn_num) {
                            // Reserve some bytes so that we can deref the 64-bit struct fields
                            // even when the ELF file is 32-bits.
                            const dyn_reserve: usize = @sizeOf(elf.Elf64_Dyn) - @sizeOf(elf.Elf32_Dyn);
                            const dyn_read_byte_len = try preadMin(
                                file,
                                dyn_buf[0 .. dyn_buf.len - dyn_reserve],
                                dyn_off,
                                dyn_size,
                            );
                            var dyn_buf_i: usize = 0;
                            while (dyn_buf_i < dyn_read_byte_len and dyn_i < dyn_num) : ({
                                dyn_i += 1;
                                dyn_off += dyn_size;
                                dyn_buf_i += dyn_size;
                            }) {
                                const dyn32 = @ptrCast(
                                    *elf.Elf32_Dyn,
                                    @alignCast(@alignOf(elf.Elf32_Dyn), &dyn_buf[dyn_buf_i]),
                                );
                                const dyn64 = @ptrCast(
                                    *elf.Elf64_Dyn,
                                    @alignCast(@alignOf(elf.Elf64_Dyn), &dyn_buf[dyn_buf_i]),
                                );
                                const tag = elfInt(is_64, need_bswap, dyn32.d_tag, dyn64.d_tag);
                                const val = elfInt(is_64, need_bswap, dyn32.d_val, dyn64.d_val);
                                if (tag == elf.DT_RUNPATH) {
                                    rpath_offset = val;
                                    break :dyn;
                                }
                            }
                        }
                    },
                    else => continue,
                }
            }
        }

        if (builtin.os.tag == .linux and result.target.isGnuLibC() and cross_target.glibc_version == null) {
            if (rpath_offset) |rpoff| {
                const shstrndx = elfInt(is_64, need_bswap, hdr32.e_shstrndx, hdr64.e_shstrndx);

                var shoff = elfInt(is_64, need_bswap, hdr32.e_shoff, hdr64.e_shoff);
                const shentsize = elfInt(is_64, need_bswap, hdr32.e_shentsize, hdr64.e_shentsize);
                const str_section_off = shoff + @as(u64, shentsize) * @as(u64, shstrndx);

                var sh_buf: [16 * @sizeOf(elf.Elf64_Shdr)]u8 align(@alignOf(elf.Elf64_Shdr)) = undefined;
                if (sh_buf.len < shentsize) return error.InvalidElfFile;

                _ = try preadMin(file, &sh_buf, str_section_off, shentsize);
                const shstr32 = @ptrCast(*elf.Elf32_Shdr, @alignCast(@alignOf(elf.Elf32_Shdr), &sh_buf));
                const shstr64 = @ptrCast(*elf.Elf64_Shdr, @alignCast(@alignOf(elf.Elf64_Shdr), &sh_buf));
                const shstrtab_off = elfInt(is_64, need_bswap, shstr32.sh_offset, shstr64.sh_offset);
                const shstrtab_size = elfInt(is_64, need_bswap, shstr32.sh_size, shstr64.sh_size);
                var strtab_buf: [4096:0]u8 = undefined;
                const shstrtab_len = std.math.min(shstrtab_size, strtab_buf.len);
                const shstrtab_read_len = try preadMin(file, &strtab_buf, shstrtab_off, shstrtab_len);
                const shstrtab = strtab_buf[0..shstrtab_read_len];

                const shnum = elfInt(is_64, need_bswap, hdr32.e_shnum, hdr64.e_shnum);
                var sh_i: u16 = 0;
                const dynstr: ?struct { offset: u64, size: u64 } = find_dyn_str: while (sh_i < shnum) {
                    // Reserve some bytes so that we can deref the 64-bit struct fields
                    // even when the ELF file is 32-bits.
                    const sh_reserve: usize = @sizeOf(elf.Elf64_Shdr) - @sizeOf(elf.Elf32_Shdr);
                    const sh_read_byte_len = try preadMin(
                        file,
                        sh_buf[0 .. sh_buf.len - sh_reserve],
                        shoff,
                        shentsize,
                    );
                    var sh_buf_i: usize = 0;
                    while (sh_buf_i < sh_read_byte_len and sh_i < shnum) : ({
                        sh_i += 1;
                        shoff += shentsize;
                        sh_buf_i += shentsize;
                    }) {
                        const sh32 = @ptrCast(
                            *elf.Elf32_Shdr,
                            @alignCast(@alignOf(elf.Elf32_Shdr), &sh_buf[sh_buf_i]),
                        );
                        const sh64 = @ptrCast(
                            *elf.Elf64_Shdr,
                            @alignCast(@alignOf(elf.Elf64_Shdr), &sh_buf[sh_buf_i]),
                        );
                        const sh_name_off = elfInt(is_64, need_bswap, sh32.sh_name, sh64.sh_name);
                        // TODO this pointer cast should not be necessary
                        const sh_name = mem.spanZ(std.meta.assumeSentinel(shstrtab[sh_name_off..].ptr, 0));
                        if (mem.eql(u8, sh_name, ".dynstr")) {
                            break :find_dyn_str .{
                                .offset = elfInt(is_64, need_bswap, sh32.sh_offset, sh64.sh_offset),
                                .size = elfInt(is_64, need_bswap, sh32.sh_size, sh64.sh_size),
                            };
                        }
                    }
                } else null;

                if (dynstr) |ds| {
                    const strtab_len = std.math.min(ds.size, strtab_buf.len);
                    const strtab_read_len = try preadMin(file, &strtab_buf, ds.offset, strtab_len);
                    const strtab = strtab_buf[0..strtab_read_len];
                    // TODO this pointer cast should not be necessary
                    const rpoff_usize = std.math.cast(usize, rpoff) catch |err| switch (err) {
                        error.Overflow => return error.InvalidElfFile,
                    };
                    const rpath_list = mem.spanZ(std.meta.assumeSentinel(strtab[rpoff_usize..].ptr, 0));
                    var it = mem.tokenize(rpath_list, ":");
                    while (it.next()) |rpath| {
                        var dir = fs.cwd().openDir(rpath, .{}) catch |err| switch (err) {
                            error.NameTooLong => unreachable,
                            error.InvalidUtf8 => unreachable,
                            error.BadPathName => unreachable,
                            error.DeviceBusy => unreachable,

                            error.FileNotFound,
                            error.NotDir,
                            error.AccessDenied,
                            error.NoDevice,
                            => continue,

                            error.ProcessFdQuotaExceeded,
                            error.SystemFdQuotaExceeded,
                            error.SystemResources,
                            error.SymLinkLoop,
                            error.Unexpected,
                            => |e| return e,
                        };
                        defer dir.close();

                        var link_buf: [std.os.PATH_MAX]u8 = undefined;
                        const link_name = std.os.readlinkatZ(
                            dir.fd,
                            glibc_so_basename,
                            &link_buf,
                        ) catch |err| switch (err) {
                            error.NameTooLong => unreachable,
                            error.InvalidUtf8 => unreachable, // Windows only
                            error.BadPathName => unreachable, // Windows only
                            error.UnsupportedReparsePointType => unreachable, // Windows only

                            error.AccessDenied,
                            error.FileNotFound,
                            error.NotDir,
                            => continue,

                            error.SystemResources,
                            error.FileSystem,
                            error.SymLinkLoop,
                            error.Unexpected,
                            => |e| return e,
                        };
                        result.target.os.version_range.linux.glibc = glibcVerFromLinkName(
                            link_name,
                        ) catch |err| switch (err) {
                            error.UnrecognizedGnuLibCFileName,
                            error.InvalidGnuLibCVersion,
                            => continue,
                        };
                        break;
                    }
                }
            }
        }

        return result;
    }

    fn preadMin(file: fs.File, buf: []u8, offset: u64, min_read_len: usize) !usize {
        var i: usize = 0;
        while (i < min_read_len) {
            const len = file.pread(buf[i .. buf.len - i], offset + i) catch |err| switch (err) {
                error.OperationAborted => unreachable, // Windows-only
                error.WouldBlock => unreachable, // Did not request blocking mode
                error.NotOpenForReading => unreachable,
                error.SystemResources => return error.SystemResources,
                error.IsDir => return error.UnableToReadElfFile,
                error.BrokenPipe => return error.UnableToReadElfFile,
                error.Unseekable => return error.UnableToReadElfFile,
                error.ConnectionResetByPeer => return error.UnableToReadElfFile,
                error.ConnectionTimedOut => return error.UnableToReadElfFile,
                error.Unexpected => return error.Unexpected,
                error.InputOutput => return error.FileSystem,
                error.AccessDenied => return error.Unexpected,
            };
            if (len == 0) return error.UnexpectedEndOfFile;
            i += len;
        }
        return i;
    }

    fn defaultAbiAndDynamicLinker(cpu: Target.Cpu, os: Target.Os, cross_target: CrossTarget) !NativeTargetInfo {
        const target: Target = .{
            .cpu = cpu,
            .os = os,
            .abi = cross_target.abi orelse Target.Abi.default(cpu.arch, os),
        };
        return NativeTargetInfo{
            .target = target,
            .dynamic_linker = if (cross_target.dynamic_linker.get() == null)
                target.standardDynamicLinkerPath()
            else
                cross_target.dynamic_linker,
        };
    }

    pub const LdInfo = struct {
        ld: DynamicLinker,
        abi: Target.Abi,
    };

    pub fn elfInt(is_64: bool, need_bswap: bool, int_32: anytype, int_64: anytype) @TypeOf(int_64) {
        if (is_64) {
            if (need_bswap) {
                return @byteSwap(@TypeOf(int_64), int_64);
            } else {
                return int_64;
            }
        } else {
            if (need_bswap) {
                return @byteSwap(@TypeOf(int_32), int_32);
            } else {
                return int_32;
            }
        }
    }

    fn detectNativeCpuAndFeatures(cpu_arch: Target.Cpu.Arch, os: Target.Os, cross_target: CrossTarget) ?Target.Cpu {
        // Here we switch on a comptime value rather than `cpu_arch`. This is valid because `cpu_arch`,
        // although it is a runtime value, is guaranteed to be one of the architectures in the set
        // of the respective switch prong.
        switch (builtin.cpu.arch) {
            .x86_64, .i386 => {
                return @import("system/x86.zig").detectNativeCpuAndFeatures(cpu_arch, os, cross_target);
            },
            else => {},
        }

        switch (builtin.os.tag) {
            .linux => return linux.detectNativeCpuAndFeatures(),
            .macos => return macos.detectNativeCpuAndFeatures(),
            else => {},
        }

        // This architecture does not have CPU model & feature detection yet.
        // See https://github.com/ziglang/zig/issues/4591
        return null;
    }
};

test {
    _ = @import("system/macos.zig");
    _ = @import("system/linux.zig");
}
