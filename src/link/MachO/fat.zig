const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.archive);
const macho = std.macho;
const mem = std.mem;
const native_endian = builtin.cpu.arch.endian();

const Arch = std.Target.Cpu.Arch;

pub fn decodeArch(cputype: macho.cpu_type_t, comptime logError: bool) !std.Target.Cpu.Arch {
    const arch: Arch = switch (cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => {
            if (logError) {
                log.err("unsupported cpu architecture 0x{x}", .{cputype});
            }
            return error.UnsupportedCpuArchitecture;
        },
    };
    return arch;
}

fn readFatStruct(reader: anytype, comptime T: type) !T {
    // Fat structures (fat_header & fat_arch) are always written and read to/from
    // disk in big endian order.
    var res = try reader.readStruct(T);
    if (native_endian != std.builtin.Endian.Big) {
        mem.bswapAllFields(T, &res);
    }
    return res;
}

pub fn getLibraryOffset(reader: anytype, arch: Arch) !u64 {
    const fat_header = try readFatStruct(reader, macho.fat_header);
    if (fat_header.magic != macho.FAT_MAGIC) return 0;

    var fat_arch_index: u32 = 0;
    while (fat_arch_index < fat_header.nfat_arch) : (fat_arch_index += 1) {
        const fat_arch = try readFatStruct(reader, macho.fat_arch);
        // If we come across an architecture that we do not know how to handle, that's
        // fine because we can keep looking for one that might match.
        const lib_arch = decodeArch(fat_arch.cputype, false) catch |err| switch (err) {
            error.UnsupportedCpuArchitecture => continue,
            else => |e| return e,
        };
        if (lib_arch == arch) {
            // We have found a matching architecture!
            return fat_arch.offset;
        }
    } else {
        log.err("Could not find matching cpu architecture in fat library: expected {s}", .{arch});
        return error.MismatchedCpuArchitecture;
    }
}
