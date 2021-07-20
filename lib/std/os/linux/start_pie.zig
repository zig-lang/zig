const std = @import("std");
const elf = std.elf;
const builtin = @import("builtin");
const assert = std.debug.assert;

const R_AMD64_RELATIVE = 8;
const R_386_RELATIVE = 8;
const R_ARM_RELATIVE = 23;
const R_AARCH64_RELATIVE = 1027;
const R_RISCV_RELATIVE = 3;
const R_SPARC_RELATIVE = 22;

const R_RELATIVE = switch (builtin.cpu.arch) {
    .i386 => R_386_RELATIVE,
    .x86_64 => R_AMD64_RELATIVE,
    .arm => R_ARM_RELATIVE,
    .aarch64 => R_AARCH64_RELATIVE,
    .riscv64 => R_RISCV_RELATIVE,
    else => @compileError("Missing R_RELATIVE definition for this target"),
};

// Obtain a pointer to the _DYNAMIC array.
// We have to compute its address as a PC-relative quantity not to require a
// relocation that, at this point, is not yet applied.
fn getDynamicSymbol() [*]elf.Dyn {
    return switch (builtin.cpu.arch) {
        .i386 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ call 1f
            \\ 1: pop %[ret]
            \\ lea _DYNAMIC-1b(%[ret]), %[ret]
            : [ret] "=r" (-> [*]elf.Dyn)
        ),
        .x86_64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ lea _DYNAMIC(%%rip), %[ret]
            : [ret] "=r" (-> [*]elf.Dyn)
        ),
        // Work around the limited offset range of `ldr`
        .arm => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ ldr %[ret], 1f
            \\ add %[ret], pc
            \\ b 2f
            \\ 1: .word _DYNAMIC-1b
            \\ 2:
            : [ret] "=r" (-> [*]elf.Dyn)
        ),
        // A simple `adr` is not enough as it has a limited offset range
        .aarch64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ adrp %[ret], _DYNAMIC
            \\ add %[ret], %[ret], #:lo12:_DYNAMIC
            : [ret] "=r" (-> [*]elf.Dyn)
        ),
        .riscv64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ lla %[ret], _DYNAMIC
            : [ret] "=r" (-> [*]elf.Dyn)
        ),
        else => {
            @compileError("PIE startup is not yet supported for this target!");
        },
    };
}

pub fn relocate(phdrs: []elf.Phdr) void {
    @setRuntimeSafety(false);

    const dynv = getDynamicSymbol();
    // Recover the delta applied by the loader by comparing the effective and
    // the theoretical load addresses for the `_DYNAMIC` symbol.
    const base_addr = base: {
        for (phdrs) |*phdr| {
            if (phdr.p_type != elf.PT_DYNAMIC) continue;
            break :base @ptrToInt(dynv) - phdr.p_vaddr;
        }
        // This is not supposed to happen for well-formed binaries.
        std.os.abort();
    };

    var rel_addr: usize = 0;
    var rela_addr: usize = 0;
    var rel_size: usize = 0;
    var rela_size: usize = 0;
    {
        var i: usize = 0;
        while (dynv[i].d_tag != elf.DT_NULL) : (i += 1) {
            switch (dynv[i].d_tag) {
                elf.DT_REL => rel_addr = base_addr + dynv[i].d_val,
                elf.DT_RELA => rela_addr = base_addr + dynv[i].d_val,
                elf.DT_RELSZ => rel_size = dynv[i].d_val,
                elf.DT_RELASZ => rela_size = dynv[i].d_val,
                else => {},
            }
        }
    }

    // Apply the relocations.
    if (rel_addr != 0) {
        const rel = std.mem.bytesAsSlice(elf.Rel, @intToPtr([*]u8, rel_addr)[0..rel_size]);
        for (rel) |r| {
            if (r.r_type() != R_RELATIVE) continue;
            @intToPtr(*usize, base_addr + r.r_offset).* += base_addr;
        }
    }
    if (rela_addr != 0) {
        const rela = std.mem.bytesAsSlice(elf.Rela, @intToPtr([*]u8, rela_addr)[0..rela_size]);
        for (rela) |r| {
            if (r.r_type() != R_RELATIVE) continue;
            @intToPtr(*usize, base_addr + r.r_offset).* += base_addr + @bitCast(usize, r.r_addend);
        }
    }
}
