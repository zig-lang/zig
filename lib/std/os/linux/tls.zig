// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const os = std.os;
const mem = std.mem;
const elf = std.elf;
const math = std.math;
const assert = std.debug.assert;
const native_arch = @import("builtin").cpu.arch;

// This file implements the two TLS variants [1] used by ELF-based systems.
//
// The variant I has the following layout in memory:
// -------------------------------------------------------
// |   DTV   |     Zig     |   DTV   | Alignment |  TLS  |
// | storage | thread data | pointer |           | block |
// ------------------------^------------------------------
//                         `-- The thread pointer register points here
//
// In this case we allocate additional space for our control structure that's
// placed _before_ the DTV pointer together with the DTV.
//
// NOTE: Some systems such as power64 or mips use this variant with a twist: the
// alignment is not present and the tp and DTV addresses are offset by a
// constant.
//
// On the other hand the variant II has the following layout in memory:
// ---------------------------------------
// |  TLS  | TCB |     Zig     |   DTV   |
// | block |     | thread data | storage |
// --------^------------------------------
//         `-- The thread pointer register points here
//
// The structure of the TCB is not defined by the ABI so we reserve enough space
// for a single pointer as some architectures such as i386 and x86_64 need a
// pointer to the TCB block itself at the address pointed by the tp.
//
// In this case the control structure and DTV are placed one after another right
// after the TLS block data.
//
// At the moment the DTV is very simple since we only support static TLS, all we
// need is a two word vector to hold the number of entries (1) and the address
// of the first TLS block.
//
// [1] https://www.akkadia.org/drepper/tls.pdf

const TLSVariant = enum {
    VariantI,
    VariantII,
};

const tls_variant = switch (native_arch) {
    .arm, .armeb, .thumb, .aarch64, .aarch64_be, .riscv32, .riscv64, .mips, .mipsel, .powerpc, .powerpc64, .powerpc64le => TLSVariant.VariantI,
    .x86_64, .i386, .sparcv9 => TLSVariant.VariantII,
    else => @compileError("undefined tls_variant for this architecture"),
};

// Controls how many bytes are reserved for the Thread Control Block
const tls_tcb_size = switch (native_arch) {
    // ARM EABI mandates enough space for two pointers: the first one points to
    // the DTV while the second one is unspecified but reserved
    .arm, .armeb, .thumb, .aarch64, .aarch64_be => 2 * @sizeOf(usize),
    // One pointer-sized word that points either to the DTV or the TCB itself
    else => @sizeOf(usize),
};

// Controls if the TP points to the end of the TCB instead of its beginning
const tls_tp_points_past_tcb = switch (native_arch) {
    .riscv32, .riscv64, .mips, .mipsel, .powerpc, .powerpc64, .powerpc64le => true,
    else => false,
};

// Some architectures add some offset to the tp and dtv addresses in order to
// make the generated code more efficient

const tls_tp_offset = switch (native_arch) {
    .mips, .mipsel, .powerpc, .powerpc64, .powerpc64le => 0x7000,
    else => 0,
};

const tls_dtv_offset = switch (native_arch) {
    .mips, .mipsel, .powerpc, .powerpc64, .powerpc64le => 0x8000,
    .riscv32, .riscv64 => 0x800,
    else => 0,
};

// Per-thread storage for Zig's use
const CustomData = struct {
    dummy: usize,
};

// Dynamic Thread Vector
const DTV = extern struct {
    entries: usize,
    tls_block: [1][*]u8,
};

// Holds all the information about the process TLS image
const TLSImage = struct {
    init_data: []const u8,
    alloc_size: usize,
    alloc_align: usize,
    tcb_offset: usize,
    dtv_offset: usize,
    data_offset: usize,
    data_size: usize,
    // Only used on the i386 architecture
    gdt_entry_number: usize,
};

pub var tls_image: TLSImage = undefined;

pub fn setThreadPointer(addr: usize) void {
    switch (native_arch) {
        .i386 => {
            var user_desc = std.os.linux.user_desc{
                .entry_number = tls_image.gdt_entry_number,
                .base_addr = addr,
                .limit = 0xfffff,
                .seg_32bit = 1,
                .contents = 0, // Data
                .read_exec_only = 0,
                .limit_in_pages = 1,
                .seg_not_present = 0,
                .useable = 1,
            };
            const rc = std.os.linux.syscall1(.set_thread_area, @ptrToInt(&user_desc));
            assert(rc == 0);

            const gdt_entry_number = user_desc.entry_number;
            // We have to keep track of our slot as it's also needed for clone()
            tls_image.gdt_entry_number = gdt_entry_number;
            // Update the %gs selector
            asm volatile ("movl %[gs_val], %%gs"
                :
                : [gs_val] "r" (gdt_entry_number << 3 | 3)
            );
        },
        .x86_64 => {
            const rc = std.os.linux.syscall2(.arch_prctl, std.os.linux.ARCH_SET_FS, addr);
            assert(rc == 0);
        },
        .aarch64 => {
            asm volatile (
                \\ msr tpidr_el0, %[addr]
                :
                : [addr] "r" (addr)
            );
        },
        .arm, .thumb => {
            const rc = std.os.linux.syscall1(.set_tls, addr);
            assert(rc == 0);
        },
        .riscv64 => {
            asm volatile (
                \\ mv tp, %[addr]
                :
                : [addr] "r" (addr)
            );
        },
        .mips, .mipsel => {
            const rc = std.os.linux.syscall1(.set_thread_area, addr);
            assert(rc == 0);
        },
        .powerpc => {
            asm volatile (
                \\ mr 2, %[addr]
                :
                : [addr] "r" (addr)
            );
        },
        .powerpc64, .powerpc64le => {
            asm volatile (
                \\ mr 13, %[addr]
                :
                : [addr] "r" (addr)
            );
        },
        .sparcv9 => {
            asm volatile (
                \\ mov %[addr], %%g7
                :
                : [addr] "r" (addr)
            );
        },
        else => @compileError("Unsupported architecture"),
    }
}

fn initTLS(phdrs: []elf.Phdr) void {
    var tls_phdr: ?*elf.Phdr = null;
    var img_base: usize = 0;

    for (phdrs) |*phdr| {
        switch (phdr.p_type) {
            elf.PT_PHDR => img_base = @ptrToInt(phdrs.ptr) - phdr.p_vaddr,
            elf.PT_TLS => tls_phdr = phdr,
            else => {},
        }
    }

    var tls_align_factor: usize = undefined;
    var tls_data: []const u8 = undefined;
    var tls_data_alloc_size: usize = undefined;
    if (tls_phdr) |phdr| {
        // The effective size in memory is represented by p_memsz, the length of
        // the data stored in the PT_TLS segment is p_filesz and may be less
        // than the former
        tls_align_factor = phdr.p_align;
        tls_data = @intToPtr([*]u8, img_base + phdr.p_vaddr)[0..phdr.p_filesz];
        tls_data_alloc_size = phdr.p_memsz;
    } else {
        tls_align_factor = @alignOf(usize);
        tls_data = &[_]u8{};
        tls_data_alloc_size = 0;
    }

    // Offsets into the allocated TLS area
    var tcb_offset: usize = undefined;
    var dtv_offset: usize = undefined;
    var data_offset: usize = undefined;
    // Compute the total size of the ABI-specific data plus our own control
    // structures. All the offset calculated here assume a well-aligned base
    // address.
    const alloc_size = switch (tls_variant) {
        .VariantI => blk: {
            var l: usize = 0;
            dtv_offset = l;
            l += @sizeOf(DTV);
            // Add some padding here so that the thread pointer (tcb_offset) is
            // aligned to p_align and the CustomData structure can be found by
            // simply subtracting its @sizeOf from the tp value
            const delta = (l + @sizeOf(CustomData)) & (tls_align_factor - 1);
            if (delta > 0)
                l += tls_align_factor - delta;
            l += @sizeOf(CustomData);
            tcb_offset = l;
            l += mem.alignForward(tls_tcb_size, tls_align_factor);
            data_offset = l;
            l += tls_data_alloc_size;
            break :blk l;
        },
        .VariantII => blk: {
            var l: usize = 0;
            data_offset = l;
            l += mem.alignForward(tls_data_alloc_size, tls_align_factor);
            // The thread pointer is aligned to p_align
            tcb_offset = l;
            l += tls_tcb_size;
            // The CustomData structure is right after the TCB with no padding
            // in between so it can be easily found
            l += @sizeOf(CustomData);
            l = mem.alignForward(l, @alignOf(DTV));
            dtv_offset = l;
            l += @sizeOf(DTV);
            break :blk l;
        },
    };

    tls_image = TLSImage{
        .init_data = tls_data,
        .alloc_size = alloc_size,
        .alloc_align = tls_align_factor,
        .tcb_offset = tcb_offset,
        .dtv_offset = dtv_offset,
        .data_offset = data_offset,
        .data_size = tls_data_alloc_size,
        .gdt_entry_number = @bitCast(usize, @as(isize, -1)),
    };
}

inline fn alignPtrCast(comptime T: type, ptr: [*]u8) *T {
    return @ptrCast(*T, @alignCast(@alignOf(T), ptr));
}

/// Initializes all the fields of the static TLS area and returns the computed
/// architecture-specific value of the thread-pointer register
pub fn prepareTLS(area: []u8) usize {
    // Clear the area we're going to use, just to be safe
    mem.set(u8, area, 0);
    // Prepare the DTV
    const dtv = alignPtrCast(DTV, area.ptr + tls_image.dtv_offset);
    dtv.entries = 1;
    dtv.tls_block[0] = area.ptr + tls_dtv_offset + tls_image.data_offset;
    // Prepare the TCB
    const tcb_ptr = alignPtrCast([*]u8, area.ptr + tls_image.tcb_offset);
    tcb_ptr.* = switch (tls_variant) {
        .VariantI => area.ptr + tls_image.dtv_offset,
        .VariantII => area.ptr + tls_image.tcb_offset,
    };
    // Copy the data
    mem.copy(u8, area[tls_image.data_offset..], tls_image.init_data);

    // Return the corrected (if needed) value for the tp register
    return @ptrToInt(area.ptr) + tls_tp_offset +
        if (tls_tp_points_past_tcb) tls_image.data_offset else tls_image.tcb_offset;
}

// The main motivation for the size chosen here is this is how much ends up being
// requested for the thread local variables of the std.crypto.random implementation.
// I'm not sure why it ends up being so much; the struct itself is only 64 bytes.
// I think it has to do with being page aligned and LLVM or LLD is not smart enough
// to lay out the TLS data in a space conserving way. Anyway I think it's fine
// because it's less than 3 pages of memory, and putting it in the ELF like this
// is equivalent to moving the mmap call below into the kernel, avoiding syscall
// overhead.
var main_thread_tls_buffer: [0x2100]u8 align(mem.page_size) = undefined;

pub fn initStaticTLS(phdrs: []elf.Phdr) void {
    initTLS(phdrs);

    const tls_area = blk: {
        // Fast path for the common case where the TLS data is really small,
        // avoid an allocation and use our local buffer.
        if (tls_image.alloc_align <= mem.page_size and
            tls_image.alloc_size <= main_thread_tls_buffer.len)
        {
            break :blk main_thread_tls_buffer[0..tls_image.alloc_size];
        }

        const alloc_tls_area = os.mmap(
            null,
            tls_image.alloc_size + tls_image.alloc_align - 1,
            os.PROT_READ | os.PROT_WRITE,
            os.MAP_PRIVATE | os.MAP_ANONYMOUS,
            -1,
            0,
        ) catch os.abort();

        // Make sure the slice is correctly aligned.
        const begin_addr = @ptrToInt(alloc_tls_area.ptr);
        const begin_aligned_addr = mem.alignForward(begin_addr, tls_image.alloc_align);
        const start = begin_aligned_addr - begin_addr;
        break :blk alloc_tls_area[start .. start + tls_image.alloc_size];
    };

    const tp_value = prepareTLS(tls_area);
    setThreadPointer(tp_value);
}
