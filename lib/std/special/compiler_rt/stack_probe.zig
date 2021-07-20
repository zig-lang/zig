// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const native_arch = @import("builtin").target.cpu.arch;

// Zig's own stack-probe routine (available only on x86 and x86_64)
pub fn zig_probe_stack() callconv(.Naked) void {
    @setRuntimeSafety(false);

    // Versions of the Linux kernel before 5.1 treat any access below SP as
    // invalid so let's update it on the go, otherwise we'll get a segfault
    // instead of triggering the stack growth.

    switch (native_arch) {
        .x86_64 => {
            // %rax = probe length, %rsp = stack pointer
            asm volatile (
                \\        push   %%rcx
                \\        mov    %%rax, %%rcx
                \\        cmp    $0x1000,%%rcx
                \\        jb     2f
                \\ 1:
                \\        sub    $0x1000,%%rsp
                \\        orl    $0,16(%%rsp)
                \\        sub    $0x1000,%%rcx
                \\        cmp    $0x1000,%%rcx
                \\        ja     1b
                \\ 2:
                \\        sub    %%rcx, %%rsp
                \\        orl    $0,16(%%rsp)
                \\        add    %%rax,%%rsp
                \\        pop    %%rcx
                \\        ret
            );
        },
        .i386 => {
            // %eax = probe length, %esp = stack pointer
            asm volatile (
                \\        push   %%ecx
                \\        mov    %%eax, %%ecx
                \\        cmp    $0x1000,%%ecx
                \\        jb     2f
                \\ 1:
                \\        sub    $0x1000,%%esp
                \\        orl    $0,8(%%esp)
                \\        sub    $0x1000,%%ecx
                \\        cmp    $0x1000,%%ecx
                \\        ja     1b
                \\ 2:
                \\        sub    %%ecx, %%esp
                \\        orl    $0,8(%%esp)
                \\        add    %%eax,%%esp
                \\        pop    %%ecx
                \\        ret
            );
        },
        else => {},
    }

    unreachable;
}

fn win_probe_stack_only() void {
    @setRuntimeSafety(false);

    switch (native_arch) {
        .x86_64 => {
            asm volatile (
                \\         push   %%rcx
                \\         push   %%rax
                \\         cmp    $0x1000,%%rax
                \\         lea    24(%%rsp),%%rcx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         sub    $0x1000,%%rax
                \\         cmp    $0x1000,%%rax
                \\         ja     2b
                \\ 1:
                \\         sub    %%rax,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         pop    %%rax
                \\         pop    %%rcx
                \\         ret
            );
        },
        .i386 => {
            asm volatile (
                \\         push   %%ecx
                \\         push   %%eax
                \\         cmp    $0x1000,%%eax
                \\         lea    12(%%esp),%%ecx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         sub    $0x1000,%%eax
                \\         cmp    $0x1000,%%eax
                \\         ja     2b
                \\ 1:
                \\         sub    %%eax,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         pop    %%eax
                \\         pop    %%ecx
                \\         ret
            );
        },
        else => {},
    }

    unreachable;
}

fn win_probe_stack_adjust_sp() void {
    @setRuntimeSafety(false);

    switch (native_arch) {
        .x86_64 => {
            asm volatile (
                \\         push   %%rcx
                \\         cmp    $0x1000,%%rax
                \\         lea    16(%%rsp),%%rcx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         sub    $0x1000,%%rax
                \\         cmp    $0x1000,%%rax
                \\         ja     2b
                \\ 1:
                \\         sub    %%rax,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\
                \\         lea    8(%%rsp),%%rax
                \\         mov    %%rcx,%%rsp
                \\         mov    -8(%%rax),%%rcx
                \\         push   (%%rax)
                \\         sub    %%rsp,%%rax
                \\         ret
            );
        },
        .i386 => {
            asm volatile (
                \\         push   %%ecx
                \\         cmp    $0x1000,%%eax
                \\         lea    8(%%esp),%%ecx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         sub    $0x1000,%%eax
                \\         cmp    $0x1000,%%eax
                \\         ja     2b
                \\ 1:
                \\         sub    %%eax,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\
                \\         lea    4(%%esp),%%eax
                \\         mov    %%ecx,%%esp
                \\         mov    -4(%%eax),%%ecx
                \\         push   (%%eax)
                \\         sub    %%esp,%%eax
                \\         ret
            );
        },
        else => {},
    }

    unreachable;
}

// Windows has a multitude of stack-probing functions with similar names and
// slightly different behaviours: some behave as alloca() and update the stack
// pointer after probing the stack, other do not.
//
// Function name        | Adjusts the SP? |
//                      | x86    | x86_64 |
// ----------------------------------------
// _chkstk (_alloca)    | yes    | yes    |
// __chkstk             | yes    | no     |
// __chkstk_ms          | no     | no     |
// ___chkstk (__alloca) | yes    | yes    |
// ___chkstk_ms         | no     | no     |

pub fn _chkstk() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.{ .modifier = .always_inline }, win_probe_stack_adjust_sp, .{});
}
pub fn __chkstk() callconv(.Naked) void {
    @setRuntimeSafety(false);
    switch (native_arch) {
        .i386 => @call(.{ .modifier = .always_inline }, win_probe_stack_adjust_sp, .{}),
        .x86_64 => @call(.{ .modifier = .always_inline }, win_probe_stack_only, .{}),
        else => unreachable,
    }
}
pub fn ___chkstk() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.{ .modifier = .always_inline }, win_probe_stack_adjust_sp, .{});
}
pub fn __chkstk_ms() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.{ .modifier = .always_inline }, win_probe_stack_only, .{});
}
pub fn ___chkstk_ms() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.{ .modifier = .always_inline }, win_probe_stack_only, .{});
}
