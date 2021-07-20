// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const builtin = @import("builtin");

fn __clzsi2_generic(a: i32) callconv(.C) i32 {
    @setRuntimeSafety(builtin.is_test);

    var x = @bitCast(u32, a);
    var n: i32 = 32;

    // Count first bit set using binary search, from Hacker's Delight
    var y: u32 = 0;
    inline for ([_]i32{ 16, 8, 4, 2, 1 }) |shift| {
        y = x >> shift;
        if (y != 0) {
            n = n - shift;
            x = y;
        }
    }

    return n - @bitCast(i32, x);
}

fn __clzsi2_thumb1() callconv(.Naked) void {
    @setRuntimeSafety(false);

    // Similar to the generic version with the last two rounds replaced by a LUT
    asm volatile (
        \\ movs r1, #32
        \\ lsrs r2, r0, #16
        \\ beq 1f
        \\ subs r1, #16
        \\ movs r0, r2
        \\ 1:
        \\ lsrs r2, r0, #8
        \\ beq 1f
        \\ subs r1, #8
        \\ movs r0, r2
        \\ 1:
        \\ lsrs r2, r0, #4
        \\ beq 1f
        \\ subs r1, #4
        \\ movs r0, r2
        \\ 1:
        \\ ldr r3, =LUT
        \\ ldrb r0, [r3, r0]
        \\ subs r0, r1, r0
        \\ bx lr
        \\ .p2align 2
        \\ // Number of bits set in the 0-15 range
        \\ LUT:
        \\ .byte 0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4
    );

    unreachable;
}

fn __clzsi2_arm32() callconv(.Naked) void {
    @setRuntimeSafety(false);

    asm volatile (
        \\ // Assumption: n != 0
        \\ // r0: n
        \\ // r1: count of leading zeros in n + 1
        \\ // r2: scratch register for shifted r0
        \\ mov r1, #1
        \\
        \\ // Basic block:
        \\ // if ((r0 >> SHIFT) == 0)
        \\ //   r1 += SHIFT;
        \\ // else
        \\ //   r0 >>= SHIFT;
        \\ // for descending powers of two as SHIFT.
        \\ lsrs r2, r0, #16
        \\ movne r0, r2
        \\ addeq r1, #16
        \\
        \\ lsrs r2, r0, #8
        \\ movne r0, r2
        \\ addeq r1, #8
        \\
        \\ lsrs r2, r0, #4
        \\ movne r0, r2
        \\ addeq r1, #4
        \\
        \\ lsrs r2, r0, #2
        \\ movne r0, r2
        \\ addeq r1, #2
        \\
        \\ // The basic block invariants at this point are (r0 >> 2) == 0 and
        \\ // r0 != 0. This means 1 <= r0 <= 3 and 0 <= (r0 >> 1) <= 1.
        \\ //
        \\ // r0 | (r0 >> 1) == 0 | (r0 >> 1) == 1 | -(r0 >> 1) | 1 - (r0 >> 1)f
        \\ // ---+----------------+----------------+------------+--------------
        \\ // 1  | 1              | 0              | 0          | 1
        \\ // 2  | 0              | 1              | -1         | 0
        \\ // 3  | 0              | 1              | -1         | 0
        \\ //
        \\ // The r1's initial value of 1 compensates for the 1 here.
        \\ sub r0, r1, r0, lsr #1
        \\ bx lr
    );

    unreachable;
}

pub const __clzsi2 = impl: {
    switch (builtin.cpu.arch) {
        .arm, .armeb, .thumb, .thumbeb => {
            const use_thumb1 =
                (builtin.cpu.arch.isThumb() or
                std.Target.arm.featureSetHas(builtin.cpu.features, .noarm)) and
                !std.Target.arm.featureSetHas(builtin.cpu.features, .thumb2);

            if (use_thumb1) break :impl __clzsi2_thumb1
            // From here on we're either targeting Thumb2 or ARM.
            else if (!builtin.cpu.arch.isThumb()) break :impl __clzsi2_arm32
            // Use the generic implementation otherwise.
            else break :impl __clzsi2_generic;
        },
        else => break :impl __clzsi2_generic,
    }
};

test "test clzsi2" {
    _ = @import("clzsi2_test.zig");
}
