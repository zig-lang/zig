// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const builtin = @import("builtin");
const is_test = builtin.is_test;
const native_endian = builtin.cpu.arch.endian();

// Ported from
// https://github.com/llvm/llvm-project/blob/llvmorg-9.0.0/compiler-rt/lib/builtins/muldi3.c

const dwords = extern union {
    all: i64,
    s: switch (native_endian) {
        .Little => extern struct {
            low: u32,
            high: u32,
        },
        .Big => extern struct {
            high: u32,
            low: u32,
        },
    },
};

fn __muldsi3(a: u32, b: u32) i64 {
    @setRuntimeSafety(is_test);

    const bits_in_word_2 = @sizeOf(i32) * 8 / 2;
    const lower_mask = (~@as(u32, 0)) >> bits_in_word_2;

    var r: dwords = undefined;
    r.s.low = (a & lower_mask) *% (b & lower_mask);
    var t: u32 = r.s.low >> bits_in_word_2;
    r.s.low &= lower_mask;
    t += (a >> bits_in_word_2) *% (b & lower_mask);
    r.s.low +%= (t & lower_mask) << bits_in_word_2;
    r.s.high = t >> bits_in_word_2;
    t = r.s.low >> bits_in_word_2;
    r.s.low &= lower_mask;
    t +%= (b >> bits_in_word_2) *% (a & lower_mask);
    r.s.low +%= (t & lower_mask) << bits_in_word_2;
    r.s.high +%= t >> bits_in_word_2;
    r.s.high +%= (a >> bits_in_word_2) *% (b >> bits_in_word_2);
    return r.all;
}

pub fn __muldi3(a: i64, b: i64) callconv(.C) i64 {
    @setRuntimeSafety(is_test);

    const x = dwords{ .all = a };
    const y = dwords{ .all = b };
    var r = dwords{ .all = __muldsi3(x.s.low, y.s.low) };
    r.s.high +%= x.s.high *% y.s.low +% x.s.low *% y.s.high;
    return r.all;
}

test "import muldi3" {
    _ = @import("muldi3_test.zig");
}
