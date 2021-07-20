// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const compiler_rt = @import("../compiler_rt.zig");
const std = @import("std");
const builtin = @import("builtin");
const is_test = builtin.is_test;
const native_endian = builtin.cpu.arch.endian();

// Ported from git@github.com:llvm-project/llvm-project-20170507.git
// ae684fad6d34858c014c94da69c15e7774a633c3
// 2018-08-13

pub fn __multi3(a: i128, b: i128) callconv(.C) i128 {
    @setRuntimeSafety(is_test);
    const x = twords{ .all = a };
    const y = twords{ .all = b };
    var r = twords{ .all = __mulddi3(x.s.low, y.s.low) };
    r.s.high +%= x.s.high *% y.s.low +% x.s.low *% y.s.high;
    return r.all;
}

const v128 = @import("std").meta.Vector(2, u64);
pub fn __multi3_windows_x86_64(a: v128, b: v128) callconv(.C) v128 {
    return @bitCast(v128, @call(.{ .modifier = .always_inline }, __multi3, .{
        @bitCast(i128, a),
        @bitCast(i128, b),
    }));
}

fn __mulddi3(a: u64, b: u64) i128 {
    const bits_in_dword_2 = (@sizeOf(i64) * 8) / 2;
    const lower_mask = ~@as(u64, 0) >> bits_in_dword_2;
    var r: twords = undefined;
    r.s.low = (a & lower_mask) *% (b & lower_mask);
    var t: u64 = r.s.low >> bits_in_dword_2;
    r.s.low &= lower_mask;
    t +%= (a >> bits_in_dword_2) *% (b & lower_mask);
    r.s.low +%= (t & lower_mask) << bits_in_dword_2;
    r.s.high = t >> bits_in_dword_2;
    t = r.s.low >> bits_in_dword_2;
    r.s.low &= lower_mask;
    t +%= (b >> bits_in_dword_2) *% (a & lower_mask);
    r.s.low +%= (t & lower_mask) << bits_in_dword_2;
    r.s.high +%= t >> bits_in_dword_2;
    r.s.high +%= (a >> bits_in_dword_2) *% (b >> bits_in_dword_2);
    return r.all;
}

const twords = extern union {
    all: i128,
    s: S,

    const S = if (native_endian == .Little)
        struct {
            low: u64,
            high: u64,
        }
    else
        struct {
            high: u64,
            low: u64,
        };
};

test "import multi3" {
    _ = @import("multi3_test.zig");
}
