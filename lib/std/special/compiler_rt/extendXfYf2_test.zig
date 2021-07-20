// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const builtin = @import("builtin");
const __extendhfsf2 = @import("extendXfYf2.zig").__extendhfsf2;
const __extendhftf2 = @import("extendXfYf2.zig").__extendhftf2;
const __extendsftf2 = @import("extendXfYf2.zig").__extendsftf2;
const __extenddftf2 = @import("extendXfYf2.zig").__extenddftf2;

fn test__extenddftf2(a: f64, expectedHi: u64, expectedLo: u64) !void {
    const x = __extenddftf2(a);

    const rep = @bitCast(u128, x);
    const hi = @intCast(u64, rep >> 64);
    const lo = @truncate(u64, rep);

    if (hi == expectedHi and lo == expectedLo)
        return;

    // test other possible NaN representation(signal NaN)
    if (expectedHi == 0x7fff800000000000 and expectedLo == 0x0) {
        if ((hi & 0x7fff000000000000) == 0x7fff000000000000 and
            ((hi & 0xffffffffffff) > 0 or lo > 0))
        {
            return;
        }
    }

    @panic("__extenddftf2 test failure");
}

fn test__extendhfsf2(a: u16, expected: u32) !void {
    const x = __extendhfsf2(a);
    const rep = @bitCast(u32, x);

    if (rep == expected) {
        if (rep & 0x7fffffff > 0x7f800000) {
            return; // NaN is always unequal.
        }
        if (x == @bitCast(f32, expected)) {
            return;
        }
    }

    return error.TestFailure;
}

fn test__extendsftf2(a: f32, expectedHi: u64, expectedLo: u64) !void {
    const x = __extendsftf2(a);

    const rep = @bitCast(u128, x);
    const hi = @intCast(u64, rep >> 64);
    const lo = @truncate(u64, rep);

    if (hi == expectedHi and lo == expectedLo)
        return;

    // test other possible NaN representation(signal NaN)
    if (expectedHi == 0x7fff800000000000 and expectedLo == 0x0) {
        if ((hi & 0x7fff000000000000) == 0x7fff000000000000 and
            ((hi & 0xffffffffffff) > 0 or lo > 0))
        {
            return;
        }
    }

    return error.TestFailure;
}

test "extenddftf2" {
    // qNaN
    try test__extenddftf2(makeQNaN64(), 0x7fff800000000000, 0x0);

    // NaN
    try test__extenddftf2(makeNaN64(0x7100000000000), 0x7fff710000000000, 0x0);

    // inf
    try test__extenddftf2(makeInf64(), 0x7fff000000000000, 0x0);

    // zero
    try test__extenddftf2(0.0, 0x0, 0x0);

    try test__extenddftf2(0x1.23456789abcdefp+5, 0x400423456789abcd, 0xf000000000000000);

    try test__extenddftf2(0x1.edcba987654321fp-9, 0x3ff6edcba9876543, 0x2000000000000000);

    try test__extenddftf2(0x1.23456789abcdefp+45, 0x402c23456789abcd, 0xf000000000000000);

    try test__extenddftf2(0x1.edcba987654321fp-45, 0x3fd2edcba9876543, 0x2000000000000000);
}

test "extendhfsf2" {
    try test__extendhfsf2(0x7e00, 0x7fc00000); // qNaN
    try test__extendhfsf2(0x7f00, 0x7fe00000); // sNaN
    // On x86 the NaN becomes quiet because the return is pushed on the x87
    // stack due to ABI requirements
    if (builtin.cpu.arch != .i386 and builtin.os.tag == .windows)
        try test__extendhfsf2(0x7c01, 0x7f802000); // sNaN

    try test__extendhfsf2(0, 0); // 0
    try test__extendhfsf2(0x8000, 0x80000000); // -0

    try test__extendhfsf2(0x7c00, 0x7f800000); // inf
    try test__extendhfsf2(0xfc00, 0xff800000); // -inf

    try test__extendhfsf2(0x0001, 0x33800000); // denormal (min), 2**-24
    try test__extendhfsf2(0x8001, 0xb3800000); // denormal (min), -2**-24

    try test__extendhfsf2(0x03ff, 0x387fc000); // denormal (max), 2**-14 - 2**-24
    try test__extendhfsf2(0x83ff, 0xb87fc000); // denormal (max), -2**-14 + 2**-24

    try test__extendhfsf2(0x0400, 0x38800000); // normal (min), 2**-14
    try test__extendhfsf2(0x8400, 0xb8800000); // normal (min), -2**-14

    try test__extendhfsf2(0x7bff, 0x477fe000); // normal (max), 65504
    try test__extendhfsf2(0xfbff, 0xc77fe000); // normal (max), -65504

    try test__extendhfsf2(0x3c01, 0x3f802000); // normal, 1 + 2**-10
    try test__extendhfsf2(0xbc01, 0xbf802000); // normal, -1 - 2**-10

    try test__extendhfsf2(0x3555, 0x3eaaa000); // normal, approx. 1/3
    try test__extendhfsf2(0xb555, 0xbeaaa000); // normal, approx. -1/3
}

test "extendsftf2" {
    // qNaN
    try test__extendsftf2(makeQNaN32(), 0x7fff800000000000, 0x0);
    // NaN
    try test__extendsftf2(makeNaN32(0x410000), 0x7fff820000000000, 0x0);
    // inf
    try test__extendsftf2(makeInf32(), 0x7fff000000000000, 0x0);
    // zero
    try test__extendsftf2(0.0, 0x0, 0x0);
    try test__extendsftf2(0x1.23456p+5, 0x4004234560000000, 0x0);
    try test__extendsftf2(0x1.edcbap-9, 0x3ff6edcba0000000, 0x0);
    try test__extendsftf2(0x1.23456p+45, 0x402c234560000000, 0x0);
    try test__extendsftf2(0x1.edcbap-45, 0x3fd2edcba0000000, 0x0);
}

fn makeQNaN64() f64 {
    return @bitCast(f64, @as(u64, 0x7ff8000000000000));
}

fn makeInf64() f64 {
    return @bitCast(f64, @as(u64, 0x7ff0000000000000));
}

fn makeNaN64(rand: u64) f64 {
    return @bitCast(f64, 0x7ff0000000000000 | (rand & 0xfffffffffffff));
}

fn makeQNaN32() f32 {
    return @bitCast(f32, @as(u32, 0x7fc00000));
}

fn makeNaN32(rand: u32) f32 {
    return @bitCast(f32, 0x7f800000 | (rand & 0x7fffff));
}

fn makeInf32() f32 {
    return @bitCast(f32, @as(u32, 0x7f800000));
}

fn test__extendhftf2(a: u16, expectedHi: u64, expectedLo: u64) !void {
    const x = __extendhftf2(a);

    const rep = @bitCast(u128, x);
    const hi = @intCast(u64, rep >> 64);
    const lo = @truncate(u64, rep);

    if (hi == expectedHi and lo == expectedLo)
        return;

    // test other possible NaN representation(signal NaN)
    if (expectedHi == 0x7fff800000000000 and expectedLo == 0x0) {
        if ((hi & 0x7fff000000000000) == 0x7fff000000000000 and
            ((hi & 0xffffffffffff) > 0 or lo > 0))
        {
            return;
        }
    }

    return error.TestFailure;
}

test "extendhftf2" {
    // qNaN
    try test__extendhftf2(0x7e00, 0x7fff800000000000, 0x0);
    // NaN
    try test__extendhftf2(0x7d00, 0x7fff400000000000, 0x0);
    // inf
    try test__extendhftf2(0x7c00, 0x7fff000000000000, 0x0);
    try test__extendhftf2(0xfc00, 0xffff000000000000, 0x0);
    // zero
    try test__extendhftf2(0x0000, 0x0000000000000000, 0x0);
    try test__extendhftf2(0x8000, 0x8000000000000000, 0x0);
    // denormal
    try test__extendhftf2(0x0010, 0x3feb000000000000, 0x0);
    try test__extendhftf2(0x0001, 0x3fe7000000000000, 0x0);
    try test__extendhftf2(0x8001, 0xbfe7000000000000, 0x0);

    // pi
    try test__extendhftf2(0x4248, 0x4000920000000000, 0x0);
    try test__extendhftf2(0xc248, 0xc000920000000000, 0x0);

    try test__extendhftf2(0x508c, 0x4004230000000000, 0x0);
    try test__extendhftf2(0x1bb7, 0x3ff6edc000000000, 0x0);
}
