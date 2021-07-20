// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const Log2Int = std.math.Log2Int;
const native_endian = @import("builtin").cpu.arch.endian();

fn Dwords(comptime T: type, comptime signed_half: bool) type {
    return extern union {
        pub const bits = @divExact(@typeInfo(T).Int.bits, 2);
        pub const HalfTU = std.meta.Int(.unsigned, bits);
        pub const HalfTS = std.meta.Int(.signed, bits);
        pub const HalfT = if (signed_half) HalfTS else HalfTU;

        all: T,
        s: if (native_endian == .Little)
            struct { low: HalfT, high: HalfT }
        else
            struct { high: HalfT, low: HalfT },
    };
}

// Arithmetic shift left
// Precondition: 0 <= b < bits_in_dword
pub fn ashlXi3(comptime T: type, a: T, b: i32) T {
    const dwords = Dwords(T, false);
    const S = Log2Int(dwords.HalfT);

    const input = dwords{ .all = a };
    var output: dwords = undefined;

    if (b >= dwords.bits) {
        output.s.low = 0;
        output.s.high = input.s.low << @intCast(S, b - dwords.bits);
    } else if (b == 0) {
        return a;
    } else {
        output.s.low = input.s.low << @intCast(S, b);
        output.s.high = input.s.high << @intCast(S, b);
        output.s.high |= input.s.low >> @intCast(S, dwords.bits - b);
    }

    return output.all;
}

// Arithmetic shift right
// Precondition: 0 <= b < T.bit_count
pub fn ashrXi3(comptime T: type, a: T, b: i32) T {
    const dwords = Dwords(T, true);
    const S = Log2Int(dwords.HalfT);

    const input = dwords{ .all = a };
    var output: dwords = undefined;

    if (b >= dwords.bits) {
        output.s.high = input.s.high >> (dwords.bits - 1);
        output.s.low = input.s.high >> @intCast(S, b - dwords.bits);
    } else if (b == 0) {
        return a;
    } else {
        output.s.high = input.s.high >> @intCast(S, b);
        output.s.low = input.s.high << @intCast(S, dwords.bits - b);
        // Avoid sign-extension here
        output.s.low |= @bitCast(
            dwords.HalfT,
            @bitCast(dwords.HalfTU, input.s.low) >> @intCast(S, b),
        );
    }

    return output.all;
}

// Logical shift right
// Precondition: 0 <= b < T.bit_count
pub fn lshrXi3(comptime T: type, a: T, b: i32) T {
    const dwords = Dwords(T, false);
    const S = Log2Int(dwords.HalfT);

    const input = dwords{ .all = a };
    var output: dwords = undefined;

    if (b >= dwords.bits) {
        output.s.high = 0;
        output.s.low = input.s.high >> @intCast(S, b - dwords.bits);
    } else if (b == 0) {
        return a;
    } else {
        output.s.high = input.s.high >> @intCast(S, b);
        output.s.low = input.s.high << @intCast(S, dwords.bits - b);
        output.s.low |= input.s.low >> @intCast(S, b);
    }

    return output.all;
}

pub fn __ashldi3(a: i64, b: i32) callconv(.C) i64 {
    return @call(.{ .modifier = .always_inline }, ashlXi3, .{ i64, a, b });
}
pub fn __ashlti3(a: i128, b: i32) callconv(.C) i128 {
    return @call(.{ .modifier = .always_inline }, ashlXi3, .{ i128, a, b });
}
pub fn __ashrdi3(a: i64, b: i32) callconv(.C) i64 {
    return @call(.{ .modifier = .always_inline }, ashrXi3, .{ i64, a, b });
}
pub fn __ashrti3(a: i128, b: i32) callconv(.C) i128 {
    return @call(.{ .modifier = .always_inline }, ashrXi3, .{ i128, a, b });
}
pub fn __lshrdi3(a: i64, b: i32) callconv(.C) i64 {
    return @call(.{ .modifier = .always_inline }, lshrXi3, .{ i64, a, b });
}
pub fn __lshrti3(a: i128, b: i32) callconv(.C) i128 {
    return @call(.{ .modifier = .always_inline }, lshrXi3, .{ i128, a, b });
}

pub fn __aeabi_llsl(a: i64, b: i32) callconv(.AAPCS) i64 {
    return __ashldi3(a, b);
}
pub fn __aeabi_lasr(a: i64, b: i32) callconv(.AAPCS) i64 {
    return __ashrdi3(a, b);
}
pub fn __aeabi_llsr(a: i64, b: i32) callconv(.AAPCS) i64 {
    return __lshrdi3(a, b);
}

test {
    _ = @import("ashrdi3_test.zig");
    _ = @import("ashrti3_test.zig");

    _ = @import("ashldi3_test.zig");
    _ = @import("ashlti3_test.zig");

    _ = @import("lshrdi3_test.zig");
    _ = @import("lshrti3_test.zig");
}
