// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const builtin = @import("builtin");
const is_test = builtin.is_test;
const native_endian = builtin.cpu.arch.endian();

const low = switch (native_endian) {
    .Big => 1,
    .Little => 0,
};
const high = 1 - low;

pub fn udivmod(comptime DoubleInt: type, a: DoubleInt, b: DoubleInt, maybe_rem: ?*DoubleInt) DoubleInt {
    @setRuntimeSafety(is_test);

    const double_int_bits = @typeInfo(DoubleInt).Int.bits;
    const single_int_bits = @divExact(double_int_bits, 2);
    const SingleInt = @import("std").meta.Int(.unsigned, single_int_bits);
    const SignedDoubleInt = @import("std").meta.Int(.signed, double_int_bits);
    const Log2SingleInt = @import("std").math.Log2Int(SingleInt);

    const n = @ptrCast(*const [2]SingleInt, &a).*; // TODO issue #421
    const d = @ptrCast(*const [2]SingleInt, &b).*; // TODO issue #421
    var q: [2]SingleInt = undefined;
    var r: [2]SingleInt = undefined;
    var sr: c_uint = undefined;
    // special cases, X is unknown, K != 0
    if (n[high] == 0) {
        if (d[high] == 0) {
            // 0 X
            // ---
            // 0 X
            if (maybe_rem) |rem| {
                rem.* = n[low] % d[low];
            }
            return n[low] / d[low];
        }
        // 0 X
        // ---
        // K X
        if (maybe_rem) |rem| {
            rem.* = n[low];
        }
        return 0;
    }
    // n[high] != 0
    if (d[low] == 0) {
        if (d[high] == 0) {
            // K X
            // ---
            // 0 0
            if (maybe_rem) |rem| {
                rem.* = n[high] % d[low];
            }
            return n[high] / d[low];
        }
        // d[high] != 0
        if (n[low] == 0) {
            // K 0
            // ---
            // K 0
            if (maybe_rem) |rem| {
                r[high] = n[high] % d[high];
                r[low] = 0;
                rem.* = @ptrCast(*align(@alignOf(SingleInt)) DoubleInt, &r[0]).*; // TODO issue #421
            }
            return n[high] / d[high];
        }
        // K K
        // ---
        // K 0
        if ((d[high] & (d[high] - 1)) == 0) {
            // d is a power of 2
            if (maybe_rem) |rem| {
                r[low] = n[low];
                r[high] = n[high] & (d[high] - 1);
                rem.* = @ptrCast(*align(@alignOf(SingleInt)) DoubleInt, &r[0]).*; // TODO issue #421
            }
            return n[high] >> @intCast(Log2SingleInt, @ctz(SingleInt, d[high]));
        }
        // K K
        // ---
        // K 0
        sr = @bitCast(c_uint, @as(c_int, @clz(SingleInt, d[high])) - @as(c_int, @clz(SingleInt, n[high])));
        // 0 <= sr <= single_int_bits - 2 or sr large
        if (sr > single_int_bits - 2) {
            if (maybe_rem) |rem| {
                rem.* = a;
            }
            return 0;
        }
        sr += 1;
        // 1 <= sr <= single_int_bits - 1
        // q.all = a << (double_int_bits - sr);
        q[low] = 0;
        q[high] = n[low] << @intCast(Log2SingleInt, single_int_bits - sr);
        // r.all = a >> sr;
        r[high] = n[high] >> @intCast(Log2SingleInt, sr);
        r[low] = (n[high] << @intCast(Log2SingleInt, single_int_bits - sr)) | (n[low] >> @intCast(Log2SingleInt, sr));
    } else {
        // d[low] != 0
        if (d[high] == 0) {
            // K X
            // ---
            // 0 K
            if ((d[low] & (d[low] - 1)) == 0) {
                // d is a power of 2
                if (maybe_rem) |rem| {
                    rem.* = n[low] & (d[low] - 1);
                }
                if (d[low] == 1) {
                    return a;
                }
                sr = @ctz(SingleInt, d[low]);
                q[high] = n[high] >> @intCast(Log2SingleInt, sr);
                q[low] = (n[high] << @intCast(Log2SingleInt, single_int_bits - sr)) | (n[low] >> @intCast(Log2SingleInt, sr));
                return @ptrCast(*align(@alignOf(SingleInt)) DoubleInt, &q[0]).*; // TODO issue #421
            }
            // K X
            // ---
            // 0 K
            sr = 1 + single_int_bits + @as(c_uint, @clz(SingleInt, d[low])) - @as(c_uint, @clz(SingleInt, n[high]));
            // 2 <= sr <= double_int_bits - 1
            // q.all = a << (double_int_bits - sr);
            // r.all = a >> sr;
            if (sr == single_int_bits) {
                q[low] = 0;
                q[high] = n[low];
                r[high] = 0;
                r[low] = n[high];
            } else if (sr < single_int_bits) {
                // 2 <= sr <= single_int_bits - 1
                q[low] = 0;
                q[high] = n[low] << @intCast(Log2SingleInt, single_int_bits - sr);
                r[high] = n[high] >> @intCast(Log2SingleInt, sr);
                r[low] = (n[high] << @intCast(Log2SingleInt, single_int_bits - sr)) | (n[low] >> @intCast(Log2SingleInt, sr));
            } else {
                // single_int_bits + 1 <= sr <= double_int_bits - 1
                q[low] = n[low] << @intCast(Log2SingleInt, double_int_bits - sr);
                q[high] = (n[high] << @intCast(Log2SingleInt, double_int_bits - sr)) | (n[low] >> @intCast(Log2SingleInt, sr - single_int_bits));
                r[high] = 0;
                r[low] = n[high] >> @intCast(Log2SingleInt, sr - single_int_bits);
            }
        } else {
            // K X
            // ---
            // K K
            sr = @bitCast(c_uint, @as(c_int, @clz(SingleInt, d[high])) - @as(c_int, @clz(SingleInt, n[high])));
            // 0 <= sr <= single_int_bits - 1 or sr large
            if (sr > single_int_bits - 1) {
                if (maybe_rem) |rem| {
                    rem.* = a;
                }
                return 0;
            }
            sr += 1;
            // 1 <= sr <= single_int_bits
            // q.all = a << (double_int_bits - sr);
            // r.all = a >> sr;
            q[low] = 0;
            if (sr == single_int_bits) {
                q[high] = n[low];
                r[high] = 0;
                r[low] = n[high];
            } else {
                r[high] = n[high] >> @intCast(Log2SingleInt, sr);
                r[low] = (n[high] << @intCast(Log2SingleInt, single_int_bits - sr)) | (n[low] >> @intCast(Log2SingleInt, sr));
                q[high] = n[low] << @intCast(Log2SingleInt, single_int_bits - sr);
            }
        }
    }
    // Not a special case
    // q and r are initialized with:
    // q.all = a << (double_int_bits - sr);
    // r.all = a >> sr;
    // 1 <= sr <= double_int_bits - 1
    var carry: u32 = 0;
    var r_all: DoubleInt = undefined;
    while (sr > 0) : (sr -= 1) {
        // r:q = ((r:q)  << 1) | carry
        r[high] = (r[high] << 1) | (r[low] >> (single_int_bits - 1));
        r[low] = (r[low] << 1) | (q[high] >> (single_int_bits - 1));
        q[high] = (q[high] << 1) | (q[low] >> (single_int_bits - 1));
        q[low] = (q[low] << 1) | carry;
        // carry = 0;
        // if (r.all >= b)
        // {
        //     r.all -= b;
        //      carry = 1;
        // }
        r_all = @ptrCast(*align(@alignOf(SingleInt)) DoubleInt, &r[0]).*; // TODO issue #421
        const s: SignedDoubleInt = @bitCast(SignedDoubleInt, b -% r_all -% 1) >> (double_int_bits - 1);
        carry = @intCast(u32, s & 1);
        r_all -= b & @bitCast(DoubleInt, s);
        r = @ptrCast(*[2]SingleInt, &r_all).*; // TODO issue #421
    }
    const q_all = ((@ptrCast(*align(@alignOf(SingleInt)) DoubleInt, &q[0]).*) << 1) | carry; // TODO issue #421
    if (maybe_rem) |rem| {
        rem.* = r_all;
    }
    return q_all;
}
