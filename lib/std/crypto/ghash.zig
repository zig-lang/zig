// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
//
// Adapted from BearSSL's ctmul64 implementation originally written by Thomas Pornin <pornin@bolet.org>

const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const utils = std.crypto.utils;

/// GHASH is a universal hash function that features multiplication
/// by a fixed parameter within a Galois field.
///
/// It is not a general purpose hash function - The key must be secret, unpredictable and never reused.
///
/// GHASH is typically used to compute the authentication tag in the AES-GCM construction.
pub const Ghash = struct {
    pub const block_length: usize = 16;
    pub const mac_length = 16;
    pub const key_length = 16;

    y0: u64 = 0,
    y1: u64 = 0,
    h0: u64,
    h1: u64,
    h2: u64,
    h0r: u64,
    h1r: u64,
    h2r: u64,

    hh0: u64 = undefined,
    hh1: u64 = undefined,
    hh2: u64 = undefined,
    hh0r: u64 = undefined,
    hh1r: u64 = undefined,
    hh2r: u64 = undefined,

    leftover: usize = 0,
    buf: [block_length]u8 align(16) = undefined,

    pub fn init(key: *const [key_length]u8) Ghash {
        const h1 = mem.readIntBig(u64, key[0..8]);
        const h0 = mem.readIntBig(u64, key[8..16]);
        const h1r = @bitReverse(u64, h1);
        const h0r = @bitReverse(u64, h0);
        const h2 = h0 ^ h1;
        const h2r = h0r ^ h1r;

        if (builtin.mode == .ReleaseSmall) {
            return Ghash{
                .h0 = h0,
                .h1 = h1,
                .h2 = h2,
                .h0r = h0r,
                .h1r = h1r,
                .h2r = h2r,
            };
        } else {
            // Precompute H^2
            var hh = Ghash{
                .h0 = h0,
                .h1 = h1,
                .h2 = h2,
                .h0r = h0r,
                .h1r = h1r,
                .h2r = h2r,
            };
            hh.update(key);
            const hh1 = hh.y1;
            const hh0 = hh.y0;
            const hh1r = @bitReverse(u64, hh1);
            const hh0r = @bitReverse(u64, hh0);
            const hh2 = hh0 ^ hh1;
            const hh2r = hh0r ^ hh1r;

            return Ghash{
                .h0 = h0,
                .h1 = h1,
                .h2 = h2,
                .h0r = h0r,
                .h1r = h1r,
                .h2r = h2r,

                .hh0 = hh0,
                .hh1 = hh1,
                .hh2 = hh2,
                .hh0r = hh0r,
                .hh1r = hh1r,
                .hh2r = hh2r,
            };
        }
    }

    inline fn clmul_pclmul(x: u64, y: u64) u64 {
        const Vector = std.meta.Vector;
        const product = asm (
            \\ vpclmulqdq $0x00, %[x], %[y], %[out]
            : [out] "=x" (-> Vector(2, u64))
            : [x] "x" (@bitCast(Vector(2, u64), @as(u128, x))),
              [y] "x" (@bitCast(Vector(2, u64), @as(u128, y)))
        );
        return product[0];
    }

    inline fn clmul_pmull(x: u64, y: u64) u64 {
        const Vector = std.meta.Vector;
        const product = asm (
            \\ pmull %[out].1q, %[x].1d, %[y].1d
            : [out] "=w" (-> Vector(2, u64))
            : [x] "w" (@bitCast(Vector(2, u64), @as(u128, x))),
              [y] "w" (@bitCast(Vector(2, u64), @as(u128, y)))
        );
        return product[0];
    }

    fn clmul_soft(x: u64, y: u64) u64 {
        const x0 = x & 0x1111111111111111;
        const x1 = x & 0x2222222222222222;
        const x2 = x & 0x4444444444444444;
        const x3 = x & 0x8888888888888888;
        const y0 = y & 0x1111111111111111;
        const y1 = y & 0x2222222222222222;
        const y2 = y & 0x4444444444444444;
        const y3 = y & 0x8888888888888888;
        var z0 = (x0 *% y0) ^ (x1 *% y3) ^ (x2 *% y2) ^ (x3 *% y1);
        var z1 = (x0 *% y1) ^ (x1 *% y0) ^ (x2 *% y3) ^ (x3 *% y2);
        var z2 = (x0 *% y2) ^ (x1 *% y1) ^ (x2 *% y0) ^ (x3 *% y3);
        var z3 = (x0 *% y3) ^ (x1 *% y2) ^ (x2 *% y1) ^ (x3 *% y0);
        z0 &= 0x1111111111111111;
        z1 &= 0x2222222222222222;
        z2 &= 0x4444444444444444;
        z3 &= 0x8888888888888888;
        return z0 | z1 | z2 | z3;
    }

    const has_pclmul = std.Target.x86.featureSetHas(builtin.cpu.features, .pclmul);
    const has_avx = std.Target.x86.featureSetHas(builtin.cpu.features, .avx);
    const has_armaes = std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes);
    const clmul = if (builtin.cpu.arch == .x86_64 and has_pclmul and has_avx) impl: {
        break :impl clmul_pclmul;
    } else if (builtin.cpu.arch == .aarch64 and has_armaes) impl: {
        break :impl clmul_pmull;
    } else impl: {
        break :impl clmul_soft;
    };

    fn blocks(st: *Ghash, msg: []const u8) void {
        assert(msg.len % 16 == 0); // GHASH blocks() expects full blocks
        var y1 = st.y1;
        var y0 = st.y0;

        var i: usize = 0;

        // 2-blocks aggregated reduction
        if (builtin.mode != .ReleaseSmall) {
            while (i + 32 <= msg.len) : (i += 32) {
                // B0 * H^2 unreduced
                y1 ^= mem.readIntBig(u64, msg[i..][0..8]);
                y0 ^= mem.readIntBig(u64, msg[i..][8..16]);

                const y1r = @bitReverse(u64, y1);
                const y0r = @bitReverse(u64, y0);
                const y2 = y0 ^ y1;
                const y2r = y0r ^ y1r;

                var z0 = clmul(y0, st.hh0);
                var z1 = clmul(y1, st.hh1);
                var z2 = clmul(y2, st.hh2) ^ z0 ^ z1;
                var z0h = clmul(y0r, st.hh0r);
                var z1h = clmul(y1r, st.hh1r);
                var z2h = clmul(y2r, st.hh2r) ^ z0h ^ z1h;

                // B1 * H unreduced
                const sy1 = mem.readIntBig(u64, msg[i..][16..24]);
                const sy0 = mem.readIntBig(u64, msg[i..][24..32]);

                const sy1r = @bitReverse(u64, sy1);
                const sy0r = @bitReverse(u64, sy0);
                const sy2 = sy0 ^ sy1;
                const sy2r = sy0r ^ sy1r;

                const sz0 = clmul(sy0, st.h0);
                const sz1 = clmul(sy1, st.h1);
                const sz2 = clmul(sy2, st.h2) ^ sz0 ^ sz1;
                const sz0h = clmul(sy0r, st.h0r);
                const sz1h = clmul(sy1r, st.h1r);
                const sz2h = clmul(sy2r, st.h2r) ^ sz0h ^ sz1h;

                // ((B0 * H^2) + B1 * H) (mod M)
                z0 ^= sz0;
                z1 ^= sz1;
                z2 ^= sz2;
                z0h ^= sz0h;
                z1h ^= sz1h;
                z2h ^= sz2h;
                z0h = @bitReverse(u64, z0h) >> 1;
                z1h = @bitReverse(u64, z1h) >> 1;
                z2h = @bitReverse(u64, z2h) >> 1;

                var v3 = z1h;
                var v2 = z1 ^ z2h;
                var v1 = z0h ^ z2;
                var v0 = z0;

                v3 = (v3 << 1) | (v2 >> 63);
                v2 = (v2 << 1) | (v1 >> 63);
                v1 = (v1 << 1) | (v0 >> 63);
                v0 = (v0 << 1);

                v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
                v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
                y1 = v3 ^ v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
                y0 = v2 ^ (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
            }
        }

        // single block
        while (i + 16 <= msg.len) : (i += 16) {
            y1 ^= mem.readIntBig(u64, msg[i..][0..8]);
            y0 ^= mem.readIntBig(u64, msg[i..][8..16]);

            const y1r = @bitReverse(u64, y1);
            const y0r = @bitReverse(u64, y0);
            const y2 = y0 ^ y1;
            const y2r = y0r ^ y1r;

            const z0 = clmul(y0, st.h0);
            const z1 = clmul(y1, st.h1);
            var z2 = clmul(y2, st.h2) ^ z0 ^ z1;
            var z0h = clmul(y0r, st.h0r);
            var z1h = clmul(y1r, st.h1r);
            var z2h = clmul(y2r, st.h2r) ^ z0h ^ z1h;
            z0h = @bitReverse(u64, z0h) >> 1;
            z1h = @bitReverse(u64, z1h) >> 1;
            z2h = @bitReverse(u64, z2h) >> 1;

            // shift & reduce
            var v3 = z1h;
            var v2 = z1 ^ z2h;
            var v1 = z0h ^ z2;
            var v0 = z0;

            v3 = (v3 << 1) | (v2 >> 63);
            v2 = (v2 << 1) | (v1 >> 63);
            v1 = (v1 << 1) | (v0 >> 63);
            v0 = (v0 << 1);

            v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
            v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
            y1 = v3 ^ v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
            y0 = v2 ^ (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
        }
        st.y1 = y1;
        st.y0 = y0;
    }

    pub fn update(st: *Ghash, m: []const u8) void {
        var mb = m;

        if (st.leftover > 0) {
            const want = math.min(block_length - st.leftover, mb.len);
            const mc = mb[0..want];
            for (mc) |x, i| {
                st.buf[st.leftover + i] = x;
            }
            mb = mb[want..];
            st.leftover += want;
            if (st.leftover < block_length) {
                return;
            }
            st.blocks(&st.buf);
            st.leftover = 0;
        }
        if (mb.len >= block_length) {
            const want = mb.len & ~(block_length - 1);
            st.blocks(mb[0..want]);
            mb = mb[want..];
        }
        if (mb.len > 0) {
            for (mb) |x, i| {
                st.buf[st.leftover + i] = x;
            }
            st.leftover += mb.len;
        }
    }

    /// Zero-pad to align the next input to the first byte of a block
    pub fn pad(st: *Ghash) void {
        if (st.leftover == 0) {
            return;
        }
        var i = st.leftover;
        while (i < block_length) : (i += 1) {
            st.buf[i] = 0;
        }
        st.blocks(&st.buf);
        st.leftover = 0;
    }

    pub fn final(st: *Ghash, out: *[mac_length]u8) void {
        st.pad();
        mem.writeIntBig(u64, out[0..8], st.y1);
        mem.writeIntBig(u64, out[8..16], st.y0);

        utils.secureZero(u8, @ptrCast([*]u8, st)[0..@sizeOf(Ghash)]);
    }

    pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
        var st = Ghash.init(key);
        st.update(msg);
        st.final(out);
    }
};

const htest = @import("test.zig");

test "ghash" {
    const key = [_]u8{0x42} ** 16;
    const m = [_]u8{0x69} ** 256;

    var st = Ghash.init(&key);
    st.update(&m);
    var out: [16]u8 = undefined;
    st.final(&out);
    try htest.assertEqual("889295fa746e8b174bf4ec80a65dea41", &out);

    st = Ghash.init(&key);
    st.update(m[0..100]);
    st.update(m[100..]);
    st.final(&out);
    try htest.assertEqual("889295fa746e8b174bf4ec80a65dea41", &out);
}
