// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;
const utils = std.crypto.utils;
const Vector = std.meta.Vector;

const Poly1305 = crypto.onetimeauth.Poly1305;
const Blake2b = crypto.hash.blake2.Blake2b;
const X25519 = crypto.dh.X25519;

const AuthenticationError = crypto.errors.AuthenticationError;
const IdentityElementError = crypto.errors.IdentityElementError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

const Salsa20VecImpl = struct {
    const Lane = Vector(4, u32);
    const Half = Vector(2, u32);
    const BlockVec = [4]Lane;

    fn initContext(key: [8]u32, d: [4]u32) BlockVec {
        const c = "expand 32-byte k";
        const constant_le = comptime [4]u32{
            mem.readIntLittle(u32, c[0..4]),
            mem.readIntLittle(u32, c[4..8]),
            mem.readIntLittle(u32, c[8..12]),
            mem.readIntLittle(u32, c[12..16]),
        };
        return BlockVec{
            Lane{ key[0], key[1], key[2], key[3] },
            Lane{ key[4], key[5], key[6], key[7] },
            Lane{ constant_le[0], constant_le[1], constant_le[2], constant_le[3] },
            Lane{ d[0], d[1], d[2], d[3] },
        };
    }

    inline fn salsa20Core(x: *BlockVec, input: BlockVec, comptime feedback: bool) void {
        const n1n2n3n0 = Lane{ input[3][1], input[3][2], input[3][3], input[3][0] };
        const n1n2 = Half{ n1n2n3n0[0], n1n2n3n0[1] };
        const n3n0 = Half{ n1n2n3n0[2], n1n2n3n0[3] };
        const k0k1 = Half{ input[0][0], input[0][1] };
        const k2k3 = Half{ input[0][2], input[0][3] };
        const k4k5 = Half{ input[1][0], input[1][1] };
        const k6k7 = Half{ input[1][2], input[1][3] };
        const n0k0 = Half{ n3n0[1], k0k1[0] };
        const k0n0 = Half{ n0k0[1], n0k0[0] };
        const k4k5k0n0 = Lane{ k4k5[0], k4k5[1], k0n0[0], k0n0[1] };
        const k1k6 = Half{ k0k1[1], k6k7[0] };
        const k6k1 = Half{ k1k6[1], k1k6[0] };
        const n1n2k6k1 = Lane{ n1n2[0], n1n2[1], k6k1[0], k6k1[1] };
        const k7n3 = Half{ k6k7[1], n3n0[0] };
        const n3k7 = Half{ k7n3[1], k7n3[0] };
        const k2k3n3k7 = Lane{ k2k3[0], k2k3[1], n3k7[0], n3k7[1] };

        var diag0 = input[2];
        var diag1 = @shuffle(u32, k4k5k0n0, undefined, [_]i32{ 1, 2, 3, 0 });
        var diag2 = @shuffle(u32, n1n2k6k1, undefined, [_]i32{ 1, 2, 3, 0 });
        var diag3 = @shuffle(u32, k2k3n3k7, undefined, [_]i32{ 1, 2, 3, 0 });

        const start0 = diag0;
        const start1 = diag1;
        const start2 = diag2;
        const start3 = diag3;

        var i: usize = 0;
        while (i < 20) : (i += 2) {
            var a0 = diag1 +% diag0;
            diag3 ^= math.rotl(Lane, a0, 7);
            var a1 = diag0 +% diag3;
            diag2 ^= math.rotl(Lane, a1, 9);
            var a2 = diag3 +% diag2;
            diag1 ^= math.rotl(Lane, a2, 13);
            var a3 = diag2 +% diag1;
            diag0 ^= math.rotl(Lane, a3, 18);

            var diag3_shift = @shuffle(u32, diag3, undefined, [_]i32{ 3, 0, 1, 2 });
            var diag2_shift = @shuffle(u32, diag2, undefined, [_]i32{ 2, 3, 0, 1 });
            var diag1_shift = @shuffle(u32, diag1, undefined, [_]i32{ 1, 2, 3, 0 });
            diag3 = diag3_shift;
            diag2 = diag2_shift;
            diag1 = diag1_shift;

            a0 = diag3 +% diag0;
            diag1 ^= math.rotl(Lane, a0, 7);
            a1 = diag0 +% diag1;
            diag2 ^= math.rotl(Lane, a1, 9);
            a2 = diag1 +% diag2;
            diag3 ^= math.rotl(Lane, a2, 13);
            a3 = diag2 +% diag3;
            diag0 ^= math.rotl(Lane, a3, 18);

            diag1_shift = @shuffle(u32, diag1, undefined, [_]i32{ 3, 0, 1, 2 });
            diag2_shift = @shuffle(u32, diag2, undefined, [_]i32{ 2, 3, 0, 1 });
            diag3_shift = @shuffle(u32, diag3, undefined, [_]i32{ 1, 2, 3, 0 });
            diag1 = diag1_shift;
            diag2 = diag2_shift;
            diag3 = diag3_shift;
        }

        if (feedback) {
            diag0 +%= start0;
            diag1 +%= start1;
            diag2 +%= start2;
            diag3 +%= start3;
        }

        const x0x1x10x11 = Lane{ diag0[0], diag1[1], diag0[2], diag1[3] };
        const x12x13x6x7 = Lane{ diag1[0], diag2[1], diag1[2], diag2[3] };
        const x8x9x2x3 = Lane{ diag2[0], diag3[1], diag2[2], diag3[3] };
        const x4x5x14x15 = Lane{ diag3[0], diag0[1], diag3[2], diag0[3] };

        x[0] = Lane{ x0x1x10x11[0], x0x1x10x11[1], x8x9x2x3[2], x8x9x2x3[3] };
        x[1] = Lane{ x4x5x14x15[0], x4x5x14x15[1], x12x13x6x7[2], x12x13x6x7[3] };
        x[2] = Lane{ x8x9x2x3[0], x8x9x2x3[1], x0x1x10x11[2], x0x1x10x11[3] };
        x[3] = Lane{ x12x13x6x7[0], x12x13x6x7[1], x4x5x14x15[2], x4x5x14x15[3] };
    }

    fn hashToBytes(out: *[64]u8, x: BlockVec) void {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            mem.writeIntLittle(u32, out[16 * i + 0 ..][0..4], x[i][0]);
            mem.writeIntLittle(u32, out[16 * i + 4 ..][0..4], x[i][1]);
            mem.writeIntLittle(u32, out[16 * i + 8 ..][0..4], x[i][2]);
            mem.writeIntLittle(u32, out[16 * i + 12 ..][0..4], x[i][3]);
        }
    }

    fn salsa20Xor(out: []u8, in: []const u8, key: [8]u32, d: [4]u32) void {
        var ctx = initContext(key, d);
        var x: BlockVec = undefined;
        var buf: [64]u8 = undefined;
        var i: usize = 0;
        while (i + 64 <= in.len) : (i += 64) {
            salsa20Core(x[0..], ctx, true);
            hashToBytes(buf[0..], x);
            var xout = out[i..];
            const xin = in[i..];
            var j: usize = 0;
            while (j < 64) : (j += 1) {
                xout[j] = xin[j];
            }
            j = 0;
            while (j < 64) : (j += 1) {
                xout[j] ^= buf[j];
            }
            ctx[3][2] +%= 1;
            if (ctx[3][2] == 0) {
                ctx[3][3] += 1;
            }
        }
        if (i < in.len) {
            salsa20Core(x[0..], ctx, true);
            hashToBytes(buf[0..], x);

            var xout = out[i..];
            const xin = in[i..];
            var j: usize = 0;
            while (j < in.len % 64) : (j += 1) {
                xout[j] = xin[j] ^ buf[j];
            }
        }
    }

    fn hsalsa20(input: [16]u8, key: [32]u8) [32]u8 {
        var c: [4]u32 = undefined;
        for (c) |_, i| {
            c[i] = mem.readIntLittle(u32, input[4 * i ..][0..4]);
        }
        const ctx = initContext(keyToWords(key), c);
        var x: BlockVec = undefined;
        salsa20Core(x[0..], ctx, false);
        var out: [32]u8 = undefined;
        mem.writeIntLittle(u32, out[0..4], x[0][0]);
        mem.writeIntLittle(u32, out[4..8], x[1][1]);
        mem.writeIntLittle(u32, out[8..12], x[2][2]);
        mem.writeIntLittle(u32, out[12..16], x[3][3]);
        mem.writeIntLittle(u32, out[16..20], x[1][2]);
        mem.writeIntLittle(u32, out[20..24], x[1][3]);
        mem.writeIntLittle(u32, out[24..28], x[2][0]);
        mem.writeIntLittle(u32, out[28..32], x[2][1]);
        return out;
    }
};

const Salsa20NonVecImpl = struct {
    const BlockVec = [16]u32;

    fn initContext(key: [8]u32, d: [4]u32) BlockVec {
        const c = "expand 32-byte k";
        const constant_le = comptime [4]u32{
            mem.readIntLittle(u32, c[0..4]),
            mem.readIntLittle(u32, c[4..8]),
            mem.readIntLittle(u32, c[8..12]),
            mem.readIntLittle(u32, c[12..16]),
        };
        return BlockVec{
            constant_le[0], key[0],         key[1],         key[2],
            key[3],         constant_le[1], d[0],           d[1],
            d[2],           d[3],           constant_le[2], key[4],
            key[5],         key[6],         key[7],         constant_le[3],
        };
    }

    const QuarterRound = struct {
        a: usize,
        b: usize,
        c: usize,
        d: u6,
    };

    inline fn Rp(a: usize, b: usize, c: usize, d: u6) QuarterRound {
        return QuarterRound{
            .a = a,
            .b = b,
            .c = c,
            .d = d,
        };
    }

    inline fn salsa20Core(x: *BlockVec, input: BlockVec, comptime feedback: bool) void {
        const arx_steps = comptime [_]QuarterRound{
            Rp(4, 0, 12, 7),   Rp(8, 4, 0, 9),    Rp(12, 8, 4, 13),   Rp(0, 12, 8, 18),
            Rp(9, 5, 1, 7),    Rp(13, 9, 5, 9),   Rp(1, 13, 9, 13),   Rp(5, 1, 13, 18),
            Rp(14, 10, 6, 7),  Rp(2, 14, 10, 9),  Rp(6, 2, 14, 13),   Rp(10, 6, 2, 18),
            Rp(3, 15, 11, 7),  Rp(7, 3, 15, 9),   Rp(11, 7, 3, 13),   Rp(15, 11, 7, 18),
            Rp(1, 0, 3, 7),    Rp(2, 1, 0, 9),    Rp(3, 2, 1, 13),    Rp(0, 3, 2, 18),
            Rp(6, 5, 4, 7),    Rp(7, 6, 5, 9),    Rp(4, 7, 6, 13),    Rp(5, 4, 7, 18),
            Rp(11, 10, 9, 7),  Rp(8, 11, 10, 9),  Rp(9, 8, 11, 13),   Rp(10, 9, 8, 18),
            Rp(12, 15, 14, 7), Rp(13, 12, 15, 9), Rp(14, 13, 12, 13), Rp(15, 14, 13, 18),
        };
        x.* = input;
        var j: usize = 0;
        while (j < 20) : (j += 2) {
            inline for (arx_steps) |r| {
                x[r.a] ^= math.rotl(u32, x[r.b] +% x[r.c], r.d);
            }
        }
        if (feedback) {
            j = 0;
            while (j < 16) : (j += 1) {
                x[j] +%= input[j];
            }
        }
    }

    fn hashToBytes(out: *[64]u8, x: BlockVec) void {
        for (x) |w, i| {
            mem.writeIntLittle(u32, out[i * 4 ..][0..4], w);
        }
    }

    fn salsa20Xor(out: []u8, in: []const u8, key: [8]u32, d: [4]u32) void {
        var ctx = initContext(key, d);
        var x: BlockVec = undefined;
        var buf: [64]u8 = undefined;
        var i: usize = 0;
        while (i + 64 <= in.len) : (i += 64) {
            salsa20Core(x[0..], ctx, true);
            hashToBytes(buf[0..], x);
            var xout = out[i..];
            const xin = in[i..];
            var j: usize = 0;
            while (j < 64) : (j += 1) {
                xout[j] = xin[j];
            }
            j = 0;
            while (j < 64) : (j += 1) {
                xout[j] ^= buf[j];
            }
            ctx[9] += @boolToInt(@addWithOverflow(u32, ctx[8], 1, &ctx[8]));
        }
        if (i < in.len) {
            salsa20Core(x[0..], ctx, true);
            hashToBytes(buf[0..], x);

            var xout = out[i..];
            const xin = in[i..];
            var j: usize = 0;
            while (j < in.len % 64) : (j += 1) {
                xout[j] = xin[j] ^ buf[j];
            }
        }
    }

    fn hsalsa20(input: [16]u8, key: [32]u8) [32]u8 {
        var c: [4]u32 = undefined;
        for (c) |_, i| {
            c[i] = mem.readIntLittle(u32, input[4 * i ..][0..4]);
        }
        const ctx = initContext(keyToWords(key), c);
        var x: BlockVec = undefined;
        salsa20Core(x[0..], ctx, false);
        var out: [32]u8 = undefined;
        mem.writeIntLittle(u32, out[0..4], x[0]);
        mem.writeIntLittle(u32, out[4..8], x[5]);
        mem.writeIntLittle(u32, out[8..12], x[10]);
        mem.writeIntLittle(u32, out[12..16], x[15]);
        mem.writeIntLittle(u32, out[16..20], x[6]);
        mem.writeIntLittle(u32, out[20..24], x[7]);
        mem.writeIntLittle(u32, out[24..28], x[8]);
        mem.writeIntLittle(u32, out[28..32], x[9]);
        return out;
    }
};

const Salsa20Impl = if (builtin.cpu.arch == .x86_64) Salsa20VecImpl else Salsa20NonVecImpl;

fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        k[i] = mem.readIntLittle(u32, key[i * 4 ..][0..4]);
    }
    return k;
}

fn extend(key: [32]u8, nonce: [24]u8) struct { key: [32]u8, nonce: [8]u8 } {
    return .{
        .key = Salsa20Impl.hsalsa20(nonce[0..16].*, key),
        .nonce = nonce[16..24].*,
    };
}

/// The Salsa20 stream cipher.
pub const Salsa20 = struct {
    /// Nonce length in bytes.
    pub const nonce_length = 8;
    /// Key length in bytes.
    pub const key_length = 32;

    /// Add the output of the Salsa20 stream cipher to `in` and stores the result into `out`.
    /// WARNING: This function doesn't provide authenticated encryption.
    /// Using the AEAD or one of the `box` versions is usually preferred.
    pub fn xor(out: []u8, in: []const u8, counter: u64, key: [key_length]u8, nonce: [nonce_length]u8) void {
        debug.assert(in.len == out.len);

        var d: [4]u32 = undefined;
        d[0] = mem.readIntLittle(u32, nonce[0..4]);
        d[1] = mem.readIntLittle(u32, nonce[4..8]);
        d[2] = @truncate(u32, counter);
        d[3] = @truncate(u32, counter >> 32);
        Salsa20Impl.salsa20Xor(out, in, keyToWords(key), d);
    }
};

/// The XSalsa20 stream cipher.
pub const XSalsa20 = struct {
    /// Nonce length in bytes.
    pub const nonce_length = 24;
    /// Key length in bytes.
    pub const key_length = 32;

    /// Add the output of the XSalsa20 stream cipher to `in` and stores the result into `out`.
    /// WARNING: This function doesn't provide authenticated encryption.
    /// Using the AEAD or one of the `box` versions is usually preferred.
    pub fn xor(out: []u8, in: []const u8, counter: u64, key: [key_length]u8, nonce: [nonce_length]u8) void {
        const extended = extend(key, nonce);
        Salsa20.xor(out, in, counter, extended.key, extended.nonce);
    }
};

/// The XSalsa20 stream cipher, combined with the Poly1305 MAC
pub const XSalsa20Poly1305 = struct {
    /// Authentication tag length in bytes.
    pub const tag_length = Poly1305.mac_length;
    /// Nonce length in bytes.
    pub const nonce_length = XSalsa20.nonce_length;
    /// Key length in bytes.
    pub const key_length = XSalsa20.key_length;

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        debug.assert(c.len == m.len);
        const extended = extend(k, npub);
        var block0 = [_]u8{0} ** 64;
        const mlen0 = math.min(32, m.len);
        mem.copy(u8, block0[32..][0..mlen0], m[0..mlen0]);
        Salsa20.xor(block0[0..], block0[0..], 0, extended.key, extended.nonce);
        mem.copy(u8, c[0..mlen0], block0[32..][0..mlen0]);
        Salsa20.xor(c[mlen0..], m[mlen0..], 1, extended.key, extended.nonce);
        var mac = Poly1305.init(block0[0..32]);
        mac.update(ad);
        mac.update(c);
        mac.final(tag);
    }

    /// m: message: output buffer should be of size c.len
    /// c: ciphertext
    /// tag: authentication tag
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        debug.assert(c.len == m.len);
        const extended = extend(k, npub);
        var block0 = [_]u8{0} ** 64;
        const mlen0 = math.min(32, c.len);
        mem.copy(u8, block0[32..][0..mlen0], c[0..mlen0]);
        Salsa20.xor(block0[0..], block0[0..], 0, extended.key, extended.nonce);
        var mac = Poly1305.init(block0[0..32]);
        mac.update(ad);
        mac.update(c);
        var computedTag: [tag_length]u8 = undefined;
        mac.final(&computedTag);
        var acc: u8 = 0;
        for (computedTag) |_, i| {
            acc |= computedTag[i] ^ tag[i];
        }
        if (acc != 0) {
            utils.secureZero(u8, &computedTag);
            return error.AuthenticationFailed;
        }
        mem.copy(u8, m[0..mlen0], block0[32..][0..mlen0]);
        Salsa20.xor(m[mlen0..], c[mlen0..], 1, extended.key, extended.nonce);
    }
};

/// NaCl-compatible secretbox API.
///
/// A secretbox contains both an encrypted message and an authentication tag to verify that it hasn't been tampered with.
/// A secret key shared by all the recipients must be already known in order to use this API.
///
/// Nonces are 192-bit large and can safely be chosen with a random number generator.
pub const SecretBox = struct {
    /// Key length in bytes.
    pub const key_length = XSalsa20Poly1305.key_length;
    /// Nonce length in bytes.
    pub const nonce_length = XSalsa20Poly1305.nonce_length;
    /// Authentication tag length in bytes.
    pub const tag_length = XSalsa20Poly1305.tag_length;

    /// Encrypt and authenticate `m` using a nonce `npub` and a key `k`.
    /// `c` must be exactly `tag_length` longer than `m`, as it will store both the ciphertext and the authentication tag.
    pub fn seal(c: []u8, m: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        debug.assert(c.len == tag_length + m.len);
        XSalsa20Poly1305.encrypt(c[tag_length..], c[0..tag_length], m, "", npub, k);
    }

    /// Verify and decrypt `c` using a nonce `npub` and a key `k`.
    /// `m` must be exactly `tag_length` smaller than `c`, as `c` includes an authentication tag in addition to the encrypted message.
    pub fn open(m: []u8, c: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        if (c.len < tag_length) {
            return error.AuthenticationFailed;
        }
        debug.assert(m.len == c.len - tag_length);
        return XSalsa20Poly1305.decrypt(m, c[tag_length..], c[0..tag_length].*, "", npub, k);
    }
};

/// NaCl-compatible box API.
///
/// A secretbox contains both an encrypted message and an authentication tag to verify that it hasn't been tampered with.
/// This construction uses public-key cryptography. A shared secret doesn't have to be known in advance by both parties.
/// Instead, a message is encrypted using a sender's secret key and a recipient's public key,
/// and is decrypted using the recipient's secret key and the sender's public key.
///
/// Nonces are 192-bit large and can safely be chosen with a random number generator.
pub const Box = struct {
    /// Public key length in bytes.
    pub const public_length = X25519.public_length;
    /// Secret key length in bytes.
    pub const secret_length = X25519.secret_length;
    /// Shared key length in bytes.
    pub const shared_length = XSalsa20Poly1305.key_length;
    /// Seed (for key pair creation) length in bytes.
    pub const seed_length = X25519.seed_length;
    /// Nonce length in bytes.
    pub const nonce_length = XSalsa20Poly1305.nonce_length;
    /// Authentication tag length in bytes.
    pub const tag_length = XSalsa20Poly1305.tag_length;

    /// A key pair.
    pub const KeyPair = X25519.KeyPair;

    /// Compute a secret suitable for `secretbox` given a recipent's public key and a sender's secret key.
    pub fn createSharedSecret(public_key: [public_length]u8, secret_key: [secret_length]u8) (IdentityElementError || WeakPublicKeyError)![shared_length]u8 {
        const p = try X25519.scalarmult(secret_key, public_key);
        const zero = [_]u8{0} ** 16;
        return Salsa20Impl.hsalsa20(zero, p);
    }

    /// Encrypt and authenticate a message using a recipient's public key `public_key` and a sender's `secret_key`.
    pub fn seal(c: []u8, m: []const u8, npub: [nonce_length]u8, public_key: [public_length]u8, secret_key: [secret_length]u8) (IdentityElementError || WeakPublicKeyError)!void {
        const shared_key = try createSharedSecret(public_key, secret_key);
        return SecretBox.seal(c, m, npub, shared_key);
    }

    /// Verify and decrypt a message using a recipient's secret key `public_key` and a sender's `public_key`.
    pub fn open(m: []u8, c: []const u8, npub: [nonce_length]u8, public_key: [public_length]u8, secret_key: [secret_length]u8) (IdentityElementError || WeakPublicKeyError || AuthenticationError)!void {
        const shared_key = try createSharedSecret(public_key, secret_key);
        return SecretBox.open(m, c, npub, shared_key);
    }
};

/// libsodium-compatible sealed boxes
///
/// Sealed boxes are designed to anonymously send messages to a recipient given their public key.
/// Only the recipient can decrypt these messages, using their private key.
/// While the recipient can verify the integrity of the message, it cannot verify the identity of the sender.
///
/// A message is encrypted using an ephemeral key pair, whose secret part is destroyed right after the encryption process.
pub const SealedBox = struct {
    pub const public_length = Box.public_length;
    pub const secret_length = Box.secret_length;
    pub const seed_length = Box.seed_length;
    pub const seal_length = Box.public_length + Box.tag_length;

    /// A key pair.
    pub const KeyPair = Box.KeyPair;

    fn createNonce(pk1: [public_length]u8, pk2: [public_length]u8) [Box.nonce_length]u8 {
        var hasher = Blake2b(Box.nonce_length * 8).init(.{});
        hasher.update(&pk1);
        hasher.update(&pk2);
        var nonce: [Box.nonce_length]u8 = undefined;
        hasher.final(&nonce);
        return nonce;
    }

    /// Encrypt a message `m` for a recipient whose public key is `public_key`.
    /// `c` must be `seal_length` bytes larger than `m`, so that the required metadata can be added.
    pub fn seal(c: []u8, m: []const u8, public_key: [public_length]u8) (WeakPublicKeyError || IdentityElementError)!void {
        debug.assert(c.len == m.len + seal_length);
        var ekp = try KeyPair.create(null);
        const nonce = createNonce(ekp.public_key, public_key);
        mem.copy(u8, c[0..public_length], ekp.public_key[0..]);
        try Box.seal(c[Box.public_length..], m, nonce, public_key, ekp.secret_key);
        utils.secureZero(u8, ekp.secret_key[0..]);
    }

    /// Decrypt a message using a key pair.
    /// `m` must be exactly `seal_length` bytes smaller than `c`, as `c` also includes metadata.
    pub fn open(m: []u8, c: []const u8, keypair: KeyPair) (IdentityElementError || WeakPublicKeyError || AuthenticationError)!void {
        if (c.len < seal_length) {
            return error.AuthenticationFailed;
        }
        const epk = c[0..public_length];
        const nonce = createNonce(epk.*, keypair.public_key);
        return Box.open(m, c[public_length..], nonce, epk.*, keypair.secret_key);
    }
};

const htest = @import("test.zig");

test "(x)salsa20" {
    const key = [_]u8{0x69} ** 32;
    const nonce = [_]u8{0x42} ** 8;
    const msg = [_]u8{0} ** 20;
    var c: [msg.len]u8 = undefined;

    Salsa20.xor(&c, msg[0..], 0, key, nonce);
    try htest.assertEqual("30ff9933aa6534ff5207142593cd1fca4b23bdd8", c[0..]);

    const extended_nonce = [_]u8{0x42} ** 24;
    XSalsa20.xor(&c, msg[0..], 0, key, extended_nonce);
    try htest.assertEqual("b4ab7d82e750ec07644fa3281bce6cd91d4243f9", c[0..]);
}

test "xsalsa20poly1305" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var key: [XSalsa20Poly1305.key_length]u8 = undefined;
    var nonce: [XSalsa20Poly1305.nonce_length]u8 = undefined;
    var tag: [XSalsa20Poly1305.tag_length]u8 = undefined;
    crypto.random.bytes(&msg);
    crypto.random.bytes(&key);
    crypto.random.bytes(&nonce);

    XSalsa20Poly1305.encrypt(c[0..], &tag, msg[0..], "ad", nonce, key);
    try XSalsa20Poly1305.decrypt(msg2[0..], c[0..], tag, "ad", nonce, key);
}

test "xsalsa20poly1305 secretbox" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var key: [XSalsa20Poly1305.key_length]u8 = undefined;
    var nonce: [Box.nonce_length]u8 = undefined;
    var boxed: [msg.len + Box.tag_length]u8 = undefined;
    crypto.random.bytes(&msg);
    crypto.random.bytes(&key);
    crypto.random.bytes(&nonce);

    SecretBox.seal(boxed[0..], msg[0..], nonce, key);
    try SecretBox.open(msg2[0..], boxed[0..], nonce, key);
}

test "xsalsa20poly1305 box" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var nonce: [Box.nonce_length]u8 = undefined;
    var boxed: [msg.len + Box.tag_length]u8 = undefined;
    crypto.random.bytes(&msg);
    crypto.random.bytes(&nonce);

    var kp1 = try Box.KeyPair.create(null);
    var kp2 = try Box.KeyPair.create(null);
    try Box.seal(boxed[0..], msg[0..], nonce, kp1.public_key, kp2.secret_key);
    try Box.open(msg2[0..], boxed[0..], nonce, kp2.public_key, kp1.secret_key);
}

test "xsalsa20poly1305 sealedbox" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var boxed: [msg.len + SealedBox.seal_length]u8 = undefined;
    crypto.random.bytes(&msg);

    var kp = try Box.KeyPair.create(null);
    try SealedBox.seal(boxed[0..], msg[0..], kp.public_key);
    try SealedBox.open(msg2[0..], boxed[0..], kp);
}

test "secretbox twoblocks" {
    const key = [_]u8{ 0xc9, 0xc9, 0x4d, 0xcf, 0x68, 0xbe, 0x00, 0xe4, 0x7f, 0xe6, 0x13, 0x26, 0xfc, 0xc4, 0x2f, 0xd0, 0xdb, 0x93, 0x91, 0x1c, 0x09, 0x94, 0x89, 0xe1, 0x1b, 0x88, 0x63, 0x18, 0x86, 0x64, 0x8b, 0x7b };
    const nonce = [_]u8{ 0xa4, 0x33, 0xe9, 0x0a, 0x07, 0x68, 0x6e, 0x9a, 0x2b, 0x6d, 0xd4, 0x59, 0x04, 0x72, 0x3e, 0xd3, 0x8a, 0x67, 0x55, 0xc7, 0x9e, 0x3e, 0x77, 0xdc };
    const msg = [_]u8{'a'} ** 97;
    var ciphertext: [msg.len + SecretBox.tag_length]u8 = undefined;
    SecretBox.seal(&ciphertext, &msg, nonce, key);
    try htest.assertEqual("b05760e217288ba079caa2fd57fd3701784974ffcfda20fe523b89211ad8af065a6eb37cdb29d51aca5bd75dafdd21d18b044c54bb7c526cf576c94ee8900f911ceab0147e82b667a28c52d58ceb29554ff45471224d37b03256b01c119b89ff6d36855de8138d103386dbc9d971f52261", &ciphertext);
}
