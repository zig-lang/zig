// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("std");
const assert = std.debug.assert;
const builtin = std.builtin;
const crypto = std.crypto;
const debug = std.debug;
const Ghash = std.crypto.onetimeauth.Ghash;
const mem = std.mem;
const modes = crypto.core.modes;
const AuthenticationError = crypto.errors.AuthenticationError;

pub const Aes128Gcm = AesGcm(crypto.core.aes.Aes128);
pub const Aes256Gcm = AesGcm(crypto.core.aes.Aes256);

fn AesGcm(comptime Aes: anytype) type {
    debug.assert(Aes.block.block_length == 16);

    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 12;
        pub const key_length = Aes.key_bits / 8;

        const zeros = [_]u8{0} ** 16;

        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            debug.assert(c.len == m.len);
            debug.assert(m.len <= 16 * ((1 << 32) - 2));

            const aes = Aes.initEnc(key);
            var h: [16]u8 = undefined;
            aes.encrypt(&h, &zeros);

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            mem.copy(u8, j[0..nonce_length], npub[0..]);
            mem.writeIntBig(u32, j[nonce_length..][0..4], 1);
            aes.encrypt(&t, &j);

            var mac = Ghash.init(&h);
            mac.update(ad);
            mac.pad();

            mem.writeIntBig(u32, j[nonce_length..][0..4], 2);
            modes.ctr(@TypeOf(aes), aes, c, m, j, std.builtin.Endian.Big);
            mac.update(c[0..m.len][0..]);
            mac.pad();

            var final_block = h;
            mem.writeIntBig(u64, final_block[0..8], ad.len * 8);
            mem.writeIntBig(u64, final_block[8..16], m.len * 8);
            mac.update(&final_block);
            mac.final(tag);
            for (t) |x, i| {
                tag[i] ^= x;
            }
        }

        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
            assert(c.len == m.len);

            const aes = Aes.initEnc(key);
            var h: [16]u8 = undefined;
            aes.encrypt(&h, &zeros);

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            mem.copy(u8, j[0..nonce_length], npub[0..]);
            mem.writeIntBig(u32, j[nonce_length..][0..4], 1);
            aes.encrypt(&t, &j);

            var mac = Ghash.init(&h);
            mac.update(ad);
            mac.pad();

            mac.update(c);
            mac.pad();

            var final_block = h;
            mem.writeIntBig(u64, final_block[0..8], ad.len * 8);
            mem.writeIntBig(u64, final_block[8..16], m.len * 8);
            mac.update(&final_block);
            var computed_tag: [Ghash.mac_length]u8 = undefined;
            mac.final(&computed_tag);
            for (t) |x, i| {
                computed_tag[i] ^= x;
            }

            var acc: u8 = 0;
            for (computed_tag) |_, p| {
                acc |= (computed_tag[p] ^ tag[p]);
            }
            if (acc != 0) {
                mem.set(u8, m, 0xaa);
                return error.AuthenticationFailed;
            }

            mem.writeIntBig(u32, j[nonce_length..][0..4], 2);
            modes.ctr(@TypeOf(aes), aes, m, c, j, std.builtin.Endian.Big);
        }
    };
}

const htest = @import("test.zig");
const testing = std.testing;

test "Aes256Gcm - Empty message and no associated data" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const ad = "";
    const m = "";
    var c: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try htest.assertEqual("6b6ff610a16fa4cd59f1fb7903154e92", &tag);
}

test "Aes256Gcm - Associated data only" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const m = "";
    const ad = "Test with associated data";
    var c: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try htest.assertEqual("262ed164c2dfb26e080a9d108dd9dd4c", &tag);
}

test "Aes256Gcm - Message only" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const m = "Test with message only";
    const ad = "";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try Aes256Gcm.decrypt(&m2, &c, tag, ad, nonce, key);
    try testing.expectEqualSlices(u8, m[0..], m2[0..]);

    try htest.assertEqual("5ca1642d90009fea33d01f78cf6eefaf01d539472f7c", &c);
    try htest.assertEqual("07cd7fc9103e2f9e9bf2dfaa319caff4", &tag);
}

test "Aes256Gcm - Message and associated data" {
    const key: [Aes256Gcm.key_length]u8 = [_]u8{0x69} ** Aes256Gcm.key_length;
    const nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes256Gcm.nonce_length;
    const m = "Test with message";
    const ad = "Test with associated data";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    Aes256Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try Aes256Gcm.decrypt(&m2, &c, tag, ad, nonce, key);
    try testing.expectEqualSlices(u8, m[0..], m2[0..]);

    try htest.assertEqual("5ca1642d90009fea33d01f78cf6eefaf01", &c);
    try htest.assertEqual("64accec679d444e2373bd9f6796c0d2c", &tag);
}
