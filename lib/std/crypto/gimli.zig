// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
// Gimli is a 384-bit permutation designed to achieve high security with high
// performance across a broad range of platforms, including 64-bit Intel/AMD
// server CPUs, 64-bit and 32-bit ARM smartphone CPUs, 32-bit ARM
// microcontrollers, 8-bit AVR microcontrollers, FPGAs, ASICs without
// side-channel protection, and ASICs with side-channel protection.
//
// https://gimli.cr.yp.to/
// https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/round-1/spec-doc/gimli-spec.pdf

const std = @import("../std.zig");
const builtin = @import("builtin");
const mem = std.mem;
const math = std.math;
const debug = std.debug;
const assert = std.debug.assert;
const testing = std.testing;
const htest = @import("test.zig");
const Vector = std.meta.Vector;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const State = struct {
    pub const BLOCKBYTES = 48;
    pub const RATE = 16;

    data: [BLOCKBYTES / 4]u32 align(16),

    const Self = @This();

    pub fn init(initial_state: [State.BLOCKBYTES]u8) Self {
        var data: [BLOCKBYTES / 4]u32 = undefined;
        var i: usize = 0;
        while (i < State.BLOCKBYTES) : (i += 4) {
            data[i / 4] = mem.readIntNative(u32, initial_state[i..][0..4]);
        }
        return Self{ .data = data };
    }

    /// TODO follow the span() convention instead of having this and `toSliceConst`
    pub fn toSlice(self: *Self) *[BLOCKBYTES]u8 {
        return mem.asBytes(&self.data);
    }

    /// TODO follow the span() convention instead of having this and `toSlice`
    pub fn toSliceConst(self: *const Self) *const [BLOCKBYTES]u8 {
        return mem.asBytes(&self.data);
    }

    inline fn endianSwap(self: *Self) void {
        for (self.data) |*w| {
            w.* = mem.littleToNative(u32, w.*);
        }
    }

    fn permute_unrolled(self: *Self) void {
        self.endianSwap();
        const state = &self.data;
        comptime var round = @as(u32, 24);
        inline while (round > 0) : (round -= 1) {
            var column = @as(usize, 0);
            while (column < 4) : (column += 1) {
                const x = math.rotl(u32, state[column], 24);
                const y = math.rotl(u32, state[4 + column], 9);
                const z = state[8 + column];
                state[8 + column] = ((x ^ (z << 1)) ^ ((y & z) << 2));
                state[4 + column] = ((y ^ x) ^ ((x | z) << 1));
                state[column] = ((z ^ y) ^ ((x & y) << 3));
            }
            switch (round & 3) {
                0 => {
                    mem.swap(u32, &state[0], &state[1]);
                    mem.swap(u32, &state[2], &state[3]);
                    state[0] ^= round | 0x9e377900;
                },
                2 => {
                    mem.swap(u32, &state[0], &state[2]);
                    mem.swap(u32, &state[1], &state[3]);
                },
                else => {},
            }
        }
        self.endianSwap();
    }

    fn permute_small(self: *Self) void {
        self.endianSwap();
        const state = &self.data;
        var round = @as(u32, 24);
        while (round > 0) : (round -= 1) {
            var column = @as(usize, 0);
            while (column < 4) : (column += 1) {
                const x = math.rotl(u32, state[column], 24);
                const y = math.rotl(u32, state[4 + column], 9);
                const z = state[8 + column];
                state[8 + column] = ((x ^ (z << 1)) ^ ((y & z) << 2));
                state[4 + column] = ((y ^ x) ^ ((x | z) << 1));
                state[column] = ((z ^ y) ^ ((x & y) << 3));
            }
            switch (round & 3) {
                0 => {
                    mem.swap(u32, &state[0], &state[1]);
                    mem.swap(u32, &state[2], &state[3]);
                    state[0] ^= round | 0x9e377900;
                },
                2 => {
                    mem.swap(u32, &state[0], &state[2]);
                    mem.swap(u32, &state[1], &state[3]);
                },
                else => {},
            }
        }
        self.endianSwap();
    }

    const Lane = Vector(4, u32);

    inline fn shift(x: Lane, comptime n: comptime_int) Lane {
        return x << @splat(4, @as(u5, n));
    }

    fn permute_vectorized(self: *Self) void {
        self.endianSwap();
        const state = &self.data;
        var x = Lane{ state[0], state[1], state[2], state[3] };
        var y = Lane{ state[4], state[5], state[6], state[7] };
        var z = Lane{ state[8], state[9], state[10], state[11] };
        var round = @as(u32, 24);
        while (round > 0) : (round -= 1) {
            x = math.rotl(Lane, x, 24);
            y = math.rotl(Lane, y, 9);
            const newz = x ^ shift(z, 1) ^ shift(y & z, 2);
            const newy = y ^ x ^ shift(x | z, 1);
            const newx = z ^ y ^ shift(x & y, 3);
            x = newx;
            y = newy;
            z = newz;
            switch (round & 3) {
                0 => {
                    x = @shuffle(u32, x, undefined, [_]i32{ 1, 0, 3, 2 });
                    x[0] ^= round | 0x9e377900;
                },
                2 => {
                    x = @shuffle(u32, x, undefined, [_]i32{ 2, 3, 0, 1 });
                },
                else => {},
            }
        }
        comptime var i: usize = 0;
        inline while (i < 4) : (i += 1) {
            state[0 + i] = x[i];
            state[4 + i] = y[i];
            state[8 + i] = z[i];
        }
        self.endianSwap();
    }

    pub const permute = if (builtin.cpu.arch == .x86_64) impl: {
        break :impl permute_vectorized;
    } else if (builtin.mode == .ReleaseSmall) impl: {
        break :impl permute_small;
    } else impl: {
        break :impl permute_unrolled;
    };

    pub fn squeeze(self: *Self, out: []u8) void {
        var i = @as(usize, 0);
        while (i + RATE <= out.len) : (i += RATE) {
            self.permute();
            mem.copy(u8, out[i..], self.toSliceConst()[0..RATE]);
        }
        const leftover = out.len - i;
        if (leftover != 0) {
            self.permute();
            mem.copy(u8, out[i..], self.toSliceConst()[0..leftover]);
        }
    }
};

test "permute" {
    // test vector from gimli-20170627
    const tv_input = [3][4]u32{
        [4]u32{ 0x00000000, 0x9e3779ba, 0x3c6ef37a, 0xdaa66d46 },
        [4]u32{ 0x78dde724, 0x1715611a, 0xb54cdb2e, 0x53845566 },
        [4]u32{ 0xf1bbcfc8, 0x8ff34a5a, 0x2e2ac522, 0xcc624026 },
    };
    var input: [48]u8 = undefined;
    var i: usize = 0;
    while (i < 12) : (i += 1) {
        mem.writeIntLittle(u32, input[i * 4 ..][0..4], tv_input[i / 4][i % 4]);
    }

    var state = State.init(input);
    state.permute();

    const tv_output = [3][4]u32{
        [4]u32{ 0xba11c85a, 0x91bad119, 0x380ce880, 0xd24c2c68 },
        [4]u32{ 0x3eceffea, 0x277a921c, 0x4f73a0bd, 0xda5a9cd8 },
        [4]u32{ 0x84b673f0, 0x34e52ff7, 0x9e2bef49, 0xf41bb8d6 },
    };
    var expected_output: [48]u8 = undefined;
    i = 0;
    while (i < 12) : (i += 1) {
        mem.writeIntLittle(u32, expected_output[i * 4 ..][0..4], tv_output[i / 4][i % 4]);
    }
    try testing.expectEqualSlices(u8, state.toSliceConst(), expected_output[0..]);
}

pub const Hash = struct {
    state: State,
    buf_off: usize,

    pub const block_length = State.RATE;
    pub const digest_length = 32;
    pub const Options = struct {};

    const Self = @This();

    pub fn init(options: Options) Self {
        _ = options;
        return Self{
            .state = State{ .data = [_]u32{0} ** (State.BLOCKBYTES / 4) },
            .buf_off = 0,
        };
    }

    /// Also known as 'absorb'
    pub fn update(self: *Self, data: []const u8) void {
        const buf = self.state.toSlice();
        var in = data;
        while (in.len > 0) {
            const left = State.RATE - self.buf_off;
            const ps = math.min(in.len, left);
            for (buf[self.buf_off .. self.buf_off + ps]) |*p, i| {
                p.* ^= in[i];
            }
            self.buf_off += ps;
            in = in[ps..];
            if (self.buf_off == State.RATE) {
                self.state.permute();
                self.buf_off = 0;
            }
        }
    }

    /// Finish the current hashing operation, writing the hash to `out`
    ///
    /// From 4.9 "Application to hashing"
    /// By default, Gimli-Hash provides a fixed-length output of 32 bytes
    /// (the concatenation of two 16-byte blocks).  However, Gimli-Hash can
    /// be used as an “extendable one-way function” (XOF).
    pub fn final(self: *Self, out: []u8) void {
        const buf = self.state.toSlice();

        // XOR 1 into the next byte of the state
        buf[self.buf_off] ^= 1;
        // XOR 1 into the last byte of the state, position 47.
        buf[buf.len - 1] ^= 1;

        self.state.squeeze(out);
    }
};

pub fn hash(out: []u8, in: []const u8, options: Hash.Options) void {
    var st = Hash.init(options);
    st.update(in);
    st.final(out);
}

test "hash" {
    // a test vector (30) from NIST KAT submission.
    var msg: [58 / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C");
    var md: [32]u8 = undefined;
    hash(&md, &msg, .{});
    try htest.assertEqual("1C9A03DC6A5DDC5444CFC6F4B154CFF5CF081633B2CEA4D7D0AE7CCFED5AAA44", &md);
}

test "hash test vector 17" {
    var msg: [32 / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, "000102030405060708090A0B0C0D0E0F");
    var md: [32]u8 = undefined;
    hash(&md, &msg, .{});
    try htest.assertEqual("404C130AF1B9023A7908200919F690FFBB756D5176E056FFDE320016A37C7282", &md);
}

test "hash test vector 33" {
    var msg: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    var md: [32]u8 = undefined;
    hash(&md, &msg, .{});
    try htest.assertEqual("A8F4FA28708BDA7EFB4C1914CA4AFA9E475B82D588D36504F87DBB0ED9AB3C4B", &md);
}

pub const Aead = struct {
    pub const tag_length = State.RATE;
    pub const nonce_length = 16;
    pub const key_length = 32;

    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    fn init(ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) State {
        var state = State{
            .data = undefined,
        };
        const buf = state.toSlice();

        // Gimli-Cipher initializes a 48-byte Gimli state to a 16-byte nonce
        // followed by a 32-byte key.
        assert(npub.len + k.len == State.BLOCKBYTES);
        std.mem.copy(u8, buf[0..npub.len], &npub);
        std.mem.copy(u8, buf[npub.len .. npub.len + k.len], &k);

        // It then applies the Gimli permutation.
        state.permute();

        {
            // Gimli-Cipher then handles each block of associated data, including
            // exactly one final non-full block, in the same way as Gimli-Hash.
            var data = ad;
            while (data.len >= State.RATE) : (data = data[State.RATE..]) {
                for (buf[0..State.RATE]) |*p, i| {
                    p.* ^= data[i];
                }
                state.permute();
            }
            for (buf[0..data.len]) |*p, i| {
                p.* ^= data[i];
            }

            // XOR 1 into the next byte of the state
            buf[data.len] ^= 1;
            // XOR 1 into the last byte of the state, position 47.
            buf[buf.len - 1] ^= 1;

            state.permute();
        }

        return state;
    }

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        assert(c.len == m.len);

        var state = Aead.init(ad, npub, k);
        const buf = state.toSlice();

        // Gimli-Cipher then handles each block of plaintext, including
        // exactly one final non-full block, in the same way as Gimli-Hash.
        // Whenever a plaintext byte is XORed into a state byte, the new state
        // byte is output as ciphertext.
        var in = m;
        var out = c;
        while (in.len >= State.RATE) : ({
            in = in[State.RATE..];
            out = out[State.RATE..];
        }) {
            for (in[0..State.RATE]) |v, i| {
                buf[i] ^= v;
            }
            mem.copy(u8, out[0..State.RATE], buf[0..State.RATE]);
            state.permute();
        }
        for (in[0..]) |v, i| {
            buf[i] ^= v;
            out[i] = buf[i];
        }

        // XOR 1 into the next byte of the state
        buf[in.len] ^= 1;
        // XOR 1 into the last byte of the state, position 47.
        buf[buf.len - 1] ^= 1;

        state.permute();

        // After the final non-full block of plaintext, the first 16 bytes
        // of the state are output as an authentication tag.
        std.mem.copy(u8, tag, buf[0..State.RATE]);
    }

    /// m: message: output buffer should be of size c.len
    /// c: ciphertext
    /// tag: authentication tag
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    /// NOTE: the check of the authentication tag is currently not done in constant time
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);

        var state = Aead.init(ad, npub, k);
        const buf = state.toSlice();

        var in = c;
        var out = m;
        while (in.len >= State.RATE) : ({
            in = in[State.RATE..];
            out = out[State.RATE..];
        }) {
            const d = in[0..State.RATE].*;
            for (d) |v, i| {
                out[i] = buf[i] ^ v;
            }
            mem.copy(u8, buf[0..State.RATE], d[0..State.RATE]);
            state.permute();
        }
        for (buf[0..in.len]) |*p, i| {
            const d = in[i];
            out[i] = p.* ^ d;
            p.* = d;
        }

        // XOR 1 into the next byte of the state
        buf[in.len] ^= 1;
        // XOR 1 into the last byte of the state, position 47.
        buf[buf.len - 1] ^= 1;

        state.permute();

        // After the final non-full block of plaintext, the first 16 bytes
        // of the state are the authentication tag.
        // TODO: use a constant-time equality check here, see https://github.com/ziglang/zig/issues/1776
        if (!mem.eql(u8, buf[0..State.RATE], &tag)) {
            @memset(m.ptr, undefined, m.len);
            return error.AuthenticationFailed;
        }
    }
};

test "cipher" {
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    var nonce: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, "000102030405060708090A0B0C0D0E0F");
    { // test vector (1) from NIST KAT submission.
        const ad: [0]u8 = undefined;
        const pt: [0]u8 = undefined;

        var ct: [pt.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        Aead.encrypt(&ct, &tag, &pt, &ad, nonce, key);
        try htest.assertEqual("", &ct);
        try htest.assertEqual("14DA9BB7120BF58B985A8E00FDEBA15B", &tag);

        var pt2: [pt.len]u8 = undefined;
        try Aead.decrypt(&pt2, &ct, tag, &ad, nonce, key);
        try testing.expectEqualSlices(u8, &pt, &pt2);
    }
    { // test vector (34) from NIST KAT submission.
        const ad: [0]u8 = undefined;
        var pt: [2 / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pt, "00");

        var ct: [pt.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        Aead.encrypt(&ct, &tag, &pt, &ad, nonce, key);
        try htest.assertEqual("7F", &ct);
        try htest.assertEqual("80492C317B1CD58A1EDC3A0D3E9876FC", &tag);

        var pt2: [pt.len]u8 = undefined;
        try Aead.decrypt(&pt2, &ct, tag, &ad, nonce, key);
        try testing.expectEqualSlices(u8, &pt, &pt2);
    }
    { // test vector (106) from NIST KAT submission.
        var ad: [12 / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&ad, "000102030405");
        var pt: [6 / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pt, "000102");

        var ct: [pt.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        Aead.encrypt(&ct, &tag, &pt, &ad, nonce, key);
        try htest.assertEqual("484D35", &ct);
        try htest.assertEqual("030BBEA23B61C00CED60A923BDCF9147", &tag);

        var pt2: [pt.len]u8 = undefined;
        try Aead.decrypt(&pt2, &ct, tag, &ad, nonce, key);
        try testing.expectEqualSlices(u8, &pt, &pt2);
    }
    { // test vector (790) from NIST KAT submission.
        var ad: [60 / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&ad, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D");
        var pt: [46 / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pt, "000102030405060708090A0B0C0D0E0F10111213141516");

        var ct: [pt.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        Aead.encrypt(&ct, &tag, &pt, &ad, nonce, key);
        try htest.assertEqual("6815B4A0ECDAD01596EAD87D9E690697475D234C6A13D1", &ct);
        try htest.assertEqual("DFE23F1642508290D68245279558B2FB", &tag);

        var pt2: [pt.len]u8 = undefined;
        try Aead.decrypt(&pt2, &ct, tag, &ad, nonce, key);
        try testing.expectEqualSlices(u8, &pt, &pt2);
    }
    { // test vector (1057) from NIST KAT submission.
        const ad: [0]u8 = undefined;
        var pt: [64 / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pt, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        var ct: [pt.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        Aead.encrypt(&ct, &tag, &pt, &ad, nonce, key);
        try htest.assertEqual("7F8A2CF4F52AA4D6B2E74105C30A2777B9D0C8AEFDD555DE35861BD3011F652F", &ct);
        try htest.assertEqual("7256456FA935AC34BBF55AE135F33257", &tag);

        var pt2: [pt.len]u8 = undefined;
        try Aead.decrypt(&pt2, &ct, tag, &ad, nonce, key);
        try testing.expectEqualSlices(u8, &pt, &pt2);
    }
}
