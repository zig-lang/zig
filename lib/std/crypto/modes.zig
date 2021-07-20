// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
// Based on Go stdlib implementation

const std = @import("../std.zig");
const builtin = std.builtin;
const mem = std.mem;
const debug = std.debug;

/// Counter mode.
///
/// This mode creates a key stream by encrypting an incrementing counter using a block cipher, and adding it to the source material.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// As a result, applications should generally never use it directly, but only in a construction that includes a MAC.
pub fn ctr(comptime BlockCipher: anytype, block_cipher: BlockCipher, dst: []u8, src: []const u8, iv: [BlockCipher.block_length]u8, endian: std.builtin.Endian) void {
    debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var counter: [BlockCipher.block_length]u8 = undefined;
    var counterInt = mem.readInt(u128, &iv, endian);
    var i: usize = 0;

    const parallel_count = BlockCipher.block.parallel.optimal_parallel_blocks;
    const wide_block_length = parallel_count * 16;
    if (src.len >= wide_block_length) {
        var counters: [parallel_count * 16]u8 = undefined;
        while (i + wide_block_length <= src.len) : (i += wide_block_length) {
            comptime var j = 0;
            inline while (j < parallel_count) : (j += 1) {
                mem.writeInt(u128, counters[j * 16 .. j * 16 + 16], counterInt, endian);
                counterInt +%= 1;
            }
            block_cipher.xorWide(parallel_count, dst[i .. i + wide_block_length][0..wide_block_length], src[i .. i + wide_block_length][0..wide_block_length], counters);
        }
    }
    while (i + block_length <= src.len) : (i += block_length) {
        mem.writeInt(u128, &counter, counterInt, endian);
        counterInt +%= 1;
        block_cipher.xor(dst[i .. i + block_length][0..block_length], src[i .. i + block_length][0..block_length], counter);
    }
    if (i < src.len) {
        mem.writeInt(u128, &counter, counterInt, endian);
        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, &pad, src[i..]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[i..], pad[0 .. src.len - i]);
    }
}
