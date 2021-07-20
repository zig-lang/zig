// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = std.builtin;
const io = std.io;
const assert = std.debug.assert;
const testing = std.testing;
const trait = std.meta.trait;
const meta = std.meta;
const math = std.math;

/// Creates a stream which allows for reading bit fields from another stream
pub fn BitReader(endian: std.builtin.Endian, comptime ReaderType: type) type {
    return struct {
        forward_reader: ReaderType,
        bit_buffer: u7,
        bit_count: u3,

        pub const Error = ReaderType.Error;
        pub const Reader = io.Reader(*Self, Error, read);

        const Self = @This();
        const u8_bit_count = meta.bitCount(u8);
        const u7_bit_count = meta.bitCount(u7);
        const u4_bit_count = meta.bitCount(u4);

        pub fn init(forward_reader: ReaderType) Self {
            return Self{
                .forward_reader = forward_reader,
                .bit_buffer = 0,
                .bit_count = 0,
            };
        }

        /// Reads `bits` bits from the stream and returns a specified unsigned int type
        ///  containing them in the least significant end, returning an error if the
        ///  specified number of bits could not be read.
        pub fn readBitsNoEof(self: *Self, comptime U: type, bits: usize) !U {
            var n: usize = undefined;
            const result = try self.readBits(U, bits, &n);
            if (n < bits) return error.EndOfStream;
            return result;
        }

        /// Reads `bits` bits from the stream and returns a specified unsigned int type
        ///  containing them in the least significant end. The number of bits successfully
        ///  read is placed in `out_bits`, as reaching the end of the stream is not an error.
        pub fn readBits(self: *Self, comptime U: type, bits: usize, out_bits: *usize) Error!U {
            comptime assert(trait.isUnsignedInt(U));

            //by extending the buffer to a minimum of u8 we can cover a number of edge cases
            // related to shifting and casting.
            const u_bit_count = comptime meta.bitCount(U);
            const buf_bit_count = bc: {
                assert(u_bit_count >= bits);
                break :bc if (u_bit_count <= u8_bit_count) u8_bit_count else u_bit_count;
            };
            const Buf = std.meta.Int(.unsigned, buf_bit_count);
            const BufShift = math.Log2Int(Buf);

            out_bits.* = @as(usize, 0);
            if (U == u0 or bits == 0) return 0;
            var out_buffer = @as(Buf, 0);

            if (self.bit_count > 0) {
                const n = if (self.bit_count >= bits) @intCast(u3, bits) else self.bit_count;
                const shift = u7_bit_count - n;
                switch (endian) {
                    .Big => {
                        out_buffer = @as(Buf, self.bit_buffer >> shift);
                        if (n >= u7_bit_count)
                            self.bit_buffer = 0
                        else
                            self.bit_buffer <<= n;
                    },
                    .Little => {
                        const value = (self.bit_buffer << shift) >> shift;
                        out_buffer = @as(Buf, value);
                        if (n >= u7_bit_count)
                            self.bit_buffer = 0
                        else
                            self.bit_buffer >>= n;
                    },
                }
                self.bit_count -= n;
                out_bits.* = n;
            }
            //at this point we know bit_buffer is empty

            //copy bytes until we have enough bits, then leave the rest in bit_buffer
            while (out_bits.* < bits) {
                const n = bits - out_bits.*;
                const next_byte = self.forward_reader.readByte() catch |err| {
                    if (err == error.EndOfStream) {
                        return @intCast(U, out_buffer);
                    }
                    //@BUG: See #1810. Not sure if the bug is that I have to do this for some
                    // streams, or that I don't for streams with emtpy errorsets.
                    return @errSetCast(Error, err);
                };

                switch (endian) {
                    .Big => {
                        if (n >= u8_bit_count) {
                            out_buffer <<= @intCast(u3, u8_bit_count - 1);
                            out_buffer <<= 1;
                            out_buffer |= @as(Buf, next_byte);
                            out_bits.* += u8_bit_count;
                            continue;
                        }

                        const shift = @intCast(u3, u8_bit_count - n);
                        out_buffer <<= @intCast(BufShift, n);
                        out_buffer |= @as(Buf, next_byte >> shift);
                        out_bits.* += n;
                        self.bit_buffer = @truncate(u7, next_byte << @intCast(u3, n - 1));
                        self.bit_count = shift;
                    },
                    .Little => {
                        if (n >= u8_bit_count) {
                            out_buffer |= @as(Buf, next_byte) << @intCast(BufShift, out_bits.*);
                            out_bits.* += u8_bit_count;
                            continue;
                        }

                        const shift = @intCast(u3, u8_bit_count - n);
                        const value = (next_byte << shift) >> shift;
                        out_buffer |= @as(Buf, value) << @intCast(BufShift, out_bits.*);
                        out_bits.* += n;
                        self.bit_buffer = @truncate(u7, next_byte >> @intCast(u3, n));
                        self.bit_count = shift;
                    },
                }
            }

            return @intCast(U, out_buffer);
        }

        pub fn alignToByte(self: *Self) void {
            self.bit_buffer = 0;
            self.bit_count = 0;
        }

        pub fn read(self: *Self, buffer: []u8) Error!usize {
            var out_bits: usize = undefined;
            var out_bits_total = @as(usize, 0);
            //@NOTE: I'm not sure this is a good idea, maybe alignToByte should be forced
            if (self.bit_count > 0) {
                for (buffer) |*b| {
                    b.* = try self.readBits(u8, u8_bit_count, &out_bits);
                    out_bits_total += out_bits;
                }
                const incomplete_byte = @boolToInt(out_bits_total % u8_bit_count > 0);
                return (out_bits_total / u8_bit_count) + incomplete_byte;
            }

            return self.forward_reader.read(buffer);
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

pub fn bitReader(
    comptime endian: std.builtin.Endian,
    underlying_stream: anytype,
) BitReader(endian, @TypeOf(underlying_stream)) {
    return BitReader(endian, @TypeOf(underlying_stream)).init(underlying_stream);
}

test "api coverage" {
    const mem_be = [_]u8{ 0b11001101, 0b00001011 };
    const mem_le = [_]u8{ 0b00011101, 0b10010101 };

    var mem_in_be = io.fixedBufferStream(&mem_be);
    var bit_stream_be = bitReader(.Big, mem_in_be.reader());

    var out_bits: usize = undefined;

    const expect = testing.expect;
    const expectError = testing.expectError;

    try expect(1 == try bit_stream_be.readBits(u2, 1, &out_bits));
    try expect(out_bits == 1);
    try expect(2 == try bit_stream_be.readBits(u5, 2, &out_bits));
    try expect(out_bits == 2);
    try expect(3 == try bit_stream_be.readBits(u128, 3, &out_bits));
    try expect(out_bits == 3);
    try expect(4 == try bit_stream_be.readBits(u8, 4, &out_bits));
    try expect(out_bits == 4);
    try expect(5 == try bit_stream_be.readBits(u9, 5, &out_bits));
    try expect(out_bits == 5);
    try expect(1 == try bit_stream_be.readBits(u1, 1, &out_bits));
    try expect(out_bits == 1);

    mem_in_be.pos = 0;
    bit_stream_be.bit_count = 0;
    try expect(0b110011010000101 == try bit_stream_be.readBits(u15, 15, &out_bits));
    try expect(out_bits == 15);

    mem_in_be.pos = 0;
    bit_stream_be.bit_count = 0;
    try expect(0b1100110100001011 == try bit_stream_be.readBits(u16, 16, &out_bits));
    try expect(out_bits == 16);

    _ = try bit_stream_be.readBits(u0, 0, &out_bits);

    try expect(0 == try bit_stream_be.readBits(u1, 1, &out_bits));
    try expect(out_bits == 0);
    try expectError(error.EndOfStream, bit_stream_be.readBitsNoEof(u1, 1));

    var mem_in_le = io.fixedBufferStream(&mem_le);
    var bit_stream_le = bitReader(.Little, mem_in_le.reader());

    try expect(1 == try bit_stream_le.readBits(u2, 1, &out_bits));
    try expect(out_bits == 1);
    try expect(2 == try bit_stream_le.readBits(u5, 2, &out_bits));
    try expect(out_bits == 2);
    try expect(3 == try bit_stream_le.readBits(u128, 3, &out_bits));
    try expect(out_bits == 3);
    try expect(4 == try bit_stream_le.readBits(u8, 4, &out_bits));
    try expect(out_bits == 4);
    try expect(5 == try bit_stream_le.readBits(u9, 5, &out_bits));
    try expect(out_bits == 5);
    try expect(1 == try bit_stream_le.readBits(u1, 1, &out_bits));
    try expect(out_bits == 1);

    mem_in_le.pos = 0;
    bit_stream_le.bit_count = 0;
    try expect(0b001010100011101 == try bit_stream_le.readBits(u15, 15, &out_bits));
    try expect(out_bits == 15);

    mem_in_le.pos = 0;
    bit_stream_le.bit_count = 0;
    try expect(0b1001010100011101 == try bit_stream_le.readBits(u16, 16, &out_bits));
    try expect(out_bits == 16);

    _ = try bit_stream_le.readBits(u0, 0, &out_bits);

    try expect(0 == try bit_stream_le.readBits(u1, 1, &out_bits));
    try expect(out_bits == 0);
    try expectError(error.EndOfStream, bit_stream_le.readBitsNoEof(u1, 1));
}
