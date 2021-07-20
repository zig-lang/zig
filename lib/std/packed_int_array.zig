// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const builtin = @import("builtin");
const debug = std.debug;
const testing = std.testing;
const native_endian = builtin.cpu.arch.endian();
const Endian = std.builtin.Endian;

pub fn PackedIntIo(comptime Int: type, comptime endian: Endian) type {
    //The general technique employed here is to cast bytes in the array to a container
    // integer (having bits % 8 == 0) large enough to contain the number of bits we want,
    // then we can retrieve or store the new value with a relative minimum of masking
    // and shifting. In this worst case, this means that we'll need an integer that's
    // actually 1 byte larger than the minimum required to store the bits, because it
    // is possible that the bits start at the end of the first byte, continue through
    // zero or more, then end in the beginning of the last. But, if we try to access
    // a value in the very last byte of memory with that integer size, that extra byte
    // will be out of bounds. Depending on the circumstances of the memory, that might
    // mean the OS fatally kills the program. Thus, we use a larger container (MaxIo)
    // most of the time, but a smaller container (MinIo) when touching the last byte
    // of the memory.
    const int_bits = comptime std.meta.bitCount(Int);

    //in the best case, this is the number of bytes we need to touch
    // to read or write a value, as bits
    const min_io_bits = ((int_bits + 7) / 8) * 8;

    //in the worst case, this is the number of bytes we need to touch
    // to read or write a value, as bits. To calculate for int_bits > 1,
    // set aside 2 bits to touch the first and last bytes, then divide
    // by 8 to see how many bytes can be filled up inbetween.
    const max_io_bits = switch (int_bits) {
        0 => 0,
        1 => 8,
        else => ((int_bits - 2) / 8 + 2) * 8,
    };

    //we bitcast the desired Int type to an unsigned version of itself
    // to avoid issues with shifting signed ints.
    const UnInt = std.meta.Int(.unsigned, int_bits);

    //The maximum container int type
    const MinIo = std.meta.Int(.unsigned, min_io_bits);

    //The minimum container int type
    const MaxIo = std.meta.Int(.unsigned, max_io_bits);

    return struct {
        pub fn get(bytes: []const u8, index: usize, bit_offset: u7) Int {
            if (int_bits == 0) return 0;

            const bit_index = (index * int_bits) + bit_offset;
            const max_end_byte = (bit_index + max_io_bits) / 8;

            //Using the larger container size will potentially read out of bounds
            if (max_end_byte > bytes.len) return getBits(bytes, MinIo, bit_index);
            return getBits(bytes, MaxIo, bit_index);
        }

        fn getBits(bytes: []const u8, comptime Container: type, bit_index: usize) Int {
            const container_bits = comptime std.meta.bitCount(Container);
            const Shift = std.math.Log2Int(Container);

            const start_byte = bit_index / 8;
            const head_keep_bits = bit_index - (start_byte * 8);
            const tail_keep_bits = container_bits - (int_bits + head_keep_bits);

            //read bytes as container
            const value_ptr = @ptrCast(*align(1) const Container, &bytes[start_byte]);
            var value = value_ptr.*;

            if (endian != native_endian) value = @byteSwap(Container, value);

            switch (endian) {
                .Big => {
                    value <<= @intCast(Shift, head_keep_bits);
                    value >>= @intCast(Shift, head_keep_bits);
                    value >>= @intCast(Shift, tail_keep_bits);
                },
                .Little => {
                    value <<= @intCast(Shift, tail_keep_bits);
                    value >>= @intCast(Shift, tail_keep_bits);
                    value >>= @intCast(Shift, head_keep_bits);
                },
            }

            return @bitCast(Int, @truncate(UnInt, value));
        }

        pub fn set(bytes: []u8, index: usize, bit_offset: u3, int: Int) void {
            if (int_bits == 0) return;

            const bit_index = (index * int_bits) + bit_offset;
            const max_end_byte = (bit_index + max_io_bits) / 8;

            //Using the larger container size will potentially write out of bounds
            if (max_end_byte > bytes.len) return setBits(bytes, MinIo, bit_index, int);
            setBits(bytes, MaxIo, bit_index, int);
        }

        fn setBits(bytes: []u8, comptime Container: type, bit_index: usize, int: Int) void {
            const container_bits = comptime std.meta.bitCount(Container);
            const Shift = std.math.Log2Int(Container);

            const start_byte = bit_index / 8;
            const head_keep_bits = bit_index - (start_byte * 8);
            const tail_keep_bits = container_bits - (int_bits + head_keep_bits);
            const keep_shift = switch (endian) {
                .Big => @intCast(Shift, tail_keep_bits),
                .Little => @intCast(Shift, head_keep_bits),
            };

            //position the bits where they need to be in the container
            const value = @intCast(Container, @bitCast(UnInt, int)) << keep_shift;

            //read existing bytes
            const target_ptr = @ptrCast(*align(1) Container, &bytes[start_byte]);
            var target = target_ptr.*;

            if (endian != native_endian) target = @byteSwap(Container, target);

            //zero the bits we want to replace in the existing bytes
            const inv_mask = @intCast(Container, std.math.maxInt(UnInt)) << keep_shift;
            const mask = ~inv_mask;
            target &= mask;

            //merge the new value
            target |= value;

            if (endian != native_endian) target = @byteSwap(Container, target);

            //save it back
            target_ptr.* = target;
        }

        fn slice(bytes: []u8, bit_offset: u3, start: usize, end: usize) PackedIntSliceEndian(Int, endian) {
            debug.assert(end >= start);

            const length = end - start;
            const bit_index = (start * int_bits) + bit_offset;
            const start_byte = bit_index / 8;
            const end_byte = (bit_index + (length * int_bits) + 7) / 8;
            const new_bytes = bytes[start_byte..end_byte];

            if (length == 0) return PackedIntSliceEndian(Int, endian).init(new_bytes[0..0], 0);

            var new_slice = PackedIntSliceEndian(Int, endian).init(new_bytes, length);
            new_slice.bit_offset = @intCast(u3, (bit_index - (start_byte * 8)));
            return new_slice;
        }

        fn sliceCast(bytes: []u8, comptime NewInt: type, comptime new_endian: Endian, bit_offset: u3, old_len: usize) PackedIntSliceEndian(NewInt, new_endian) {
            const new_int_bits = comptime std.meta.bitCount(NewInt);
            const New = PackedIntSliceEndian(NewInt, new_endian);

            const total_bits = (old_len * int_bits);
            const new_int_count = total_bits / new_int_bits;

            debug.assert(total_bits == new_int_count * new_int_bits);

            var new = New.init(bytes, new_int_count);
            new.bit_offset = bit_offset;

            return new;
        }
    };
}

///Creates a bit-packed array of integers of type Int. Bits
/// are packed using native endianess and without storing any meta
/// data. PackedIntArray(i3, 8) will occupy exactly 3 bytes of memory.
pub fn PackedIntArray(comptime Int: type, comptime int_count: usize) type {
    return PackedIntArrayEndian(Int, native_endian, int_count);
}

///Creates a bit-packed array of integers of type Int. Bits
/// are packed using specified endianess and without storing any meta
/// data.
pub fn PackedIntArrayEndian(comptime Int: type, comptime endian: Endian, comptime int_count: usize) type {
    const int_bits = comptime std.meta.bitCount(Int);
    const total_bits = int_bits * int_count;
    const total_bytes = (total_bits + 7) / 8;

    const Io = PackedIntIo(Int, endian);

    return struct {
        const Self = @This();

        bytes: [total_bytes]u8,

        ///Returns the number of elements in the packed array
        pub fn len(self: Self) usize {
            _ = self;
            return int_count;
        }

        ///Initialize a packed array using an unpacked array
        /// or, more likely, an array literal.
        pub fn init(ints: [int_count]Int) Self {
            var self = @as(Self, undefined);
            for (ints) |int, i| self.set(i, int);
            return self;
        }

        ///Initialize all entries of a packed array to the same value
        pub fn initAllTo(int: Int) Self {
            // TODO: use `var self = @as(Self, undefined);` https://github.com/ziglang/zig/issues/7635
            var self = Self{ .bytes = [_]u8{0} ** total_bytes };
            self.setAll(int);
            return self;
        }

        ///Return the Int stored at index
        pub fn get(self: Self, index: usize) Int {
            debug.assert(index < int_count);
            return Io.get(&self.bytes, index, 0);
        }

        ///Copy int into the array at index
        pub fn set(self: *Self, index: usize, int: Int) void {
            debug.assert(index < int_count);
            return Io.set(&self.bytes, index, 0, int);
        }

        ///Set all entries of a packed array to the same value
        pub fn setAll(self: *Self, int: Int) void {
            var i: usize = 0;
            while (i < int_count) : (i += 1) {
                self.set(i, int);
            }
        }

        ///Create a PackedIntSlice of the array from given start to given end
        pub fn slice(self: *Self, start: usize, end: usize) PackedIntSliceEndian(Int, endian) {
            debug.assert(start < int_count);
            debug.assert(end <= int_count);
            return Io.slice(&self.bytes, 0, start, end);
        }

        ///Create a PackedIntSlice of the array using NewInt as the bit width integer.
        /// NewInt's bit width must fit evenly within the array's Int's total bits.
        pub fn sliceCast(self: *Self, comptime NewInt: type) PackedIntSlice(NewInt) {
            return self.sliceCastEndian(NewInt, endian);
        }

        ///Create a PackedIntSlice of the array using NewInt as the bit width integer
        /// and new_endian as the new endianess. NewInt's bit width must fit evenly within
        /// the array's Int's total bits.
        pub fn sliceCastEndian(self: *Self, comptime NewInt: type, comptime new_endian: Endian) PackedIntSliceEndian(NewInt, new_endian) {
            return Io.sliceCast(&self.bytes, NewInt, new_endian, 0, int_count);
        }
    };
}

///Uses a slice as a bit-packed block of int_count integers of type Int.
/// Bits are packed using native endianess and without storing any meta
/// data.
pub fn PackedIntSlice(comptime Int: type) type {
    return PackedIntSliceEndian(Int, native_endian);
}

///Uses a slice as a bit-packed block of int_count integers of type Int.
/// Bits are packed using specified endianess and without storing any meta
/// data.
pub fn PackedIntSliceEndian(comptime Int: type, comptime endian: Endian) type {
    const int_bits = comptime std.meta.bitCount(Int);
    const Io = PackedIntIo(Int, endian);

    return struct {
        const Self = @This();

        bytes: []u8,
        int_count: usize,
        bit_offset: u3,

        ///Returns the number of elements in the packed slice
        pub fn len(self: Self) usize {
            return self.int_count;
        }

        ///Calculates the number of bytes required to store a desired count
        /// of Ints
        pub fn bytesRequired(int_count: usize) usize {
            const total_bits = int_bits * int_count;
            const total_bytes = (total_bits + 7) / 8;
            return total_bytes;
        }

        ///Initialize a packed slice using the memory at bytes, with int_count
        /// elements. bytes must be large enough to accomodate the requested
        /// count.
        pub fn init(bytes: []u8, int_count: usize) Self {
            debug.assert(bytes.len >= bytesRequired(int_count));

            return Self{
                .bytes = bytes,
                .int_count = int_count,
                .bit_offset = 0,
            };
        }

        ///Return the Int stored at index
        pub fn get(self: Self, index: usize) Int {
            debug.assert(index < self.int_count);
            return Io.get(self.bytes, index, self.bit_offset);
        }

        ///Copy int into the array at index
        pub fn set(self: *Self, index: usize, int: Int) void {
            debug.assert(index < self.int_count);
            return Io.set(self.bytes, index, self.bit_offset, int);
        }

        ///Create a PackedIntSlice of this slice from given start to given end
        pub fn slice(self: Self, start: usize, end: usize) PackedIntSliceEndian(Int, endian) {
            debug.assert(start < self.int_count);
            debug.assert(end <= self.int_count);
            return Io.slice(self.bytes, self.bit_offset, start, end);
        }

        ///Create a PackedIntSlice of this slice using NewInt as the bit width integer.
        /// NewInt's bit width must fit evenly within this slice's Int's total bits.
        pub fn sliceCast(self: Self, comptime NewInt: type) PackedIntSliceEndian(NewInt, endian) {
            return self.sliceCastEndian(NewInt, endian);
        }

        ///Create a PackedIntSlice of this slice using NewInt as the bit width integer
        /// and new_endian as the new endianess. NewInt's bit width must fit evenly within
        /// this slice's Int's total bits.
        pub fn sliceCastEndian(self: Self, comptime NewInt: type, comptime new_endian: Endian) PackedIntSliceEndian(NewInt, new_endian) {
            return Io.sliceCast(self.bytes, NewInt, new_endian, self.bit_offset, self.int_count);
        }
    };
}

const we_are_testing_this_with_stage1_which_leaks_comptime_memory = true;

test "PackedIntArray" {
    // TODO @setEvalBranchQuota generates panics in wasm32. Investigate.
    if (builtin.cpu.arch == .wasm32) return error.SkipZigTest;
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;

    @setEvalBranchQuota(10000);
    const max_bits = 256;
    const int_count = 19;

    comptime var bits = 0;
    inline while (bits <= max_bits) : (bits += 1) {
        //alternate unsigned and signed
        const sign: std.builtin.Signedness = if (bits % 2 == 0) .signed else .unsigned;
        const I = std.meta.Int(sign, bits);

        const PackedArray = PackedIntArray(I, int_count);
        const expected_bytes = ((bits * int_count) + 7) / 8;
        try testing.expect(@sizeOf(PackedArray) == expected_bytes);

        var data = @as(PackedArray, undefined);

        //write values, counting up
        var i = @as(usize, 0);
        var count = @as(I, 0);
        while (i < data.len()) : (i += 1) {
            data.set(i, count);
            if (bits > 0) count +%= 1;
        }

        //read and verify values
        i = 0;
        count = 0;
        while (i < data.len()) : (i += 1) {
            const val = data.get(i);
            try testing.expect(val == count);
            if (bits > 0) count +%= 1;
        }
    }
}

test "PackedIntIo" {
    const bytes = [_]u8{ 0b01101_000, 0b01011_110, 0b00011_101 };
    try testing.expectEqual(@as(u15, 0x2bcd), PackedIntIo(u15, .Little).get(&bytes, 0, 3));
    try testing.expectEqual(@as(u16, 0xabcd), PackedIntIo(u16, .Little).get(&bytes, 0, 3));
    try testing.expectEqual(@as(u17, 0x1abcd), PackedIntIo(u17, .Little).get(&bytes, 0, 3));
    try testing.expectEqual(@as(u18, 0x3abcd), PackedIntIo(u18, .Little).get(&bytes, 0, 3));
}

test "PackedIntArray init" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;
    const PackedArray = PackedIntArray(u3, 8);
    var packed_array = PackedArray.init([_]u3{ 0, 1, 2, 3, 4, 5, 6, 7 });
    var i = @as(usize, 0);
    while (i < packed_array.len()) : (i += 1) try testing.expectEqual(@intCast(u3, i), packed_array.get(i));
}

test "PackedIntArray initAllTo" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;
    const PackedArray = PackedIntArray(u3, 8);
    var packed_array = PackedArray.initAllTo(5);
    var i = @as(usize, 0);
    while (i < packed_array.len()) : (i += 1) try testing.expectEqual(@as(u3, 5), packed_array.get(i));
}

test "PackedIntSlice" {
    // TODO @setEvalBranchQuota generates panics in wasm32. Investigate.
    if (builtin.cpu.arch == .wasm32) return error.SkipZigTest;
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;

    @setEvalBranchQuota(10000);
    const max_bits = 256;
    const int_count = 19;
    const total_bits = max_bits * int_count;
    const total_bytes = (total_bits + 7) / 8;

    var buffer: [total_bytes]u8 = undefined;

    comptime var bits = 0;
    inline while (bits <= max_bits) : (bits += 1) {
        //alternate unsigned and signed
        const sign: std.builtin.Signedness = if (bits % 2 == 0) .signed else .unsigned;
        const I = std.meta.Int(sign, bits);
        const P = PackedIntSlice(I);

        var data = P.init(&buffer, int_count);

        //write values, counting up
        var i = @as(usize, 0);
        var count = @as(I, 0);
        while (i < data.len()) : (i += 1) {
            data.set(i, count);
            if (bits > 0) count +%= 1;
        }

        //read and verify values
        i = 0;
        count = 0;
        while (i < data.len()) : (i += 1) {
            const val = data.get(i);
            try testing.expect(val == count);
            if (bits > 0) count +%= 1;
        }
    }
}

test "PackedIntSlice of PackedInt(Array/Slice)" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;
    const max_bits = 16;
    const int_count = 19;

    comptime var bits = 0;
    inline while (bits <= max_bits) : (bits += 1) {
        const Int = std.meta.Int(.unsigned, bits);

        const PackedArray = PackedIntArray(Int, int_count);
        var packed_array = @as(PackedArray, undefined);

        const limit = (1 << bits);

        var i = @as(usize, 0);
        while (i < packed_array.len()) : (i += 1) {
            packed_array.set(i, @intCast(Int, i % limit));
        }

        //slice of array
        var packed_slice = packed_array.slice(2, 5);
        try testing.expect(packed_slice.len() == 3);
        const ps_bit_count = (bits * packed_slice.len()) + packed_slice.bit_offset;
        const ps_expected_bytes = (ps_bit_count + 7) / 8;
        try testing.expect(packed_slice.bytes.len == ps_expected_bytes);
        try testing.expect(packed_slice.get(0) == 2 % limit);
        try testing.expect(packed_slice.get(1) == 3 % limit);
        try testing.expect(packed_slice.get(2) == 4 % limit);
        packed_slice.set(1, 7 % limit);
        try testing.expect(packed_slice.get(1) == 7 % limit);

        //write through slice
        try testing.expect(packed_array.get(3) == 7 % limit);

        //slice of a slice
        const packed_slice_two = packed_slice.slice(0, 3);
        try testing.expect(packed_slice_two.len() == 3);
        const ps2_bit_count = (bits * packed_slice_two.len()) + packed_slice_two.bit_offset;
        const ps2_expected_bytes = (ps2_bit_count + 7) / 8;
        try testing.expect(packed_slice_two.bytes.len == ps2_expected_bytes);
        try testing.expect(packed_slice_two.get(1) == 7 % limit);
        try testing.expect(packed_slice_two.get(2) == 4 % limit);

        //size one case
        const packed_slice_three = packed_slice_two.slice(1, 2);
        try testing.expect(packed_slice_three.len() == 1);
        const ps3_bit_count = (bits * packed_slice_three.len()) + packed_slice_three.bit_offset;
        const ps3_expected_bytes = (ps3_bit_count + 7) / 8;
        try testing.expect(packed_slice_three.bytes.len == ps3_expected_bytes);
        try testing.expect(packed_slice_three.get(0) == 7 % limit);

        //empty slice case
        const packed_slice_empty = packed_slice.slice(0, 0);
        try testing.expect(packed_slice_empty.len() == 0);
        try testing.expect(packed_slice_empty.bytes.len == 0);

        //slicing at byte boundaries
        const packed_slice_edge = packed_array.slice(8, 16);
        try testing.expect(packed_slice_edge.len() == 8);
        const pse_bit_count = (bits * packed_slice_edge.len()) + packed_slice_edge.bit_offset;
        const pse_expected_bytes = (pse_bit_count + 7) / 8;
        try testing.expect(packed_slice_edge.bytes.len == pse_expected_bytes);
        try testing.expect(packed_slice_edge.bit_offset == 0);
    }
}

test "PackedIntSlice accumulating bit offsets" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;
    //bit_offset is u3, so standard debugging asserts should catch
    // anything
    {
        const PackedArray = PackedIntArray(u3, 16);
        var packed_array = @as(PackedArray, undefined);

        var packed_slice = packed_array.slice(0, packed_array.len());
        var i = @as(usize, 0);
        while (i < packed_array.len() - 1) : (i += 1) {
            packed_slice = packed_slice.slice(1, packed_slice.len());
        }
    }
    {
        const PackedArray = PackedIntArray(u11, 88);
        var packed_array = @as(PackedArray, undefined);

        var packed_slice = packed_array.slice(0, packed_array.len());
        var i = @as(usize, 0);
        while (i < packed_array.len() - 1) : (i += 1) {
            packed_slice = packed_slice.slice(1, packed_slice.len());
        }
    }
}

//@NOTE: As I do not have a big endian system to test this on,
// big endian values were not tested
test "PackedInt(Array/Slice) sliceCast" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;

    const PackedArray = PackedIntArray(u1, 16);
    var packed_array = PackedArray.init([_]u1{ 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1 });
    const packed_slice_cast_2 = packed_array.sliceCast(u2);
    const packed_slice_cast_4 = packed_slice_cast_2.sliceCast(u4);
    var packed_slice_cast_9 = packed_array.slice(0, (packed_array.len() / 9) * 9).sliceCast(u9);
    const packed_slice_cast_3 = packed_slice_cast_9.sliceCast(u3);

    var i = @as(usize, 0);
    while (i < packed_slice_cast_2.len()) : (i += 1) {
        const val = switch (native_endian) {
            .Big => 0b01,
            .Little => 0b10,
        };
        try testing.expect(packed_slice_cast_2.get(i) == val);
    }
    i = 0;
    while (i < packed_slice_cast_4.len()) : (i += 1) {
        const val = switch (native_endian) {
            .Big => 0b0101,
            .Little => 0b1010,
        };
        try testing.expect(packed_slice_cast_4.get(i) == val);
    }
    i = 0;
    while (i < packed_slice_cast_9.len()) : (i += 1) {
        const val = 0b010101010;
        try testing.expect(packed_slice_cast_9.get(i) == val);
        packed_slice_cast_9.set(i, 0b111000111);
    }
    i = 0;
    while (i < packed_slice_cast_3.len()) : (i += 1) {
        const val = switch (native_endian) {
            .Big => if (i % 2 == 0) @as(u3, 0b111) else @as(u3, 0b000),
            .Little => if (i % 2 == 0) @as(u3, 0b111) else @as(u3, 0b000),
        };
        try testing.expect(packed_slice_cast_3.get(i) == val);
    }
}

test "PackedInt(Array/Slice)Endian" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;

    {
        const PackedArrayBe = PackedIntArrayEndian(u4, .Big, 8);
        var packed_array_be = PackedArrayBe.init([_]u4{ 0, 1, 2, 3, 4, 5, 6, 7 });
        try testing.expect(packed_array_be.bytes[0] == 0b00000001);
        try testing.expect(packed_array_be.bytes[1] == 0b00100011);

        var i = @as(usize, 0);
        while (i < packed_array_be.len()) : (i += 1) {
            try testing.expect(packed_array_be.get(i) == i);
        }

        var packed_slice_le = packed_array_be.sliceCastEndian(u4, .Little);
        i = 0;
        while (i < packed_slice_le.len()) : (i += 1) {
            const val = if (i % 2 == 0) i + 1 else i - 1;
            try testing.expect(packed_slice_le.get(i) == val);
        }

        var packed_slice_le_shift = packed_array_be.slice(1, 5).sliceCastEndian(u4, .Little);
        i = 0;
        while (i < packed_slice_le_shift.len()) : (i += 1) {
            const val = if (i % 2 == 0) i else i + 2;
            try testing.expect(packed_slice_le_shift.get(i) == val);
        }
    }

    {
        const PackedArrayBe = PackedIntArrayEndian(u11, .Big, 8);
        var packed_array_be = PackedArrayBe.init([_]u11{ 0, 1, 2, 3, 4, 5, 6, 7 });
        try testing.expect(packed_array_be.bytes[0] == 0b00000000);
        try testing.expect(packed_array_be.bytes[1] == 0b00000000);
        try testing.expect(packed_array_be.bytes[2] == 0b00000100);
        try testing.expect(packed_array_be.bytes[3] == 0b00000001);
        try testing.expect(packed_array_be.bytes[4] == 0b00000000);

        var i = @as(usize, 0);
        while (i < packed_array_be.len()) : (i += 1) {
            try testing.expect(packed_array_be.get(i) == i);
        }

        var packed_slice_le = packed_array_be.sliceCastEndian(u11, .Little);
        try testing.expect(packed_slice_le.get(0) == 0b00000000000);
        try testing.expect(packed_slice_le.get(1) == 0b00010000000);
        try testing.expect(packed_slice_le.get(2) == 0b00000000100);
        try testing.expect(packed_slice_le.get(3) == 0b00000000000);
        try testing.expect(packed_slice_le.get(4) == 0b00010000011);
        try testing.expect(packed_slice_le.get(5) == 0b00000000010);
        try testing.expect(packed_slice_le.get(6) == 0b10000010000);
        try testing.expect(packed_slice_le.get(7) == 0b00000111001);

        var packed_slice_le_shift = packed_array_be.slice(1, 5).sliceCastEndian(u11, .Little);
        try testing.expect(packed_slice_le_shift.get(0) == 0b00010000000);
        try testing.expect(packed_slice_le_shift.get(1) == 0b00000000100);
        try testing.expect(packed_slice_le_shift.get(2) == 0b00000000000);
        try testing.expect(packed_slice_le_shift.get(3) == 0b00010000011);
    }
}

//@NOTE: Need to manually update this list as more posix os's get
// added to DirectAllocator.

//These tests prove we aren't accidentally accessing memory past
// the end of the array/slice by placing it at the end of a page
// and reading the last element. The assumption is that the page
// after this one is not mapped and will cause a segfault if we
// don't account for the bounds.
test "PackedIntArray at end of available memory" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;

    switch (builtin.os.tag) {
        .linux, .macos, .ios, .freebsd, .netbsd, .openbsd, .windows => {},
        else => return,
    }
    const PackedArray = PackedIntArray(u3, 8);

    const Padded = struct {
        _: [std.mem.page_size - @sizeOf(PackedArray)]u8,
        p: PackedArray,
    };

    const allocator = std.testing.allocator;

    var pad = try allocator.create(Padded);
    defer allocator.destroy(pad);
    pad.p.set(7, std.math.maxInt(u3));
}

test "PackedIntSlice at end of available memory" {
    if (we_are_testing_this_with_stage1_which_leaks_comptime_memory) return error.SkipZigTest;

    switch (builtin.os.tag) {
        .linux, .macos, .ios, .freebsd, .netbsd, .openbsd, .windows => {},
        else => return,
    }
    const PackedSlice = PackedIntSlice(u11);

    const allocator = std.testing.allocator;

    var page = try allocator.alloc(u8, std.mem.page_size);
    defer allocator.free(page);

    var p = PackedSlice.init(page[std.mem.page_size - 2 ..], 1);
    p.set(0, std.math.maxInt(u11));
}
