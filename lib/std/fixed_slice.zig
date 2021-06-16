// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("std.zig");
const testing = std.testing;

/// A structure with an array and a length, that can be used as a slice.
///
/// Useful to pass around small arrays whose exact size is only known at
/// runtime, but whose maximum size is known at comptime, without requiring
/// an `Allocator`.
///
/// ```zig
/// var actual_size = 32;
/// var fs = try FixedSlice(u8, 64).init(actual_size);
/// var slice = fs.slice(); // a slice of the 64-byte array
/// var fs_clone = fs; // creates a copy - the structure doesn't use any internal pointers
/// ```
pub fn FixedSlice(comptime T: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();
        buffer: [capacity]T,
        len: usize = 0,

        /// Set the actual length of the slice.
        /// Returns error.SliceTooBig if it exceeds the length of the backing array.
        pub fn init(len: usize) !Self {
            if (len > capacity) return error.SliceTooBig;
            return Self{ .buffer = undefined, .len = len };
        }

        /// View the internal array as a mutable slice whose size was previously set.
        pub fn slice(self: *Self) []T {
            return self.buffer[0..self.len];
        }

        /// View the internal array as a constant slice whose size was previously set.
        pub fn constSlice(self: Self) []const T {
            return self.buffer[0..self.len];
        }

        /// Change the size of the slices being returned by slice() and constSlice().
        pub fn resize(self: *Self, len: usize) ![]T {
            if (len > capacity) return error.SliceTooBig;
            self.len = len;
            return self.slice();
        }

        /// Copy the content of an existing slice.
        pub fn fromSlice(m: []const T) !Self {
            var fixed_slice = try init(m.len);
            std.mem.copy(T, fixed_slice.slice(), m);
            return fixed_slice;
        }

        /// Return the maximum length of a slice.
        pub fn capacity(self: Self) usize {
            return self.buffer.len;
        }
    };
}

test "fixed slices" {
    var fs = try FixedSlice(u8, 64).init(32);

    try testing.expectEqual(fs.capacity(), 64);
    try testing.expectEqual(fs.slice().len, 32);
    try testing.expectEqual(fs.constSlice().len, 32);

    const another_slice = try fs.resize(48);
    try testing.expectEqual(another_slice.len, 48);

    const x = [_]u8{1} ** 10;
    fs = try FixedSlice(u8, 64).fromSlice(&x);
    try testing.expectEqualSlices(u8, &x, fs.constSlice());

    var fs2 = fs;
    try testing.expectEqualSlices(u8, fs.constSlice(), fs.constSlice());
    fs2.slice()[0] = 0;
    try testing.expect(fs.constSlice()[0] != fs2.constSlice()[0]);

    try testing.expectError(error.SliceTooBig, fs.resize(100));
    try testing.expectError(error.SliceTooBig, FixedSlice(u8, x.len - 1).fromSlice(&x));
}
