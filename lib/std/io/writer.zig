// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const assert = std.debug.assert;
const builtin = std.builtin;
const mem = std.mem;

pub fn Writer(
    comptime Context: type,
    comptime WriteError: type,
    comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize,
) type {
    return struct {
        context: Context,

        const Self = @This();
        pub const Error = WriteError;

        pub fn write(self: Self, bytes: []const u8) Error!usize {
            return writeFn(self.context, bytes);
        }

        pub fn writeAll(self: Self, bytes: []const u8) Error!void {
            var index: usize = 0;
            while (index != bytes.len) {
                index += try self.write(bytes[index..]);
            }
        }

        pub fn print(self: Self, comptime format: []const u8, args: anytype) Error!void {
            return std.fmt.format(self, format, args);
        }

        pub fn writeByte(self: Self, byte: u8) Error!void {
            const array = [1]u8{byte};
            return self.writeAll(&array);
        }

        pub fn writeByteNTimes(self: Self, byte: u8, n: usize) Error!void {
            var bytes: [256]u8 = undefined;
            mem.set(u8, bytes[0..], byte);

            var remaining: usize = n;
            while (remaining > 0) {
                const to_write = std.math.min(remaining, bytes.len);
                try self.writeAll(bytes[0..to_write]);
                remaining -= to_write;
            }
        }

        /// Write a native-endian integer.
        /// TODO audit non-power-of-two int sizes
        pub fn writeIntNative(self: Self, comptime T: type, value: T) Error!void {
            var bytes: [(@typeInfo(T).Int.bits + 7) / 8]u8 = undefined;
            mem.writeIntNative(T, &bytes, value);
            return self.writeAll(&bytes);
        }

        /// Write a foreign-endian integer.
        /// TODO audit non-power-of-two int sizes
        pub fn writeIntForeign(self: Self, comptime T: type, value: T) Error!void {
            var bytes: [(@typeInfo(T).Int.bits + 7) / 8]u8 = undefined;
            mem.writeIntForeign(T, &bytes, value);
            return self.writeAll(&bytes);
        }

        /// TODO audit non-power-of-two int sizes
        pub fn writeIntLittle(self: Self, comptime T: type, value: T) Error!void {
            var bytes: [(@typeInfo(T).Int.bits + 7) / 8]u8 = undefined;
            mem.writeIntLittle(T, &bytes, value);
            return self.writeAll(&bytes);
        }

        /// TODO audit non-power-of-two int sizes
        pub fn writeIntBig(self: Self, comptime T: type, value: T) Error!void {
            var bytes: [(@typeInfo(T).Int.bits + 7) / 8]u8 = undefined;
            mem.writeIntBig(T, &bytes, value);
            return self.writeAll(&bytes);
        }

        /// TODO audit non-power-of-two int sizes
        pub fn writeInt(self: Self, comptime T: type, value: T, endian: std.builtin.Endian) Error!void {
            var bytes: [(@typeInfo(T).Int.bits + 7) / 8]u8 = undefined;
            mem.writeInt(T, &bytes, value, endian);
            return self.writeAll(&bytes);
        }

        pub fn writeStruct(self: Self, value: anytype) Error!void {
            // Only extern and packed structs have defined in-memory layout.
            comptime assert(@typeInfo(@TypeOf(value)).Struct.layout != std.builtin.TypeInfo.ContainerLayout.Auto);
            return self.writeAll(mem.asBytes(&value));
        }
    };
}
