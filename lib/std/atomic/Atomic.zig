// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const builtin = @import("builtin");

const testing = std.testing;
const target = builtin.target;
const Ordering = std.atomic.Ordering;

pub fn Atomic(comptime T: type) type {
    return extern struct {
        value: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return .{ .value = value };
        }

        /// Non-atomically load from the atomic value without synchronization.
        /// Care must be taken to avoid data-races when interacting with other atomic operations.
        pub fn loadUnchecked(self: Self) T {
            return self.value;
        }

        /// Non-atomically store to the atomic value without synchronization.
        /// Care must be taken to avoid data-races when interacting with other atomic operations.
        pub fn storeUnchecked(self: *Self, value: T) void {
            self.value = value;
        }

        pub fn load(self: *const Self, comptime ordering: Ordering) T {
            return switch (ordering) {
                .AcqRel => @compileError(@tagName(ordering) ++ " implies " ++ @tagName(Ordering.Release) ++ " which is only allowed on atomic stores"),
                .Release => @compileError(@tagName(ordering) ++ " is only allowed on atomic stores"),
                else => @atomicLoad(T, &self.value, ordering),
            };
        }

        pub fn store(self: *Self, value: T, comptime ordering: Ordering) void {
            return switch (ordering) {
                .AcqRel => @compileError(@tagName(ordering) ++ " implies " ++ @tagName(Ordering.Acquire) ++ " which is only allowed on atomic loads"),
                .Acquire => @compileError(@tagName(ordering) ++ " is only allowed on atomic loads"),
                else => @atomicStore(T, &self.value, value, ordering),
            };
        }

        pub inline fn swap(self: *Self, value: T, comptime ordering: Ordering) T {
            return self.rmw(.Xchg, value, ordering);
        }

        pub inline fn compareAndSwap(
            self: *Self,
            compare: T,
            exchange: T,
            comptime success: Ordering,
            comptime failure: Ordering,
        ) ?T {
            return self.cmpxchg(true, compare, exchange, success, failure);
        }

        pub inline fn tryCompareAndSwap(
            self: *Self,
            compare: T,
            exchange: T,
            comptime success: Ordering,
            comptime failure: Ordering,
        ) ?T {
            return self.cmpxchg(false, compare, exchange, success, failure);
        }

        inline fn cmpxchg(
            self: *Self,
            comptime is_strong: bool,
            compare: T,
            exchange: T,
            comptime success: Ordering,
            comptime failure: Ordering,
        ) ?T {
            if (success == .Unordered or failure == .Unordered) {
                @compileError(@tagName(Ordering.Unordered) ++ " is only allowed on atomic loads and stores");
            }

            comptime var success_is_stronger = switch (failure) {
                .SeqCst => success == .SeqCst,
                .AcqRel => @compileError(@tagName(failure) ++ " implies " ++ @tagName(Ordering.Release) ++ " which is only allowed on success"),
                .Acquire => success == .SeqCst or success == .AcqRel or success == .Acquire,
                .Release => @compileError(@tagName(failure) ++ " is only allowed on success"),
                .Monotonic => true,
                .Unordered => unreachable,
            };

            if (!success_is_stronger) {
                @compileError(@tagName(success) ++ " must be stronger than " ++ @tagName(failure));
            }

            return switch (is_strong) {
                true => @cmpxchgStrong(T, &self.value, compare, exchange, success, failure),
                false => @cmpxchgWeak(T, &self.value, compare, exchange, success, failure),
            };
        }

        inline fn rmw(
            self: *Self,
            comptime op: std.builtin.AtomicRmwOp,
            value: T,
            comptime ordering: Ordering,
        ) T {
            return @atomicRmw(T, &self.value, op, value, ordering);
        }

        fn exportWhen(comptime condition: bool, comptime functions: type) type {
            return if (condition) functions else struct {};
        }

        pub usingnamespace exportWhen(std.meta.trait.isNumber(T), struct {
            pub inline fn fetchAdd(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.Add, value, ordering);
            }

            pub inline fn fetchSub(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.Sub, value, ordering);
            }

            pub inline fn fetchMin(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.Min, value, ordering);
            }

            pub inline fn fetchMax(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.Max, value, ordering);
            }
        });

        pub usingnamespace exportWhen(std.meta.trait.isIntegral(T), struct {
            pub inline fn fetchAnd(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.And, value, ordering);
            }

            pub inline fn fetchNand(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.Nand, value, ordering);
            }

            pub inline fn fetchOr(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.Or, value, ordering);
            }

            pub inline fn fetchXor(self: *Self, value: T, comptime ordering: Ordering) T {
                return self.rmw(.Xor, value, ordering);
            }

            const Bit = std.math.Log2Int(T);
            const BitRmwOp = enum {
                Set,
                Reset,
                Toggle,
            };

            pub inline fn bitSet(self: *Self, bit: Bit, comptime ordering: Ordering) u1 {
                return bitRmw(self, .Set, bit, ordering);
            }

            pub inline fn bitReset(self: *Self, bit: Bit, comptime ordering: Ordering) u1 {
                return bitRmw(self, .Reset, bit, ordering);
            }

            pub inline fn bitToggle(self: *Self, bit: Bit, comptime ordering: Ordering) u1 {
                return bitRmw(self, .Toggle, bit, ordering);
            }

            inline fn bitRmw(
                self: *Self,
                comptime op: BitRmwOp,
                bit: Bit,
                comptime ordering: Ordering,
            ) u1 {
                // x86 supports dedicated bitwise instructions
                if (comptime target.cpu.arch.isX86() and @sizeOf(T) >= 2 and @sizeOf(T) <= 8) {
                    const instruction = switch (op) {
                        .Set => "lock bts",
                        .Reset => "lock btr",
                        .Toggle => "lock btc",
                    };

                    const suffix = switch (@sizeOf(T)) {
                        2 => "w",
                        4 => "l",
                        8 => "q",
                        else => @compileError("Invalid atomic type " ++ @typeName(T)),
                    };

                    const old_bit = asm volatile (instruction ++ suffix ++ " %[bit], %[ptr]"
                        : [result] "={@ccc}" (-> u8) // LLVM doesn't support u1 flag register return values
                        : [ptr] "*p" (&self.value),
                          [bit] "X" (@as(T, bit))
                        : "cc", "memory"
                    );

                    return @intCast(u1, old_bit);
                }

                const mask = @as(T, 1) << bit;
                const value = switch (op) {
                    .Set => self.fetchOr(mask, ordering),
                    .Reset => self.fetchAnd(~mask, ordering),
                    .Toggle => self.fetchXor(mask, ordering),
                };

                return @boolToInt(value & mask != 0);
            }
        });
    };
}

fn atomicIntTypes() []const type {
    comptime var bytes = 1;
    comptime var types: []const type = &[_]type{};
    inline while (bytes <= @sizeOf(usize)) : (bytes *= 2) {
        types = types ++ &[_]type{std.meta.Int(.unsigned, bytes * 8)};
    }
    return types;
}

test "Atomic.loadUnchecked" {
    inline for (atomicIntTypes()) |Int| {
        var x = Atomic(Int).init(5);
        try testing.expectEqual(x.loadUnchecked(), 5);
    }
}

test "Atomic.storeUnchecked" {
    inline for (atomicIntTypes()) |Int| {
        _ = Int;
        var x = Atomic(usize).init(5);
        x.storeUnchecked(10);
        try testing.expectEqual(x.loadUnchecked(), 10);
    }
}

test "Atomic.load" {
    inline for (atomicIntTypes()) |Int| {
        inline for (.{ .Unordered, .Monotonic, .Acquire, .SeqCst }) |ordering| {
            var x = Atomic(Int).init(5);
            try testing.expectEqual(x.load(ordering), 5);
        }
    }
}

test "Atomic.store" {
    inline for (atomicIntTypes()) |Int| {
        inline for (.{ .Unordered, .Monotonic, .Release, .SeqCst }) |ordering| {
            _ = Int;
            var x = Atomic(usize).init(5);
            x.store(10, ordering);
            try testing.expectEqual(x.load(.SeqCst), 10);
        }
    }
}

const atomic_rmw_orderings = [_]Ordering{
    .Monotonic,
    .Acquire,
    .Release,
    .AcqRel,
    .SeqCst,
};

test "Atomic.swap" {
    inline for (atomic_rmw_orderings) |ordering| {
        var x = Atomic(usize).init(5);
        try testing.expectEqual(x.swap(10, ordering), 5);
        try testing.expectEqual(x.load(.SeqCst), 10);

        var y = Atomic(enum(usize) { a, b, c }).init(.c);
        try testing.expectEqual(y.swap(.a, ordering), .c);
        try testing.expectEqual(y.load(.SeqCst), .a);

        var z = Atomic(f32).init(5.0);
        try testing.expectEqual(z.swap(10.0, ordering), 5.0);
        try testing.expectEqual(z.load(.SeqCst), 10.0);

        var a = Atomic(bool).init(false);
        try testing.expectEqual(a.swap(true, ordering), false);
        try testing.expectEqual(a.load(.SeqCst), true);

        var b = Atomic(?*u8).init(null);
        try testing.expectEqual(b.swap(@intToPtr(?*u8, @alignOf(u8)), ordering), null);
        try testing.expectEqual(b.load(.SeqCst), @intToPtr(?*u8, @alignOf(u8)));
    }
}

const atomic_cmpxchg_orderings = [_][2]Ordering{
    .{ .Monotonic, .Monotonic },
    .{ .Acquire, .Monotonic },
    .{ .Acquire, .Acquire },
    .{ .Release, .Monotonic },
    // Although accepted by LLVM, acquire failure implies AcqRel success
    // .{ .Release, .Acquire },
    .{ .AcqRel, .Monotonic },
    .{ .AcqRel, .Acquire },
    .{ .SeqCst, .Monotonic },
    .{ .SeqCst, .Acquire },
    .{ .SeqCst, .SeqCst },
};

test "Atomic.compareAndSwap" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_cmpxchg_orderings) |ordering| {
            var x = Atomic(Int).init(0);
            try testing.expectEqual(x.compareAndSwap(1, 0, ordering[0], ordering[1]), 0);
            try testing.expectEqual(x.load(.SeqCst), 0);
            try testing.expectEqual(x.compareAndSwap(0, 1, ordering[0], ordering[1]), null);
            try testing.expectEqual(x.load(.SeqCst), 1);
            try testing.expectEqual(x.compareAndSwap(1, 0, ordering[0], ordering[1]), null);
            try testing.expectEqual(x.load(.SeqCst), 0);
        }
    }
}

test "Atomic.tryCompareAndSwap" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_cmpxchg_orderings) |ordering| {
            var x = Atomic(Int).init(0);

            try testing.expectEqual(x.tryCompareAndSwap(1, 0, ordering[0], ordering[1]), 0);
            try testing.expectEqual(x.load(.SeqCst), 0);

            while (x.tryCompareAndSwap(0, 1, ordering[0], ordering[1])) |_| {}
            try testing.expectEqual(x.load(.SeqCst), 1);

            while (x.tryCompareAndSwap(1, 0, ordering[0], ordering[1])) |_| {}
            try testing.expectEqual(x.load(.SeqCst), 0);
        }
    }
}

test "Atomic.fetchAdd" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(5);
            try testing.expectEqual(x.fetchAdd(5, ordering), 5);
            try testing.expectEqual(x.load(.SeqCst), 10);
            try testing.expectEqual(x.fetchAdd(std.math.maxInt(Int), ordering), 10);
            try testing.expectEqual(x.load(.SeqCst), 9);
        }
    }
}

test "Atomic.fetchSub" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(5);
            try testing.expectEqual(x.fetchSub(5, ordering), 5);
            try testing.expectEqual(x.load(.SeqCst), 0);
            try testing.expectEqual(x.fetchSub(1, ordering), 0);
            try testing.expectEqual(x.load(.SeqCst), std.math.maxInt(Int));
        }
    }
}

test "Atomic.fetchMin" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(5);
            try testing.expectEqual(x.fetchMin(0, ordering), 5);
            try testing.expectEqual(x.load(.SeqCst), 0);
            try testing.expectEqual(x.fetchMin(10, ordering), 0);
            try testing.expectEqual(x.load(.SeqCst), 0);
        }
    }
}

test "Atomic.fetchMax" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(5);
            try testing.expectEqual(x.fetchMax(10, ordering), 5);
            try testing.expectEqual(x.load(.SeqCst), 10);
            try testing.expectEqual(x.fetchMax(5, ordering), 10);
            try testing.expectEqual(x.load(.SeqCst), 10);
        }
    }
}

test "Atomic.fetchAnd" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(0b11);
            try testing.expectEqual(x.fetchAnd(0b10, ordering), 0b11);
            try testing.expectEqual(x.load(.SeqCst), 0b10);
            try testing.expectEqual(x.fetchAnd(0b00, ordering), 0b10);
            try testing.expectEqual(x.load(.SeqCst), 0b00);
        }
    }
}

test "Atomic.fetchNand" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(0b11);
            try testing.expectEqual(x.fetchNand(0b10, ordering), 0b11);
            try testing.expectEqual(x.load(.SeqCst), ~@as(Int, 0b10));
            try testing.expectEqual(x.fetchNand(0b00, ordering), ~@as(Int, 0b10));
            try testing.expectEqual(x.load(.SeqCst), ~@as(Int, 0b00));
        }
    }
}

test "Atomic.fetchOr" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(0b11);
            try testing.expectEqual(x.fetchOr(0b100, ordering), 0b11);
            try testing.expectEqual(x.load(.SeqCst), 0b111);
            try testing.expectEqual(x.fetchOr(0b010, ordering), 0b111);
            try testing.expectEqual(x.load(.SeqCst), 0b111);
        }
    }
}

test "Atomic.fetchXor" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(0b11);
            try testing.expectEqual(x.fetchXor(0b10, ordering), 0b11);
            try testing.expectEqual(x.load(.SeqCst), 0b01);
            try testing.expectEqual(x.fetchXor(0b01, ordering), 0b01);
            try testing.expectEqual(x.load(.SeqCst), 0b00);
        }
    }
}

test "Atomic.bitSet" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(0);
            const bit_array = @as([std.meta.bitCount(Int)]void, undefined);

            for (bit_array) |_, bit_index| {
                const bit = @intCast(std.math.Log2Int(Int), bit_index);
                const mask = @as(Int, 1) << bit;

                // setting the bit should change the bit
                try testing.expect(x.load(.SeqCst) & mask == 0);
                try testing.expectEqual(x.bitSet(bit, ordering), 0);
                try testing.expect(x.load(.SeqCst) & mask != 0);

                // setting it again shouldn't change the bit
                try testing.expectEqual(x.bitSet(bit, ordering), 1);
                try testing.expect(x.load(.SeqCst) & mask != 0);

                // all the previous bits should have not changed (still be set)
                for (bit_array[0..bit_index]) |_, prev_bit_index| {
                    const prev_bit = @intCast(std.math.Log2Int(Int), prev_bit_index);
                    const prev_mask = @as(Int, 1) << prev_bit;
                    try testing.expect(x.load(.SeqCst) & prev_mask != 0);
                }
            }
        }
    }
}

test "Atomic.bitReset" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(0);
            const bit_array = @as([std.meta.bitCount(Int)]void, undefined);

            for (bit_array) |_, bit_index| {
                const bit = @intCast(std.math.Log2Int(Int), bit_index);
                const mask = @as(Int, 1) << bit;
                x.storeUnchecked(x.loadUnchecked() | mask);

                // unsetting the bit should change the bit
                try testing.expect(x.load(.SeqCst) & mask != 0);
                try testing.expectEqual(x.bitReset(bit, ordering), 1);
                try testing.expect(x.load(.SeqCst) & mask == 0);

                // unsetting it again shouldn't change the bit
                try testing.expectEqual(x.bitReset(bit, ordering), 0);
                try testing.expect(x.load(.SeqCst) & mask == 0);

                // all the previous bits should have not changed (still be reset)
                for (bit_array[0..bit_index]) |_, prev_bit_index| {
                    const prev_bit = @intCast(std.math.Log2Int(Int), prev_bit_index);
                    const prev_mask = @as(Int, 1) << prev_bit;
                    try testing.expect(x.load(.SeqCst) & prev_mask == 0);
                }
            }
        }
    }
}

test "Atomic.bitToggle" {
    inline for (atomicIntTypes()) |Int| {
        inline for (atomic_rmw_orderings) |ordering| {
            var x = Atomic(Int).init(0);
            const bit_array = @as([std.meta.bitCount(Int)]void, undefined);

            for (bit_array) |_, bit_index| {
                const bit = @intCast(std.math.Log2Int(Int), bit_index);
                const mask = @as(Int, 1) << bit;

                // toggling the bit should change the bit
                try testing.expect(x.load(.SeqCst) & mask == 0);
                try testing.expectEqual(x.bitToggle(bit, ordering), 0);
                try testing.expect(x.load(.SeqCst) & mask != 0);

                // toggling it again *should* change the bit
                try testing.expectEqual(x.bitToggle(bit, ordering), 1);
                try testing.expect(x.load(.SeqCst) & mask == 0);

                // all the previous bits should have not changed (still be toggled back)
                for (bit_array[0..bit_index]) |_, prev_bit_index| {
                    const prev_bit = @intCast(std.math.Log2Int(Int), prev_bit_index);
                    const prev_mask = @as(Int, 1) << prev_bit;
                    try testing.expect(x.load(.SeqCst) & prev_mask == 0);
                }
            }
        }
    }
}
