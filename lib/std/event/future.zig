// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const Lock = std.event.Lock;

/// This is a value that starts out unavailable, until resolve() is called
/// While it is unavailable, functions suspend when they try to get() it,
/// and then are resumed when resolve() is called.
/// At this point the value remains forever available, and another resolve() is not allowed.
pub fn Future(comptime T: type) type {
    return struct {
        lock: Lock,
        data: T,
        available: Available,

        const Available = enum(u8) {
            NotStarted,
            Started,
            Finished,
        };

        const Self = @This();
        const Queue = std.atomic.Queue(anyframe);

        pub fn init() Self {
            return Self{
                .lock = Lock.initLocked(),
                .available = .NotStarted,
                .data = undefined,
            };
        }

        /// Obtain the value. If it's not available, wait until it becomes
        /// available.
        /// Thread-safe.
        pub fn get(self: *Self) callconv(.Async) *T {
            if (@atomicLoad(Available, &self.available, .SeqCst) == .Finished) {
                return &self.data;
            }
            const held = self.lock.acquire();
            held.release();

            return &self.data;
        }

        /// Gets the data without waiting for it. If it's available, a pointer is
        /// returned. Otherwise, null is returned.
        pub fn getOrNull(self: *Self) ?*T {
            if (@atomicLoad(Available, &self.available, .SeqCst) == .Finished) {
                return &self.data;
            } else {
                return null;
            }
        }

        /// If someone else has started working on the data, wait for them to complete
        /// and return a pointer to the data. Otherwise, return null, and the caller
        /// should start working on the data.
        /// It's not required to call start() before resolve() but it can be useful since
        /// this method is thread-safe.
        pub fn start(self: *Self) callconv(.Async) ?*T {
            const state = @cmpxchgStrong(Available, &self.available, .NotStarted, .Started, .SeqCst, .SeqCst) orelse return null;
            switch (state) {
                .Started => {
                    const held = self.lock.acquire();
                    held.release();
                    return &self.data;
                },
                .Finished => return &self.data,
                else => unreachable,
            }
        }

        /// Make the data become available. May be called only once.
        /// Before calling this, modify the `data` property.
        pub fn resolve(self: *Self) void {
            const prev = @atomicRmw(Available, &self.available, .Xchg, .Finished, .SeqCst);
            assert(prev != .Finished); // resolve() called twice
            Lock.Held.release(Lock.Held{ .lock = &self.lock });
        }
    };
}

test "std.event.Future" {
    // https://github.com/ziglang/zig/issues/1908
    if (builtin.single_threaded) return error.SkipZigTest;
    // https://github.com/ziglang/zig/issues/3251
    if (builtin.os.tag == .freebsd) return error.SkipZigTest;
    // TODO provide a way to run tests in evented I/O mode
    if (!std.io.is_async) return error.SkipZigTest;

    testFuture();
}

fn testFuture() void {
    var future = Future(i32).init();

    var a = async waitOnFuture(&future);
    var b = async waitOnFuture(&future);
    resolveFuture(&future);

    const result = (await a) + (await b);

    try testing.expect(result == 12);
}

fn waitOnFuture(future: *Future(i32)) i32 {
    return future.get().*;
}

fn resolveFuture(future: *Future(i32)) void {
    future.data = 6;
    future.resolve();
}
