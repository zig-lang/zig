// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std.zig");
const builtin = @import("builtin");
const testing = std.testing;

pub fn once(comptime f: fn () void) Once(f) {
    return Once(f){};
}

/// An object that executes the function `f` just once.
pub fn Once(comptime f: fn () void) type {
    return struct {
        done: bool = false,
        mutex: std.Thread.Mutex = std.Thread.Mutex{},

        /// Call the function `f`.
        /// If `call` is invoked multiple times `f` will be executed only the
        /// first time.
        /// The invocations are thread-safe.
        pub fn call(self: *@This()) void {
            if (@atomicLoad(bool, &self.done, .Acquire))
                return;

            return self.callSlow();
        }

        fn callSlow(self: *@This()) void {
            @setCold(true);

            const T = self.mutex.acquire();
            defer T.release();

            // The first thread to acquire the mutex gets to run the initializer
            if (!self.done) {
                f();
                @atomicStore(bool, &self.done, true, .Release);
            }
        }
    };
}

var global_number: i32 = 0;
var global_once = once(incr);

fn incr() void {
    global_number += 1;
}

test "Once executes its function just once" {
    if (builtin.single_threaded) {
        global_once.call();
        global_once.call();
    } else {
        var threads: [10]std.Thread = undefined;
        defer for (threads) |handle| handle.join();

        for (threads) |*handle| {
            handle.* = try std.Thread.spawn(.{}, struct {
                fn thread_fn(x: u8) void {
                    _ = x;
                    global_once.call();
                }
            }.thread_fn, .{0});
        }
    }

    try testing.expectEqual(@as(i32, 1), global_number);
}
