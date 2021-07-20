// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const Loop = std.event.Loop;

/// Thread-safe async/await lock.
/// Functions which are waiting for the lock are suspended, and
/// are resumed when the lock is released, in order.
/// Allows only one actor to hold the lock.
/// TODO: make this API also work in blocking I/O mode.
pub const Lock = struct {
    mutex: std.Thread.Mutex = std.Thread.Mutex{},
    head: usize = UNLOCKED,

    const UNLOCKED = 0;
    const LOCKED = 1;

    const global_event_loop = Loop.instance orelse
        @compileError("std.event.Lock currently only works with event-based I/O");

    const Waiter = struct {
        // forced Waiter alignment to ensure it doesn't clash with LOCKED
        next: ?*Waiter align(2),
        tail: *Waiter,
        node: Loop.NextTickNode,
    };

    pub fn initLocked() Lock {
        return Lock{ .head = LOCKED };
    }

    pub fn acquire(self: *Lock) Held {
        const held = self.mutex.acquire();

        // self.head transitions from multiple stages depending on the value:
        // UNLOCKED -> LOCKED:
        //   acquire Lock ownership when theres no waiters
        // LOCKED -> <Waiter head ptr>:
        //   Lock is already owned, enqueue first Waiter
        // <head ptr> -> <head ptr>:
        //   Lock is owned with pending waiters. Push our waiter to the queue.

        if (self.head == UNLOCKED) {
            self.head = LOCKED;
            held.release();
            return Held{ .lock = self };
        }

        var waiter: Waiter = undefined;
        waiter.next = null;
        waiter.tail = &waiter;

        const head = switch (self.head) {
            UNLOCKED => unreachable,
            LOCKED => null,
            else => @intToPtr(*Waiter, self.head),
        };

        if (head) |h| {
            h.tail.next = &waiter;
            h.tail = &waiter;
        } else {
            self.head = @ptrToInt(&waiter);
        }

        suspend {
            waiter.node = Loop.NextTickNode{
                .prev = undefined,
                .next = undefined,
                .data = @frame(),
            };
            held.release();
        }

        return Held{ .lock = self };
    }

    pub const Held = struct {
        lock: *Lock,

        pub fn release(self: Held) void {
            const waiter = blk: {
                const held = self.lock.mutex.acquire();
                defer held.release();

                // self.head goes through the reverse transition from acquire():
                // <head ptr> -> <new head ptr>:
                //   pop a waiter from the queue to give Lock ownership when theres still others pending
                // <head ptr> -> LOCKED:
                //   pop the laster waiter from the queue, while also giving it lock ownership when awaken
                // LOCKED -> UNLOCKED:
                //   last lock owner releases lock while no one else is waiting for it

                switch (self.lock.head) {
                    UNLOCKED => {
                        unreachable; // Lock unlocked while unlocking
                    },
                    LOCKED => {
                        self.lock.head = UNLOCKED;
                        break :blk null;
                    },
                    else => {
                        const waiter = @intToPtr(*Waiter, self.lock.head);
                        self.lock.head = if (waiter.next == null) LOCKED else @ptrToInt(waiter.next);
                        if (waiter.next) |next|
                            next.tail = waiter.tail;
                        break :blk waiter;
                    },
                }
            };

            if (waiter) |w| {
                global_event_loop.onNextTick(&w.node);
            }
        }
    };
};

test "std.event.Lock" {
    if (!std.io.is_async) return error.SkipZigTest;

    // TODO https://github.com/ziglang/zig/issues/1908
    if (builtin.single_threaded) return error.SkipZigTest;

    // TODO https://github.com/ziglang/zig/issues/3251
    if (builtin.os.tag == .freebsd) return error.SkipZigTest;

    var lock = Lock{};
    testLock(&lock);

    const expected_result = [1]i32{3 * @intCast(i32, shared_test_data.len)} ** shared_test_data.len;
    try testing.expectEqualSlices(i32, &expected_result, &shared_test_data);
}
fn testLock(lock: *Lock) void {
    var handle1 = async lockRunner(lock);
    var handle2 = async lockRunner(lock);
    var handle3 = async lockRunner(lock);

    await handle1;
    await handle2;
    await handle3;
}

var shared_test_data = [1]i32{0} ** 10;
var shared_test_index: usize = 0;

fn lockRunner(lock: *Lock) void {
    Lock.global_event_loop.yield();

    var i: usize = 0;
    while (i < shared_test_data.len) : (i += 1) {
        const handle = lock.acquire();
        defer handle.release();

        shared_test_index = 0;
        while (shared_test_index < shared_test_data.len) : (shared_test_index += 1) {
            shared_test_data[shared_test_index] = shared_test_data[shared_test_index] + 1;
        }
    }
}
