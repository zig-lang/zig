// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const Loop = std.event.Loop;

/// A WaitGroup keeps track and waits for a group of async tasks to finish.
/// Call `begin` when creating new tasks, and have tasks call `finish` when done.
/// You can provide a count for both operations to perform them in bulk.
/// Call `wait` to suspend until all tasks are completed.
/// Multiple waiters are supported.
///
/// WaitGroup is an instance of WaitGroupGeneric, which takes in a bitsize
/// for the internal counter. WaitGroup defaults to a `usize` counter.
/// It's also possible to define a max value for the counter so that
/// `begin` will return error.Overflow when the limit is reached, even
/// if the integer type has not has not overflowed.
/// By default `max_value` is set to std.math.maxInt(CounterType).
pub const WaitGroup = WaitGroupGeneric(std.meta.bitCount(usize));

pub fn WaitGroupGeneric(comptime counter_size: u16) type {
    const CounterType = std.meta.Int(.unsigned, counter_size);

    const global_event_loop = Loop.instance orelse
        @compileError("std.event.WaitGroup currently only works with event-based I/O");

    return struct {
        counter: CounterType = 0,
        max_counter: CounterType = std.math.maxInt(CounterType),
        mutex: std.Thread.Mutex = .{},
        waiters: ?*Waiter = null,
        const Waiter = struct {
            next: ?*Waiter,
            tail: *Waiter,
            node: Loop.NextTickNode,
        };

        const Self = @This();
        pub fn begin(self: *Self, count: CounterType) error{Overflow}!void {
            const held = self.mutex.acquire();
            defer held.release();

            const new_counter = try std.math.add(CounterType, self.counter, count);
            if (new_counter > self.max_counter) return error.Overflow;
            self.counter = new_counter;
        }

        pub fn finish(self: *Self, count: CounterType) void {
            var waiters = blk: {
                const held = self.mutex.acquire();
                defer held.release();
                self.counter = std.math.sub(CounterType, self.counter, count) catch unreachable;
                if (self.counter == 0) {
                    const temp = self.waiters;
                    self.waiters = null;
                    break :blk temp;
                }
                break :blk null;
            };

            // We don't need to hold the lock to reschedule any potential waiter.
            while (waiters) |w| {
                const temp_w = w;
                waiters = w.next;
                global_event_loop.onNextTick(&temp_w.node);
            }
        }

        pub fn wait(self: *Self) void {
            const held = self.mutex.acquire();

            if (self.counter == 0) {
                held.release();
                return;
            }

            var self_waiter: Waiter = undefined;
            self_waiter.node.data = @frame();
            if (self.waiters) |head| {
                head.tail.next = &self_waiter;
                head.tail = &self_waiter;
            } else {
                self.waiters = &self_waiter;
                self_waiter.tail = &self_waiter;
                self_waiter.next = null;
            }
            suspend {
                held.release();
            }
        }
    };
}

test "basic WaitGroup usage" {
    if (!std.io.is_async) return error.SkipZigTest;

    // TODO https://github.com/ziglang/zig/issues/1908
    if (builtin.single_threaded) return error.SkipZigTest;

    // TODO https://github.com/ziglang/zig/issues/3251
    if (builtin.os.tag == .freebsd) return error.SkipZigTest;

    var initial_wg = WaitGroup{};
    var final_wg = WaitGroup{};

    try initial_wg.begin(1);
    try final_wg.begin(1);
    var task_frame = async task(&initial_wg, &final_wg);
    initial_wg.finish(1);
    final_wg.wait();
    await task_frame;
}

fn task(wg_i: *WaitGroup, wg_f: *WaitGroup) void {
    wg_i.wait();
    wg_f.finish(1);
}
