// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! A semaphore is an unsigned integer that blocks the kernel thread if
//! the number would become negative.
//! This API supports static initialization and does not require deinitialization.

const std = @import("../std.zig");
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;

const Semaphore = @This();

permits: usize = 0,
mutex: Mutex = .{},
cond: Condition = .{},

pub fn wait(self: *Semaphore) void {
    var held = self.mutex.acquire();
    defer held.release();

    while (self.permits == 0) {
        self.cond.wait(&held);
    }

    self.permits -= 1;
    if (self.permits > 0) {
        self.cond.signal();
    }
}

pub fn post(self: *Semaphore) void {
    const held = self.mutex.acquire();
    defer held.release();

    self.permits += 1;
    self.cond.signal();
}

test "Semaphore" {
    if (std.builtin.single_threaded) {
        return;
    }

    const Relay = struct {
        request: Semaphore = .{},
        reply: Semaphore = .{},

        fn ping(self: *@This()) void {
            self.request.post();
            self.reply.wait();
        }

        fn pong(self: *@This()) void {
            self.request.wait();
            self.reply.post();
        }
    };

    var relay = Relay{};
    var threads = [_]*std.Thread{undefined} ** 8;

    for (threads) |*t| 
        t.* = try std.Thread.spawn(Relay.pong, &relay);

    for (threads) |_|
        relay.ping();

    for (threads) |t| 
        t.wait();
}