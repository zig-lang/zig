// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! Similar to `StaticResetEvent` but on `set()` it also (atomically) does `reset()`.
//! Unlike StaticResetEvent, `wait()` can only be called by one thread (MPSC-like).
//!
//! AutoResetEvent has 3 possible states:
//! - UNSET: the AutoResetEvent is currently unset
//! - SET: the AutoResetEvent was notified before a wait() was called
//! - <StaticResetEvent pointer>: there is an active waiter waiting for a notification.
//!
//! When attempting to wait:
//!  if the event is unset, it registers a ResetEvent pointer to be notified when the event is set
//!  if the event is already set, then it consumes the notification and resets the event.
//!
//! When attempting to notify:
//!  if the event is unset, then we set the event
//!  if theres a waiting ResetEvent, then we unset the event and notify the ResetEvent
//!
//! This ensures that the event is automatically reset after a wait() has been issued
//! and avoids the race condition when using StaticResetEvent in the following scenario:
//!  thread 1                  | thread 2
//!  StaticResetEvent.wait()   |
//!                            | StaticResetEvent.set()
//!                            | StaticResetEvent.set()
//!  StaticResetEvent.reset()  |
//!  StaticResetEvent.wait()   | (missed the second .set() notification above)

state: usize = UNSET,

const std = @import("../std.zig");
const builtin = @import("builtin");
const testing = std.testing;
const assert = std.debug.assert;
const StaticResetEvent = std.Thread.StaticResetEvent;
const AutoResetEvent = @This();

const UNSET = 0;
const SET = 1;

/// the minimum alignment for the `*StaticResetEvent` created by wait*()
const event_align = std.math.max(@alignOf(StaticResetEvent), 2);

pub fn wait(self: *AutoResetEvent) void {
    self.waitFor(null) catch unreachable;
}

pub fn timedWait(self: *AutoResetEvent, timeout: u64) error{TimedOut}!void {
    return self.waitFor(timeout);
}

fn waitFor(self: *AutoResetEvent, timeout: ?u64) error{TimedOut}!void {
    // lazily initialized StaticResetEvent
    var reset_event: StaticResetEvent align(event_align) = undefined;
    var has_reset_event = false;

    var state = @atomicLoad(usize, &self.state, .SeqCst);
    while (true) {
        // consume a notification if there is any
        if (state == SET) {
            @atomicStore(usize, &self.state, UNSET, .SeqCst);
            return;
        }

        // check if theres currently a pending ResetEvent pointer already registered
        if (state != UNSET) {
            unreachable; // multiple waiting threads on the same AutoResetEvent
        }

        // lazily initialize the ResetEvent if it hasn't been already
        if (!has_reset_event) {
            has_reset_event = true;
            reset_event = .{};
        }

        // Since the AutoResetEvent currently isnt set,
        // try to register our ResetEvent on it to wait
        // for a set() call from another thread.
        if (@cmpxchgWeak(
            usize,
            &self.state,
            UNSET,
            @ptrToInt(&reset_event),
            .SeqCst,
            .SeqCst,
        )) |new_state| {
            state = new_state;
            continue;
        }

        // if no timeout was specified, then just wait forever
        const timeout_ns = timeout orelse {
            reset_event.wait();
            return;
        };

        // wait with a timeout and return if signalled via set()
        switch (reset_event.timedWait(timeout_ns)) {
            .event_set => return,
            .timed_out => {},
        }

        // If we timed out, we need to transition the AutoResetEvent back to UNSET.
        // If we don't, then when we return, a set() thread could observe a pointer to an invalid ResetEvent.
        state = @cmpxchgStrong(
            usize,
            &self.state,
            @ptrToInt(&reset_event),
            UNSET,
            .SeqCst,
            .SeqCst,
        ) orelse return error.TimedOut;

        // We didn't manage to unregister ourselves from the state.
        if (state == SET) {
            unreachable; // AutoResetEvent notified without waking up the waiting thread
        } else if (state != UNSET) {
            unreachable; // multiple waiting threads on the same AutoResetEvent observed when timing out
        }

        // This menas a set() thread saw our ResetEvent pointer, acquired it, and is trying to wake it up.
        // We need to wait for it to wake up our ResetEvent before we can return and invalidate it.
        // We don't return error.TimedOut here as it technically notified us while we were "timing out".
        reset_event.wait();
        return;
    }
}

pub fn set(self: *AutoResetEvent) void {
    var state = @atomicLoad(usize, &self.state, .SeqCst);
    while (true) {
        // If the AutoResetEvent is already set, there is nothing else left to do
        if (state == SET) {
            return;
        }

        // If the AutoResetEvent isn't set,
        // then try to leave a notification for the wait() thread that we set() it.
        if (state == UNSET) {
            state = @cmpxchgWeak(
                usize,
                &self.state,
                UNSET,
                SET,
                .SeqCst,
                .SeqCst,
            ) orelse return;
            continue;
        }

        // There is a ResetEvent pointer registered on the AutoResetEvent event thats waiting.
        // Try to acquire ownership of it so that we can wake it up.
        // This also resets the AutoResetEvent so that there is no race condition as defined above.
        if (@cmpxchgWeak(
            usize,
            &self.state,
            state,
            UNSET,
            .SeqCst,
            .SeqCst,
        )) |new_state| {
            state = new_state;
            continue;
        }

        const reset_event = @intToPtr(*align(event_align) StaticResetEvent, state);
        reset_event.set();
        return;
    }
}

test "basic usage" {
    // test local code paths
    {
        var event = AutoResetEvent{};
        try testing.expectError(error.TimedOut, event.timedWait(1));
        event.set();
        event.wait();
    }

    // test cross-thread signaling
    if (builtin.single_threaded)
        return;

    const Context = struct {
        value: u128 = 0,
        in: AutoResetEvent = AutoResetEvent{},
        out: AutoResetEvent = AutoResetEvent{},

        const Self = @This();

        fn sender(self: *Self) !void {
            try testing.expect(self.value == 0);
            self.value = 1;
            self.out.set();

            self.in.wait();
            try testing.expect(self.value == 2);
            self.value = 3;
            self.out.set();

            self.in.wait();
            try testing.expect(self.value == 4);
        }

        fn receiver(self: *Self) !void {
            self.out.wait();
            try testing.expect(self.value == 1);
            self.value = 2;
            self.in.set();

            self.out.wait();
            try testing.expect(self.value == 3);
            self.value = 4;
            self.in.set();
        }
    };

    var context = Context{};
    const send_thread = try std.Thread.spawn(.{}, Context.sender, .{&context});
    const recv_thread = try std.Thread.spawn(.{}, Context.receiver, .{&context});

    send_thread.join();
    recv_thread.join();
}
