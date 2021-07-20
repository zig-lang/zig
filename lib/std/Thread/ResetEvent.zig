// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! A thread-safe resource which supports blocking until signaled.
//! This API is for kernel threads, not evented I/O.
//! This API requires being initialized at runtime, and initialization
//! can fail. Once initialized, the core operations cannot fail.
//! If you need an abstraction that cannot fail to be initialized, see
//! `std.Thread.StaticResetEvent`. However if you can handle initialization failure,
//! it is preferred to use `ResetEvent`.

const ResetEvent = @This();
const std = @import("../std.zig");
const builtin = @import("builtin");
const testing = std.testing;
const assert = std.debug.assert;
const c = std.c;
const os = std.os;
const time = std.time;

impl: Impl,

pub const Impl = if (builtin.single_threaded)
    std.Thread.StaticResetEvent.DebugEvent
else if (builtin.target.isDarwin())
    DarwinEvent
else if (std.Thread.use_pthreads)
    PosixEvent
else
    std.Thread.StaticResetEvent.AtomicEvent;

pub const InitError = error{SystemResources};

/// After `init`, it is legal to call any other function.
pub fn init(ev: *ResetEvent) InitError!void {
    return ev.impl.init();
}

/// This function is not thread-safe.
/// After `deinit`, the only legal function to call is `init`.
pub fn deinit(ev: *ResetEvent) void {
    return ev.impl.deinit();
}

/// Sets the event if not already set and wakes up all the threads waiting on
/// the event. It is safe to call `set` multiple times before calling `wait`.
/// However it is illegal to call `set` after `wait` is called until the event
/// is `reset`. This function is thread-safe.
pub fn set(ev: *ResetEvent) void {
    return ev.impl.set();
}

/// Resets the event to its original, unset state.
/// This function is *not* thread-safe. It is equivalent to calling
/// `deinit` followed by `init` but without the possibility of failure.
pub fn reset(ev: *ResetEvent) void {
    return ev.impl.reset();
}

/// Wait for the event to be set by blocking the current thread.
/// Thread-safe. No spurious wakeups.
/// Upon return from `wait`, the only functions available to be called
/// in `ResetEvent` are `reset` and `deinit`.
pub fn wait(ev: *ResetEvent) void {
    return ev.impl.wait();
}

pub const TimedWaitResult = enum { event_set, timed_out };

/// Wait for the event to be set by blocking the current thread.
/// A timeout in nanoseconds can be provided as a hint for how
/// long the thread should block on the unset event before returning
/// `TimedWaitResult.timed_out`.
/// Thread-safe. No precision of timing is guaranteed.
/// Upon return from `wait`, the only functions available to be called
/// in `ResetEvent` are `reset` and `deinit`.
pub fn timedWait(ev: *ResetEvent, timeout_ns: u64) TimedWaitResult {
    return ev.impl.timedWait(timeout_ns);
}

/// Apple has decided to not support POSIX semaphores, so we go with a
/// different approach using Grand Central Dispatch. This API is exposed
/// by libSystem so it is guaranteed to be available on all Darwin platforms.
pub const DarwinEvent = struct {
    sem: c.dispatch_semaphore_t = undefined,

    pub fn init(ev: *DarwinEvent) !void {
        ev.* = .{
            .sem = c.dispatch_semaphore_create(0) orelse return error.SystemResources,
        };
    }

    pub fn deinit(ev: *DarwinEvent) void {
        c.dispatch_release(ev.sem);
        ev.* = undefined;
    }

    pub fn set(ev: *DarwinEvent) void {
        // Empirically this returns the numerical value of the semaphore.
        _ = c.dispatch_semaphore_signal(ev.sem);
    }

    pub fn wait(ev: *DarwinEvent) void {
        assert(c.dispatch_semaphore_wait(ev.sem, c.DISPATCH_TIME_FOREVER) == 0);
    }

    pub fn timedWait(ev: *DarwinEvent, timeout_ns: u64) TimedWaitResult {
        const t = c.dispatch_time(c.DISPATCH_TIME_NOW, @intCast(i64, timeout_ns));
        if (c.dispatch_semaphore_wait(ev.sem, t) != 0) {
            return .timed_out;
        } else {
            return .event_set;
        }
    }

    pub fn reset(ev: *DarwinEvent) void {
        // Keep calling until the semaphore goes back down to 0.
        while (c.dispatch_semaphore_wait(ev.sem, c.DISPATCH_TIME_NOW) == 0) {}
    }
};

/// POSIX semaphores must be initialized at runtime because they are allowed to
/// be implemented as file descriptors, in which case initialization would require
/// a syscall to open the fd.
pub const PosixEvent = struct {
    sem: c.sem_t = undefined,

    pub fn init(ev: *PosixEvent) !void {
        switch (c.getErrno(c.sem_init(&ev.sem, 0, 0))) {
            0 => return,
            else => return error.SystemResources,
        }
    }

    pub fn deinit(ev: *PosixEvent) void {
        assert(c.sem_destroy(&ev.sem) == 0);
        ev.* = undefined;
    }

    pub fn set(ev: *PosixEvent) void {
        assert(c.sem_post(&ev.sem) == 0);
    }

    pub fn wait(ev: *PosixEvent) void {
        while (true) {
            switch (c.getErrno(c.sem_wait(&ev.sem))) {
                0 => return,
                c.EINTR => continue,
                c.EINVAL => unreachable,
                else => unreachable,
            }
        }
    }

    pub fn timedWait(ev: *PosixEvent, timeout_ns: u64) TimedWaitResult {
        var ts: os.timespec = undefined;
        var timeout_abs = timeout_ns;
        os.clock_gettime(os.CLOCK_REALTIME, &ts) catch return .timed_out;
        timeout_abs += @intCast(u64, ts.tv_sec) * time.ns_per_s;
        timeout_abs += @intCast(u64, ts.tv_nsec);
        ts.tv_sec = @intCast(@TypeOf(ts.tv_sec), @divFloor(timeout_abs, time.ns_per_s));
        ts.tv_nsec = @intCast(@TypeOf(ts.tv_nsec), @mod(timeout_abs, time.ns_per_s));
        while (true) {
            switch (c.getErrno(c.sem_timedwait(&ev.sem, &ts))) {
                0 => return .event_set,
                c.EINTR => continue,
                c.EINVAL => unreachable,
                c.ETIMEDOUT => return .timed_out,
                else => unreachable,
            }
        }
    }

    pub fn reset(ev: *PosixEvent) void {
        while (true) {
            switch (c.getErrno(c.sem_trywait(&ev.sem))) {
                0 => continue, // Need to make it go to zero.
                c.EINTR => continue,
                c.EINVAL => unreachable,
                c.EAGAIN => return, // The semaphore currently has the value zero.
                else => unreachable,
            }
        }
    }
};

test "basic usage" {
    var event: ResetEvent = undefined;
    try event.init();
    defer event.deinit();

    // test event setting
    event.set();

    // test event resetting
    event.reset();

    // test event waiting (non-blocking)
    event.set();
    event.wait();
    event.reset();

    event.set();
    try testing.expectEqual(TimedWaitResult.event_set, event.timedWait(1));

    // test cross-thread signaling
    if (builtin.single_threaded)
        return;

    const Context = struct {
        const Self = @This();

        value: u128,
        in: ResetEvent,
        out: ResetEvent,

        fn init(self: *Self) !void {
            self.* = .{
                .value = 0,
                .in = undefined,
                .out = undefined,
            };
            try self.in.init();
            try self.out.init();
        }

        fn deinit(self: *Self) void {
            self.in.deinit();
            self.out.deinit();
            self.* = undefined;
        }

        fn sender(self: *Self) !void {
            // update value and signal input
            try testing.expect(self.value == 0);
            self.value = 1;
            self.in.set();

            // wait for receiver to update value and signal output
            self.out.wait();
            try testing.expect(self.value == 2);

            // update value and signal final input
            self.value = 3;
            self.in.set();
        }

        fn receiver(self: *Self) !void {
            // wait for sender to update value and signal input
            self.in.wait();
            try testing.expect(self.value == 1);

            // update value and signal output
            self.in.reset();
            self.value = 2;
            self.out.set();

            // wait for sender to update value and signal final input
            self.in.wait();
            try testing.expect(self.value == 3);
        }

        fn sleeper(self: *Self) void {
            self.in.set();
            time.sleep(time.ns_per_ms * 2);
            self.value = 5;
            self.out.set();
        }

        fn timedWaiter(self: *Self) !void {
            self.in.wait();
            try testing.expectEqual(TimedWaitResult.timed_out, self.out.timedWait(time.ns_per_us));
            try self.out.timedWait(time.ns_per_ms * 100);
            try testing.expect(self.value == 5);
        }
    };

    var context: Context = undefined;
    try context.init();
    defer context.deinit();
    const receiver = try std.Thread.spawn(.{}, Context.receiver, .{&context});
    defer receiver.join();
    try context.sender();

    if (false) {
        // I have now observed this fail on macOS, Windows, and Linux.
        // https://github.com/ziglang/zig/issues/7009
        var timed = Context.init();
        defer timed.deinit();
        const sleeper = try std.Thread.spawn(.{}, Context.sleeper, .{&timed});
        defer sleeper.join();
        try timed.timedWaiter();
    }
}
