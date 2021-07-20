// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! A thread-safe resource which supports blocking until signaled.
//! This API is for kernel threads, not evented I/O.
//! This API is statically initializable. It cannot fail to be initialized
//! and it requires no deinitialization. The downside is that it may not
//! integrate as cleanly into other synchronization APIs, or, in a worst case,
//! may be forced to fall back on spin locking. As a rule of thumb, prefer
//! to use `std.Thread.ResetEvent` when possible, and use `StaticResetEvent` when
//! the logic needs stronger API guarantees.

const std = @import("../std.zig");
const builtin = @import("builtin");
const StaticResetEvent = @This();
const assert = std.debug.assert;
const os = std.os;
const time = std.time;
const linux = std.os.linux;
const windows = std.os.windows;
const testing = std.testing;

impl: Impl = .{},

pub const Impl = if (builtin.single_threaded)
    DebugEvent
else
    AtomicEvent;

/// Sets the event if not already set and wakes up all the threads waiting on
/// the event. It is safe to call `set` multiple times before calling `wait`.
/// However it is illegal to call `set` after `wait` is called until the event
/// is `reset`. This function is thread-safe.
pub fn set(ev: *StaticResetEvent) void {
    return ev.impl.set();
}

/// Wait for the event to be set by blocking the current thread.
/// Thread-safe. No spurious wakeups.
/// Upon return from `wait`, the only function available to be called
/// in `StaticResetEvent` is `reset`.
pub fn wait(ev: *StaticResetEvent) void {
    return ev.impl.wait();
}

/// Resets the event to its original, unset state.
/// This function is *not* thread-safe. It is equivalent to calling
/// `deinit` followed by `init` but without the possibility of failure.
pub fn reset(ev: *StaticResetEvent) void {
    return ev.impl.reset();
}

pub const TimedWaitResult = std.Thread.ResetEvent.TimedWaitResult;

/// Wait for the event to be set by blocking the current thread.
/// A timeout in nanoseconds can be provided as a hint for how
/// long the thread should block on the unset event before returning
/// `TimedWaitResult.timed_out`.
/// Thread-safe. No precision of timing is guaranteed.
/// Upon return from `timedWait`, the only function available to be called
/// in `StaticResetEvent` is `reset`.
pub fn timedWait(ev: *StaticResetEvent, timeout_ns: u64) TimedWaitResult {
    return ev.impl.timedWait(timeout_ns);
}

/// For single-threaded builds, we use this to detect deadlocks.
/// In unsafe modes this ends up being no-ops.
pub const DebugEvent = struct {
    state: State = State.unset,

    const State = enum {
        unset,
        set,
        waited,
    };

    /// This function is provided so that this type can be re-used inside
    /// `std.Thread.ResetEvent`.
    pub fn init(ev: *DebugEvent) void {
        ev.* = .{};
    }

    /// This function is provided so that this type can be re-used inside
    /// `std.Thread.ResetEvent`.
    pub fn deinit(ev: *DebugEvent) void {
        ev.* = undefined;
    }

    pub fn set(ev: *DebugEvent) void {
        switch (ev.state) {
            .unset => ev.state = .set,
            .set => {},
            .waited => unreachable, // Not allowed to call `set` until `reset`.
        }
    }

    pub fn wait(ev: *DebugEvent) void {
        switch (ev.state) {
            .unset => unreachable, // Deadlock detected.
            .set => return,
            .waited => unreachable, // Not allowed to call `wait` until `reset`.
        }
    }

    pub fn timedWait(ev: *DebugEvent, timeout: u64) TimedWaitResult {
        _ = timeout;
        switch (ev.state) {
            .unset => return .timed_out,
            .set => return .event_set,
            .waited => unreachable, // Not allowed to call `wait` until `reset`.
        }
    }

    pub fn reset(ev: *DebugEvent) void {
        ev.state = .unset;
    }
};

pub const AtomicEvent = struct {
    waiters: u32 = 0,

    const WAKE = 1 << 0;
    const WAIT = 1 << 1;

    /// This function is provided so that this type can be re-used inside
    /// `std.Thread.ResetEvent`.
    pub fn init(ev: *AtomicEvent) void {
        ev.* = .{};
    }

    /// This function is provided so that this type can be re-used inside
    /// `std.Thread.ResetEvent`.
    pub fn deinit(ev: *AtomicEvent) void {
        ev.* = undefined;
    }

    pub fn set(ev: *AtomicEvent) void {
        const waiters = @atomicRmw(u32, &ev.waiters, .Xchg, WAKE, .Release);
        if (waiters >= WAIT) {
            return Futex.wake(&ev.waiters, waiters >> 1);
        }
    }

    pub fn wait(ev: *AtomicEvent) void {
        switch (ev.timedWait(null)) {
            .timed_out => unreachable,
            .event_set => return,
        }
    }

    pub fn timedWait(ev: *AtomicEvent, timeout: ?u64) TimedWaitResult {
        var waiters = @atomicLoad(u32, &ev.waiters, .Acquire);
        while (waiters != WAKE) {
            waiters = @cmpxchgWeak(u32, &ev.waiters, waiters, waiters + WAIT, .Acquire, .Acquire) orelse {
                if (Futex.wait(&ev.waiters, timeout)) |_| {
                    return .event_set;
                } else |_| {
                    return .timed_out;
                }
            };
        }
        return .event_set;
    }

    pub fn reset(ev: *AtomicEvent) void {
        @atomicStore(u32, &ev.waiters, 0, .Monotonic);
    }

    pub const Futex = switch (builtin.os.tag) {
        .windows => WindowsFutex,
        .linux => LinuxFutex,
        else => SpinFutex,
    };

    pub const SpinFutex = struct {
        fn wake(waiters: *u32, wake_count: u32) void {
            _ = waiters;
            _ = wake_count;
        }

        fn wait(waiters: *u32, timeout: ?u64) !void {
            var timer: time.Timer = undefined;
            if (timeout != null)
                timer = time.Timer.start() catch return error.TimedOut;

            while (@atomicLoad(u32, waiters, .Acquire) != WAKE) {
                std.os.sched_yield() catch std.atomic.spinLoopHint();
                if (timeout) |timeout_ns| {
                    if (timer.read() >= timeout_ns)
                        return error.TimedOut;
                }
            }
        }
    };

    pub const LinuxFutex = struct {
        fn wake(waiters: *u32, wake_count: u32) void {
            _ = wake_count;
            const waiting = std.math.maxInt(i32); // wake_count
            const ptr = @ptrCast(*const i32, waiters);
            const rc = linux.futex_wake(ptr, linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG, waiting);
            assert(linux.getErrno(rc) == 0);
        }

        fn wait(waiters: *u32, timeout: ?u64) !void {
            var ts: linux.timespec = undefined;
            var ts_ptr: ?*linux.timespec = null;
            if (timeout) |timeout_ns| {
                ts_ptr = &ts;
                ts.tv_sec = @intCast(isize, timeout_ns / time.ns_per_s);
                ts.tv_nsec = @intCast(isize, timeout_ns % time.ns_per_s);
            }

            while (true) {
                const waiting = @atomicLoad(u32, waiters, .Acquire);
                if (waiting == WAKE)
                    return;
                const expected = @intCast(i32, waiting);
                const ptr = @ptrCast(*const i32, waiters);
                const rc = linux.futex_wait(ptr, linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG, expected, ts_ptr);
                switch (linux.getErrno(rc)) {
                    0 => continue,
                    os.ETIMEDOUT => return error.TimedOut,
                    os.EINTR => continue,
                    os.EAGAIN => return,
                    else => unreachable,
                }
            }
        }
    };

    pub const WindowsFutex = struct {
        pub fn wake(waiters: *u32, wake_count: u32) void {
            const handle = getEventHandle() orelse return SpinFutex.wake(waiters, wake_count);
            const key = @ptrCast(*const c_void, waiters);

            var waiting = wake_count;
            while (waiting != 0) : (waiting -= 1) {
                const rc = windows.ntdll.NtReleaseKeyedEvent(handle, key, windows.FALSE, null);
                assert(rc == .SUCCESS);
            }
        }

        pub fn wait(waiters: *u32, timeout: ?u64) !void {
            const handle = getEventHandle() orelse return SpinFutex.wait(waiters, timeout);
            const key = @ptrCast(*const c_void, waiters);

            // NT uses timeouts in units of 100ns with negative value being relative
            var timeout_ptr: ?*windows.LARGE_INTEGER = null;
            var timeout_value: windows.LARGE_INTEGER = undefined;
            if (timeout) |timeout_ns| {
                timeout_ptr = &timeout_value;
                timeout_value = -@intCast(windows.LARGE_INTEGER, timeout_ns / 100);
            }

            // NtWaitForKeyedEvent doesnt have spurious wake-ups
            var rc = windows.ntdll.NtWaitForKeyedEvent(handle, key, windows.FALSE, timeout_ptr);
            switch (rc) {
                .TIMEOUT => {
                    // update the wait count to signal that we're not waiting anymore.
                    // if the .set() thread already observed that we are, perform a
                    // matching NtWaitForKeyedEvent so that the .set() thread doesn't
                    // deadlock trying to run NtReleaseKeyedEvent above.
                    var waiting = @atomicLoad(u32, waiters, .Monotonic);
                    while (true) {
                        if (waiting == WAKE) {
                            rc = windows.ntdll.NtWaitForKeyedEvent(handle, key, windows.FALSE, null);
                            assert(rc == windows.NTSTATUS.WAIT_0);
                            break;
                        } else {
                            waiting = @cmpxchgWeak(u32, waiters, waiting, waiting - WAIT, .Acquire, .Monotonic) orelse break;
                            continue;
                        }
                    }
                    return error.TimedOut;
                },
                windows.NTSTATUS.WAIT_0 => {},
                else => unreachable,
            }
        }

        var event_handle: usize = EMPTY;
        const EMPTY = ~@as(usize, 0);
        const LOADING = EMPTY - 1;

        pub fn getEventHandle() ?windows.HANDLE {
            var handle = @atomicLoad(usize, &event_handle, .Monotonic);
            while (true) {
                switch (handle) {
                    EMPTY => handle = @cmpxchgWeak(usize, &event_handle, EMPTY, LOADING, .Acquire, .Monotonic) orelse {
                        const handle_ptr = @ptrCast(*windows.HANDLE, &handle);
                        const access_mask = windows.GENERIC_READ | windows.GENERIC_WRITE;
                        if (windows.ntdll.NtCreateKeyedEvent(handle_ptr, access_mask, null, 0) != .SUCCESS)
                            handle = 0;
                        @atomicStore(usize, &event_handle, handle, .Monotonic);
                        return @intToPtr(?windows.HANDLE, handle);
                    },
                    LOADING => {
                        std.os.sched_yield() catch std.atomic.spinLoopHint();
                        handle = @atomicLoad(usize, &event_handle, .Monotonic);
                    },
                    else => {
                        return @intToPtr(?windows.HANDLE, handle);
                    },
                }
            }
        }
    };
};

test "basic usage" {
    var event = StaticResetEvent{};

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

        value: u128 = 0,
        in: StaticResetEvent = .{},
        out: StaticResetEvent = .{},

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

    var context = Context{};
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
