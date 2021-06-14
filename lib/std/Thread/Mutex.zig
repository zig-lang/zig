// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! Lock may be held only once. If the same thread tries to acquire
//! the same mutex twice, it deadlocks.  This type supports static
//! initialization and is at most `@sizeOf(usize)` in size.  When an
//! application is built in single threaded release mode, all the
//! functions are no-ops. In single threaded debug mode, there is
//! deadlock detection.
//!
//! Example usage:
//! var m = Mutex{};
//!
//! const lock = m.acquire();
//! defer lock.release();
//! ... critical code
//!
//! Non-blocking:
//! if (m.tryAcquire) |lock| {
//!     defer lock.release();
//!     // ... critical section
//! } else {
//!     // ... lock not acquired
//! }

impl: Impl = .{},

const Mutex = @This();
const std = @import("../std.zig");
const builtin = std.builtin;
const os = std.os;
const assert = std.debug.assert;
const windows = os.windows;
const linux = os.linux;
const testing = std.testing;
const StaticResetEvent = std.thread.StaticResetEvent;

/// Try to acquire the mutex without blocking. Returns `null` if the mutex is
/// unavailable. Otherwise returns `Held`. Call `release` on `Held`.
pub fn tryAcquire(m: *Mutex) ?Impl.Held {
    return m.impl.tryAcquire();
}

/// Acquire the mutex. Deadlocks if the mutex is already
/// held by the calling thread.
pub fn acquire(m: *Mutex) Impl.Held {
    return m.impl.acquire();
}

pub const Impl = if (builtin.single_threaded)
    Dummy
else if (builtin.os.tag == .windows)
    WindowsMutex
else if (std.Thread.use_pthreads)
    PthreadMutex
else
    AtomicMutex;

pub const AtomicMutex = struct {
    state: State = .unlocked,

    const State = enum(i32) {
        unlocked,
        locked,
        waiting,
    };

    pub const Held = struct {
        mutex: *AtomicMutex,

        pub fn release(held: Held) void {
            switch (@atomicRmw(State, &held.mutex.state, .Xchg, .unlocked, .Release)) {
                .unlocked => unreachable,
                .locked => {},
                .waiting => held.mutex.unlockSlow(),
            }
        }
    };

    pub fn tryAcquire(m: *AtomicMutex) ?Held {
        if (@cmpxchgStrong(
            State,
            &m.state,
            .unlocked,
            .locked,
            .Acquire,
            .Monotonic,
        ) == null) {
            return Held{ .mutex = m };
        } else {
            return null;
        }
    }

    pub fn acquire(m: *AtomicMutex) Held {
        switch (@atomicRmw(State, &m.state, .Xchg, .locked, .Acquire)) {
            .unlocked => {},
            else => |s| m.lockSlow(s),
        }
        return Held{ .mutex = m };
    }

    fn lockSlow(m: *AtomicMutex, current_state: State) void {
        @setCold(true);
        var new_state = current_state;

        var spin: u8 = 0;
        while (spin < 100) : (spin += 1) {
            const state = @cmpxchgWeak(
                State,
                &m.state,
                .unlocked,
                new_state,
                .Acquire,
                .Monotonic,
            ) orelse return;

            switch (state) {
                .unlocked => {},
                .locked => {},
                .waiting => break,
            }

            var iter = std.math.min(32, spin + 1);
            while (iter > 0) : (iter -= 1)
                std.atomic.spinLoopHint();
        }

        new_state = .waiting;
        while (true) {
            switch (@atomicRmw(State, &m.state, .Xchg, new_state, .Acquire)) {
                .unlocked => return,
                else => {},
            }
            switch (std.Target.current.os.tag) {
                .linux => {
                    switch (linux.getErrno(linux.futex_wait(
                        @ptrCast(*const i32, &m.state),
                        linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAIT,
                        @enumToInt(new_state),
                        null,
                    ))) {
                        0 => {},
                        std.os.EINTR => {},
                        std.os.EAGAIN => {},
                        else => unreachable,
                    }
                },
                else => std.atomic.spinLoopHint(),
            }
        }
    }

    fn unlockSlow(m: *AtomicMutex) void {
        @setCold(true);

        switch (std.Target.current.os.tag) {
            .linux => {
                switch (linux.getErrno(linux.futex_wake(
                    @ptrCast(*const i32, &m.state),
                    linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAKE,
                    1,
                ))) {
                    0 => {},
                    std.os.EFAULT => {},
                    else => unreachable,
                }
            },
            else => {},
        }
    }
};

pub const PthreadMutex = struct {
    pthread_mutex: std.c.pthread_mutex_t = .{},

    pub const Held = struct {
        mutex: *PthreadMutex,

        pub fn release(held: Held) void {
            switch (std.c.pthread_mutex_unlock(&held.mutex.pthread_mutex)) {
                0 => return,
                std.c.EINVAL => unreachable,
                std.c.EAGAIN => unreachable,
                std.c.EPERM => unreachable,
                else => unreachable,
            }
        }
    };

    /// Try to acquire the mutex without blocking. Returns null if
    /// the mutex is unavailable. Otherwise returns Held. Call
    /// release on Held.
    pub fn tryAcquire(m: *PthreadMutex) ?Held {
        if (std.c.pthread_mutex_trylock(&m.pthread_mutex) == 0) {
            return Held{ .mutex = m };
        } else {
            return null;
        }
    }

    /// Acquire the mutex. Will deadlock if the mutex is already
    /// held by the calling thread.
    pub fn acquire(m: *PthreadMutex) Held {
        switch (std.c.pthread_mutex_lock(&m.pthread_mutex)) {
            0 => return Held{ .mutex = m },
            std.c.EINVAL => unreachable,
            std.c.EBUSY => unreachable,
            std.c.EAGAIN => unreachable,
            std.c.EDEADLK => unreachable,
            std.c.EPERM => unreachable,
            else => unreachable,
        }
    }
};

/// This has the sematics as `Mutex`, however it does not actually do any
/// synchronization. Operations are safety-checked no-ops.
pub const Dummy = struct {
    lock: @TypeOf(lock_init) = lock_init,

    const lock_init = if (std.debug.runtime_safety) false else {};

    pub const Held = struct {
        mutex: *Dummy,

        pub fn release(held: Held) void {
            if (std.debug.runtime_safety) {
                held.mutex.lock = false;
            }
        }
    };

    /// Try to acquire the mutex without blocking. Returns null if
    /// the mutex is unavailable. Otherwise returns Held. Call
    /// release on Held.
    pub fn tryAcquire(m: *Dummy) ?Held {
        if (std.debug.runtime_safety) {
            if (m.lock) return null;
            m.lock = true;
        }
        return Held{ .mutex = m };
    }

    /// Acquire the mutex. Will deadlock if the mutex is already
    /// held by the calling thread.
    pub fn acquire(m: *Dummy) Held {
        return m.tryAcquire() orelse @panic("deadlock detected");
    }
};

const WindowsMutex = struct {
    srwlock: windows.SRWLOCK = windows.SRWLOCK_INIT,

    pub const Held = struct {
        mutex: *WindowsMutex,

        pub fn release(held: Held) void {
            windows.kernel32.ReleaseSRWLockExclusive(&held.mutex.srwlock);
        }
    };

    pub fn tryAcquire(m: *WindowsMutex) ?Held {
        if (windows.kernel32.TryAcquireSRWLockExclusive(&m.srwlock) != windows.FALSE) {
            return Held{ .mutex = m };
        } else {
            return null;
        }
    }

    pub fn acquire(m: *WindowsMutex) Held {
        windows.kernel32.AcquireSRWLockExclusive(&m.srwlock);
        return Held{ .mutex = m };
    }
};

const TestContext = struct {
    mutex: *Mutex,
    data: i128,

    const incr_count = 10000;
};

test "basic usage" {
    var mutex = Mutex{};

    var context = TestContext{
        .mutex = &mutex,
        .data = 0,
    };

    if (builtin.single_threaded) {
        worker(&context);
        try testing.expect(context.data == TestContext.incr_count);
    } else {
        const thread_count = 10;
        var threads: [thread_count]*std.Thread = undefined;
        for (threads) |*t| {
            t.* = try std.Thread.spawn(worker, &context);
        }
        for (threads) |t|
            t.wait();

        try testing.expect(context.data == thread_count * TestContext.incr_count);
    }
}

fn worker(ctx: *TestContext) void {
    var i: usize = 0;
    while (i != TestContext.incr_count) : (i += 1) {
        const held = ctx.mutex.acquire();
        defer held.release();

        ctx.data += 1;
    }
}
