// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../std.zig");
const deadline = @import("deadline.zig");
const target = std.Target.current;
const Atomic = std.atomic.Atomic;
const Futex = std.Thread.Futex;

const Mutex = @This();
const Impl = if (std.builtin.single_threaded)
    SerialMutexImpl
else if (target.cpu.arch.isX86())
    X86MutexImpl
else 
    MutexImpl;

impl: Impl = .{},

pub fn tryAcquire(self: *Mutex) ?Held {
    if (!self.impl.tryAcquire()) return null;
    return Held{ .impl = &self.impl };
}

pub fn acquire(self: *Mutex) Held {
    self.impl.acquire();
    return Held{ .impl = &self.impl };
}

pub fn timedAcquire(self: *Mutex, timeout_ns: u64) error{TimedOut}!Held {
    try self.impl.timedAcquire(timeout_ns);
    return Held{ .impl = &self.impl };
}

pub const Held = extern struct {
    impl: *Impl,
    
    pub fn release(self: Held) void {
        return self.impl.release();
    }
};

const SerialMutexImpl = extern struct {
    locked: bool = false,

    fn tryAcquire(self: *Impl) bool {
        if (self.locked) return false;
        self.locked = true;
        return true;
    }

    fn acquire(self: *Impl) void {
        assert(self.tryAcquire());
    }

    fn timedAcquire(self: *Impl, timeout_ns: u64) error{TimedOut}!void {
       if (self.tryAcquire()) return;
       std.time.sleep(timeout_ns);
       return error.TimedOut;
    }

    fn release(self: *Impl) void {
        assert(self.locked);
        self.locked = false;
    }
};

const X86MutexImpl = extern struct {
    state: extern union {
        dword: Atomic(u32),
        byte: extern struct {
            locked: Atomic(u8),
            contended: Atomic(u8),
        },
    } = .{
        .dword = Atomic(u32).init(UNLOCKED),
    },

    const UNLOCKED = 0;
    const LOCKED = 1 << 0;
    const CONTENDED = 1 << 8;

    fn tryAcquire(self: *Impl) callconv(.Inline) bool {
        const locked = self.state.byte.locked.swap(LOCKED, .Acquire);
        return locked == UNLOCKED;
    }

    fn acquire(self: *Impl) void {
        if (self.tryAcquire()) return;
        return self.acquireSlow(null) catch unreachable;
    }

    fn timedAcquire(self: *Impl, timeout_ns: u64) error{TimedOut}!void {
        if (self.tryAcquire()) return;
        return self.acquireSlow(timeout_ns);
    }

    fn acquireSlow(self: *Impl, timeout_ns: anytype) error{TimedOut}!void {
        @setCold(true);

        // create a deadline in which the timeout actually expires
        var deadline_ns: u64 = undefined;
        if (@TypeOf(timeout_ns) == u64) {
            deadline_ns = std.time.now() + timeout_ns;
        }

        var spin: u8 = 100;
        while (spin > 0) : (spin -= 1) {
            std.atomic.spinLoopHint();

            const dword = self.state.dword.load(.Monotonic);
            if (dword & CONTENDED != 0) {
                break;
            }

            if (dword & LOCKED != 0) continue;
            if (self.tryAcquire()) {
                return;
            }
        }

        while (true) {
            std.atomic.spinLoopHint();
            
            // Transition the Mutex to CONTENDED, which assumes it's LOCKED (so LOCKED | CONTENDED).
            // Transitioning to LOCKED | CONTENDED when not LOCKED also acquires the Mutex.
            var dword = self.state.dword.load(.Monotonic);
            if (dword != LOCKED | CONTENDED) {
                dword = self.state.dword.swap(LOCKED | CONTENDED, .Acquire);
                if (dword & LOCKED == 0) {
                    return;
                }
            }

            // Figure out the actual timeout for sleeping on the futex using the deadline
            var timeout: ?u64 = null;
            if (@TypeOf(timeout_ns) == u64) {
                const now_ns = std.time.now();
                if (now_ns >= deadline_ns) return error.TimedOut;
                timeout = deadline_ns - now_ns;
            }

            try Futex.wait(
                &self.state.dword, 
                LOCKED | CONTENDED, 
                timeout,
            );
        }
    }

    fn release(self: *Impl) void {
        self.byte.locked.store(UNLOCKED, .Release);

        // shouldn't be reordered before the byte store above
        // since they technically have the same address
        const state = self.state.load(.Monotonic);
        if (state == CONTENDED) {
            self.releaseSlow();
        }
    }

    fn releaseSlow(self: *Impl) void {
        @setCold(true);

        // If it's no longer CONTENDED, its either:
        // - UNLOCKED: 
        // Another releaseSlow() thread already completed the CAS
        //
        // - LOCKED: 
        // Another releaseSlow() completed, then another thread acquire()'d.
        // Let them be the one to do the wake-up instead.
        //
        // - LOCKED | CONTENDED: 
        // A contended (or previously contended) thread updated the state
        // and either acquired the lock or went back to sleep.
        // If they wen't back to sleep, that means theres another thread which acquired()'d
        // so we don't have to do the wake-up since they would wake to an already locked Mutex.
        // Again, let the acquire()'d thread be the one to do the wake-up instead.
        if (self.state.compareAndSwap(
            CONTENDED,
            UNLOCKED,
            .Monotonic,
            .Monotonic,
        )) |updated| {
            return;
        }

        const num_waiters = 1;
        Futex.wake(&self.state, num_waiters);
    }
};

const MutexImpl = extern struct {
    state: Atomic(u32) = Atomic(u32).init(UNLOCKED),

    const UNLOCKED: u32 = 0;
    const LOCKED: u32 = 1;
    const CONTENDED: u32 = 2;
    
    fn init() Impl {
        return .{};
    }

    fn tryAcquire(self: *Impl) callconv(.Inline) bool {
        return self.state.compareAndSwap(
            UNLOCKED,
            LOCKED,
            .Acquire,
            .Monotonic,
        ) == null;
    }

    fn acquire(self: *Impl) void {
        if (self.acquireFast()) return;
        return self.acquireSlow(null) catch unreachable;
    }

    fn timedAcquire(self: *Impl, timeout_ns: u64) error{TimedOut}!void {
        if (self.acquireFast()) return;
        return self.acquireSlow(timeout_ns);
    }

    fn acquireFast(self: *Impl) callconv(.Inline) bool {
        return self.state.tryCompareAndSwap(
            UNLOCKED,
            LOCKED,
            .Acquire,
            .Monotonic,
        ) == null;
    }

    fn acquireSlow(self: *Impl, timeout_ns: anytype) error{TimedOut}!void {
        @setCold(true);

        // create a deadline in which the timeout actually expires
        var deadline_ns: u64 = undefined;
        if (@TypeOf(timeout_ns) == u64) {
            deadline_ns = std.time.now() + timeout_ns;
        }

        var spin: u8 = 10;
        var acquire_state = LOCKED;
        var state = self.state.load(.Monotonic);

        while (true) {
            // Try to lock the Mutex if its unlocked.
            // acquire_state is changed to CONTENDED if this thread goes to sleep.
            //
            // We acquire with CONTENDED instead of LOCKED in that scenario 
            // to make sure that we wake another thread sleeping in release()
            // which didn't see the transition to UNLOCKED since it was asleep.
            //
            // A CONTENDED acquire unfortunately results in one extra wake() 
            // if there were no other sleeping threads at the time of the acquire.
            if (state == UNLOCKED) {
                state = self.state.tryCompareAndSwap(
                    state,
                    acquire_state,
                    .Acquire,
                    .Monotonic,
                ) orelse return;
                continue;
            }

            if (state != CONTENDED) {
                // If there's no pending threads, try to spin on the Mutex a few times.
                // This makes the throughput close to a spinlock when under micro-contention.
                if (spin > 0) {
                    spin -= 1;
                    std.atomic.spinLoopHint();
                    state = self.state.load(.Monotonic);
                    continue;
                }

                // For other platforms, mark the Mutex as CONTENDED if it's not already.
                // This just indicates that there's waiting threads so no Acquire barrier needed.
                if (self.state.tryCompareAndSwap(
                    state,
                    CONTENDED,
                    .Monotonic,
                    .Monotonic,
                )) |updated| {
                    state = updated;
                    continue;
                }
            }

            // Figure out the actual timeout for sleeping on the futex using the deadline
            var timeout: ?u64 = null;
            if (@TypeOf(timeout_ns) == u64) {
                const now_ns = std.time.now();
                if (now_ns >= deadline_ns) return error.TimedOut;
                timeout = deadline_ns - now_ns;
            }

            try Futex.wait(
                &self.state, 
                CONTENDED, 
                timeout,
            );

            spin = 10;
            acquire_state = CONTENDED;
            state = self.state.load(.Monotonic);
        }
    }

    fn release(self: *Impl) void {
        const state = self.state.swap(UNLOCKED, .Release);
        
        // Wake up a sleeping thread if it was previously CONTENDED.
        // The woken up thread would acquire by updating the state to CONTENDED again.
        // This is to make sure a future release() wouldn't miss waking up threads that 
        // don't see the reset to UNLOCKED above due to them being asleep.
        switch (state) {
            UNLOCKED => unreachable, // unlocked an unlocked mutex
            LOCKED => {},
            CONTENDED => self.releaseSlow(),
            else => unreachable, // invalid mutex state
        }
    }

    fn releaseSlow(self: *Impl) void {
        @setCold(true);

        const num_waiters = 1;
        Futex.wake(&self.state, num_waiters);
    }
};

test "Mutex" {
    return error.TODO;
}
