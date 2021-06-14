// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! A condition provides a way for a kernel thread to block until it is signaled
//! to wake up. Spurious wakeups are possible.
//! This API supports static initialization and does not require deinitialization.

impl: Impl = .{},

const std = @import("../std.zig");
const Condition = @This();
const windows = std.os.windows;
const linux = std.os.linux;
const Mutex = std.Thread.Mutex;
const assert = std.debug.assert;

pub fn wait(cond: *Condition, held_mutex: *Mutex.Impl.Held) void {
    cond.impl.wait(held_mutex);
}

pub fn signal(cond: *Condition) void {
    cond.impl.signal();
}

pub fn broadcast(cond: *Condition) void {
    cond.impl.broadcast();
}

const Impl = if (std.builtin.single_threaded)
    SingleThreadedCondition
else if (std.Target.current.os.tag == .windows)
    WindowsCondition
else if (std.Thread.use_pthreads)
    PthreadCondition
else
    AtomicCondition;

pub const SingleThreadedCondition = struct {
    pub fn wait(cond: *SingleThreadedCondition, held_mutex: *Mutex.Impl.Held) void {
        unreachable; // deadlock detected
    }

    pub fn signal(cond: *SingleThreadedCondition) void {}

    pub fn broadcast(cond: *SingleThreadedCondition) void {}
};

pub const WindowsCondition = struct {
    cond: windows.CONDITION_VARIABLE = windows.CONDITION_VARIABLE_INIT,

    pub fn wait(cond: *WindowsCondition, held_mutex: *Mutex.Impl.Held) void {
        const rc = windows.kernel32.SleepConditionVariableSRW(
            &cond.cond,
            &held_mutex.mutex.srwlock,
            windows.INFINITE,
            @as(windows.ULONG, 0),
        );
        assert(rc != windows.FALSE);
    }

    pub fn signal(cond: *WindowsCondition) void {
        windows.kernel32.WakeConditionVariable(&cond.cond);
    }

    pub fn broadcast(cond: *WindowsCondition) void {
        windows.kernel32.WakeAllConditionVariable(&cond.cond);
    }
};

pub const PthreadCondition = struct {
    cond: std.c.pthread_cond_t = .{},

    pub fn wait(cond: *PthreadCondition, held_mutex: *Mutex.Impl.Held) void {
        const rc = std.c.pthread_cond_wait(&cond.cond, &held_mutex.mutex.pthread_mutex);
        assert(rc == 0);
    }

    pub fn signal(cond: *PthreadCondition) void {
        const rc = std.c.pthread_cond_signal(&cond.cond);
        assert(rc == 0);
    }

    pub fn broadcast(cond: *PthreadCondition) void {
        const rc = std.c.pthread_cond_broadcast(&cond.cond);
        assert(rc == 0);
    }
};

pub const AtomicCondition = struct {
    pending: bool = false,
    queue_mutex: Mutex = .{},
    queue_list: QueueList = .{},

    pub const QueueList = std.SinglyLinkedList(QueueItem);

    pub const QueueItem = struct {
        futex: i32 = 0,

        fn wait(cond: *@This()) void {
            while (@atomicLoad(i32, &cond.futex, .Acquire) == 0) {
                switch (std.Target.current.os.tag) {
                    .linux => {
                        switch (linux.getErrno(linux.futex_wait(
                            &cond.futex,
                            linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_WAIT,
                            0,
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

        fn notify(cond: *@This()) void {
            @atomicStore(i32, &cond.futex, 1, .Release);

            switch (std.Target.current.os.tag) {
                .linux => {
                    switch (linux.getErrno(linux.futex_wake(
                        &cond.futex,
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

    pub fn wait(cond: *AtomicCondition, held_mutex: *Mutex.Impl.Held) void {
        var waiter = QueueList.Node{ .data = .{} };

        {
            const held = cond.queue_mutex.acquire();
            defer held.release();

            cond.queue_list.prepend(&waiter);
            @atomicStore(bool, &cond.pending, true, .SeqCst);
        }

        held_mutex.release();
        waiter.data.wait();
        held_mutex.* = held_mutex.mutex.acquire();
    }

    pub fn signal(cond: *AtomicCondition) void {
        if (@atomicLoad(bool, &cond.pending, .SeqCst) == false)
            return;

        const maybe_waiter = blk: {
            const held = cond.queue_mutex.acquire();
            defer held.release();

            const maybe_waiter = cond.queue_list.popFirst();
            @atomicStore(bool, &cond.pending, cond.queue_list.first != null, .SeqCst);
            break :blk maybe_waiter;
        };

        if (maybe_waiter) |waiter|
            waiter.data.notify();
    }

    pub fn broadcast(cond: *AtomicCondition) void {
        if (@atomicLoad(bool, &cond.pending, .SeqCst) == false)
            return;

        @atomicStore(bool, &cond.pending, false, .SeqCst);

        var waiters = blk: {
            const held = cond.queue_mutex.acquire();
            defer held.release();

            const waiters = cond.queue_list;
            cond.queue_list = .{};
            break :blk waiters;
        };

        while (waiters.popFirst()) |waiter|
            waiter.data.notify();
    }
};

test "Condition.signal" {
    if (std.builtin.single_threaded) {
        return;
    }

    const Signal = struct {
        notified: bool = false,
        mutex: Mutex = .{},
        cond: Condition = .{},

        fn wait(self: *@This()) void {
            var held = self.mutex.acquire();
            defer held.release();

            while (!self.notified)
                self.cond.wait(&held);
        }

        fn notify(self: *@This()) void {
            var held = self.mutex.acquire();
            defer held.release();

            self.notified = true;
            self.cond.signal();
        }
    };

    const SignalThread = struct {
        signals: []Signal,
        index: usize,

        fn run(self: @This()) void {
            self.signals[self.index].wait();
            self.signals[(self.index + 1) % self.signals.len].notify();
        }
    };

    var signals = [_]Signal{.{}} ** 4;
    var threads = [_]*std.Thread{undefined} ** signals.len;

    for (threads) |*t, index| {
        t.* = try std.Thread.spawn(SignalThread.run, .{
            .signals = &signals,
            .index = index,
        });
    }

    signals[0].notify();

    for (threads) |t| {
        t.wait();
    }
}

test "Condition.broadcast" {
    if (std.builtin.single_threaded) {
        return;
    }

    const Barrier = struct {
        count: usize,
        mutex: Mutex = .{},
        cond: Condition = .{},

        fn wait(self: *@This()) void {
            var held = self.mutex.acquire();
            defer held.release();

            assert(self.count > 0);
            self.count -= 1;

            if (self.count == 0) {
                self.cond.broadcast();
                return;
            }

            while (self.count != 0) {
                self.cond.wait(&held);
            }
        }
    };
    
    var threads = [_]*std.Thread{undefined} ** 10;
    var barrier = Barrier{ .count = threads.len };

    for (threads) |*t| t.* = try std.Thread.spawn(Barrier.wait, &barrier);
    for (threads) |t| t.wait();

    try std.testing.expectEqual(@as(usize, 0), blk: {
        const held = barrier.mutex.acquire();
        defer held.release();
        break :blk barrier.count;
    });
}