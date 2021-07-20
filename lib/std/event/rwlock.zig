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
/// Many readers can hold the lock at the same time; however locking for writing is exclusive.
/// When a read lock is held, it will not be released until the reader queue is empty.
/// When a write lock is held, it will not be released until the writer queue is empty.
/// TODO: make this API also work in blocking I/O mode
pub const RwLock = struct {
    shared_state: State,
    writer_queue: Queue,
    reader_queue: Queue,
    writer_queue_empty: bool,
    reader_queue_empty: bool,
    reader_lock_count: usize,

    const State = enum(u8) {
        Unlocked,
        WriteLock,
        ReadLock,
    };

    const Queue = std.atomic.Queue(anyframe);

    const global_event_loop = Loop.instance orelse
        @compileError("std.event.RwLock currently only works with event-based I/O");

    pub const HeldRead = struct {
        lock: *RwLock,

        pub fn release(self: HeldRead) void {
            // If other readers still hold the lock, we're done.
            if (@atomicRmw(usize, &self.lock.reader_lock_count, .Sub, 1, .SeqCst) != 1) {
                return;
            }

            @atomicStore(bool, &self.lock.reader_queue_empty, true, .SeqCst);
            if (@cmpxchgStrong(State, &self.lock.shared_state, .ReadLock, .Unlocked, .SeqCst, .SeqCst) != null) {
                // Didn't unlock. Someone else's problem.
                return;
            }

            self.lock.commonPostUnlock();
        }
    };

    pub const HeldWrite = struct {
        lock: *RwLock,

        pub fn release(self: HeldWrite) void {
            // See if we can leave it locked for writing, and pass the lock to the next writer
            // in the queue to grab the lock.
            if (self.lock.writer_queue.get()) |node| {
                global_event_loop.onNextTick(node);
                return;
            }

            // We need to release the write lock. Check if any readers are waiting to grab the lock.
            if (!@atomicLoad(bool, &self.lock.reader_queue_empty, .SeqCst)) {
                // Switch to a read lock.
                @atomicStore(State, &self.lock.shared_state, .ReadLock, .SeqCst);
                while (self.lock.reader_queue.get()) |node| {
                    global_event_loop.onNextTick(node);
                }
                return;
            }

            @atomicStore(bool, &self.lock.writer_queue_empty, true, .SeqCst);
            @atomicStore(State, &self.lock.shared_state, .Unlocked, .SeqCst);

            self.lock.commonPostUnlock();
        }
    };

    pub fn init() RwLock {
        return .{
            .shared_state = .Unlocked,
            .writer_queue = Queue.init(),
            .writer_queue_empty = true,
            .reader_queue = Queue.init(),
            .reader_queue_empty = true,
            .reader_lock_count = 0,
        };
    }

    /// Must be called when not locked. Not thread safe.
    /// All calls to acquire() and release() must complete before calling deinit().
    pub fn deinit(self: *RwLock) void {
        assert(self.shared_state == .Unlocked);
        while (self.writer_queue.get()) |node| resume node.data;
        while (self.reader_queue.get()) |node| resume node.data;
    }

    pub fn acquireRead(self: *RwLock) callconv(.Async) HeldRead {
        _ = @atomicRmw(usize, &self.reader_lock_count, .Add, 1, .SeqCst);

        suspend {
            var my_tick_node = Loop.NextTickNode{
                .data = @frame(),
                .prev = undefined,
                .next = undefined,
            };

            self.reader_queue.put(&my_tick_node);

            // At this point, we are in the reader_queue, so we might have already been resumed.

            // We set this bit so that later we can rely on the fact, that if reader_queue_empty == true,
            // some actor will attempt to grab the lock.
            @atomicStore(bool, &self.reader_queue_empty, false, .SeqCst);

            // Here we don't care if we are the one to do the locking or if it was already locked for reading.
            const have_read_lock = if (@cmpxchgStrong(State, &self.shared_state, .Unlocked, .ReadLock, .SeqCst, .SeqCst)) |old_state| old_state == .ReadLock else true;
            if (have_read_lock) {
                // Give out all the read locks.
                if (self.reader_queue.get()) |first_node| {
                    while (self.reader_queue.get()) |node| {
                        global_event_loop.onNextTick(node);
                    }
                    resume first_node.data;
                }
            }
        }
        return HeldRead{ .lock = self };
    }

    pub fn acquireWrite(self: *RwLock) callconv(.Async) HeldWrite {
        suspend {
            var my_tick_node = Loop.NextTickNode{
                .data = @frame(),
                .prev = undefined,
                .next = undefined,
            };

            self.writer_queue.put(&my_tick_node);

            // At this point, we are in the writer_queue, so we might have already been resumed.

            // We set this bit so that later we can rely on the fact, that if writer_queue_empty == true,
            // some actor will attempt to grab the lock.
            @atomicStore(bool, &self.writer_queue_empty, false, .SeqCst);

            // Here we must be the one to acquire the write lock. It cannot already be locked.
            if (@cmpxchgStrong(State, &self.shared_state, .Unlocked, .WriteLock, .SeqCst, .SeqCst) == null) {
                // We now have a write lock.
                if (self.writer_queue.get()) |node| {
                    // Whether this node is us or someone else, we tail resume it.
                    resume node.data;
                }
            }
        }
        return HeldWrite{ .lock = self };
    }

    fn commonPostUnlock(self: *RwLock) void {
        while (true) {
            // There might be a writer_queue item or a reader_queue item
            // If we check and both are empty, we can be done, because the other actors will try to
            // obtain the lock.
            // But if there's a writer_queue item or a reader_queue item,
            // we are the actor which must loop and attempt to grab the lock again.
            if (!@atomicLoad(bool, &self.writer_queue_empty, .SeqCst)) {
                if (@cmpxchgStrong(State, &self.shared_state, .Unlocked, .WriteLock, .SeqCst, .SeqCst) != null) {
                    // We did not obtain the lock. Great, the queues are someone else's problem.
                    return;
                }
                // If there's an item in the writer queue, give them the lock, and we're done.
                if (self.writer_queue.get()) |node| {
                    global_event_loop.onNextTick(node);
                    return;
                }
                // Release the lock again.
                @atomicStore(bool, &self.writer_queue_empty, true, .SeqCst);
                @atomicStore(State, &self.shared_state, .Unlocked, .SeqCst);
                continue;
            }

            if (!@atomicLoad(bool, &self.reader_queue_empty, .SeqCst)) {
                if (@cmpxchgStrong(State, &self.shared_state, .Unlocked, .ReadLock, .SeqCst, .SeqCst) != null) {
                    // We did not obtain the lock. Great, the queues are someone else's problem.
                    return;
                }
                // If there are any items in the reader queue, give out all the reader locks, and we're done.
                if (self.reader_queue.get()) |first_node| {
                    global_event_loop.onNextTick(first_node);
                    while (self.reader_queue.get()) |node| {
                        global_event_loop.onNextTick(node);
                    }
                    return;
                }
                // Release the lock again.
                @atomicStore(bool, &self.reader_queue_empty, true, .SeqCst);
                if (@cmpxchgStrong(State, &self.shared_state, .ReadLock, .Unlocked, .SeqCst, .SeqCst) != null) {
                    // Didn't unlock. Someone else's problem.
                    return;
                }
                continue;
            }
            return;
        }
    }
};

test "std.event.RwLock" {
    // https://github.com/ziglang/zig/issues/2377
    if (true) return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/1908
    if (builtin.single_threaded) return error.SkipZigTest;

    // TODO provide a way to run tests in evented I/O mode
    if (!std.io.is_async) return error.SkipZigTest;

    var lock = RwLock.init();
    defer lock.deinit();

    _ = testLock(std.heap.page_allocator, &lock);

    const expected_result = [1]i32{shared_it_count * @intCast(i32, shared_test_data.len)} ** shared_test_data.len;
    try testing.expectEqualSlices(i32, expected_result, shared_test_data);
}
fn testLock(allocator: *Allocator, lock: *RwLock) callconv(.Async) void {
    var read_nodes: [100]Loop.NextTickNode = undefined;
    for (read_nodes) |*read_node| {
        const frame = allocator.create(@Frame(readRunner)) catch @panic("memory");
        read_node.data = frame;
        frame.* = async readRunner(lock);
        Loop.instance.?.onNextTick(read_node);
    }

    var write_nodes: [shared_it_count]Loop.NextTickNode = undefined;
    for (write_nodes) |*write_node| {
        const frame = allocator.create(@Frame(writeRunner)) catch @panic("memory");
        write_node.data = frame;
        frame.* = async writeRunner(lock);
        Loop.instance.?.onNextTick(write_node);
    }

    for (write_nodes) |*write_node| {
        const casted = @ptrCast(*const @Frame(writeRunner), write_node.data);
        await casted;
        allocator.destroy(casted);
    }
    for (read_nodes) |*read_node| {
        const casted = @ptrCast(*const @Frame(readRunner), read_node.data);
        await casted;
        allocator.destroy(casted);
    }
}

const shared_it_count = 10;
var shared_test_data = [1]i32{0} ** 10;
var shared_test_index: usize = 0;
var shared_count: usize = 0;
fn writeRunner(lock: *RwLock) callconv(.Async) void {
    suspend {} // resumed by onNextTick

    var i: usize = 0;
    while (i < shared_test_data.len) : (i += 1) {
        std.time.sleep(100 * std.time.microsecond);
        const lock_promise = async lock.acquireWrite();
        const handle = await lock_promise;
        defer handle.release();

        shared_count += 1;
        while (shared_test_index < shared_test_data.len) : (shared_test_index += 1) {
            shared_test_data[shared_test_index] = shared_test_data[shared_test_index] + 1;
        }
        shared_test_index = 0;
    }
}
fn readRunner(lock: *RwLock) callconv(.Async) void {
    suspend {} // resumed by onNextTick
    std.time.sleep(1);

    var i: usize = 0;
    while (i < shared_test_data.len) : (i += 1) {
        const lock_promise = async lock.acquireRead();
        const handle = await lock_promise;
        defer handle.release();

        try testing.expect(shared_test_index == 0);
        try testing.expect(shared_test_data[i] == @intCast(i32, shared_count));
    }
}
