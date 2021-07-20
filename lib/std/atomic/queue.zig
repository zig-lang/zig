// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const expect = std.testing.expect;

/// Many producer, many consumer, non-allocating, thread-safe.
/// Uses a mutex to protect access.
/// The queue does not manage ownership and the user is responsible to
/// manage the storage of the nodes.
pub fn Queue(comptime T: type) type {
    return struct {
        head: ?*Node,
        tail: ?*Node,
        mutex: std.Thread.Mutex,

        pub const Self = @This();
        pub const Node = std.TailQueue(T).Node;

        /// Initializes a new queue. The queue does not provide a `deinit()`
        /// function, so the user must take care of cleaning up the queue elements.
        pub fn init() Self {
            return Self{
                .head = null,
                .tail = null,
                .mutex = std.Thread.Mutex{},
            };
        }

        /// Appends `node` to the queue.
        /// The lifetime of `node` must be longer than lifetime of queue.
        pub fn put(self: *Self, node: *Node) void {
            node.next = null;

            const held = self.mutex.acquire();
            defer held.release();

            node.prev = self.tail;
            self.tail = node;
            if (node.prev) |prev_tail| {
                prev_tail.next = node;
            } else {
                assert(self.head == null);
                self.head = node;
            }
        }

        /// Gets a previously inserted node or returns `null` if there is none.
        /// It is safe to `get()` a node from the queue while another thread tries
        /// to `remove()` the same node at the same time.
        pub fn get(self: *Self) ?*Node {
            const held = self.mutex.acquire();
            defer held.release();

            const head = self.head orelse return null;
            self.head = head.next;
            if (head.next) |new_head| {
                new_head.prev = null;
            } else {
                self.tail = null;
            }
            // This way, a get() and a remove() are thread-safe with each other.
            head.prev = null;
            head.next = null;
            return head;
        }

        pub fn unget(self: *Self, node: *Node) void {
            node.prev = null;

            const held = self.mutex.acquire();
            defer held.release();

            const opt_head = self.head;
            self.head = node;
            if (opt_head) |head| {
                head.next = node;
            } else {
                assert(self.tail == null);
                self.tail = node;
            }
        }

        /// Removes a node from the queue, returns whether node was actually removed.
        /// It is safe to `remove()` a node from the queue while another thread tries
        /// to `get()` the same node at the same time.
        pub fn remove(self: *Self, node: *Node) bool {
            const held = self.mutex.acquire();
            defer held.release();

            if (node.prev == null and node.next == null and self.head != node) {
                return false;
            }

            if (node.prev) |prev| {
                prev.next = node.next;
            } else {
                self.head = node.next;
            }
            if (node.next) |next| {
                next.prev = node.prev;
            } else {
                self.tail = node.prev;
            }
            node.prev = null;
            node.next = null;
            return true;
        }

        /// Returns `true` if the queue is currently empty.
        /// Note that in a multi-consumer environment a return value of `false`
        /// does not mean that `get` will yield a non-`null` value!
        pub fn isEmpty(self: *Self) bool {
            const held = self.mutex.acquire();
            defer held.release();
            return self.head == null;
        }

        /// Dumps the contents of the queue to `stderr`.
        pub fn dump(self: *Self) void {
            self.dumpToStream(std.io.getStdErr().writer()) catch return;
        }

        /// Dumps the contents of the queue to `stream`.
        /// Up to 4 elements from the head are dumped and the tail of the queue is
        /// dumped as well.
        pub fn dumpToStream(self: *Self, stream: anytype) !void {
            const S = struct {
                fn dumpRecursive(
                    s: anytype,
                    optional_node: ?*Node,
                    indent: usize,
                    comptime depth: comptime_int,
                ) !void {
                    try s.writeByteNTimes(' ', indent);
                    if (optional_node) |node| {
                        try s.print("0x{x}={}\n", .{ @ptrToInt(node), node.data });
                        if (depth == 0) {
                            try s.print("(max depth)\n", .{});
                            return;
                        }
                        try dumpRecursive(s, node.next, indent + 1, depth - 1);
                    } else {
                        try s.print("(null)\n", .{});
                    }
                }
            };
            const held = self.mutex.acquire();
            defer held.release();

            try stream.print("head: ", .{});
            try S.dumpRecursive(stream, self.head, 0, 4);
            try stream.print("tail: ", .{});
            try S.dumpRecursive(stream, self.tail, 0, 4);
        }
    };
}

const Context = struct {
    allocator: *std.mem.Allocator,
    queue: *Queue(i32),
    put_sum: isize,
    get_sum: isize,
    get_count: usize,
    puts_done: bool,
};

// TODO add lazy evaluated build options and then put puts_per_thread behind
// some option such as: "AggressiveMultithreadedFuzzTest". In the AppVeyor
// CI we would use a less aggressive setting since at 1 core, while we still
// want this test to pass, we need a smaller value since there is so much thrashing
// we would also use a less aggressive setting when running in valgrind
const puts_per_thread = 500;
const put_thread_count = 3;

test "std.atomic.Queue" {
    var plenty_of_memory = try std.heap.page_allocator.alloc(u8, 300 * 1024);
    defer std.heap.page_allocator.free(plenty_of_memory);

    var fixed_buffer_allocator = std.heap.ThreadSafeFixedBufferAllocator.init(plenty_of_memory);
    var a = &fixed_buffer_allocator.allocator;

    var queue = Queue(i32).init();
    var context = Context{
        .allocator = a,
        .queue = &queue,
        .put_sum = 0,
        .get_sum = 0,
        .puts_done = false,
        .get_count = 0,
    };

    if (builtin.single_threaded) {
        try expect(context.queue.isEmpty());
        {
            var i: usize = 0;
            while (i < put_thread_count) : (i += 1) {
                try expect(startPuts(&context) == 0);
            }
        }
        try expect(!context.queue.isEmpty());
        context.puts_done = true;
        {
            var i: usize = 0;
            while (i < put_thread_count) : (i += 1) {
                try expect(startGets(&context) == 0);
            }
        }
        try expect(context.queue.isEmpty());
    } else {
        try expect(context.queue.isEmpty());

        var putters: [put_thread_count]std.Thread = undefined;
        for (putters) |*t| {
            t.* = try std.Thread.spawn(.{}, startPuts, .{&context});
        }
        var getters: [put_thread_count]std.Thread = undefined;
        for (getters) |*t| {
            t.* = try std.Thread.spawn(.{}, startGets, .{&context});
        }

        for (putters) |t|
            t.join();
        @atomicStore(bool, &context.puts_done, true, .SeqCst);
        for (getters) |t|
            t.join();

        try expect(context.queue.isEmpty());
    }

    if (context.put_sum != context.get_sum) {
        std.debug.panic("failure\nput_sum:{} != get_sum:{}", .{ context.put_sum, context.get_sum });
    }

    if (context.get_count != puts_per_thread * put_thread_count) {
        std.debug.panic("failure\nget_count:{} != puts_per_thread:{} * put_thread_count:{}", .{
            context.get_count,
            @as(u32, puts_per_thread),
            @as(u32, put_thread_count),
        });
    }
}

fn startPuts(ctx: *Context) u8 {
    var put_count: usize = puts_per_thread;
    var r = std.rand.DefaultPrng.init(0xdeadbeef);
    while (put_count != 0) : (put_count -= 1) {
        std.time.sleep(1); // let the os scheduler be our fuzz
        const x = @bitCast(i32, r.random.int(u32));
        const node = ctx.allocator.create(Queue(i32).Node) catch unreachable;
        node.* = .{
            .prev = undefined,
            .next = undefined,
            .data = x,
        };
        ctx.queue.put(node);
        _ = @atomicRmw(isize, &ctx.put_sum, .Add, x, .SeqCst);
    }
    return 0;
}

fn startGets(ctx: *Context) u8 {
    while (true) {
        const last = @atomicLoad(bool, &ctx.puts_done, .SeqCst);

        while (ctx.queue.get()) |node| {
            std.time.sleep(1); // let the os scheduler be our fuzz
            _ = @atomicRmw(isize, &ctx.get_sum, .Add, node.data, .SeqCst);
            _ = @atomicRmw(usize, &ctx.get_count, .Add, 1, .SeqCst);
        }

        if (last) return 0;
    }
}

test "std.atomic.Queue single-threaded" {
    var queue = Queue(i32).init();
    try expect(queue.isEmpty());

    var node_0 = Queue(i32).Node{
        .data = 0,
        .next = undefined,
        .prev = undefined,
    };
    queue.put(&node_0);
    try expect(!queue.isEmpty());

    var node_1 = Queue(i32).Node{
        .data = 1,
        .next = undefined,
        .prev = undefined,
    };
    queue.put(&node_1);
    try expect(!queue.isEmpty());

    try expect(queue.get().?.data == 0);
    try expect(!queue.isEmpty());

    var node_2 = Queue(i32).Node{
        .data = 2,
        .next = undefined,
        .prev = undefined,
    };
    queue.put(&node_2);
    try expect(!queue.isEmpty());

    var node_3 = Queue(i32).Node{
        .data = 3,
        .next = undefined,
        .prev = undefined,
    };
    queue.put(&node_3);
    try expect(!queue.isEmpty());

    try expect(queue.get().?.data == 1);
    try expect(!queue.isEmpty());

    try expect(queue.get().?.data == 2);
    try expect(!queue.isEmpty());

    var node_4 = Queue(i32).Node{
        .data = 4,
        .next = undefined,
        .prev = undefined,
    };
    queue.put(&node_4);
    try expect(!queue.isEmpty());

    try expect(queue.get().?.data == 3);
    node_3.next = null;
    try expect(!queue.isEmpty());

    try expect(queue.get().?.data == 4);
    try expect(queue.isEmpty());

    try expect(queue.get() == null);
    try expect(queue.isEmpty());
}

test "std.atomic.Queue dump" {
    const mem = std.mem;
    var buffer: [1024]u8 = undefined;
    var expected_buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);

    var queue = Queue(i32).init();

    // Test empty stream
    fbs.reset();
    try queue.dumpToStream(fbs.writer());
    try expect(mem.eql(u8, buffer[0..fbs.pos],
        \\head: (null)
        \\tail: (null)
        \\
    ));

    // Test a stream with one element
    var node_0 = Queue(i32).Node{
        .data = 1,
        .next = undefined,
        .prev = undefined,
    };
    queue.put(&node_0);

    fbs.reset();
    try queue.dumpToStream(fbs.writer());

    var expected = try std.fmt.bufPrint(expected_buffer[0..],
        \\head: 0x{x}=1
        \\ (null)
        \\tail: 0x{x}=1
        \\ (null)
        \\
    , .{ @ptrToInt(queue.head), @ptrToInt(queue.tail) });
    try expect(mem.eql(u8, buffer[0..fbs.pos], expected));

    // Test a stream with two elements
    var node_1 = Queue(i32).Node{
        .data = 2,
        .next = undefined,
        .prev = undefined,
    };
    queue.put(&node_1);

    fbs.reset();
    try queue.dumpToStream(fbs.writer());

    expected = try std.fmt.bufPrint(expected_buffer[0..],
        \\head: 0x{x}=1
        \\ 0x{x}=2
        \\  (null)
        \\tail: 0x{x}=2
        \\ (null)
        \\
    , .{ @ptrToInt(queue.head), @ptrToInt(queue.head.?.next), @ptrToInt(queue.tail) });
    try expect(mem.eql(u8, buffer[0..fbs.pos], expected));
}
