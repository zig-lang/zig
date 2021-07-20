// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const Loop = std.event.Loop;

/// Many producer, many consumer, thread-safe, runtime configurable buffer size.
/// When buffer is empty, consumers suspend and are resumed by producers.
/// When buffer is full, producers suspend and are resumed by consumers.
pub fn Channel(comptime T: type) type {
    return struct {
        getters: std.atomic.Queue(GetNode),
        or_null_queue: std.atomic.Queue(*std.atomic.Queue(GetNode).Node),
        putters: std.atomic.Queue(PutNode),
        get_count: usize,
        put_count: usize,
        dispatch_lock: bool,
        need_dispatch: bool,

        // simple fixed size ring buffer
        buffer_nodes: []T,
        buffer_index: usize,
        buffer_len: usize,

        const SelfChannel = @This();
        const GetNode = struct {
            tick_node: *Loop.NextTickNode,
            data: Data,

            const Data = union(enum) {
                Normal: Normal,
                OrNull: OrNull,
            };

            const Normal = struct {
                ptr: *T,
            };

            const OrNull = struct {
                ptr: *?T,
                or_null: *std.atomic.Queue(*std.atomic.Queue(GetNode).Node).Node,
            };
        };
        const PutNode = struct {
            data: T,
            tick_node: *Loop.NextTickNode,
        };

        const global_event_loop = Loop.instance orelse
            @compileError("std.event.Channel currently only works with event-based I/O");

        /// Call `deinit` to free resources when done.
        /// `buffer` must live until `deinit` is called.
        /// For a zero length buffer, use `[0]T{}`.
        /// TODO https://github.com/ziglang/zig/issues/2765
        pub fn init(self: *SelfChannel, buffer: []T) void {
            // The ring buffer implementation only works with power of 2 buffer sizes
            // because of relying on subtracting across zero. For example (0 -% 1) % 10 == 5
            assert(buffer.len == 0 or @popCount(usize, buffer.len) == 1);

            self.* = SelfChannel{
                .buffer_len = 0,
                .buffer_nodes = buffer,
                .buffer_index = 0,
                .dispatch_lock = false,
                .need_dispatch = false,
                .getters = std.atomic.Queue(GetNode).init(),
                .putters = std.atomic.Queue(PutNode).init(),
                .or_null_queue = std.atomic.Queue(*std.atomic.Queue(GetNode).Node).init(),
                .get_count = 0,
                .put_count = 0,
            };
        }

        /// Must be called when all calls to put and get have suspended and no more calls occur.
        /// This can be omitted if caller can guarantee that the suspended putters and getters
        /// do not need to be run to completion. Note that this may leave awaiters hanging.
        pub fn deinit(self: *SelfChannel) void {
            while (self.getters.get()) |get_node| {
                resume get_node.data.tick_node.data;
            }
            while (self.putters.get()) |put_node| {
                resume put_node.data.tick_node.data;
            }
            self.* = undefined;
        }

        /// puts a data item in the channel. The function returns when the value has been added to the
        /// buffer, or in the case of a zero size buffer, when the item has been retrieved by a getter.
        /// Or when the channel is destroyed.
        pub fn put(self: *SelfChannel, data: T) void {
            var my_tick_node = Loop.NextTickNode{ .data = @frame() };
            var queue_node = std.atomic.Queue(PutNode).Node{
                .data = PutNode{
                    .tick_node = &my_tick_node,
                    .data = data,
                },
            };

            suspend {
                self.putters.put(&queue_node);
                _ = @atomicRmw(usize, &self.put_count, .Add, 1, .SeqCst);

                self.dispatch();
            }
        }

        /// await this function to get an item from the channel. If the buffer is empty, the frame will
        /// complete when the next item is put in the channel.
        pub fn get(self: *SelfChannel) callconv(.Async) T {
            // TODO https://github.com/ziglang/zig/issues/2765
            var result: T = undefined;
            var my_tick_node = Loop.NextTickNode{ .data = @frame() };
            var queue_node = std.atomic.Queue(GetNode).Node{
                .data = GetNode{
                    .tick_node = &my_tick_node,
                    .data = GetNode.Data{
                        .Normal = GetNode.Normal{ .ptr = &result },
                    },
                },
            };

            suspend {
                self.getters.put(&queue_node);
                _ = @atomicRmw(usize, &self.get_count, .Add, 1, .SeqCst);

                self.dispatch();
            }
            return result;
        }

        //pub async fn select(comptime EnumUnion: type, channels: ...) EnumUnion {
        //    assert(@memberCount(EnumUnion) == channels.len); // enum union and channels mismatch
        //    assert(channels.len != 0); // enum unions cannot have 0 fields
        //    if (channels.len == 1) {
        //        const result = await (async channels[0].get() catch unreachable);
        //        return @unionInit(EnumUnion, @memberName(EnumUnion, 0), result);
        //    }
        //}

        /// Get an item from the channel. If the buffer is empty and there are no
        /// puts waiting, this returns `null`.
        pub fn getOrNull(self: *SelfChannel) ?T {
            // TODO integrate this function with named return values
            // so we can get rid of this extra result copy
            var result: ?T = null;
            var my_tick_node = Loop.NextTickNode{ .data = @frame() };
            var or_null_node = std.atomic.Queue(*std.atomic.Queue(GetNode).Node).Node{ .data = undefined };
            var queue_node = std.atomic.Queue(GetNode).Node{
                .data = GetNode{
                    .tick_node = &my_tick_node,
                    .data = GetNode.Data{
                        .OrNull = GetNode.OrNull{
                            .ptr = &result,
                            .or_null = &or_null_node,
                        },
                    },
                },
            };
            or_null_node.data = &queue_node;

            suspend {
                self.getters.put(&queue_node);
                _ = @atomicRmw(usize, &self.get_count, .Add, 1, .SeqCst);
                self.or_null_queue.put(&or_null_node);

                self.dispatch();
            }
            return result;
        }

        fn dispatch(self: *SelfChannel) void {
            // set the "need dispatch" flag
            @atomicStore(bool, &self.need_dispatch, true, .SeqCst);

            lock: while (true) {
                // set the lock flag
                if (@atomicRmw(bool, &self.dispatch_lock, .Xchg, true, .SeqCst)) return;

                // clear the need_dispatch flag since we're about to do it
                @atomicStore(bool, &self.need_dispatch, false, .SeqCst);

                while (true) {
                    one_dispatch: {
                        // later we correct these extra subtractions
                        var get_count = @atomicRmw(usize, &self.get_count, .Sub, 1, .SeqCst);
                        var put_count = @atomicRmw(usize, &self.put_count, .Sub, 1, .SeqCst);

                        // transfer self.buffer to self.getters
                        while (self.buffer_len != 0) {
                            if (get_count == 0) break :one_dispatch;

                            const get_node = &self.getters.get().?.data;
                            switch (get_node.data) {
                                GetNode.Data.Normal => |info| {
                                    info.ptr.* = self.buffer_nodes[(self.buffer_index -% self.buffer_len) % self.buffer_nodes.len];
                                },
                                GetNode.Data.OrNull => |info| {
                                    _ = self.or_null_queue.remove(info.or_null);
                                    info.ptr.* = self.buffer_nodes[(self.buffer_index -% self.buffer_len) % self.buffer_nodes.len];
                                },
                            }
                            global_event_loop.onNextTick(get_node.tick_node);
                            self.buffer_len -= 1;

                            get_count = @atomicRmw(usize, &self.get_count, .Sub, 1, .SeqCst);
                        }

                        // direct transfer self.putters to self.getters
                        while (get_count != 0 and put_count != 0) {
                            const get_node = &self.getters.get().?.data;
                            const put_node = &self.putters.get().?.data;

                            switch (get_node.data) {
                                GetNode.Data.Normal => |info| {
                                    info.ptr.* = put_node.data;
                                },
                                GetNode.Data.OrNull => |info| {
                                    _ = self.or_null_queue.remove(info.or_null);
                                    info.ptr.* = put_node.data;
                                },
                            }
                            global_event_loop.onNextTick(get_node.tick_node);
                            global_event_loop.onNextTick(put_node.tick_node);

                            get_count = @atomicRmw(usize, &self.get_count, .Sub, 1, .SeqCst);
                            put_count = @atomicRmw(usize, &self.put_count, .Sub, 1, .SeqCst);
                        }

                        // transfer self.putters to self.buffer
                        while (self.buffer_len != self.buffer_nodes.len and put_count != 0) {
                            const put_node = &self.putters.get().?.data;

                            self.buffer_nodes[self.buffer_index % self.buffer_nodes.len] = put_node.data;
                            global_event_loop.onNextTick(put_node.tick_node);
                            self.buffer_index +%= 1;
                            self.buffer_len += 1;

                            put_count = @atomicRmw(usize, &self.put_count, .Sub, 1, .SeqCst);
                        }
                    }

                    // undo the extra subtractions
                    _ = @atomicRmw(usize, &self.get_count, .Add, 1, .SeqCst);
                    _ = @atomicRmw(usize, &self.put_count, .Add, 1, .SeqCst);

                    // All the "get or null" functions should resume now.
                    var remove_count: usize = 0;
                    while (self.or_null_queue.get()) |or_null_node| {
                        remove_count += @boolToInt(self.getters.remove(or_null_node.data));
                        global_event_loop.onNextTick(or_null_node.data.data.tick_node);
                    }
                    if (remove_count != 0) {
                        _ = @atomicRmw(usize, &self.get_count, .Sub, remove_count, .SeqCst);
                    }

                    // clear need-dispatch flag
                    if (@atomicRmw(bool, &self.need_dispatch, .Xchg, false, .SeqCst)) continue;

                    assert(@atomicRmw(bool, &self.dispatch_lock, .Xchg, false, .SeqCst));

                    // we have to check again now that we unlocked
                    if (@atomicLoad(bool, &self.need_dispatch, .SeqCst)) continue :lock;

                    return;
                }
            }
        }
    };
}

test "std.event.Channel" {
    if (!std.io.is_async) return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/1908
    if (builtin.single_threaded) return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/3251
    if (builtin.os.tag == .freebsd) return error.SkipZigTest;

    var channel: Channel(i32) = undefined;
    channel.init(&[0]i32{});
    defer channel.deinit();

    var handle = async testChannelGetter(&channel);
    var putter = async testChannelPutter(&channel);

    await handle;
    await putter;
}

test "std.event.Channel wraparound" {

    // TODO provide a way to run tests in evented I/O mode
    if (!std.io.is_async) return error.SkipZigTest;

    const channel_size = 2;

    var buf: [channel_size]i32 = undefined;
    var channel: Channel(i32) = undefined;
    channel.init(&buf);
    defer channel.deinit();

    // add items to channel and pull them out until
    // the buffer wraps around, make sure it doesn't crash.
    channel.put(5);
    try testing.expectEqual(@as(i32, 5), channel.get());
    channel.put(6);
    try testing.expectEqual(@as(i32, 6), channel.get());
    channel.put(7);
    try testing.expectEqual(@as(i32, 7), channel.get());
}
fn testChannelGetter(channel: *Channel(i32)) callconv(.Async) void {
    const value1 = channel.get();
    try testing.expect(value1 == 1234);

    const value2 = channel.get();
    try testing.expect(value2 == 4567);

    const value3 = channel.getOrNull();
    try testing.expect(value3 == null);

    var last_put = async testPut(channel, 4444);
    const value4 = channel.getOrNull();
    try testing.expect(value4.? == 4444);
    await last_put;
}
fn testChannelPutter(channel: *Channel(i32)) callconv(.Async) void {
    channel.put(1234);
    channel.put(4567);
}
fn testPut(channel: *Channel(i32), value: i32) callconv(.Async) void {
    channel.put(value);
}
