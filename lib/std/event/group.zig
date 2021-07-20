// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const Lock = std.event.Lock;
const testing = std.testing;
const Allocator = std.mem.Allocator;

/// ReturnType must be `void` or `E!void`
/// TODO This API was created back with the old design of async/await, when calling any
/// async function required an allocator. There is an ongoing experiment to transition
/// all uses of this API to the simpler and more resource-aware `std.event.Batch` API.
/// If the transition goes well, all usages of `Group` will be gone, and this API
/// will be deleted.
pub fn Group(comptime ReturnType: type) type {
    return struct {
        frame_stack: Stack,
        alloc_stack: AllocStack,
        lock: Lock,
        allocator: *Allocator,

        const Self = @This();

        const Error = switch (@typeInfo(ReturnType)) {
            .ErrorUnion => |payload| payload.error_set,
            else => void,
        };
        const Stack = std.atomic.Stack(anyframe->ReturnType);
        const AllocStack = std.atomic.Stack(Node);

        pub const Node = struct {
            bytes: []const u8 = &[0]u8{},
            handle: anyframe->ReturnType,
        };

        pub fn init(allocator: *Allocator) Self {
            return Self{
                .frame_stack = Stack.init(),
                .alloc_stack = AllocStack.init(),
                .lock = Lock.init(),
                .allocator = allocator,
            };
        }

        /// Add a frame to the group. Thread-safe.
        pub fn add(self: *Self, handle: anyframe->ReturnType) (error{OutOfMemory}!void) {
            const node = try self.allocator.create(AllocStack.Node);
            node.* = AllocStack.Node{
                .next = undefined,
                .data = Node{
                    .handle = handle,
                },
            };
            self.alloc_stack.push(node);
        }

        /// Add a node to the group. Thread-safe. Cannot fail.
        /// `node.data` should be the frame handle to add to the group.
        /// The node's memory should be in the function frame of
        /// the handle that is in the node, or somewhere guaranteed to live
        /// at least as long.
        pub fn addNode(self: *Self, node: *Stack.Node) void {
            self.frame_stack.push(node);
        }

        /// This is equivalent to adding a frame to the group but the memory of its frame is
        /// allocated by the group and freed by `wait`.
        /// `func` must be async and have return type `ReturnType`.
        /// Thread-safe.
        pub fn call(self: *Self, comptime func: anytype, args: anytype) error{OutOfMemory}!void {
            var frame = try self.allocator.create(@TypeOf(@call(.{ .modifier = .async_kw }, func, args)));
            errdefer self.allocator.destroy(frame);
            const node = try self.allocator.create(AllocStack.Node);
            errdefer self.allocator.destroy(node);
            node.* = AllocStack.Node{
                .next = undefined,
                .data = Node{
                    .handle = frame,
                    .bytes = std.mem.asBytes(frame),
                },
            };
            frame.* = @call(.{ .modifier = .async_kw }, func, args);
            self.alloc_stack.push(node);
        }

        /// Wait for all the calls and promises of the group to complete.
        /// Thread-safe.
        /// Safe to call any number of times.
        pub fn wait(self: *Self) callconv(.Async) ReturnType {
            const held = self.lock.acquire();
            defer held.release();

            var result: ReturnType = {};

            while (self.frame_stack.pop()) |node| {
                if (Error == void) {
                    await node.data;
                } else {
                    (await node.data) catch |err| {
                        result = err;
                    };
                }
            }
            while (self.alloc_stack.pop()) |node| {
                const handle = node.data.handle;
                if (Error == void) {
                    await handle;
                } else {
                    (await handle) catch |err| {
                        result = err;
                    };
                }
                self.allocator.free(node.data.bytes);
                self.allocator.destroy(node);
            }
            return result;
        }
    };
}

test "std.event.Group" {
    // https://github.com/ziglang/zig/issues/1908
    if (builtin.single_threaded) return error.SkipZigTest;

    if (!std.io.is_async) return error.SkipZigTest;

    // TODO this file has bit-rotted. repair it
    if (true) return error.SkipZigTest;

    _ = async testGroup(std.heap.page_allocator);
}
fn testGroup(allocator: *Allocator) callconv(.Async) void {
    var count: usize = 0;
    var group = Group(void).init(allocator);
    var sleep_a_little_frame = async sleepALittle(&count);
    group.add(&sleep_a_little_frame) catch @panic("memory");
    var increase_by_ten_frame = async increaseByTen(&count);
    group.add(&increase_by_ten_frame) catch @panic("memory");
    group.wait();
    try testing.expect(count == 11);

    var another = Group(anyerror!void).init(allocator);
    var something_else_frame = async somethingElse();
    another.add(&something_else_frame) catch @panic("memory");
    var something_that_fails_frame = async doSomethingThatFails();
    another.add(&something_that_fails_frame) catch @panic("memory");
    try testing.expectError(error.ItBroke, another.wait());
}
fn sleepALittle(count: *usize) callconv(.Async) void {
    std.time.sleep(1 * std.time.ns_per_ms);
    _ = @atomicRmw(usize, count, .Add, 1, .SeqCst);
}
fn increaseByTen(count: *usize) callconv(.Async) void {
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        _ = @atomicRmw(usize, count, .Add, 1, .SeqCst);
    }
}
fn doSomethingThatFails() callconv(.Async) anyerror!void {}
fn somethingElse() callconv(.Async) anyerror!void {
    return error.ItBroke;
}
