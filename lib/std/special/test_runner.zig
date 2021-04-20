// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const io = std.io;
const builtin = @import("builtin");

pub const io_mode: io.Mode = builtin.test_io_mode;

var log_err_count: usize = 0;

var args_buffer: [std.fs.MAX_PATH_BYTES + std.mem.page_size]u8 = undefined;
var args_allocator = std.heap.FixedBufferAllocator.init(&args_buffer);

extern "c" fn getpid() std.os.pid_t;

fn oot(seconds: u32) void {
    std.time.sleep(@as(u64, seconds) * 1_000_000_000);
    std.debug.warn("\n\n*** OOT killer sending SEGV\n\n",.{});
    std.os.kill(getpid(), std.os.SIGSEGV) catch unreachable;
}

pub fn main() anyerror!void {
    var epb: [256]u8 = undefined;
    const ep = try std.fs.selfExePath(&epb);
    std.debug.warn("EXE NAME: {s}\n", .{ ep });
    const out = try std.fs.cwd().createFile("test.exename", .{});
    try out.writeAll(ep);
    out.close();

    const killer = try std.Thread.spawn(oot, 600);
    std.debug.warn("OOT killer installed\n",.{});

    const args = std.process.argsAlloc(&args_allocator.allocator) catch {
        @panic("Too many bytes passed over the CLI to the test runner");
    };
    std.testing.zig_exe_path = args[1];

    const test_fn_list = builtin.test_functions;
    var ok_count: usize = 0;
    var skip_count: usize = 0;
    var progress = std.Progress{};
    const root_node = progress.start("Test", test_fn_list.len) catch |err| switch (err) {
        // TODO still run tests in this case
        error.TimerUnsupported => @panic("timer unsupported"),
    };

    var async_frame_buffer: []align(std.Target.stack_align) u8 = undefined;
    // TODO this is on the next line (using `undefined` above) because otherwise zig incorrectly
    // ignores the alignment of the slice.
    async_frame_buffer = &[_]u8{};

    var leaks: usize = 0;
    for (test_fn_list) |test_fn, i| {
        std.testing.allocator_instance = .{};
        defer {
            if (std.testing.allocator_instance.deinit()) {
                leaks += 1;
            }
        }
        std.testing.log_level = .warn;

        var test_node = root_node.start(test_fn.name, 0);
        test_node.activate();
        progress.refresh();
        if (progress.terminal == null) {
            std.debug.print("{d}/{d} {s}... ", .{ i + 1, test_fn_list.len, test_fn.name });
        }
        const result = if (test_fn.async_frame_size) |size| switch (io_mode) {
            .evented => blk: {
                if (async_frame_buffer.len < size) {
                    std.heap.page_allocator.free(async_frame_buffer);
                    async_frame_buffer = try std.heap.page_allocator.alignedAlloc(u8, std.Target.stack_align, size);
                }
                const casted_fn = @ptrCast(fn () callconv(.Async) anyerror!void, test_fn.func);
                break :blk await @asyncCall(async_frame_buffer, {}, casted_fn, .{});
            },
            .blocking => {
                skip_count += 1;
                test_node.end();
                progress.log("{s}...SKIP (async test)\n", .{test_fn.name});
                if (progress.terminal == null) std.debug.print("SKIP (async test)\n", .{});
                continue;
            },
        } else test_fn.func();
        if (result) |_| {
            ok_count += 1;
            test_node.end();
            if (progress.terminal == null) std.debug.print("OK\n", .{});
        } else |err| switch (err) {
            error.SkipZigTest => {
                skip_count += 1;
                test_node.end();
                progress.log("{s}...SKIP\n", .{test_fn.name});
                if (progress.terminal == null) std.debug.print("SKIP\n", .{});
            },
            else => {
                progress.log("", .{});
                return err;
            },
        }
    }
    root_node.end();
    if (ok_count == test_fn_list.len) {
        std.debug.print("All {d} tests passed.\n", .{ok_count});
    } else {
        std.debug.print("{d} passed; {d} skipped.\n", .{ ok_count, skip_count });
    }
    if (log_err_count != 0) {
        std.debug.print("{d} errors were logged.\n", .{log_err_count});
    }
    if (leaks != 0) {
        std.debug.print("{d} tests leaked memory.\n", .{leaks});
    }
    if (leaks != 0 or log_err_count != 0) {
        std.process.exit(1);
    }
}

pub fn log(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@enumToInt(message_level) <= @enumToInt(std.log.Level.err)) {
        log_err_count += 1;
    }
    if (@enumToInt(message_level) <= @enumToInt(std.testing.log_level)) {
        std.debug.print("[{s}] ({s}): " ++ format ++ "\n", .{ @tagName(scope), @tagName(message_level) } ++ args);
    }
}
