// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

//! This API non-allocating, non-fallible, and thread-safe.
//! The tradeoff is that users of this API must provide the storage
//! for each `Progress.Node`.
//!
//! Initialize the struct directly, overriding these fields as desired:
//! * `refresh_rate_ms`
//! * `initial_delay_ms`

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const testing = std.testing;
const assert = std.debug.assert;
const Progress = @This();

/// `null` if the current node (and its children) should
/// not print on update()
terminal: ?std.fs.File = undefined,

/// Is this a windows API terminal (note: this is not the same as being run on windows
/// because other terminals exist like MSYS/git-bash)
is_windows_terminal: bool = false,

/// Whether the terminal supports ANSI escape codes.
supports_ansi_escape_codes: bool = false,

/// If the terminal is "dumb", don't print output.
/// This can be useful if you don't want to print all
/// the stages of code generation if there are a lot.
/// You should not use it if the user should see output
/// for example showing the user what tests run.
dont_print_on_dumb: bool = false,

root: Node = undefined,

/// Keeps track of how much time has passed since the beginning.
/// Used to compare with `initial_delay_ms` and `refresh_rate_ms`.
timer: std.time.Timer = undefined,

/// When the previous refresh was written to the terminal.
/// Used to compare with `refresh_rate_ms`.
prev_refresh_timestamp: u64 = undefined,

/// This buffer represents the maximum number of bytes written to the terminal
/// with each refresh.
output_buffer: [100]u8 = undefined,

/// How many nanoseconds between writing updates to the terminal.
refresh_rate_ns: u64 = 50 * std.time.ns_per_ms,

/// How many nanoseconds to keep the output hidden
initial_delay_ns: u64 = 500 * std.time.ns_per_ms,

done: bool = true,

/// Protects the `refresh` function, as well as `node.recently_updated_child`.
/// Without this, callsites would call `Node.end` and then free `Node` memory
/// while it was still being accessed by the `refresh` function.
update_lock: std.Thread.Mutex = .{},

/// Represents one unit of progress. Each node can have children nodes, or
/// one can use integers with `update`.
pub const Node = struct {
    context: *Progress,
    parent: ?*Node,
    name: []const u8,
    /// Must be handled atomically to be thread-safe.
    recently_updated_child: ?*Node = null,
    /// Must be handled atomically to be thread-safe. 0 means null.
    unprotected_estimated_total_items: usize,
    /// Must be handled atomically to be thread-safe.
    unprotected_completed_items: usize,

    /// Create a new child progress node. Thread-safe.
    /// Call `Node.end` when done.
    /// TODO solve https://github.com/ziglang/zig/issues/2765 and then change this
    /// API to set `self.parent.recently_updated_child` with the return value.
    /// Until that is fixed you probably want to call `activate` on the return value.
    /// Passing 0 for `estimated_total_items` means unknown.
    pub fn start(self: *Node, name: []const u8, estimated_total_items: usize) Node {
        return Node{
            .context = self.context,
            .parent = self,
            .name = name,
            .unprotected_estimated_total_items = estimated_total_items,
            .unprotected_completed_items = 0,
        };
    }

    /// This is the same as calling `start` and then `end` on the returned `Node`. Thread-safe.
    pub fn completeOne(self: *Node) void {
        self.activate();
        _ = @atomicRmw(usize, &self.unprotected_completed_items, .Add, 1, .Monotonic);
        self.context.maybeRefresh();
    }

    /// Finish a started `Node`. Thread-safe.
    pub fn end(self: *Node) void {
        self.context.maybeRefresh();
        if (self.parent) |parent| {
            {
                const held = self.context.update_lock.acquire();
                defer held.release();
                _ = @cmpxchgStrong(?*Node, &parent.recently_updated_child, self, null, .Monotonic, .Monotonic);
            }
            parent.completeOne();
        } else {
            const held = self.context.update_lock.acquire();
            defer held.release();
            self.context.done = true;
            self.context.refreshWithHeldLock();
        }
    }

    /// Tell the parent node that this node is actively being worked on. Thread-safe.
    pub fn activate(self: *Node) void {
        if (self.parent) |parent| {
            @atomicStore(?*Node, &parent.recently_updated_child, self, .Release);
        }
    }

    /// Thread-safe. 0 means unknown.
    pub fn setEstimatedTotalItems(self: *Node, count: usize) void {
        @atomicStore(usize, &self.unprotected_estimated_total_items, count, .Monotonic);
    }

    /// Thread-safe.
    pub fn setCompletedItems(self: *Node, completed_items: usize) void {
        @atomicStore(usize, &self.unprotected_completed_items, completed_items, .Monotonic);
    }
};

/// Create a new progress node.
/// Call `Node.end` when done.
/// TODO solve https://github.com/ziglang/zig/issues/2765 and then change this
/// API to return Progress rather than accept it as a parameter.
/// `estimated_total_items` value of 0 means unknown.
pub fn start(self: *Progress, name: []const u8, estimated_total_items: usize) !*Node {
    const stderr = std.io.getStdErr();
    self.terminal = null;
    if (stderr.supportsAnsiEscapeCodes()) {
        self.terminal = stderr;
        self.supports_ansi_escape_codes = true;
    } else if (builtin.os.tag == .windows and stderr.isTty()) {
        self.is_windows_terminal = true;
        self.terminal = stderr;
    } else if (builtin.os.tag != .windows) {
        // we are in a "dumb" terminal like in acme or writing to a file
        self.terminal = stderr;
    }
    self.root = Node{
        .context = self,
        .parent = null,
        .name = name,
        .unprotected_estimated_total_items = estimated_total_items,
        .unprotected_completed_items = 0,
    };
    self.prev_refresh_timestamp = 0;
    self.timer = try std.time.Timer.start();
    self.done = false;
    return &self.root;
}

/// Updates the terminal if enough time has passed since last update. Thread-safe.
pub fn maybeRefresh(self: *Progress) void {
    const now = self.timer.read();
    if (now < self.initial_delay_ns) return;
    const held = self.update_lock.tryAcquire() orelse return;
    defer held.release();
    // TODO I have observed this to happen sometimes. I think we need to follow Rust's
    // lead and guarantee monotonically increasing times in the std lib itself.
    if (now < self.prev_refresh_timestamp) return;
    if (now - self.prev_refresh_timestamp < self.refresh_rate_ns) return;
    return self.refreshWithHeldLock();
}

/// Updates the terminal and resets `self.next_refresh_timestamp`. Thread-safe.
pub fn refresh(self: *Progress) void {
    const held = self.update_lock.tryAcquire() orelse return;
    defer held.release();

    return self.refreshWithHeldLock();
}

// ED -- Clear screen
const ED = "\x1b[J";
// DECSC -- Save cursor position
const DECSC = "\x1b7";
// DECRC -- Restore cursor position
const DECRC = "\x1b8";
// Note that ESC7/ESC8 are used instead of CSI s/CSI u as the latter are not
// supported by some terminals (eg. Terminal.app).

fn refreshWithHeldLock(self: *Progress) void {
    const is_dumb = !self.supports_ansi_escape_codes and !self.is_windows_terminal;
    if (is_dumb and self.dont_print_on_dumb) return;

    const file = self.terminal orelse return;

    var end: usize = 0;
    // Save the cursor position and clear the part of the screen below.
    // Clearing only the line is not enough as the terminal may wrap the line
    // when it becomes too long.
    var saved_cursor_pos: windows.COORD = undefined;
    if (self.supports_ansi_escape_codes) {
        const seq_before = DECSC ++ ED;
        std.mem.copy(u8, self.output_buffer[end..], seq_before);
        end += seq_before.len;
    } else if (builtin.os.tag == .windows) winapi: {
        std.debug.assert(self.is_windows_terminal);

        var info: windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
        if (windows.kernel32.GetConsoleScreenBufferInfo(file.handle, &info) != windows.TRUE)
            unreachable;

        saved_cursor_pos = info.dwCursorPosition;

        const window_height = @intCast(windows.DWORD, info.srWindow.Bottom - info.srWindow.Top + 1);
        const window_width = @intCast(windows.DWORD, info.srWindow.Right - info.srWindow.Left + 1);
        // Number of terminal cells to clear, starting from the cursor position
        // and ending at the window bottom right corner.
        const fill_chars = if (window_width == 0 or window_height == 0) 0 else chars: {
            break :chars window_width * (window_height -
                @intCast(windows.DWORD, info.dwCursorPosition.Y - info.srWindow.Top)) -
                @intCast(windows.DWORD, info.dwCursorPosition.X - info.srWindow.Left);
        };

        var written: windows.DWORD = undefined;
        if (windows.kernel32.FillConsoleOutputAttribute(
            file.handle,
            info.wAttributes,
            fill_chars,
            saved_cursor_pos,
            &written,
        ) != windows.TRUE) {
            // Stop trying to write to this file.
            self.terminal = null;
            break :winapi;
        }
        if (windows.kernel32.FillConsoleOutputCharacterW(
            file.handle,
            ' ',
            fill_chars,
            saved_cursor_pos,
            &written,
        ) != windows.TRUE) {
            unreachable;
        }
    }

    if (!self.done) {
        var need_ellipse = false;
        var maybe_node: ?*Node = &self.root;
        while (maybe_node) |node| {
            if (need_ellipse) {
                self.bufWrite(&end, "... ", .{});
            }
            need_ellipse = false;
            const eti = @atomicLoad(usize, &node.unprotected_estimated_total_items, .Monotonic);
            const completed_items = @atomicLoad(usize, &node.unprotected_completed_items, .Monotonic);
            if (node.name.len != 0 or eti > 0) {
                if (node.name.len != 0) {
                    self.bufWrite(&end, "{s}", .{node.name});
                    need_ellipse = true;
                }
                if (eti > 0) {
                    if (need_ellipse) self.bufWrite(&end, " ", .{});
                    self.bufWrite(&end, "[{d}/{d}] ", .{ completed_items + 1, eti });
                    need_ellipse = false;
                } else if (completed_items != 0) {
                    if (need_ellipse) self.bufWrite(&end, " ", .{});
                    self.bufWrite(&end, "[{d}] ", .{completed_items + 1});
                    need_ellipse = false;
                }
            }
            maybe_node = @atomicLoad(?*Node, &node.recently_updated_child, .Acquire);
        }
        if (need_ellipse) {
            self.bufWrite(&end, "... ", .{});
        }
    }

    // We're done printing the updated message, restore the cursor position.
    if (self.supports_ansi_escape_codes) {
        const seq_after = DECRC;
        std.mem.copy(u8, self.output_buffer[end..], seq_after);
        end += seq_after.len;
    } else if (!self.is_windows_terminal) {
        self.output_buffer[end] = '\n';
        end += 1;
    }

    _ = file.write(self.output_buffer[0..end]) catch {
        // Stop trying to write to this file once it errors.
        self.terminal = null;
    };

    if (builtin.os.tag == .windows) {
        if (self.is_windows_terminal) {
            const res = windows.kernel32.SetConsoleCursorPosition(file.handle, saved_cursor_pos);
            std.debug.assert(res == windows.TRUE);
        }
    }

    self.prev_refresh_timestamp = self.timer.read();
}

pub fn log(self: *Progress, comptime format: []const u8, args: anytype) void {
    const file = self.terminal orelse return;
    self.refresh();
    file.writer().print(format, args) catch {
        self.terminal = null;
        return;
    };
}

fn bufWrite(self: *Progress, end: *usize, comptime format: []const u8, args: anytype) void {
    if (std.fmt.bufPrint(self.output_buffer[end.*..], format, args)) |written| {
        const amt = written.len;
        end.* += amt;
    } else |err| switch (err) {
        error.NoSpaceLeft => {
            end.* = self.output_buffer.len;
        },
    }
    const bytes_needed_for_esc_codes_at_end: u8 = if (self.is_windows_terminal) 0 else 11;
    const max_end = self.output_buffer.len - bytes_needed_for_esc_codes_at_end;
    if (end.* > max_end) {
        const suffix = "... ";
        std.mem.copy(u8, self.output_buffer[max_end..], suffix);
        end.* = max_end + suffix.len;
    }
}

test "basic functionality" {
    var disable = true;
    if (disable) {
        // This test is disabled because it uses time.sleep() and is therefore slow. It also
        // prints bogus progress data to stderr.
        return error.SkipZigTest;
    }
    var progress = Progress{};
    const root_node = try progress.start("", 100);
    defer root_node.end();

    const sub_task_names = [_][]const u8{
        "reticulating splines",
        "adjusting shoes",
        "climbing towers",
        "pouring juice",
    };
    var next_sub_task: usize = 0;

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var node = root_node.start(sub_task_names[next_sub_task], 5);
        node.activate();
        next_sub_task = (next_sub_task + 1) % sub_task_names.len;

        node.completeOne();
        std.time.sleep(5 * std.time.ns_per_ms);
        node.completeOne();
        node.completeOne();
        std.time.sleep(5 * std.time.ns_per_ms);
        node.completeOne();
        node.completeOne();
        std.time.sleep(5 * std.time.ns_per_ms);

        node.end();

        std.time.sleep(5 * std.time.ns_per_ms);
    }
    {
        var node = root_node.start("this is a really long name designed to activate the truncation code. let's find out if it works", 0);
        node.activate();
        std.time.sleep(10 * std.time.ns_per_ms);
        progress.refresh();
        std.time.sleep(10 * std.time.ns_per_ms);
        node.end();
    }
}
