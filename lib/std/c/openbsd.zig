// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = std.builtin;

usingnamespace std.c;

extern "c" fn __errno() *c_int;
pub const _errno = __errno;

pub const dl_iterate_phdr_callback = fn (info: *dl_phdr_info, size: usize, data: ?*c_void) callconv(.C) c_int;
pub extern "c" fn dl_iterate_phdr(callback: dl_iterate_phdr_callback, data: ?*c_void) c_int;

pub extern "c" fn arc4random_buf(buf: [*]u8, len: usize) void;

pub extern "c" fn getthrid() pid_t;
pub extern "c" fn pipe2(fds: *[2]fd_t, flags: u32) c_int;

pub extern "c" fn getdents(fd: c_int, buf_ptr: [*]u8, nbytes: usize) usize;
pub extern "c" fn sigaltstack(ss: ?*stack_t, old_ss: ?*stack_t) c_int;

pub const pthread_mutex_t = extern struct {
    inner: ?*c_void = null,
};
pub const pthread_cond_t = extern struct {
    inner: ?*c_void = null,
};
pub const pthread_rwlock_t = extern struct {
    ptr: ?*c_void = null,
};
pub const pthread_spinlock_t = extern struct {
    inner: ?*c_void = null,
};
pub const pthread_attr_t = extern struct {
    inner: ?*c_void = null,
};
pub const pthread_key_t = c_int;

pub const sem_t = ?*opaque {};

pub extern "c" fn posix_memalign(memptr: *?*c_void, alignment: usize, size: usize) c_int;

pub extern "c" fn pledge(promises: ?[*:0]const u8, execpromises: ?[*:0]const u8) c_int;
pub extern "c" fn unveil(path: ?[*:0]const u8, permissions: ?[*:0]const u8) c_int;

pub extern "c" fn pthread_set_name_np(thread: std.c.pthread_t, name: [*:0]const u8) void;
pub extern "c" fn pthread_get_name_np(thread: std.c.pthread_t, name: [*:0]u8, len: usize) void;
