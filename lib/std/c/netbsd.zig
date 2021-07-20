// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");

usingnamespace std.c;

extern "c" fn __errno() *c_int;
pub const _errno = __errno;

pub const dl_iterate_phdr_callback = fn (info: *dl_phdr_info, size: usize, data: ?*c_void) callconv(.C) c_int;
pub extern "c" fn dl_iterate_phdr(callback: dl_iterate_phdr_callback, data: ?*c_void) c_int;

pub extern "c" fn _lwp_self() lwpid_t;

pub extern "c" fn pipe2(fds: *[2]fd_t, flags: u32) c_int;
pub extern "c" fn arc4random_buf(buf: [*]u8, len: usize) void;
pub extern "c" fn __fstat50(fd: fd_t, buf: *libc_stat) c_int;
pub extern "c" fn __stat50(path: [*:0]const u8, buf: *libc_stat) c_int;
pub extern "c" fn __clock_gettime50(clk_id: c_int, tp: *timespec) c_int;
pub extern "c" fn __clock_getres50(clk_id: c_int, tp: *timespec) c_int;
pub extern "c" fn __getdents30(fd: c_int, buf_ptr: [*]u8, nbytes: usize) c_int;
pub extern "c" fn __sigaltstack14(ss: ?*stack_t, old_ss: ?*stack_t) c_int;
pub extern "c" fn __nanosleep50(rqtp: *const timespec, rmtp: ?*timespec) c_int;
pub extern "c" fn __sigaction14(sig: c_int, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) c_int;
pub extern "c" fn __sigprocmask14(how: c_int, noalias set: ?*const sigset_t, noalias oset: ?*sigset_t) c_int;
pub extern "c" fn __socket30(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
pub extern "c" fn __gettimeofday50(noalias tv: ?*timeval, noalias tz: ?*timezone) c_int;
pub extern "c" fn __getrusage50(who: c_int, usage: *rusage) c_int;
// libc aliases this as sched_yield
pub extern "c" fn __libc_thr_yield() c_int;

pub extern "c" fn posix_memalign(memptr: *?*c_void, alignment: usize, size: usize) c_int;

pub const pthread_mutex_t = extern struct {
    ptm_magic: u32 = 0x33330003,
    ptm_errorcheck: padded_pthread_spin_t = 0,
    ptm_ceiling: padded_pthread_spin_t = 0,
    ptm_owner: usize = 0,
    ptm_waiters: ?*u8 = null,
    ptm_recursed: u32 = 0,
    ptm_spare2: ?*c_void = null,
};

pub const pthread_cond_t = extern struct {
    ptc_magic: u32 = 0x55550005,
    ptc_lock: pthread_spin_t = 0,
    ptc_waiters_first: ?*u8 = null,
    ptc_waiters_last: ?*u8 = null,
    ptc_mutex: ?*pthread_mutex_t = null,
    ptc_private: ?*c_void = null,
};

pub const pthread_rwlock_t = extern struct {
    ptr_magic: c_uint = 0x99990009,
    ptr_interlock: switch (builtin.cpu.arch) {
        .aarch64, .sparc, .x86_64, .i386 => u8,
        .arm, .powerpc => c_int,
        else => unreachable,
    } = 0,
    ptr_rblocked_first: ?*u8 = null,
    ptr_rblocked_last: ?*u8 = null,
    ptr_wblocked_first: ?*u8 = null,
    ptr_wblocked_last: ?*u8 = null,
    ptr_nreaders: c_uint = 0,
    ptr_owner: std.c.pthread_t = null,
    ptr_private: ?*c_void = null,
};

const pthread_spin_t = switch (builtin.cpu.arch) {
    .aarch64, .aarch64_be, .aarch64_32 => u8,
    .mips, .mipsel, .mips64, .mips64el => u32,
    .powerpc, .powerpc64, .powerpc64le => i32,
    .i386, .x86_64 => u8,
    .arm, .armeb, .thumb, .thumbeb => i32,
    .sparc, .sparcel, .sparcv9 => u8,
    .riscv32, .riscv64 => u32,
    else => @compileError("undefined pthread_spin_t for this arch"),
};

const padded_pthread_spin_t = switch (builtin.cpu.arch) {
    .i386, .x86_64 => u32,
    .sparc, .sparcel, .sparcv9 => u32,
    else => pthread_spin_t,
};

pub const pthread_attr_t = extern struct {
    pta_magic: u32,
    pta_flags: i32,
    pta_private: ?*c_void,
};

pub const sem_t = ?*opaque {};
