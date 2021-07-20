// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../std.zig");
const builtin = @import("builtin");
const maxInt = std.math.maxInt;
const abi = builtin.abi;
const arch = builtin.cpu.arch;
const os_tag = builtin.os.tag;
usingnamespace std.c;

pub const _errno = switch (abi) {
    .android => struct {
        extern "c" var __errno: c_int;
        fn getErrno() *c_int {
            return &__errno;
        }
    }.getErrno,
    else => struct {
        extern "c" fn __errno_location() *c_int;
    }.__errno_location,
};

pub const MAP_FAILED = @intToPtr(*c_void, maxInt(usize));

pub const AI_PASSIVE = 0x01;
pub const AI_CANONNAME = 0x02;
pub const AI_NUMERICHOST = 0x04;
pub const AI_V4MAPPED = 0x08;
pub const AI_ALL = 0x10;
pub const AI_ADDRCONFIG = 0x20;
pub const AI_NUMERICSERV = 0x400;

pub const NI_NUMERICHOST = 0x01;
pub const NI_NUMERICSERV = 0x02;
pub const NI_NOFQDN = 0x04;
pub const NI_NAMEREQD = 0x08;
pub const NI_DGRAM = 0x10;
pub const NI_NUMERICSCOPE = 0x100;

pub const EAI = enum(c_int) {
    BADFLAGS = -1,
    NONAME = -2,
    AGAIN = -3,
    FAIL = -4,
    FAMILY = -6,
    SOCKTYPE = -7,
    SERVICE = -8,
    MEMORY = -10,
    SYSTEM = -11,
    OVERFLOW = -12,

    NODATA = -5,
    ADDRFAMILY = -9,
    INPROGRESS = -100,
    CANCELED = -101,
    NOTCANCELED = -102,
    ALLDONE = -103,
    INTR = -104,
    IDN_ENCODE = -105,

    _,
};

pub extern "c" fn fallocate64(fd: fd_t, mode: c_int, offset: off_t, len: off_t) c_int;
pub extern "c" fn fopen64(noalias filename: [*:0]const u8, noalias modes: [*:0]const u8) ?*FILE;
pub extern "c" fn fstat64(fd: fd_t, buf: *libc_stat) c_int;
pub extern "c" fn fstatat64(dirfd: fd_t, path: [*:0]const u8, stat_buf: *libc_stat, flags: u32) c_int;
pub extern "c" fn ftruncate64(fd: c_int, length: off_t) c_int;
pub extern "c" fn getrlimit64(resource: rlimit_resource, rlim: *rlimit) c_int;
pub extern "c" fn lseek64(fd: fd_t, offset: i64, whence: c_int) i64;
pub extern "c" fn mmap64(addr: ?*align(std.mem.page_size) c_void, len: usize, prot: c_uint, flags: c_uint, fd: fd_t, offset: i64) *c_void;
pub extern "c" fn open64(path: [*:0]const u8, oflag: c_uint, ...) c_int;
pub extern "c" fn openat64(fd: c_int, path: [*:0]const u8, oflag: c_uint, ...) c_int;
pub extern "c" fn pread64(fd: fd_t, buf: [*]u8, nbyte: usize, offset: i64) isize;
pub extern "c" fn preadv64(fd: c_int, iov: [*]const iovec, iovcnt: c_uint, offset: i64) isize;
pub extern "c" fn pwrite64(fd: fd_t, buf: [*]const u8, nbyte: usize, offset: i64) isize;
pub extern "c" fn pwritev64(fd: c_int, iov: [*]const iovec_const, iovcnt: c_uint, offset: i64) isize;
pub extern "c" fn sendfile64(out_fd: fd_t, in_fd: fd_t, offset: ?*i64, count: usize) isize;
pub extern "c" fn setrlimit64(resource: rlimit_resource, rlim: *const rlimit) c_int;

pub extern "c" fn getrandom(buf_ptr: [*]u8, buf_len: usize, flags: c_uint) isize;
pub extern "c" fn sched_getaffinity(pid: c_int, size: usize, set: *cpu_set_t) c_int;
pub extern "c" fn eventfd(initval: c_uint, flags: c_uint) c_int;
pub extern "c" fn epoll_ctl(epfd: fd_t, op: c_uint, fd: fd_t, event: ?*epoll_event) c_int;
pub extern "c" fn epoll_create1(flags: c_uint) c_int;
pub extern "c" fn epoll_wait(epfd: fd_t, events: [*]epoll_event, maxevents: c_uint, timeout: c_int) c_int;
pub extern "c" fn epoll_pwait(
    epfd: fd_t,
    events: [*]epoll_event,
    maxevents: c_int,
    timeout: c_int,
    sigmask: *const sigset_t,
) c_int;
pub extern "c" fn inotify_init1(flags: c_uint) c_int;
pub extern "c" fn inotify_add_watch(fd: fd_t, pathname: [*:0]const u8, mask: u32) c_int;
pub extern "c" fn inotify_rm_watch(fd: fd_t, wd: c_int) c_int;

/// See std.elf for constants for this
pub extern "c" fn getauxval(__type: c_ulong) c_ulong;

pub const dl_iterate_phdr_callback = fn (info: *dl_phdr_info, size: usize, data: ?*c_void) callconv(.C) c_int;
pub extern "c" fn dl_iterate_phdr(callback: dl_iterate_phdr_callback, data: ?*c_void) c_int;

pub extern "c" fn sigaltstack(ss: ?*stack_t, old_ss: ?*stack_t) c_int;

pub extern "c" fn memfd_create(name: [*:0]const u8, flags: c_uint) c_int;
pub extern "c" fn pipe2(fds: *[2]fd_t, flags: u32) c_int;

pub extern "c" fn fallocate(fd: fd_t, mode: c_int, offset: off_t, len: off_t) c_int;

pub extern "c" fn sendfile(
    out_fd: fd_t,
    in_fd: fd_t,
    offset: ?*off_t,
    count: usize,
) isize;

pub extern "c" fn copy_file_range(fd_in: fd_t, off_in: ?*i64, fd_out: fd_t, off_out: ?*i64, len: usize, flags: c_uint) isize;

pub extern "c" fn signalfd(fd: fd_t, mask: *const sigset_t, flags: c_uint) c_int;

pub extern "c" fn prlimit(pid: pid_t, resource: rlimit_resource, new_limit: *const rlimit, old_limit: *rlimit) c_int;
pub extern "c" fn posix_memalign(memptr: *?*c_void, alignment: usize, size: usize) c_int;
pub extern "c" fn malloc_usable_size(?*const c_void) usize;

pub extern "c" fn madvise(
    addr: *align(std.mem.page_size) c_void,
    length: usize,
    advice: c_uint,
) c_int;

pub const pthread_attr_t = extern struct {
    __size: [56]u8,
    __align: c_long,
};

pub const pthread_mutex_t = extern struct {
    size: [__SIZEOF_PTHREAD_MUTEX_T]u8 align(@alignOf(usize)) = [_]u8{0} ** __SIZEOF_PTHREAD_MUTEX_T,
};
pub const pthread_cond_t = extern struct {
    size: [__SIZEOF_PTHREAD_COND_T]u8 align(@alignOf(usize)) = [_]u8{0} ** __SIZEOF_PTHREAD_COND_T,
};
pub const pthread_rwlock_t = switch (abi) {
    .android => switch (@sizeOf(usize)) {
        4 => extern struct {
            lock: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER,
            cond: std.c.pthread_cond_t = std.c.PTHREAD_COND_INITIALIZER,
            numLocks: c_int = 0,
            writerThreadId: c_int = 0,
            pendingReaders: c_int = 0,
            pendingWriters: c_int = 0,
            attr: i32 = 0,
            __reserved: [12]u8 = [_]u8{0} ** 2,
        },
        8 => extern struct {
            numLocks: c_int = 0,
            writerThreadId: c_int = 0,
            pendingReaders: c_int = 0,
            pendingWriters: c_int = 0,
            attr: i32 = 0,
            __reserved: [36]u8 = [_]u8{0} ** 36,
        },
        else => @compileError("impossible pointer size"),
    },
    else => extern struct {
        size: [56]u8 align(@alignOf(usize)) = [_]u8{0} ** 56,
    },
};
pub const sem_t = extern struct {
    __size: [__SIZEOF_SEM_T]u8 align(@alignOf(usize)),
};

const __SIZEOF_PTHREAD_COND_T = 48;
const __SIZEOF_PTHREAD_MUTEX_T = if (os_tag == .fuchsia) 40 else switch (abi) {
    .musl, .musleabi, .musleabihf => if (@sizeOf(usize) == 8) 40 else 24,
    .gnu, .gnuabin32, .gnuabi64, .gnueabi, .gnueabihf, .gnux32 => switch (arch) {
        .aarch64 => 48,
        .x86_64 => if (abi == .gnux32) 40 else 32,
        .mips64, .powerpc64, .powerpc64le, .sparcv9 => 40,
        else => if (@sizeOf(usize) == 8) 40 else 24,
    },
    .android => if (@sizeOf(usize) == 8) 40 else 4,
    else => @compileError("unsupported ABI"),
};
const __SIZEOF_SEM_T = 4 * @sizeOf(usize);

pub const RTLD_LAZY = 1;
pub const RTLD_NOW = 2;
pub const RTLD_NOLOAD = 4;
pub const RTLD_NODELETE = 4096;
pub const RTLD_GLOBAL = 256;
pub const RTLD_LOCAL = 0;
