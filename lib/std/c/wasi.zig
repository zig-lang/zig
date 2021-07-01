// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
usingnamespace @import("../os/bits.zig");

extern threadlocal var errno: c_int;

pub fn _errno() *c_int {
    return &errno;
}

pub const pid_t = c_int;
pub const uid_t = u32;
pub const gid_t = u32;
pub const off_t = i64;

pub const libc_stat = extern struct {
    dev: i32,
    ino: ino_t,
    nlink: u64,

    mode: mode_t,
    uid: uid_t,
    gid: gid_t,
    __pad0: isize,
    rdev: i32,
    size: off_t,
    blksize: i32,
    blocks: i64,

    atimesec: time_t,
    atimensec: isize,
    mtimesec: time_t,
    mtimensec: isize,
    ctimesec: time_t,
    ctimensec: isize,

    pub fn atime(self: @This()) timespec {
        return timespec{
            .tv_sec = self.atimesec,
            .tv_nsec = self.atimensec,
        };
    }

    pub fn mtime(self: @This()) timespec {
        return timespec{
            .tv_sec = self.mtimesec,
            .tv_nsec = self.mtimensec,
        };
    }

    pub fn ctime(self: @This()) timespec {
        return timespec{
            .tv_sec = self.ctimesec,
            .tv_nsec = self.ctimensec,
        };
    }
};

pub extern fn fopen(noalias filename: [*:0]const u8, noalias modes: [*:0]const u8) ?*FILE;
pub extern fn fclose(stream: *FILE) c_int;
pub extern fn fwrite(noalias ptr: [*]const u8, size_of_type: usize, item_count: usize, noalias stream: *FILE) usize;
pub extern fn fread(noalias ptr: [*]u8, size_of_type: usize, item_count: usize, noalias stream: *FILE) usize;

pub extern fn printf(format: [*:0]const u8, ...) c_int;
pub extern fn abort() noreturn;

pub extern fn exit(code: c_int) noreturn;
pub extern fn _exit(code: c_int) noreturn;
pub extern fn isatty(fd: fd_t) c_int;
pub extern fn close(fd: fd_t) c_int;
pub extern fn lseek(fd: fd_t, offset: off_t, whence: c_int) off_t;
pub extern fn open(path: [*:0]const u8, oflag: c_uint, ...) c_int;
pub extern fn openat(fd: c_int, path: [*:0]const u8, oflag: c_uint, ...) c_int;
pub extern fn ftruncate(fd: c_int, length: off_t) c_int;
pub extern fn raise(sig: c_int) c_int;
pub extern fn read(fd: fd_t, buf: [*]u8, nbyte: usize) isize;
pub extern fn readv(fd: c_int, iov: [*]const iovec, iovcnt: c_uint) isize;
pub extern fn pread(fd: fd_t, buf: [*]u8, nbyte: usize, offset: off_t) isize;
pub extern fn preadv(fd: c_int, iov: [*]const iovec, iovcnt: c_uint, offset: off_t) isize;
pub extern fn writev(fd: c_int, iov: [*]const iovec_const, iovcnt: c_uint) isize;
pub extern fn pwritev(fd: c_int, iov: [*]const iovec_const, iovcnt: c_uint, offset: off_t) isize;
pub extern fn write(fd: fd_t, buf: [*]const u8, nbyte: usize) isize;
pub extern fn pwrite(fd: fd_t, buf: [*]const u8, nbyte: usize, offset: off_t) isize;
pub extern fn mmap(addr: ?*align(page_size) c_void, len: usize, prot: c_uint, flags: c_uint, fd: fd_t, offset: off_t) *c_void;
pub extern fn munmap(addr: *align(page_size) const c_void, len: usize) c_int;
pub extern fn mprotect(addr: *align(page_size) c_void, len: usize, prot: c_uint) c_int;
pub extern fn link(oldpath: [*:0]const u8, newpath: [*:0]const u8, flags: c_int) c_int;
pub extern fn linkat(oldfd: fd_t, oldpath: [*:0]const u8, newfd: fd_t, newpath: [*:0]const u8, flags: c_int) c_int;
pub extern fn unlink(path: [*:0]const u8) c_int;
pub extern fn unlinkat(dirfd: fd_t, path: [*:0]const u8, flags: c_uint) c_int;
pub extern fn getcwd(buf: [*]u8, size: usize) ?[*]u8;
pub extern fn waitpid(pid: pid_t, stat_loc: ?*c_int, options: c_int) pid_t;
pub extern fn fork() c_int;
pub extern fn access(path: [*:0]const u8, mode: c_uint) c_int;
pub extern fn faccessat(dirfd: fd_t, path: [*:0]const u8, mode: c_uint, flags: c_uint) c_int;
pub extern fn pipe(fds: *[2]fd_t) c_int;
pub extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
pub extern fn mkdirat(dirfd: fd_t, path: [*:0]const u8, mode: u32) c_int;
pub extern fn symlink(existing: [*:0]const u8, new: [*:0]const u8) c_int;
pub extern fn symlinkat(oldpath: [*:0]const u8, newdirfd: fd_t, newpath: [*:0]const u8) c_int;
pub extern fn rename(old: [*:0]const u8, new: [*:0]const u8) c_int;
pub extern fn renameat(olddirfd: fd_t, old: [*:0]const u8, newdirfd: fd_t, new: [*:0]const u8) c_int;
pub extern fn chdir(path: [*:0]const u8) c_int;
pub extern fn fchdir(fd: fd_t) c_int;
pub extern fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) c_int;
pub extern fn dup(fd: fd_t) c_int;
pub extern fn dup2(old_fd: fd_t, new_fd: fd_t) c_int;
pub extern fn readlink(noalias path: [*:0]const u8, noalias buf: [*]u8, bufsize: usize) isize;
pub extern fn readlinkat(dirfd: fd_t, noalias path: [*:0]const u8, noalias buf: [*]u8, bufsize: usize) isize;

pub extern fn fstatat(dirfd: fd_t, path: [*:0]const u8, stat_buf: *libc_stat, flags: u32) c_int;

pub extern fn rmdir(path: [*:0]const u8) c_int;
pub extern fn getenv(name: [*:0]const u8) ?[*:0]u8;
pub extern fn sysctl(name: [*]const c_int, namelen: c_uint, oldp: ?*c_void, oldlenp: ?*usize, newp: ?*c_void, newlen: usize) c_int;
pub extern fn sysctlbyname(name: [*:0]const u8, oldp: ?*c_void, oldlenp: ?*usize, newp: ?*c_void, newlen: usize) c_int;
pub extern fn sysctlnametomib(name: [*:0]const u8, mibp: ?*c_int, sizep: ?*usize) c_int;
pub extern fn tcgetattr(fd: fd_t, termios_p: *termios) c_int;
pub extern fn tcsetattr(fd: fd_t, optional_action: TCSA, termios_p: *const termios) c_int;
pub extern fn fcntl(fd: fd_t, cmd: c_int, ...) c_int;
pub extern fn flock(fd: fd_t, operation: c_int) c_int;
pub extern fn ioctl(fd: fd_t, request: c_int, ...) c_int;
pub extern fn uname(buf: *utsname) c_int;

pub extern fn gethostname(name: [*]u8, len: usize) c_int;
pub extern fn shutdown(socket: fd_t, how: c_int) c_int;
pub extern fn bind(socket: fd_t, address: ?*const sockaddr, address_len: socklen_t) c_int;
pub extern fn socketpair(domain: c_uint, sock_type: c_uint, protocol: c_uint, sv: *[2]fd_t) c_int;
pub extern fn listen(sockfd: fd_t, backlog: c_uint) c_int;
pub extern fn getsockname(sockfd: fd_t, noalias addr: *sockaddr, noalias addrlen: *socklen_t) c_int;
pub extern fn getpeername(sockfd: fd_t, noalias addr: *sockaddr, noalias addrlen: *socklen_t) c_int;
pub extern fn connect(sockfd: fd_t, sock_addr: *const sockaddr, addrlen: socklen_t) c_int;
pub extern fn accept(sockfd: fd_t, noalias addr: ?*sockaddr, noalias addrlen: ?*socklen_t) c_int;
pub extern fn accept4(sockfd: fd_t, noalias addr: ?*sockaddr, noalias addrlen: ?*socklen_t, flags: c_uint) c_int;
pub extern fn getsockopt(sockfd: fd_t, level: u32, optname: u32, noalias optval: ?*c_void, noalias optlen: *socklen_t) c_int;
pub extern fn setsockopt(sockfd: fd_t, level: u32, optname: u32, optval: ?*const c_void, optlen: socklen_t) c_int;
pub extern fn send(sockfd: fd_t, buf: *const c_void, len: usize, flags: u32) isize;
pub extern fn sendto(
    sockfd: fd_t,
    buf: *const c_void,
    len: usize,
    flags: u32,
    dest_addr: ?*const sockaddr,
    addrlen: socklen_t,
) isize;
pub extern fn sendmsg(sockfd: fd_t, msg: *const std.x.os.Socket.Message, flags: c_int) isize;

pub extern fn recv(sockfd: fd_t, arg1: ?*c_void, arg2: usize, arg3: c_int) isize;
pub extern fn recvfrom(
    sockfd: fd_t,
    noalias buf: *c_void,
    len: usize,
    flags: u32,
    noalias src_addr: ?*sockaddr,
    noalias addrlen: ?*socklen_t,
) isize;
pub extern fn recvmsg(sockfd: fd_t, msg: *std.x.os.Socket.Message, flags: c_int) isize;

pub extern fn clock_getres(clk_id: c_int, tp: *timespec) c_int;
pub extern fn clock_gettime(clk_id: c_int, tp: *timespec) c_int;
pub extern fn fstat(fd: fd_t, buf: *libc_stat) c_int;
pub extern fn getrusage(who: c_int, usage: *rusage) c_int;
pub extern fn gettimeofday(noalias tv: ?*timeval, noalias tz: ?*timezone) c_int;
pub extern fn nanosleep(rqtp: *const timespec, rmtp: ?*timespec) c_int;
pub extern fn sched_yield() c_int;
pub extern fn sigaction(sig: c_int, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) c_int;
pub extern fn sigprocmask(how: c_int, noalias set: ?*const sigset_t, noalias oset: ?*sigset_t) c_int;
pub extern fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
pub extern fn stat(noalias path: [*:0]const u8, noalias buf: *libc_stat) c_int;
pub extern fn sigfillset(set: ?*sigset_t) void;
pub extern fn alarm(seconds: c_uint) c_uint;
pub extern fn sigwait(set: ?*sigset_t, sig: ?*c_int) c_int;

pub extern fn kill(pid: pid_t, sig: c_int) c_int;
pub extern fn getdirentries(fd: fd_t, buf_ptr: [*]u8, nbytes: usize, basep: *i64) isize;

pub extern fn setuid(uid: uid_t) c_int;
pub extern fn setgid(gid: gid_t) c_int;
pub extern fn seteuid(euid: uid_t) c_int;
pub extern fn setegid(egid: gid_t) c_int;
pub extern fn setreuid(ruid: uid_t, euid: uid_t) c_int;
pub extern fn setregid(rgid: gid_t, egid: gid_t) c_int;
pub extern fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) c_int;
pub extern fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) c_int;

pub extern fn malloc(usize) ?*c_void;
pub extern fn realloc(?*c_void, usize) ?*c_void;
pub extern fn free(?*c_void) void;

pub extern fn futimes(fd: fd_t, times: *[2]timeval) c_int;
pub extern fn utimes(path: [*:0]const u8, times: *[2]timeval) c_int;

pub extern fn utimensat(dirfd: fd_t, pathname: [*:0]const u8, times: *[2]timespec, flags: u32) c_int;
pub extern fn futimens(fd: fd_t, times: *const [2]timespec) c_int;

pub extern fn sem_init(sem: *sem_t, pshared: c_int, value: c_uint) c_int;
pub extern fn sem_destroy(sem: *sem_t) c_int;
pub extern fn sem_post(sem: *sem_t) c_int;
pub extern fn sem_wait(sem: *sem_t) c_int;
pub extern fn sem_trywait(sem: *sem_t) c_int;
pub extern fn sem_timedwait(sem: *sem_t, abs_timeout: *const timespec) c_int;
pub extern fn sem_getvalue(sem: *sem_t, sval: *c_int) c_int;

pub extern fn kqueue() c_int;
pub extern fn kevent(
    kq: c_int,
    changelist: [*]const Kevent,
    nchanges: c_int,
    eventlist: [*]Kevent,
    nevents: c_int,
    timeout: ?*const timespec,
) c_int;

pub extern fn getaddrinfo(
    noalias node: ?[*:0]const u8,
    noalias service: ?[*:0]const u8,
    noalias hints: ?*const addrinfo,
    noalias res: **addrinfo,
) EAI;

pub extern fn freeaddrinfo(res: *addrinfo) void;

pub extern fn getnameinfo(
    noalias addr: *const sockaddr,
    addrlen: socklen_t,
    noalias host: [*]u8,
    hostlen: socklen_t,
    noalias serv: [*]u8,
    servlen: socklen_t,
    flags: u32,
) EAI;

pub extern fn gai_strerror(errcode: EAI) [*:0]const u8;

pub extern fn poll(fds: [*]pollfd, nfds: nfds_t, timeout: c_int) c_int;
pub extern fn ppoll(fds: [*]pollfd, nfds: nfds_t, timeout: ?*const timespec, sigmask: ?*const sigset_t) c_int;

pub extern fn dn_expand(
    msg: [*:0]const u8,
    eomorig: [*:0]const u8,
    comp_dn: [*:0]const u8,
    exp_dn: [*:0]u8,
    length: c_int,
) c_int;

pub const FILE = opaque {};

pub extern fn dlopen(path: [*:0]const u8, mode: c_int) ?*c_void;
pub extern fn dlclose(handle: *c_void) c_int;
pub extern fn dlsym(handle: ?*c_void, symbol: [*:0]const u8) ?*c_void;

pub extern fn sync() void;
pub extern fn syncfs(fd: c_int) c_int;
pub extern fn fsync(fd: c_int) c_int;
pub extern fn fdatasync(fd: c_int) c_int;

pub extern fn prctl(option: c_int, ...) c_int;

pub extern fn getrlimit(resource: rlimit_resource, rlim: *rlimit) c_int;
pub extern fn setrlimit(resource: rlimit_resource, rlim: *const rlimit) c_int;

pub extern fn fmemopen(noalias buf: ?*c_void, size: usize, noalias mode: [*:0]const u8) ?*FILE;

pub extern fn syslog(priority: c_int, message: [*:0]const u8, ...) void;
pub extern fn openlog(ident: [*:0]const u8, logopt: c_int, facility: c_int) void;
pub extern fn closelog() void;
pub extern fn setlogmask(maskpri: c_int) c_int;

pub const max_align_t = struct {
    a: c_longlong,
    b: c_longdouble,
};
