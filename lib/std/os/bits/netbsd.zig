// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const maxInt = std.math.maxInt;

pub const blkcnt_t = i64;
pub const blksize_t = i32;
pub const clock_t = u32;
pub const dev_t = u64;
pub const fd_t = i32;
pub const gid_t = u32;
pub const ino_t = u64;
pub const mode_t = u32;
pub const nlink_t = u32;
pub const off_t = i64;
pub const pid_t = i32;
pub const socklen_t = u32;
pub const time_t = i64;
pub const uid_t = u32;
pub const lwpid_t = i32;
pub const suseconds_t = c_int;

/// Renamed from `kevent` to `Kevent` to avoid conflict with function name.
pub const Kevent = extern struct {
    ident: usize,
    filter: i32,
    flags: u32,
    fflags: u32,
    data: i64,
    udata: usize,
};

pub const RTLD_LAZY = 1;
pub const RTLD_NOW = 2;
pub const RTLD_GLOBAL = 0x100;
pub const RTLD_LOCAL = 0x200;
pub const RTLD_NODELETE = 0x01000;
pub const RTLD_NOLOAD = 0x02000;

pub const RTLD_NEXT = @intToPtr(*c_void, @bitCast(usize, @as(isize, -1)));
pub const RTLD_DEFAULT = @intToPtr(*c_void, @bitCast(usize, @as(isize, -2)));
pub const RTLD_SELF = @intToPtr(*c_void, @bitCast(usize, @as(isize, -3)));

pub const dl_phdr_info = extern struct {
    dlpi_addr: usize,
    dlpi_name: ?[*:0]const u8,
    dlpi_phdr: [*]std.elf.Phdr,
    dlpi_phnum: u16,
};

pub const Flock = extern struct {
    l_start: off_t,
    l_len: off_t,
    l_pid: pid_t,
    l_type: i16,
    l_whence: i16,
};

pub const addrinfo = extern struct {
    flags: i32,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: socklen_t,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,
};

pub const EAI = enum(c_int) {
    /// address family for hostname not supported
    ADDRFAMILY = 1,

    /// name could not be resolved at this time
    AGAIN = 2,

    /// flags parameter had an invalid value
    BADFLAGS = 3,

    /// non-recoverable failure in name resolution
    FAIL = 4,

    /// address family not recognized
    FAMILY = 5,

    /// memory allocation failure
    MEMORY = 6,

    /// no address associated with hostname
    NODATA = 7,

    /// name does not resolve
    NONAME = 8,

    /// service not recognized for socket type
    SERVICE = 9,

    /// intended socket type was not recognized
    SOCKTYPE = 10,

    /// system error returned in errno
    SYSTEM = 11,

    /// invalid value for hints
    BADHINTS = 12,

    /// resolved protocol is unknown
    PROTOCOL = 13,

    /// argument buffer overflow
    OVERFLOW = 14,

    _,
};

pub const EAI_MAX = 15;

pub const msghdr = extern struct {
    /// optional address
    msg_name: ?*sockaddr,

    /// size of address
    msg_namelen: socklen_t,

    /// scatter/gather array
    msg_iov: [*]iovec,

    /// # elements in msg_iov
    msg_iovlen: i32,

    /// ancillary data
    msg_control: ?*c_void,

    /// ancillary data buffer len
    msg_controllen: socklen_t,

    /// flags on received message
    msg_flags: i32,
};

pub const msghdr_const = extern struct {
    /// optional address
    msg_name: ?*const sockaddr,

    /// size of address
    msg_namelen: socklen_t,

    /// scatter/gather array
    msg_iov: [*]iovec_const,

    /// # elements in msg_iov
    msg_iovlen: i32,

    /// ancillary data
    msg_control: ?*c_void,

    /// ancillary data buffer len
    msg_controllen: socklen_t,

    /// flags on received message
    msg_flags: i32,
};

pub const libc_stat = extern struct {
    dev: dev_t,
    mode: mode_t,
    ino: ino_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    birthtim: timespec,
    size: off_t,
    blocks: blkcnt_t,
    blksize: blksize_t,
    flags: u32,
    gen: u32,
    __spare: [2]u32,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const timespec = extern struct {
    tv_sec: i64,
    tv_nsec: isize,
};

pub const timeval = extern struct {
    /// seconds
    tv_sec: time_t,
    /// microseconds
    tv_usec: suseconds_t,
};

pub const MAXNAMLEN = 511;

pub const dirent = extern struct {
    d_fileno: ino_t,
    d_reclen: u16,
    d_namlen: u16,
    d_type: u8,
    d_name: [MAXNAMLEN:0]u8,

    pub fn reclen(self: dirent) u16 {
        return self.d_reclen;
    }
};

pub const SOCK_STREAM = 1;
pub const SOCK_DGRAM = 2;
pub const SOCK_RAW = 3;
pub const SOCK_RDM = 4;
pub const SOCK_SEQPACKET = 5;
pub const SOCK_CONN_DGRAM = 6;
pub const SOCK_DCCP = SOCK_CONN_DGRAM;

pub const SOCK_CLOEXEC = 0x10000000;
pub const SOCK_NONBLOCK = 0x20000000;
pub const SOCK_NOSIGPIPE = 0x40000000;
pub const SOCK_FLAGS_MASK = 0xf0000000;

pub const SO_DEBUG = 0x0001;
pub const SO_ACCEPTCONN = 0x0002;
pub const SO_REUSEADDR = 0x0004;
pub const SO_KEEPALIVE = 0x0008;
pub const SO_DONTROUTE = 0x0010;
pub const SO_BROADCAST = 0x0020;
pub const SO_USELOOPBACK = 0x0040;
pub const SO_LINGER = 0x0080;
pub const SO_OOBINLINE = 0x0100;
pub const SO_REUSEPORT = 0x0200;
pub const SO_NOSIGPIPE = 0x0800;
pub const SO_ACCEPTFILTER = 0x1000;
pub const SO_TIMESTAMP = 0x2000;
pub const SO_RERROR = 0x4000;

pub const SO_SNDBUF = 0x1001;
pub const SO_RCVBUF = 0x1002;
pub const SO_SNDLOWAT = 0x1003;
pub const SO_RCVLOWAT = 0x1004;
pub const SO_ERROR = 0x1007;
pub const SO_TYPE = 0x1008;
pub const SO_OVERFLOWED = 0x1009;

pub const SO_NOHEADER = 0x100a;
pub const SO_SNDTIMEO = 0x100b;
pub const SO_RCVTIMEO = 0x100c;

pub const SOL_SOCKET = 0xffff;

pub const PF_UNSPEC = AF_UNSPEC;
pub const PF_LOCAL = AF_LOCAL;
pub const PF_UNIX = PF_LOCAL;
pub const PF_INET = AF_INET;
pub const PF_IMPLINK = AF_IMPLINK;
pub const PF_PUP = AF_PUP;
pub const PF_CHAOS = AF_CHAOS;
pub const PF_NS = AF_NS;
pub const PF_ISO = AF_ISO;
pub const PF_OSI = AF_ISO;
pub const PF_ECMA = AF_ECMA;
pub const PF_DATAKIT = AF_DATAKIT;
pub const PF_CCITT = AF_CCITT;
pub const PF_SNA = AF_SNA;
pub const PF_DECnet = AF_DECnet;
pub const PF_DLI = AF_DLI;
pub const PF_LAT = AF_LAT;
pub const PF_HYLINK = AF_HYLINK;
pub const PF_APPLETALK = AF_APPLETALK;
pub const PF_OROUTE = AF_OROUTE;
pub const PF_LINK = AF_LINK;
pub const PF_COIP = AF_COIP;
pub const PF_CNT = AF_CNT;
pub const PF_INET6 = AF_INET6;
pub const PF_IPX = AF_IPX;
pub const PF_ISDN = AF_ISDN;
pub const PF_E164 = AF_E164;
pub const PF_NATM = AF_NATM;
pub const PF_ARP = AF_ARP;
pub const PF_BLUETOOTH = AF_BLUETOOTH;
pub const PF_MPLS = AF_MPLS;
pub const PF_ROUTE = AF_ROUTE;
pub const PF_CAN = AF_CAN;
pub const PF_ETHER = AF_ETHER;
pub const PF_MAX = AF_MAX;

pub const AF_UNSPEC = 0;
pub const AF_LOCAL = 1;
pub const AF_UNIX = AF_LOCAL;
pub const AF_INET = 2;
pub const AF_IMPLINK = 3;
pub const AF_PUP = 4;
pub const AF_CHAOS = 5;
pub const AF_NS = 6;
pub const AF_ISO = 7;
pub const AF_OSI = AF_ISO;
pub const AF_ECMA = 8;
pub const AF_DATAKIT = 9;
pub const AF_CCITT = 10;
pub const AF_SNA = 11;
pub const AF_DECnet = 12;
pub const AF_DLI = 13;
pub const AF_LAT = 14;
pub const AF_HYLINK = 15;
pub const AF_APPLETALK = 16;
pub const AF_OROUTE = 17;
pub const AF_LINK = 18;
pub const AF_COIP = 20;
pub const AF_CNT = 21;
pub const AF_IPX = 23;
pub const AF_INET6 = 24;
pub const AF_ISDN = 26;
pub const AF_E164 = AF_ISDN;
pub const AF_NATM = 27;
pub const AF_ARP = 28;
pub const AF_BLUETOOTH = 31;
pub const AF_IEEE80211 = 32;
pub const AF_MPLS = 33;
pub const AF_ROUTE = 34;
pub const AF_CAN = 35;
pub const AF_ETHER = 36;
pub const AF_MAX = 37;

pub const in_port_t = u16;
pub const sa_family_t = u8;

pub const sockaddr = extern struct {
    /// total length
    len: u8,

    /// address family
    family: sa_family_t,

    /// actually longer; address value
    data: [14]u8,
};

pub const sockaddr_storage = std.x.os.Socket.Address.Native.Storage;

pub const sockaddr_in = extern struct {
    len: u8 = @sizeOf(sockaddr_in),
    family: sa_family_t = AF_INET,
    port: in_port_t,
    addr: u32,
    zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

pub const sockaddr_in6 = extern struct {
    len: u8 = @sizeOf(sockaddr_in6),
    family: sa_family_t = AF_INET6,
    port: in_port_t,
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

/// Definitions for UNIX IPC domain.
pub const sockaddr_un = extern struct {
    /// total sockaddr length
    len: u8 = @sizeOf(sockaddr_un),

    /// AF_LOCAL
    family: sa_family_t = AF_LOCAL,

    /// path name
    path: [104]u8,
};

/// get address to use bind()
pub const AI_PASSIVE = 0x00000001;

/// fill ai_canonname
pub const AI_CANONNAME = 0x00000002;

/// prevent host name resolution
pub const AI_NUMERICHOST = 0x00000004;

/// prevent service name resolution
pub const AI_NUMERICSERV = 0x00000008;

/// only if any address is assigned
pub const AI_ADDRCONFIG = 0x00000400;

pub const CTL_KERN = 1;
pub const CTL_DEBUG = 5;

pub const KERN_PROC_ARGS = 48; // struct: process argv/env
pub const KERN_PROC_PATHNAME = 5; // path to executable

pub const PATH_MAX = 1024;

pub const STDIN_FILENO = 0;
pub const STDOUT_FILENO = 1;
pub const STDERR_FILENO = 2;

pub const PROT_NONE = 0;
pub const PROT_READ = 1;
pub const PROT_WRITE = 2;
pub const PROT_EXEC = 4;

pub const CLOCK_REALTIME = 0;
pub const CLOCK_VIRTUAL = 1;
pub const CLOCK_PROF = 2;
pub const CLOCK_MONOTONIC = 3;
pub const CLOCK_THREAD_CPUTIME_ID = 0x20000000;
pub const CLOCK_PROCESS_CPUTIME_ID = 0x40000000;

pub const MAP_FAILED = @intToPtr(*c_void, maxInt(usize));
pub const MAP_SHARED = 0x0001;
pub const MAP_PRIVATE = 0x0002;
pub const MAP_REMAPDUP = 0x0004;
pub const MAP_FIXED = 0x0010;
pub const MAP_RENAME = 0x0020;
pub const MAP_NORESERVE = 0x0040;
pub const MAP_INHERIT = 0x0080;
pub const MAP_HASSEMAPHORE = 0x0200;
pub const MAP_TRYFIXED = 0x0400;
pub const MAP_WIRED = 0x0800;

pub const MAP_FILE = 0x0000;
pub const MAP_NOSYNC = 0x0800;
pub const MAP_ANON = 0x1000;
pub const MAP_ANONYMOUS = MAP_ANON;
pub const MAP_STACK = 0x2000;

pub const WNOHANG = 0x00000001;
pub const WUNTRACED = 0x00000002;
pub const WSTOPPED = WUNTRACED;
pub const WCONTINUED = 0x00000010;
pub const WNOWAIT = 0x00010000;
pub const WEXITED = 0x00000020;
pub const WTRAPPED = 0x00000040;

pub const SA_ONSTACK = 0x0001;
pub const SA_RESTART = 0x0002;
pub const SA_RESETHAND = 0x0004;
pub const SA_NOCLDSTOP = 0x0008;
pub const SA_NODEFER = 0x0010;
pub const SA_NOCLDWAIT = 0x0020;
pub const SA_SIGINFO = 0x0040;

pub const SIGHUP = 1;
pub const SIGINT = 2;
pub const SIGQUIT = 3;
pub const SIGILL = 4;
pub const SIGTRAP = 5;
pub const SIGABRT = 6;
pub const SIGIOT = SIGABRT;
pub const SIGEMT = 7;
pub const SIGFPE = 8;
pub const SIGKILL = 9;
pub const SIGBUS = 10;
pub const SIGSEGV = 11;
pub const SIGSYS = 12;
pub const SIGPIPE = 13;
pub const SIGALRM = 14;
pub const SIGTERM = 15;
pub const SIGURG = 16;
pub const SIGSTOP = 17;
pub const SIGTSTP = 18;
pub const SIGCONT = 19;
pub const SIGCHLD = 20;
pub const SIGTTIN = 21;
pub const SIGTTOU = 22;
pub const SIGIO = 23;
pub const SIGXCPU = 24;
pub const SIGXFSZ = 25;
pub const SIGVTALRM = 26;
pub const SIGPROF = 27;
pub const SIGWINCH = 28;
pub const SIGINFO = 29;
pub const SIGUSR1 = 30;
pub const SIGUSR2 = 31;
pub const SIGPWR = 32;

pub const SIGRTMIN = 33;
pub const SIGRTMAX = 63;

// access function
pub const F_OK = 0; // test for existence of file
pub const X_OK = 1; // test for execute or search permission
pub const W_OK = 2; // test for write permission
pub const R_OK = 4; // test for read permission

/// open for reading only
pub const O_RDONLY = 0x00000000;

/// open for writing only
pub const O_WRONLY = 0x00000001;

/// open for reading and writing
pub const O_RDWR = 0x00000002;

/// mask for above modes
pub const O_ACCMODE = 0x00000003;

/// no delay
pub const O_NONBLOCK = 0x00000004;

/// set append mode
pub const O_APPEND = 0x00000008;

/// open with shared file lock
pub const O_SHLOCK = 0x00000010;

/// open with exclusive file lock
pub const O_EXLOCK = 0x00000020;

/// signal pgrp when data ready
pub const O_ASYNC = 0x00000040;

/// synchronous writes
pub const O_SYNC = 0x00000080;

/// don't follow symlinks on the last
pub const O_NOFOLLOW = 0x00000100;

/// create if nonexistent
pub const O_CREAT = 0x00000200;

/// truncate to zero length
pub const O_TRUNC = 0x00000400;

/// error if already exists
pub const O_EXCL = 0x00000800;

/// don't assign controlling terminal
pub const O_NOCTTY = 0x00008000;

/// write: I/O data completion
pub const O_DSYNC = 0x00010000;

/// read: I/O completion as for write
pub const O_RSYNC = 0x00020000;

/// use alternate i/o semantics
pub const O_ALT_IO = 0x00040000;

/// direct I/O hint
pub const O_DIRECT = 0x00080000;

/// fail if not a directory
pub const O_DIRECTORY = 0x00200000;

/// set close on exec
pub const O_CLOEXEC = 0x00400000;

/// skip search permission checks
pub const O_SEARCH = 0x00800000;

pub const F_DUPFD = 0;
pub const F_GETFD = 1;
pub const F_SETFD = 2;
pub const F_GETFL = 3;
pub const F_SETFL = 4;

pub const F_GETOWN = 5;
pub const F_SETOWN = 6;

pub const F_GETLK = 7;
pub const F_SETLK = 8;
pub const F_SETLKW = 9;

pub const F_RDLCK = 1;
pub const F_WRLCK = 3;
pub const F_UNLCK = 2;

pub const LOCK_SH = 1;
pub const LOCK_EX = 2;
pub const LOCK_UN = 8;
pub const LOCK_NB = 4;

pub const FD_CLOEXEC = 1;

pub const SEEK_SET = 0;
pub const SEEK_CUR = 1;
pub const SEEK_END = 2;

pub const SIG_BLOCK = 1;
pub const SIG_UNBLOCK = 2;
pub const SIG_SETMASK = 3;

pub const DT_UNKNOWN = 0;
pub const DT_FIFO = 1;
pub const DT_CHR = 2;
pub const DT_DIR = 4;
pub const DT_BLK = 6;
pub const DT_REG = 8;
pub const DT_LNK = 10;
pub const DT_SOCK = 12;
pub const DT_WHT = 14;

/// add event to kq (implies enable)
pub const EV_ADD = 0x0001;

/// delete event from kq
pub const EV_DELETE = 0x0002;

/// enable event
pub const EV_ENABLE = 0x0004;

/// disable event (not reported)
pub const EV_DISABLE = 0x0008;

/// only report one occurrence
pub const EV_ONESHOT = 0x0010;

/// clear event state after reporting
pub const EV_CLEAR = 0x0020;

/// force immediate event output
/// ... with or without EV_ERROR
/// ... use KEVENT_FLAG_ERROR_EVENTS
///     on syscalls supporting flags
pub const EV_RECEIPT = 0x0040;

/// disable event after reporting
pub const EV_DISPATCH = 0x0080;

pub const EVFILT_READ = 0;
pub const EVFILT_WRITE = 1;

/// attached to aio requests
pub const EVFILT_AIO = 2;

/// attached to vnodes
pub const EVFILT_VNODE = 3;

/// attached to struct proc
pub const EVFILT_PROC = 4;

/// attached to struct proc
pub const EVFILT_SIGNAL = 5;

/// timers
pub const EVFILT_TIMER = 6;

/// Filesystem events
pub const EVFILT_FS = 7;

/// On input, NOTE_TRIGGER causes the event to be triggered for output.
pub const NOTE_TRIGGER = 0x08000000;

/// low water mark
pub const NOTE_LOWAT = 0x00000001;

/// vnode was removed
pub const NOTE_DELETE = 0x00000001;

/// data contents changed
pub const NOTE_WRITE = 0x00000002;

/// size increased
pub const NOTE_EXTEND = 0x00000004;

/// attributes changed
pub const NOTE_ATTRIB = 0x00000008;

/// link count changed
pub const NOTE_LINK = 0x00000010;

/// vnode was renamed
pub const NOTE_RENAME = 0x00000020;

/// vnode access was revoked
pub const NOTE_REVOKE = 0x00000040;

/// process exited
pub const NOTE_EXIT = 0x80000000;

/// process forked
pub const NOTE_FORK = 0x40000000;

/// process exec'd
pub const NOTE_EXEC = 0x20000000;

/// mask for signal & exit status
pub const NOTE_PDATAMASK = 0x000fffff;
pub const NOTE_PCTRLMASK = 0xf0000000;

pub const TIOCCBRK = 0x2000747a;
pub const TIOCCDTR = 0x20007478;
pub const TIOCCONS = 0x80047462;
pub const TIOCDCDTIMESTAMP = 0x40107458;
pub const TIOCDRAIN = 0x2000745e;
pub const TIOCEXCL = 0x2000740d;
pub const TIOCEXT = 0x80047460;
pub const TIOCFLAG_CDTRCTS = 0x10;
pub const TIOCFLAG_CLOCAL = 0x2;
pub const TIOCFLAG_CRTSCTS = 0x4;
pub const TIOCFLAG_MDMBUF = 0x8;
pub const TIOCFLAG_SOFTCAR = 0x1;
pub const TIOCFLUSH = 0x80047410;
pub const TIOCGETA = 0x402c7413;
pub const TIOCGETD = 0x4004741a;
pub const TIOCGFLAGS = 0x4004745d;
pub const TIOCGLINED = 0x40207442;
pub const TIOCGPGRP = 0x40047477;
pub const TIOCGQSIZE = 0x40047481;
pub const TIOCGRANTPT = 0x20007447;
pub const TIOCGSID = 0x40047463;
pub const TIOCGSIZE = 0x40087468;
pub const TIOCGWINSZ = 0x40087468;
pub const TIOCMBIC = 0x8004746b;
pub const TIOCMBIS = 0x8004746c;
pub const TIOCMGET = 0x4004746a;
pub const TIOCMSET = 0x8004746d;
pub const TIOCM_CAR = 0x40;
pub const TIOCM_CD = 0x40;
pub const TIOCM_CTS = 0x20;
pub const TIOCM_DSR = 0x100;
pub const TIOCM_DTR = 0x2;
pub const TIOCM_LE = 0x1;
pub const TIOCM_RI = 0x80;
pub const TIOCM_RNG = 0x80;
pub const TIOCM_RTS = 0x4;
pub const TIOCM_SR = 0x10;
pub const TIOCM_ST = 0x8;
pub const TIOCNOTTY = 0x20007471;
pub const TIOCNXCL = 0x2000740e;
pub const TIOCOUTQ = 0x40047473;
pub const TIOCPKT = 0x80047470;
pub const TIOCPKT_DATA = 0x0;
pub const TIOCPKT_DOSTOP = 0x20;
pub const TIOCPKT_FLUSHREAD = 0x1;
pub const TIOCPKT_FLUSHWRITE = 0x2;
pub const TIOCPKT_IOCTL = 0x40;
pub const TIOCPKT_NOSTOP = 0x10;
pub const TIOCPKT_START = 0x8;
pub const TIOCPKT_STOP = 0x4;
pub const TIOCPTMGET = 0x40287446;
pub const TIOCPTSNAME = 0x40287448;
pub const TIOCRCVFRAME = 0x80087445;
pub const TIOCREMOTE = 0x80047469;
pub const TIOCSBRK = 0x2000747b;
pub const TIOCSCTTY = 0x20007461;
pub const TIOCSDTR = 0x20007479;
pub const TIOCSETA = 0x802c7414;
pub const TIOCSETAF = 0x802c7416;
pub const TIOCSETAW = 0x802c7415;
pub const TIOCSETD = 0x8004741b;
pub const TIOCSFLAGS = 0x8004745c;
pub const TIOCSIG = 0x2000745f;
pub const TIOCSLINED = 0x80207443;
pub const TIOCSPGRP = 0x80047476;
pub const TIOCSQSIZE = 0x80047480;
pub const TIOCSSIZE = 0x80087467;
pub const TIOCSTART = 0x2000746e;
pub const TIOCSTAT = 0x80047465;
pub const TIOCSTI = 0x80017472;
pub const TIOCSTOP = 0x2000746f;
pub const TIOCSWINSZ = 0x80087467;
pub const TIOCUCNTL = 0x80047466;
pub const TIOCXMTFRAME = 0x80087444;

pub fn WEXITSTATUS(s: u32) u8 {
    return @intCast(u8, (s >> 8) & 0xff);
}
pub fn WTERMSIG(s: u32) u32 {
    return s & 0x7f;
}
pub fn WSTOPSIG(s: u32) u32 {
    return WEXITSTATUS(s);
}
pub fn WIFEXITED(s: u32) bool {
    return WTERMSIG(s) == 0;
}

pub fn WIFCONTINUED(s: u32) bool {
    return ((s & 0x7f) == 0xffff);
}

pub fn WIFSTOPPED(s: u32) bool {
    return ((s & 0x7f != 0x7f) and !WIFCONTINUED(s));
}

pub fn WIFSIGNALED(s: u32) bool {
    return !WIFSTOPPED(s) and !WIFCONTINUED(s) and !WIFEXITED(s);
}

pub const winsize = extern struct {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
};

const NSIG = 32;

pub const SIG_DFL = @intToPtr(?Sigaction.sigaction_fn, 0);
pub const SIG_IGN = @intToPtr(?Sigaction.sigaction_fn, 1);
pub const SIG_ERR = @intToPtr(?Sigaction.sigaction_fn, maxInt(usize));

/// Renamed from `sigaction` to `Sigaction` to avoid conflict with the syscall.
pub const Sigaction = extern struct {
    pub const handler_fn = fn (c_int) callconv(.C) void;
    pub const sigaction_fn = fn (c_int, *const siginfo_t, ?*const c_void) callconv(.C) void;

    /// signal handler
    handler: extern union {
        handler: ?handler_fn,
        sigaction: ?sigaction_fn,
    },
    /// signal mask to apply
    mask: sigset_t,
    /// signal options
    flags: c_uint,
};

pub const sigval_t = extern union {
    int: i32,
    ptr: ?*c_void,
};

pub const siginfo_t = extern union {
    pad: [128]u8,
    info: _ksiginfo,
};

pub const _ksiginfo = extern struct {
    signo: i32,
    code: i32,
    errno: i32,
    // 64bit architectures insert 4bytes of padding here, this is done by
    // correctly aligning the reason field
    reason: extern union {
        rt: extern struct {
            pid: pid_t,
            uid: uid_t,
            value: sigval_t,
        },
        child: extern struct {
            pid: pid_t,
            uid: uid_t,
            status: i32,
            utime: clock_t,
            stime: clock_t,
        },
        fault: extern struct {
            addr: ?*c_void,
            trap: i32,
            trap2: i32,
            trap3: i32,
        },
        poll: extern struct {
            band: i32,
            fd: i32,
        },
        syscall: extern struct {
            sysnum: i32,
            retval: [2]i32,
            @"error": i32,
            args: [8]u64,
        },
        ptrace_state: extern struct {
            pe_report_event: i32,
            option: extern union {
                pe_other_pid: pid_t,
                pe_lwp: lwpid_t,
            },
        },
    } align(@sizeOf(usize)),
};

pub const _SIG_WORDS = 4;
pub const _SIG_MAXSIG = 128;

pub inline fn _SIG_IDX(sig: usize) usize {
    return sig - 1;
}
pub inline fn _SIG_WORD(sig: usize) usize {
    return_SIG_IDX(sig) >> 5;
}
pub inline fn _SIG_BIT(sig: usize) usize {
    return 1 << (_SIG_IDX(sig) & 31);
}
pub inline fn _SIG_VALID(sig: usize) usize {
    return sig <= _SIG_MAXSIG and sig > 0;
}

pub const sigset_t = extern struct {
    __bits: [_SIG_WORDS]u32,
};

pub const empty_sigset = sigset_t{ .__bits = [_]u32{0} ** _SIG_WORDS };

// XXX x86_64 specific
pub const mcontext_t = extern struct {
    gregs: [26]u64,
    mc_tlsbase: u64,
    fpregs: [512]u8 align(8),
};

pub const REG_RBP = 12;
pub const REG_RIP = 21;
pub const REG_RSP = 24;

pub const ucontext_t = extern struct {
    flags: u32,
    link: ?*ucontext_t,
    sigmask: sigset_t,
    stack: stack_t,
    mcontext: mcontext_t,
    __pad: [
        switch (builtin.cpu.arch) {
            .i386 => 4,
            .mips, .mipsel, .mips64, .mips64el => 14,
            .arm, .armeb, .thumb, .thumbeb => 1,
            .sparc, .sparcel, .sparcv9 => if (@sizeOf(usize) == 4) 43 else 8,
            else => 0,
        }
    ]u32,
};

pub const EPERM = 1; // Operation not permitted
pub const ENOENT = 2; // No such file or directory
pub const ESRCH = 3; // No such process
pub const EINTR = 4; // Interrupted system call
pub const EIO = 5; // Input/output error
pub const ENXIO = 6; // Device not configured
pub const E2BIG = 7; // Argument list too long
pub const ENOEXEC = 8; // Exec format error
pub const EBADF = 9; // Bad file descriptor
pub const ECHILD = 10; // No child processes
pub const EDEADLK = 11; // Resource deadlock avoided
// 11 was EAGAIN
pub const ENOMEM = 12; // Cannot allocate memory
pub const EACCES = 13; // Permission denied
pub const EFAULT = 14; // Bad address
pub const ENOTBLK = 15; // Block device required
pub const EBUSY = 16; // Device busy
pub const EEXIST = 17; // File exists
pub const EXDEV = 18; // Cross-device link
pub const ENODEV = 19; // Operation not supported by device
pub const ENOTDIR = 20; // Not a directory
pub const EISDIR = 21; // Is a directory
pub const EINVAL = 22; // Invalid argument
pub const ENFILE = 23; // Too many open files in system
pub const EMFILE = 24; // Too many open files
pub const ENOTTY = 25; // Inappropriate ioctl for device
pub const ETXTBSY = 26; // Text file busy
pub const EFBIG = 27; // File too large
pub const ENOSPC = 28; // No space left on device
pub const ESPIPE = 29; // Illegal seek
pub const EROFS = 30; // Read-only file system
pub const EMLINK = 31; // Too many links
pub const EPIPE = 32; // Broken pipe

// math software
pub const EDOM = 33; // Numerical argument out of domain
pub const ERANGE = 34; // Result too large or too small

// non-blocking and interrupt i/o
pub const EAGAIN = 35; // Resource temporarily unavailable
pub const EWOULDBLOCK = EAGAIN; // Operation would block
pub const EINPROGRESS = 36; // Operation now in progress
pub const EALREADY = 37; // Operation already in progress

// ipc/network software -- argument errors
pub const ENOTSOCK = 38; // Socket operation on non-socket
pub const EDESTADDRREQ = 39; // Destination address required
pub const EMSGSIZE = 40; // Message too long
pub const EPROTOTYPE = 41; // Protocol wrong type for socket
pub const ENOPROTOOPT = 42; // Protocol option not available
pub const EPROTONOSUPPORT = 43; // Protocol not supported
pub const ESOCKTNOSUPPORT = 44; // Socket type not supported
pub const EOPNOTSUPP = 45; // Operation not supported
pub const EPFNOSUPPORT = 46; // Protocol family not supported
pub const EAFNOSUPPORT = 47; // Address family not supported by protocol family
pub const EADDRINUSE = 48; // Address already in use
pub const EADDRNOTAVAIL = 49; // Can't assign requested address

// ipc/network software -- operational errors
pub const ENETDOWN = 50; // Network is down
pub const ENETUNREACH = 51; // Network is unreachable
pub const ENETRESET = 52; // Network dropped connection on reset
pub const ECONNABORTED = 53; // Software caused connection abort
pub const ECONNRESET = 54; // Connection reset by peer
pub const ENOBUFS = 55; // No buffer space available
pub const EISCONN = 56; // Socket is already connected
pub const ENOTCONN = 57; // Socket is not connected
pub const ESHUTDOWN = 58; // Can't send after socket shutdown
pub const ETOOMANYREFS = 59; // Too many references: can't splice
pub const ETIMEDOUT = 60; // Operation timed out
pub const ECONNREFUSED = 61; // Connection refused

pub const ELOOP = 62; // Too many levels of symbolic links
pub const ENAMETOOLONG = 63; // File name too long

// should be rearranged
pub const EHOSTDOWN = 64; // Host is down
pub const EHOSTUNREACH = 65; // No route to host
pub const ENOTEMPTY = 66; // Directory not empty

// quotas & mush
pub const EPROCLIM = 67; // Too many processes
pub const EUSERS = 68; // Too many users
pub const EDQUOT = 69; // Disc quota exceeded

// Network File System
pub const ESTALE = 70; // Stale NFS file handle
pub const EREMOTE = 71; // Too many levels of remote in path
pub const EBADRPC = 72; // RPC struct is bad
pub const ERPCMISMATCH = 73; // RPC version wrong
pub const EPROGUNAVAIL = 74; // RPC prog. not avail
pub const EPROGMISMATCH = 75; // Program version wrong
pub const EPROCUNAVAIL = 76; // Bad procedure for program

pub const ENOLCK = 77; // No locks available
pub const ENOSYS = 78; // Function not implemented

pub const EFTYPE = 79; // Inappropriate file type or format
pub const EAUTH = 80; // Authentication error
pub const ENEEDAUTH = 81; // Need authenticator

// SystemV IPC
pub const EIDRM = 82; // Identifier removed
pub const ENOMSG = 83; // No message of desired type
pub const EOVERFLOW = 84; // Value too large to be stored in data type

// Wide/multibyte-character handling, ISO/IEC 9899/AMD1:1995
pub const EILSEQ = 85; // Illegal byte sequence

// From IEEE Std 1003.1-2001
// Base, Realtime, Threads or Thread Priority Scheduling option errors
pub const ENOTSUP = 86; // Not supported

// Realtime option errors
pub const ECANCELED = 87; // Operation canceled

// Realtime, XSI STREAMS option errors
pub const EBADMSG = 88; // Bad or Corrupt message

// XSI STREAMS option errors
pub const ENODATA = 89; // No message available
pub const ENOSR = 90; // No STREAM resources
pub const ENOSTR = 91; // Not a STREAM
pub const ETIME = 92; // STREAM ioctl timeout

// File system extended attribute errors
pub const ENOATTR = 93; // Attribute not found

// Realtime, XSI STREAMS option errors
pub const EMULTIHOP = 94; // Multihop attempted
pub const ENOLINK = 95; // Link has been severed
pub const EPROTO = 96; // Protocol error

pub const ELAST = 96; // Must equal largest errno

pub const MINSIGSTKSZ = 8192;
pub const SIGSTKSZ = MINSIGSTKSZ + 32768;

pub const SS_ONSTACK = 1;
pub const SS_DISABLE = 4;

pub const stack_t = extern struct {
    ss_sp: [*]u8,
    ss_size: isize,
    ss_flags: i32,
};

pub const S_IFMT = 0o170000;

pub const S_IFIFO = 0o010000;
pub const S_IFCHR = 0o020000;
pub const S_IFDIR = 0o040000;
pub const S_IFBLK = 0o060000;
pub const S_IFREG = 0o100000;
pub const S_IFLNK = 0o120000;
pub const S_IFSOCK = 0o140000;
pub const S_IFWHT = 0o160000;

pub const S_ISUID = 0o4000;
pub const S_ISGID = 0o2000;
pub const S_ISVTX = 0o1000;
pub const S_IRWXU = 0o700;
pub const S_IRUSR = 0o400;
pub const S_IWUSR = 0o200;
pub const S_IXUSR = 0o100;
pub const S_IRWXG = 0o070;
pub const S_IRGRP = 0o040;
pub const S_IWGRP = 0o020;
pub const S_IXGRP = 0o010;
pub const S_IRWXO = 0o007;
pub const S_IROTH = 0o004;
pub const S_IWOTH = 0o002;
pub const S_IXOTH = 0o001;

pub fn S_ISFIFO(m: u32) bool {
    return m & S_IFMT == S_IFIFO;
}

pub fn S_ISCHR(m: u32) bool {
    return m & S_IFMT == S_IFCHR;
}

pub fn S_ISDIR(m: u32) bool {
    return m & S_IFMT == S_IFDIR;
}

pub fn S_ISBLK(m: u32) bool {
    return m & S_IFMT == S_IFBLK;
}

pub fn S_ISREG(m: u32) bool {
    return m & S_IFMT == S_IFREG;
}

pub fn S_ISLNK(m: u32) bool {
    return m & S_IFMT == S_IFLNK;
}

pub fn S_ISSOCK(m: u32) bool {
    return m & S_IFMT == S_IFSOCK;
}

pub fn S_IWHT(m: u32) bool {
    return m & S_IFMT == S_IFWHT;
}

/// Magic value that specify the use of the current working directory
/// to determine the target of relative file paths in the openat() and
/// similar syscalls.
pub const AT_FDCWD = -100;

/// Check access using effective user and group ID
pub const AT_EACCESS = 0x0100;

/// Do not follow symbolic links
pub const AT_SYMLINK_NOFOLLOW = 0x0200;

/// Follow symbolic link
pub const AT_SYMLINK_FOLLOW = 0x0400;

/// Remove directory instead of file
pub const AT_REMOVEDIR = 0x0800;

pub const HOST_NAME_MAX = 255;

/// dummy for IP
pub const IPPROTO_IP = 0;

/// IP6 hop-by-hop options
pub const IPPROTO_HOPOPTS = 0;

/// control message protocol
pub const IPPROTO_ICMP = 1;

/// group mgmt protocol
pub const IPPROTO_IGMP = 2;

/// gateway^2 (deprecated)
pub const IPPROTO_GGP = 3;

/// IP header
pub const IPPROTO_IPV4 = 4;

/// IP inside IP
pub const IPPROTO_IPIP = 4;

/// tcp
pub const IPPROTO_TCP = 6;

/// exterior gateway protocol
pub const IPPROTO_EGP = 8;

/// pup
pub const IPPROTO_PUP = 12;

/// user datagram protocol
pub const IPPROTO_UDP = 17;

/// xns idp
pub const IPPROTO_IDP = 22;

/// tp-4 w/ class negotiation
pub const IPPROTO_TP = 29;

/// DCCP
pub const IPPROTO_DCCP = 33;

/// IP6 header
pub const IPPROTO_IPV6 = 41;

/// IP6 routing header
pub const IPPROTO_ROUTING = 43;

/// IP6 fragmentation header
pub const IPPROTO_FRAGMENT = 44;

/// resource reservation
pub const IPPROTO_RSVP = 46;

/// GRE encaps RFC 1701
pub const IPPROTO_GRE = 47;

/// encap. security payload
pub const IPPROTO_ESP = 50;

/// authentication header
pub const IPPROTO_AH = 51;

/// IP Mobility RFC 2004
pub const IPPROTO_MOBILE = 55;

/// IPv6 ICMP
pub const IPPROTO_IPV6_ICMP = 58;

/// ICMP6
pub const IPPROTO_ICMPV6 = 58;

/// IP6 no next header
pub const IPPROTO_NONE = 59;

/// IP6 destination option
pub const IPPROTO_DSTOPTS = 60;

/// ISO cnlp
pub const IPPROTO_EON = 80;

/// Ethernet-in-IP
pub const IPPROTO_ETHERIP = 97;

/// encapsulation header
pub const IPPROTO_ENCAP = 98;

/// Protocol indep. multicast
pub const IPPROTO_PIM = 103;

/// IP Payload Comp. Protocol
pub const IPPROTO_IPCOMP = 108;

/// VRRP RFC 2338
pub const IPPROTO_VRRP = 112;

/// Common Address Resolution Protocol
pub const IPPROTO_CARP = 112;

/// L2TPv3
pub const IPPROTO_L2TP = 115;

/// SCTP
pub const IPPROTO_SCTP = 132;

/// PFSYNC
pub const IPPROTO_PFSYNC = 240;

/// raw IP packet
pub const IPPROTO_RAW = 255;

pub const rlimit_resource = enum(c_int) {
    CPU = 0,
    FSIZE = 1,
    DATA = 2,
    STACK = 3,
    CORE = 4,
    RSS = 5,
    MEMLOCK = 6,
    NPROC = 7,
    NOFILE = 8,
    SBSIZE = 9,
    VMEM = 10,
    NTHR = 11,
    _,

    pub const AS: rlimit_resource = .VMEM;
};

pub const rlim_t = u64;

/// No limit
pub const RLIM_INFINITY: rlim_t = (1 << 63) - 1;

pub const RLIM_SAVED_MAX = RLIM_INFINITY;
pub const RLIM_SAVED_CUR = RLIM_INFINITY;

pub const rlimit = extern struct {
    /// Soft limit
    cur: rlim_t,
    /// Hard limit
    max: rlim_t,
};

pub const SHUT_RD = 0;
pub const SHUT_WR = 1;
pub const SHUT_RDWR = 2;

pub const nfds_t = u32;

pub const pollfd = extern struct {
    fd: fd_t,
    events: i16,
    revents: i16,
};

/// Testable events (may be specified in events field).
pub const POLLIN = 0x0001;
pub const POLLPRI = 0x0002;
pub const POLLOUT = 0x0004;
pub const POLLRDNORM = 0x0040;
pub const POLLWRNORM = POLLOUT;
pub const POLLRDBAND = 0x0080;
pub const POLLWRBAND = 0x0100;

/// Non-testable events (may not be specified in events field).
pub const POLLERR = 0x0008;
pub const POLLHUP = 0x0010;
pub const POLLNVAL = 0x0020;
