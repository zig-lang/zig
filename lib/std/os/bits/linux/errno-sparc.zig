// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

// These match the SunOS error numbering scheme.

pub const EPERM = 1;
pub const ENOENT = 2;
pub const ESRCH = 3;
pub const EINTR = 4;
pub const EIO = 5;
pub const ENXIO = 6;
pub const E2BIG = 7;
pub const ENOEXEC = 8;
pub const EBADF = 9;
pub const ECHILD = 10;
pub const EAGAIN = 11;
pub const ENOMEM = 12;
pub const EACCES = 13;
pub const EFAULT = 14;
pub const ENOTBLK = 15;
pub const EBUSY = 16;
pub const EEXIST = 17;
pub const EXDEV = 18;
pub const ENODEV = 19;
pub const ENOTDIR = 20;
pub const EISDIR = 21;
pub const EINVAL = 22;
pub const ENFILE = 23;
pub const EMFILE = 24;
pub const ENOTTY = 25;
pub const ETXTBSY = 26;
pub const EFBIG = 27;
pub const ENOSPC = 28;
pub const ESPIPE = 29;
pub const EROFS = 30;
pub const EMLINK = 31;
pub const EPIPE = 32;
pub const EDOM = 33;
pub const ERANGE = 34;

pub const EWOULDBLOCK = EAGAIN;
pub const EINPROGRESS = 36;
pub const EALREADY = 37;
pub const ENOTSOCK = 38;
pub const EDESTADDRREQ = 39;
pub const EMSGSIZE = 40;
pub const EPROTOTYPE = 41;
pub const ENOPROTOOPT = 42;
pub const EPROTONOSUPPORT = 43;
pub const ESOCKTNOSUPPORT = 44;
pub const EOPNOTSUPP = 45;
pub const ENOTSUP = EOPNOTSUPP;
pub const EPFNOSUPPORT = 46;
pub const EAFNOSUPPORT = 47;
pub const EADDRINUSE = 48;
pub const EADDRNOTAVAIL = 49;
pub const ENETDOWN = 50;
pub const ENETUNREACH = 51;
pub const ENETRESET = 52;
pub const ECONNABORTED = 53;
pub const ECONNRESET = 54;
pub const ENOBUFS = 55;
pub const EISCONN = 56;
pub const ENOTCONN = 57;
pub const ESHUTDOWN = 58;
pub const ETOOMANYREFS = 59;
pub const ETIMEDOUT = 60;
pub const ECONNREFUSED = 61;
pub const ELOOP = 62;
pub const ENAMETOOLONG = 63;
pub const EHOSTDOWN = 64;
pub const EHOSTUNREACH = 65;
pub const ENOTEMPTY = 66;
pub const EPROCLIM = 67;
pub const EUSERS = 68;
pub const EDQUOT = 69;
pub const ESTALE = 70;
pub const EREMOTE = 71;
pub const ENOSTR = 72;
pub const ETIME = 73;
pub const ENOSR = 74;
pub const ENOMSG = 75;
pub const EBADMSG = 76;
pub const EIDRM = 77;
pub const EDEADLK = 78;
pub const ENOLCK = 79;
pub const ENONET = 80;
pub const ERREMOTE = 81;
pub const ENOLINK = 82;
pub const EADV = 83;
pub const ESRMNT = 84;
pub const ECOMM = 85;
pub const EPROTO = 86;
pub const EMULTIHOP = 87;
pub const EDOTDOT = 88;
pub const EREMCHG = 89;
pub const ENOSYS = 90;
pub const ESTRPIPE = 91;
pub const EOVERFLOW = 92;
pub const EBADFD = 93;
pub const ECHRNG = 94;
pub const EL2NSYNC = 95;
pub const EL3HLT = 96;
pub const EL3RST = 97;
pub const ELNRNG = 98;
pub const EUNATCH = 99;
pub const ENOCSI = 100;
pub const EL2HLT = 101;
pub const EBADE = 102;
pub const EBADR = 103;
pub const EXFULL = 104;
pub const ENOANO = 105;
pub const EBADRQC = 106;
pub const EBADSLT = 107;
pub const EDEADLOCK = 108;
pub const EBFONT = 109;
pub const ELIBEXEC = 110;
pub const ENODATA = 111;
pub const ELIBBAD = 112;
pub const ENOPKG = 113;
pub const ELIBACC = 114;
pub const ENOTUNIQ = 115;
pub const ERESTART = 116;
pub const EUCLEAN = 117;
pub const ENOTNAM = 118;
pub const ENAVAIL = 119;
pub const EISNAM = 120;
pub const EREMOTEIO = 121;
pub const EILSEQ = 122;
pub const ELIBMAX = 123;
pub const ELIBSCN = 124;
pub const ENOMEDIUM = 125;
pub const EMEDIUMTYPE = 126;
pub const ECANCELED = 127;
pub const ENOKEY = 128;
pub const EKEYEXPIRED = 129;
pub const EKEYREVOKED = 130;
pub const EKEYREJECTED = 131;
pub const EOWNERDEAD = 132;
pub const ENOTRECOVERABLE = 133;
pub const ERFKILL = 134;
pub const EHWPOISON = 135;
