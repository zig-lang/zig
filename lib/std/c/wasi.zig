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
