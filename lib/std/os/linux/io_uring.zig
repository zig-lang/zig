// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("../../std.zig");
const assert = std.debug.assert;
const builtin = @import("builtin");
const mem = std.mem;
const net = std.net;
const os = std.os;
const linux = os.linux;
const testing = std.testing;

const io_uring_params = linux.io_uring_params;
const io_uring_sqe = linux.io_uring_sqe;
const io_uring_cqe = linux.io_uring_cqe;

pub const IO_Uring = struct {
    fd: os.fd_t = -1,
    sq: SubmissionQueue,
    cq: CompletionQueue,
    flags: u32,
    features: u32,

    /// A friendly way to setup an io_uring, with default io_uring_params.
    /// `entries` must be a power of two between 1 and 4096, although the kernel will make the final
    /// call on how many entries the submission and completion queues will ultimately have,
    /// see https://github.com/torvalds/linux/blob/v5.8/fs/io_uring.c#L8027-L8050.
    /// Matches the interface of io_uring_queue_init() in liburing.
    pub fn init(entries: u13, flags: u32) !IO_Uring {
        var params = mem.zeroInit(io_uring_params, .{
            .flags = flags,
            .sq_thread_idle = 1000,
        });
        return try IO_Uring.init_params(entries, &params);
    }

    /// A powerful way to setup an io_uring, if you want to tweak io_uring_params such as submission
    /// queue thread cpu affinity or thread idle timeout (the kernel and our default is 1 second).
    /// `params` is passed by reference because the kernel needs to modify the parameters.
    /// Matches the interface of io_uring_queue_init_params() in liburing.
    pub fn init_params(entries: u13, p: *io_uring_params) !IO_Uring {
        if (entries == 0) return error.EntriesZero;
        if (!std.math.isPowerOfTwo(entries)) return error.EntriesNotPowerOfTwo;

        assert(p.sq_entries == 0);
        assert(p.cq_entries == 0 or p.flags & linux.IORING_SETUP_CQSIZE != 0);
        assert(p.features == 0);
        assert(p.wq_fd == 0 or p.flags & linux.IORING_SETUP_ATTACH_WQ != 0);
        assert(p.resv[0] == 0);
        assert(p.resv[1] == 0);
        assert(p.resv[2] == 0);

        const res = linux.io_uring_setup(entries, p);
        switch (linux.getErrno(res)) {
            0 => {},
            linux.EFAULT => return error.ParamsOutsideAccessibleAddressSpace,
            // The resv array contains non-zero data, p.flags contains an unsupported flag,
            // entries out of bounds, IORING_SETUP_SQ_AFF was specified without IORING_SETUP_SQPOLL,
            // or IORING_SETUP_CQSIZE was specified but io_uring_params.cq_entries was invalid:
            linux.EINVAL => return error.ArgumentsInvalid,
            linux.EMFILE => return error.ProcessFdQuotaExceeded,
            linux.ENFILE => return error.SystemFdQuotaExceeded,
            linux.ENOMEM => return error.SystemResources,
            // IORING_SETUP_SQPOLL was specified but effective user ID lacks sufficient privileges,
            // or a container seccomp policy prohibits io_uring syscalls:
            linux.EPERM => return error.PermissionDenied,
            linux.ENOSYS => return error.SystemOutdated,
            else => |errno| return os.unexpectedErrno(errno),
        }
        const fd = @intCast(os.fd_t, res);
        assert(fd >= 0);
        errdefer os.close(fd);

        // Kernel versions 5.4 and up use only one mmap() for the submission and completion queues.
        // This is not an optional feature for us... if the kernel does it, we have to do it.
        // The thinking on this by the kernel developers was that both the submission and the
        // completion queue rings have sizes just over a power of two, but the submission queue ring
        // is significantly smaller with u32 slots. By bundling both in a single mmap, the kernel
        // gets the submission queue ring for free.
        // See https://patchwork.kernel.org/patch/11115257 for the kernel patch.
        // We do not support the double mmap() done before 5.4, because we want to keep the
        // init/deinit mmap paths simple and because io_uring has had many bug fixes even since 5.4.
        if ((p.features & linux.IORING_FEAT_SINGLE_MMAP) == 0) {
            return error.SystemOutdated;
        }

        // Check that the kernel has actually set params and that "impossible is nothing".
        assert(p.sq_entries != 0);
        assert(p.cq_entries != 0);
        assert(p.cq_entries >= p.sq_entries);

        // From here on, we only need to read from params, so pass `p` by value as immutable.
        // The completion queue shares the mmap with the submission queue, so pass `sq` there too.
        var sq = try SubmissionQueue.init(fd, p.*);
        errdefer sq.deinit();
        var cq = try CompletionQueue.init(fd, p.*, sq);
        errdefer cq.deinit();

        // Check that our starting state is as we expect.
        assert(sq.head.* == 0);
        assert(sq.tail.* == 0);
        assert(sq.mask == p.sq_entries - 1);
        // Allow flags.* to be non-zero, since the kernel may set IORING_SQ_NEED_WAKEUP at any time.
        assert(sq.dropped.* == 0);
        assert(sq.array.len == p.sq_entries);
        assert(sq.sqes.len == p.sq_entries);
        assert(sq.sqe_head == 0);
        assert(sq.sqe_tail == 0);

        assert(cq.head.* == 0);
        assert(cq.tail.* == 0);
        assert(cq.mask == p.cq_entries - 1);
        assert(cq.overflow.* == 0);
        assert(cq.cqes.len == p.cq_entries);

        return IO_Uring{
            .fd = fd,
            .sq = sq,
            .cq = cq,
            .flags = p.flags,
            .features = p.features,
        };
    }

    pub fn deinit(self: *IO_Uring) void {
        assert(self.fd >= 0);
        // The mmaps depend on the fd, so the order of these calls is important:
        self.cq.deinit();
        self.sq.deinit();
        os.close(self.fd);
        self.fd = -1;
    }

    /// Returns a pointer to a vacant SQE, or an error if the submission queue is full.
    /// We follow the implementation (and atomics) of liburing's `io_uring_get_sqe()` exactly.
    /// However, instead of a null we return an error to force safe handling.
    /// Any situation where the submission queue is full tends more towards a control flow error,
    /// and the null return in liburing is more a C idiom than anything else, for lack of a better
    /// alternative. In Zig, we have first-class error handling... so let's use it.
    /// Matches the implementation of io_uring_get_sqe() in liburing.
    pub fn get_sqe(self: *IO_Uring) !*io_uring_sqe {
        const head = @atomicLoad(u32, self.sq.head, .Acquire);
        // Remember that these head and tail offsets wrap around every four billion operations.
        // We must therefore use wrapping addition and subtraction to avoid a runtime crash.
        const next = self.sq.sqe_tail +% 1;
        if (next -% head > self.sq.sqes.len) return error.SubmissionQueueFull;
        var sqe = &self.sq.sqes[self.sq.sqe_tail & self.sq.mask];
        self.sq.sqe_tail = next;
        return sqe;
    }

    /// Submits the SQEs acquired via get_sqe() to the kernel. You can call this once after you have
    /// called get_sqe() multiple times to setup multiple I/O requests.
    /// Returns the number of SQEs submitted.
    /// Matches the implementation of io_uring_submit() in liburing.
    pub fn submit(self: *IO_Uring) !u32 {
        return self.submit_and_wait(0);
    }

    /// Like submit(), but allows waiting for events as well.
    /// Returns the number of SQEs submitted.
    /// Matches the implementation of io_uring_submit_and_wait() in liburing.
    pub fn submit_and_wait(self: *IO_Uring, wait_nr: u32) !u32 {
        const submitted = self.flush_sq();
        var flags: u32 = 0;
        if (self.sq_ring_needs_enter(&flags) or wait_nr > 0) {
            if (wait_nr > 0 or (self.flags & linux.IORING_SETUP_IOPOLL) != 0) {
                flags |= linux.IORING_ENTER_GETEVENTS;
            }
            return try self.enter(submitted, wait_nr, flags);
        }
        return submitted;
    }

    /// Tell the kernel we have submitted SQEs and/or want to wait for CQEs.
    /// Returns the number of SQEs submitted.
    pub fn enter(self: *IO_Uring, to_submit: u32, min_complete: u32, flags: u32) !u32 {
        assert(self.fd >= 0);
        const res = linux.io_uring_enter(self.fd, to_submit, min_complete, flags, null);
        switch (linux.getErrno(res)) {
            0 => {},
            // The kernel was unable to allocate memory or ran out of resources for the request.
            // The application should wait for some completions and try again:
            linux.EAGAIN => return error.SystemResources,
            // The SQE `fd` is invalid, or IOSQE_FIXED_FILE was set but no files were registered:
            linux.EBADF => return error.FileDescriptorInvalid,
            // The file descriptor is valid, but the ring is not in the right state.
            // See io_uring_register(2) for how to enable the ring.
            linux.EBADFD => return error.FileDescriptorInBadState,
            // The application attempted to overcommit the number of requests it can have pending.
            // The application should wait for some completions and try again:
            linux.EBUSY => return error.CompletionQueueOvercommitted,
            // The SQE is invalid, or valid but the ring was setup with IORING_SETUP_IOPOLL:
            linux.EINVAL => return error.SubmissionQueueEntryInvalid,
            // The buffer is outside the process' accessible address space, or IORING_OP_READ_FIXED
            // or IORING_OP_WRITE_FIXED was specified but no buffers were registered, or the range
            // described by `addr` and `len` is not within the buffer registered at `buf_index`:
            linux.EFAULT => return error.BufferInvalid,
            linux.ENXIO => return error.RingShuttingDown,
            // The kernel believes our `self.fd` does not refer to an io_uring instance,
            // or the opcode is valid but not supported by this kernel (more likely):
            linux.EOPNOTSUPP => return error.OpcodeNotSupported,
            // The operation was interrupted by a delivery of a signal before it could complete.
            // This can happen while waiting for events with IORING_ENTER_GETEVENTS:
            linux.EINTR => return error.SignalInterrupt,
            else => |errno| return os.unexpectedErrno(errno),
        }
        return @intCast(u32, res);
    }

    /// Sync internal state with kernel ring state on the SQ side.
    /// Returns the number of all pending events in the SQ ring, for the shared ring.
    /// This return value includes previously flushed SQEs, as per liburing.
    /// The rationale is to suggest that an io_uring_enter() call is needed rather than not.
    /// Matches the implementation of __io_uring_flush_sq() in liburing.
    pub fn flush_sq(self: *IO_Uring) u32 {
        if (self.sq.sqe_head != self.sq.sqe_tail) {
            // Fill in SQEs that we have queued up, adding them to the kernel ring.
            const to_submit = self.sq.sqe_tail -% self.sq.sqe_head;
            var tail = self.sq.tail.*;
            var i: usize = 0;
            while (i < to_submit) : (i += 1) {
                self.sq.array[tail & self.sq.mask] = self.sq.sqe_head & self.sq.mask;
                tail +%= 1;
                self.sq.sqe_head +%= 1;
            }
            // Ensure that the kernel can actually see the SQE updates when it sees the tail update.
            @atomicStore(u32, self.sq.tail, tail, .Release);
        }
        return self.sq_ready();
    }

    /// Returns true if we are not using an SQ thread (thus nobody submits but us),
    /// or if IORING_SQ_NEED_WAKEUP is set and the SQ thread must be explicitly awakened.
    /// For the latter case, we set the SQ thread wakeup flag.
    /// Matches the implementation of sq_ring_needs_enter() in liburing.
    pub fn sq_ring_needs_enter(self: *IO_Uring, flags: *u32) bool {
        assert(flags.* == 0);
        if ((self.flags & linux.IORING_SETUP_SQPOLL) == 0) return true;
        if ((@atomicLoad(u32, self.sq.flags, .Unordered) & linux.IORING_SQ_NEED_WAKEUP) != 0) {
            flags.* |= linux.IORING_ENTER_SQ_WAKEUP;
            return true;
        }
        return false;
    }

    /// Returns the number of flushed and unflushed SQEs pending in the submission queue.
    /// In other words, this is the number of SQEs in the submission queue, i.e. its length.
    /// These are SQEs that the kernel is yet to consume.
    /// Matches the implementation of io_uring_sq_ready in liburing.
    pub fn sq_ready(self: *IO_Uring) u32 {
        // Always use the shared ring state (i.e. head and not sqe_head) to avoid going out of sync,
        // see https://github.com/axboe/liburing/issues/92.
        return self.sq.sqe_tail -% @atomicLoad(u32, self.sq.head, .Acquire);
    }

    /// Returns the number of CQEs in the completion queue, i.e. its length.
    /// These are CQEs that the application is yet to consume.
    /// Matches the implementation of io_uring_cq_ready in liburing.
    pub fn cq_ready(self: *IO_Uring) u32 {
        return @atomicLoad(u32, self.cq.tail, .Acquire) -% self.cq.head.*;
    }

    /// Copies as many CQEs as are ready, and that can fit into the destination `cqes` slice.
    /// If none are available, enters into the kernel to wait for at most `wait_nr` CQEs.
    /// Returns the number of CQEs copied, advancing the CQ ring.
    /// Provides all the wait/peek methods found in liburing, but with batching and a single method.
    /// The rationale for copying CQEs rather than copying pointers is that pointers are 8 bytes
    /// whereas CQEs are not much more at only 16 bytes, and this provides a safer faster interface.
    /// Safer, because you no longer need to call cqe_seen(), avoiding idempotency bugs.
    /// Faster, because we can now amortize the atomic store release to `cq.head` across the batch.
    /// See https://github.com/axboe/liburing/issues/103#issuecomment-686665007.
    /// Matches the implementation of io_uring_peek_batch_cqe() in liburing, but supports waiting.
    pub fn copy_cqes(self: *IO_Uring, cqes: []io_uring_cqe, wait_nr: u32) !u32 {
        const count = self.copy_cqes_ready(cqes, wait_nr);
        if (count > 0) return count;
        if (self.cq_ring_needs_flush() or wait_nr > 0) {
            _ = try self.enter(0, wait_nr, linux.IORING_ENTER_GETEVENTS);
            return self.copy_cqes_ready(cqes, wait_nr);
        }
        return 0;
    }

    fn copy_cqes_ready(self: *IO_Uring, cqes: []io_uring_cqe, wait_nr: u32) u32 {
        _ = wait_nr;
        const ready = self.cq_ready();
        const count = std.math.min(cqes.len, ready);
        var head = self.cq.head.*;
        var tail = head +% count;
        // TODO Optimize this by using 1 or 2 memcpy's (if the tail wraps) rather than a loop.
        var i: usize = 0;
        // Do not use "less-than" operator since head and tail may wrap:
        while (head != tail) {
            cqes[i] = self.cq.cqes[head & self.cq.mask]; // Copy struct by value.
            head +%= 1;
            i += 1;
        }
        self.cq_advance(count);
        return count;
    }

    /// Returns a copy of an I/O completion, waiting for it if necessary, and advancing the CQ ring.
    /// A convenience method for `copy_cqes()` for when you don't need to batch or peek.
    pub fn copy_cqe(ring: *IO_Uring) !io_uring_cqe {
        var cqes: [1]io_uring_cqe = undefined;
        const count = try ring.copy_cqes(&cqes, 1);
        assert(count == 1);
        return cqes[0];
    }

    /// Matches the implementation of cq_ring_needs_flush() in liburing.
    pub fn cq_ring_needs_flush(self: *IO_Uring) bool {
        return (@atomicLoad(u32, self.sq.flags, .Unordered) & linux.IORING_SQ_CQ_OVERFLOW) != 0;
    }

    /// For advanced use cases only that implement custom completion queue methods.
    /// If you use copy_cqes() or copy_cqe() you must not call cqe_seen() or cq_advance().
    /// Must be called exactly once after a zero-copy CQE has been processed by your application.
    /// Not idempotent, calling more than once will result in other CQEs being lost.
    /// Matches the implementation of cqe_seen() in liburing.
    pub fn cqe_seen(self: *IO_Uring, cqe: *io_uring_cqe) void {
        _ = cqe;
        self.cq_advance(1);
    }

    /// For advanced use cases only that implement custom completion queue methods.
    /// Matches the implementation of cq_advance() in liburing.
    pub fn cq_advance(self: *IO_Uring, count: u32) void {
        if (count > 0) {
            // Ensure the kernel only sees the new head value after the CQEs have been read.
            @atomicStore(u32, self.cq.head, self.cq.head.* +% count, .Release);
        }
    }

    /// Queues (but does not submit) an SQE to perform an `fsync(2)`.
    /// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
    /// For example, for `fdatasync()` you can set `IORING_FSYNC_DATASYNC` in the SQE's `rw_flags`.
    /// N.B. While SQEs are initiated in the order in which they appear in the submission queue,
    /// operations execute in parallel and completions are unordered. Therefore, an application that
    /// submits a write followed by an fsync in the submission queue cannot expect the fsync to
    /// apply to the write, since the fsync may complete before the write is issued to the disk.
    /// You should preferably use `link_with_next_sqe()` on a write's SQE to link it with an fsync,
    /// or else insert a full write barrier using `drain_previous_sqes()` when queueing an fsync.
    pub fn fsync(self: *IO_Uring, user_data: u64, fd: os.fd_t, flags: u32) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_fsync(sqe, fd, flags);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a no-op.
    /// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
    /// A no-op is more useful than may appear at first glance.
    /// For example, you could call `drain_previous_sqes()` on the returned SQE, to use the no-op to
    /// know when the ring is idle before acting on a kill signal.
    pub fn nop(self: *IO_Uring, user_data: u64) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_nop(sqe);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `read(2)`.
    /// Returns a pointer to the SQE.
    pub fn read(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        buffer: []u8,
        offset: u64,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_read(sqe, fd, buffer, offset);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `write(2)`.
    /// Returns a pointer to the SQE.
    pub fn write(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        buffer: []const u8,
        offset: u64,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_write(sqe, fd, buffer, offset);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `preadv()`.
    /// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
    /// For example, if you want to do a `preadv2()` then set `rw_flags` on the returned SQE.
    /// See https://linux.die.net/man/2/preadv.
    pub fn readv(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        iovecs: []const os.iovec,
        offset: u64,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_readv(sqe, fd, iovecs, offset);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `pwritev()`.
    /// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
    /// For example, if you want to do a `pwritev2()` then set `rw_flags` on the returned SQE.
    /// See https://linux.die.net/man/2/pwritev.
    pub fn writev(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        iovecs: []const os.iovec_const,
        offset: u64,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_writev(sqe, fd, iovecs, offset);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform an `accept4(2)` on a socket.
    /// Returns a pointer to the SQE.
    pub fn accept(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        addr: *os.sockaddr,
        addrlen: *os.socklen_t,
        flags: u32,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_accept(sqe, fd, addr, addrlen, flags);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queue (but does not submit) an SQE to perform a `connect(2)` on a socket.
    /// Returns a pointer to the SQE.
    pub fn connect(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        addr: *const os.sockaddr,
        addrlen: os.socklen_t,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_connect(sqe, fd, addr, addrlen);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `epoll_ctl(2)`.
    /// Returns a pointer to the SQE.
    pub fn epoll_ctl(
        self: *IO_Uring,
        user_data: u64,
        epfd: os.fd_t,
        fd: os.fd_t,
        op: u32,
        ev: ?*linux.epoll_event,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_epoll_ctl(sqe, epfd, fd, op, ev);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `recv(2)`.
    /// Returns a pointer to the SQE.
    pub fn recv(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        buffer: []u8,
        flags: u32,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_recv(sqe, fd, buffer, flags);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `send(2)`.
    /// Returns a pointer to the SQE.
    pub fn send(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        buffer: []const u8,
        flags: u32,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_send(sqe, fd, buffer, flags);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform an `openat(2)`.
    /// Returns a pointer to the SQE.
    pub fn openat(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        path: [*:0]const u8,
        flags: u32,
        mode: os.mode_t,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_openat(sqe, fd, path, flags, mode);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `close(2)`.
    /// Returns a pointer to the SQE.
    pub fn close(self: *IO_Uring, user_data: u64, fd: os.fd_t) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_close(sqe, fd);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to register a timeout operation.
    /// Returns a pointer to the SQE.
    ///
    /// The timeout will complete when either the timeout expires, or after the specified number of
    /// events complete (if `count` is greater than `0`).
    ///
    /// `flags` may be `0` for a relative timeout, or `IORING_TIMEOUT_ABS` for an absolute timeout.
    ///
    /// The completion event result will be `-ETIME` if the timeout completed through expiration,
    /// `0` if the timeout completed after the specified number of events, or `-ECANCELED` if the
    /// timeout was removed before it expired.
    ///
    /// io_uring timeouts use the `CLOCK_MONOTONIC` clock source.
    pub fn timeout(
        self: *IO_Uring,
        user_data: u64,
        ts: *const os.__kernel_timespec,
        count: u32,
        flags: u32,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_timeout(sqe, ts, count, flags);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to remove an existing timeout operation.
    /// Returns a pointer to the SQE.
    ///
    /// The timeout is identified by its `user_data`.
    ///
    /// The completion event result will be `0` if the timeout was found and cancelled successfully,
    /// `-EBUSY` if the timeout was found but expiration was already in progress, or
    /// `-ENOENT` if the timeout was not found.
    pub fn timeout_remove(
        self: *IO_Uring,
        user_data: u64,
        timeout_user_data: u64,
        flags: u32,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_timeout_remove(sqe, timeout_user_data, flags);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform a `poll(2)`.
    /// Returns a pointer to the SQE.
    pub fn poll_add(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        poll_mask: u32,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_poll_add(sqe, fd, poll_mask);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to remove an existing poll operation.
    /// Returns a pointer to the SQE.
    pub fn poll_remove(
        self: *IO_Uring,
        user_data: u64,
        target_user_data: u64,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_poll_remove(sqe, target_user_data);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Queues (but does not submit) an SQE to perform an `fallocate(2)`.
    /// Returns a pointer to the SQE.
    pub fn fallocate(
        self: *IO_Uring,
        user_data: u64,
        fd: os.fd_t,
        mode: i32,
        offset: u64,
        len: u64,
    ) !*io_uring_sqe {
        const sqe = try self.get_sqe();
        io_uring_prep_fallocate(sqe, fd, mode, offset, len);
        sqe.user_data = user_data;
        return sqe;
    }

    /// Registers an array of file descriptors.
    /// Every time a file descriptor is put in an SQE and submitted to the kernel, the kernel must
    /// retrieve a reference to the file, and once I/O has completed the file reference must be
    /// dropped. The atomic nature of this file reference can be a slowdown for high IOPS workloads.
    /// This slowdown can be avoided by pre-registering file descriptors.
    /// To refer to a registered file descriptor, IOSQE_FIXED_FILE must be set in the SQE's flags,
    /// and the SQE's fd must be set to the index of the file descriptor in the registered array.
    /// Registering file descriptors will wait for the ring to idle.
    /// Files are automatically unregistered by the kernel when the ring is torn down.
    /// An application need unregister only if it wants to register a new array of file descriptors.
    pub fn register_files(self: *IO_Uring, fds: []const os.fd_t) !void {
        assert(self.fd >= 0);
        comptime assert(@sizeOf(os.fd_t) == @sizeOf(c_int));
        const res = linux.io_uring_register(
            self.fd,
            .REGISTER_FILES,
            @ptrCast(*const c_void, fds.ptr),
            @intCast(u32, fds.len),
        );
        switch (linux.getErrno(res)) {
            0 => {},
            // One or more fds in the array are invalid, or the kernel does not support sparse sets:
            linux.EBADF => return error.FileDescriptorInvalid,
            linux.EBUSY => return error.FilesAlreadyRegistered,
            linux.EINVAL => return error.FilesEmpty,
            // Adding `nr_args` file references would exceed the maximum allowed number of files the
            // user is allowed to have according to the per-user RLIMIT_NOFILE resource limit and
            // the CAP_SYS_RESOURCE capability is not set, or `nr_args` exceeds the maximum allowed
            // for a fixed file set (older kernels have a limit of 1024 files vs 64K files):
            linux.EMFILE => return error.UserFdQuotaExceeded,
            // Insufficient kernel resources, or the caller had a non-zero RLIMIT_MEMLOCK soft
            // resource limit but tried to lock more memory than the limit permitted (not enforced
            // when the process is privileged with CAP_IPC_LOCK):
            linux.ENOMEM => return error.SystemResources,
            // Attempt to register files on a ring already registering files or being torn down:
            linux.ENXIO => return error.RingShuttingDownOrAlreadyRegisteringFiles,
            else => |errno| return os.unexpectedErrno(errno),
        }
    }

    /// Unregisters all registered file descriptors previously associated with the ring.
    pub fn unregister_files(self: *IO_Uring) !void {
        assert(self.fd >= 0);
        const res = linux.io_uring_register(self.fd, .UNREGISTER_FILES, null, 0);
        switch (linux.getErrno(res)) {
            0 => {},
            linux.ENXIO => return error.FilesNotRegistered,
            else => |errno| return os.unexpectedErrno(errno),
        }
    }
};

pub const SubmissionQueue = struct {
    head: *u32,
    tail: *u32,
    mask: u32,
    flags: *u32,
    dropped: *u32,
    array: []u32,
    sqes: []io_uring_sqe,
    mmap: []align(mem.page_size) u8,
    mmap_sqes: []align(mem.page_size) u8,

    // We use `sqe_head` and `sqe_tail` in the same way as liburing:
    // We increment `sqe_tail` (but not `tail`) for each call to `get_sqe()`.
    // We then set `tail` to `sqe_tail` once, only when these events are actually submitted.
    // This allows us to amortize the cost of the @atomicStore to `tail` across multiple SQEs.
    sqe_head: u32 = 0,
    sqe_tail: u32 = 0,

    pub fn init(fd: os.fd_t, p: io_uring_params) !SubmissionQueue {
        assert(fd >= 0);
        assert((p.features & linux.IORING_FEAT_SINGLE_MMAP) != 0);
        const size = std.math.max(
            p.sq_off.array + p.sq_entries * @sizeOf(u32),
            p.cq_off.cqes + p.cq_entries * @sizeOf(io_uring_cqe),
        );
        const mmap = try os.mmap(
            null,
            size,
            os.PROT_READ | os.PROT_WRITE,
            os.MAP_SHARED | os.MAP_POPULATE,
            fd,
            linux.IORING_OFF_SQ_RING,
        );
        errdefer os.munmap(mmap);
        assert(mmap.len == size);

        // The motivation for the `sqes` and `array` indirection is to make it possible for the
        // application to preallocate static io_uring_sqe entries and then replay them when needed.
        const size_sqes = p.sq_entries * @sizeOf(io_uring_sqe);
        const mmap_sqes = try os.mmap(
            null,
            size_sqes,
            os.PROT_READ | os.PROT_WRITE,
            os.MAP_SHARED | os.MAP_POPULATE,
            fd,
            linux.IORING_OFF_SQES,
        );
        errdefer os.munmap(mmap_sqes);
        assert(mmap_sqes.len == size_sqes);

        const array = @ptrCast([*]u32, @alignCast(@alignOf(u32), &mmap[p.sq_off.array]));
        const sqes = @ptrCast([*]io_uring_sqe, @alignCast(@alignOf(io_uring_sqe), &mmap_sqes[0]));
        // We expect the kernel copies p.sq_entries to the u32 pointed to by p.sq_off.ring_entries,
        // see https://github.com/torvalds/linux/blob/v5.8/fs/io_uring.c#L7843-L7844.
        assert(
            p.sq_entries ==
                @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.sq_off.ring_entries])).*,
        );
        return SubmissionQueue{
            .head = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.sq_off.head])),
            .tail = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.sq_off.tail])),
            .mask = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.sq_off.ring_mask])).*,
            .flags = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.sq_off.flags])),
            .dropped = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.sq_off.dropped])),
            .array = array[0..p.sq_entries],
            .sqes = sqes[0..p.sq_entries],
            .mmap = mmap,
            .mmap_sqes = mmap_sqes,
        };
    }

    pub fn deinit(self: *SubmissionQueue) void {
        os.munmap(self.mmap_sqes);
        os.munmap(self.mmap);
    }
};

pub const CompletionQueue = struct {
    head: *u32,
    tail: *u32,
    mask: u32,
    overflow: *u32,
    cqes: []io_uring_cqe,

    pub fn init(fd: os.fd_t, p: io_uring_params, sq: SubmissionQueue) !CompletionQueue {
        assert(fd >= 0);
        assert((p.features & linux.IORING_FEAT_SINGLE_MMAP) != 0);
        const mmap = sq.mmap;
        const cqes = @ptrCast(
            [*]io_uring_cqe,
            @alignCast(@alignOf(io_uring_cqe), &mmap[p.cq_off.cqes]),
        );
        assert(p.cq_entries ==
            @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.cq_off.ring_entries])).*);
        return CompletionQueue{
            .head = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.cq_off.head])),
            .tail = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.cq_off.tail])),
            .mask = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.cq_off.ring_mask])).*,
            .overflow = @ptrCast(*u32, @alignCast(@alignOf(u32), &mmap[p.cq_off.overflow])),
            .cqes = cqes[0..p.cq_entries],
        };
    }

    pub fn deinit(self: *CompletionQueue) void {
        _ = self;
        // A no-op since we now share the mmap with the submission queue.
        // Here for symmetry with the submission queue, and for any future feature support.
    }
};

pub fn io_uring_prep_nop(sqe: *io_uring_sqe) void {
    sqe.* = .{
        .opcode = .NOP,
        .flags = 0,
        .ioprio = 0,
        .fd = 0,
        .off = 0,
        .addr = 0,
        .len = 0,
        .rw_flags = 0,
        .user_data = 0,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    };
}

pub fn io_uring_prep_fsync(sqe: *io_uring_sqe, fd: os.fd_t, flags: u32) void {
    sqe.* = .{
        .opcode = .FSYNC,
        .flags = 0,
        .ioprio = 0,
        .fd = fd,
        .off = 0,
        .addr = 0,
        .len = 0,
        .rw_flags = flags,
        .user_data = 0,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    };
}

pub fn io_uring_prep_rw(
    op: linux.IORING_OP,
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    addr: u64,
    len: usize,
    offset: u64,
) void {
    sqe.* = .{
        .opcode = op,
        .flags = 0,
        .ioprio = 0,
        .fd = fd,
        .off = offset,
        .addr = addr,
        .len = @intCast(u32, len),
        .rw_flags = 0,
        .user_data = 0,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    };
}

pub fn io_uring_prep_read(sqe: *io_uring_sqe, fd: os.fd_t, buffer: []u8, offset: u64) void {
    io_uring_prep_rw(.READ, sqe, fd, @ptrToInt(buffer.ptr), buffer.len, offset);
}

pub fn io_uring_prep_write(sqe: *io_uring_sqe, fd: os.fd_t, buffer: []const u8, offset: u64) void {
    io_uring_prep_rw(.WRITE, sqe, fd, @ptrToInt(buffer.ptr), buffer.len, offset);
}

pub fn io_uring_prep_readv(
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    iovecs: []const os.iovec,
    offset: u64,
) void {
    io_uring_prep_rw(.READV, sqe, fd, @ptrToInt(iovecs.ptr), iovecs.len, offset);
}

pub fn io_uring_prep_writev(
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    iovecs: []const os.iovec_const,
    offset: u64,
) void {
    io_uring_prep_rw(.WRITEV, sqe, fd, @ptrToInt(iovecs.ptr), iovecs.len, offset);
}

pub fn io_uring_prep_accept(
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    addr: *os.sockaddr,
    addrlen: *os.socklen_t,
    flags: u32,
) void {
    // `addr` holds a pointer to `sockaddr`, and `addr2` holds a pointer to socklen_t`.
    // `addr2` maps to `sqe.off` (u64) instead of `sqe.len` (which is only a u32).
    io_uring_prep_rw(.ACCEPT, sqe, fd, @ptrToInt(addr), 0, @ptrToInt(addrlen));
    sqe.rw_flags = flags;
}

pub fn io_uring_prep_connect(
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    addr: *const os.sockaddr,
    addrlen: os.socklen_t,
) void {
    // `addrlen` maps to `sqe.off` (u64) instead of `sqe.len` (which is only a u32).
    io_uring_prep_rw(.CONNECT, sqe, fd, @ptrToInt(addr), 0, addrlen);
}

pub fn io_uring_prep_epoll_ctl(
    sqe: *io_uring_sqe,
    epfd: os.fd_t,
    fd: os.fd_t,
    op: u32,
    ev: ?*linux.epoll_event,
) void {
    io_uring_prep_rw(.EPOLL_CTL, sqe, epfd, @ptrToInt(ev), op, @intCast(u64, fd));
}

pub fn io_uring_prep_recv(sqe: *io_uring_sqe, fd: os.fd_t, buffer: []u8, flags: u32) void {
    io_uring_prep_rw(.RECV, sqe, fd, @ptrToInt(buffer.ptr), buffer.len, 0);
    sqe.rw_flags = flags;
}

pub fn io_uring_prep_send(sqe: *io_uring_sqe, fd: os.fd_t, buffer: []const u8, flags: u32) void {
    io_uring_prep_rw(.SEND, sqe, fd, @ptrToInt(buffer.ptr), buffer.len, 0);
    sqe.rw_flags = flags;
}

pub fn io_uring_prep_openat(
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    path: [*:0]const u8,
    flags: u32,
    mode: os.mode_t,
) void {
    io_uring_prep_rw(.OPENAT, sqe, fd, @ptrToInt(path), mode, 0);
    sqe.rw_flags = flags;
}

pub fn io_uring_prep_close(sqe: *io_uring_sqe, fd: os.fd_t) void {
    sqe.* = .{
        .opcode = .CLOSE,
        .flags = 0,
        .ioprio = 0,
        .fd = fd,
        .off = 0,
        .addr = 0,
        .len = 0,
        .rw_flags = 0,
        .user_data = 0,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    };
}

pub fn io_uring_prep_timeout(
    sqe: *io_uring_sqe,
    ts: *const os.__kernel_timespec,
    count: u32,
    flags: u32,
) void {
    io_uring_prep_rw(.TIMEOUT, sqe, -1, @ptrToInt(ts), 1, count);
    sqe.rw_flags = flags;
}

pub fn io_uring_prep_timeout_remove(sqe: *io_uring_sqe, timeout_user_data: u64, flags: u32) void {
    sqe.* = .{
        .opcode = .TIMEOUT_REMOVE,
        .flags = 0,
        .ioprio = 0,
        .fd = -1,
        .off = 0,
        .addr = timeout_user_data,
        .len = 0,
        .rw_flags = flags,
        .user_data = 0,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    };
}

pub fn io_uring_prep_poll_add(
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    poll_mask: u32,
) void {
    io_uring_prep_rw(.POLL_ADD, sqe, fd, @ptrToInt(@as(?*c_void, null)), 0, 0);
    sqe.rw_flags = std.mem.nativeToLittle(u32, poll_mask);
}

pub fn io_uring_prep_poll_remove(
    sqe: *io_uring_sqe,
    target_user_data: u64,
) void {
    io_uring_prep_rw(.POLL_REMOVE, sqe, -1, target_user_data, 0, 0);
}

pub fn io_uring_prep_fallocate(
    sqe: *io_uring_sqe,
    fd: os.fd_t,
    mode: i32,
    offset: u64,
    len: u64,
) void {
    sqe.* = .{
        .opcode = .FALLOCATE,
        .flags = 0,
        .ioprio = 0,
        .fd = fd,
        .off = offset,
        .addr = len,
        .len = @intCast(u32, mode),
        .rw_flags = 0,
        .user_data = 0,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    };
}

test "structs/offsets/entries" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    try testing.expectEqual(@as(usize, 120), @sizeOf(io_uring_params));
    try testing.expectEqual(@as(usize, 64), @sizeOf(io_uring_sqe));
    try testing.expectEqual(@as(usize, 16), @sizeOf(io_uring_cqe));

    try testing.expectEqual(0, linux.IORING_OFF_SQ_RING);
    try testing.expectEqual(0x8000000, linux.IORING_OFF_CQ_RING);
    try testing.expectEqual(0x10000000, linux.IORING_OFF_SQES);

    try testing.expectError(error.EntriesZero, IO_Uring.init(0, 0));
    try testing.expectError(error.EntriesNotPowerOfTwo, IO_Uring.init(3, 0));
}

test "nop" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer {
        ring.deinit();
        testing.expectEqual(@as(os.fd_t, -1), ring.fd) catch @panic("test failed");
    }

    const sqe = try ring.nop(0xaaaaaaaa);
    try testing.expectEqual(io_uring_sqe{
        .opcode = .NOP,
        .flags = 0,
        .ioprio = 0,
        .fd = 0,
        .off = 0,
        .addr = 0,
        .len = 0,
        .rw_flags = 0,
        .user_data = 0xaaaaaaaa,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    }, sqe.*);

    try testing.expectEqual(@as(u32, 0), ring.sq.sqe_head);
    try testing.expectEqual(@as(u32, 1), ring.sq.sqe_tail);
    try testing.expectEqual(@as(u32, 0), ring.sq.tail.*);
    try testing.expectEqual(@as(u32, 0), ring.cq.head.*);
    try testing.expectEqual(@as(u32, 1), ring.sq_ready());
    try testing.expectEqual(@as(u32, 0), ring.cq_ready());

    try testing.expectEqual(@as(u32, 1), try ring.submit());
    try testing.expectEqual(@as(u32, 1), ring.sq.sqe_head);
    try testing.expectEqual(@as(u32, 1), ring.sq.sqe_tail);
    try testing.expectEqual(@as(u32, 1), ring.sq.tail.*);
    try testing.expectEqual(@as(u32, 0), ring.cq.head.*);
    try testing.expectEqual(@as(u32, 0), ring.sq_ready());

    try testing.expectEqual(io_uring_cqe{
        .user_data = 0xaaaaaaaa,
        .res = 0,
        .flags = 0,
    }, try ring.copy_cqe());
    try testing.expectEqual(@as(u32, 1), ring.cq.head.*);
    try testing.expectEqual(@as(u32, 0), ring.cq_ready());

    const sqe_barrier = try ring.nop(0xbbbbbbbb);
    sqe_barrier.flags |= linux.IOSQE_IO_DRAIN;
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    try testing.expectEqual(io_uring_cqe{
        .user_data = 0xbbbbbbbb,
        .res = 0,
        .flags = 0,
    }, try ring.copy_cqe());
    try testing.expectEqual(@as(u32, 2), ring.sq.sqe_head);
    try testing.expectEqual(@as(u32, 2), ring.sq.sqe_tail);
    try testing.expectEqual(@as(u32, 2), ring.sq.tail.*);
    try testing.expectEqual(@as(u32, 2), ring.cq.head.*);
}

test "readv" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const fd = try os.openZ("/dev/zero", os.O_RDONLY | os.O_CLOEXEC, 0);
    defer os.close(fd);

    // Linux Kernel 5.4 supports IORING_REGISTER_FILES but not sparse fd sets (i.e. an fd of -1).
    // Linux Kernel 5.5 adds support for sparse fd sets.
    // Compare:
    // https://github.com/torvalds/linux/blob/v5.4/fs/io_uring.c#L3119-L3124 vs
    // https://github.com/torvalds/linux/blob/v5.8/fs/io_uring.c#L6687-L6691
    // We therefore avoid stressing sparse fd sets here:
    var registered_fds = [_]os.fd_t{0} ** 1;
    const fd_index = 0;
    registered_fds[fd_index] = fd;
    try ring.register_files(registered_fds[0..]);

    var buffer = [_]u8{42} ** 128;
    var iovecs = [_]os.iovec{os.iovec{ .iov_base = &buffer, .iov_len = buffer.len }};
    const sqe = try ring.readv(0xcccccccc, fd_index, iovecs[0..], 0);
    try testing.expectEqual(linux.IORING_OP.READV, sqe.opcode);
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    try testing.expectError(error.SubmissionQueueFull, ring.nop(0));
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xcccccccc,
        .res = buffer.len,
        .flags = 0,
    }, try ring.copy_cqe());
    try testing.expectEqualSlices(u8, &([_]u8{0} ** buffer.len), buffer[0..]);

    try ring.unregister_files();
}

test "writev/fsync/readv" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(4, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const path = "test_io_uring_writev_fsync_readv";
    const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = true });
    defer file.close();
    defer std.fs.cwd().deleteFile(path) catch {};
    const fd = file.handle;

    const buffer_write = [_]u8{42} ** 128;
    const iovecs_write = [_]os.iovec_const{
        os.iovec_const{ .iov_base = &buffer_write, .iov_len = buffer_write.len },
    };
    var buffer_read = [_]u8{0} ** 128;
    var iovecs_read = [_]os.iovec{
        os.iovec{ .iov_base = &buffer_read, .iov_len = buffer_read.len },
    };

    const sqe_writev = try ring.writev(0xdddddddd, fd, iovecs_write[0..], 17);
    try testing.expectEqual(linux.IORING_OP.WRITEV, sqe_writev.opcode);
    try testing.expectEqual(@as(u64, 17), sqe_writev.off);
    sqe_writev.flags |= linux.IOSQE_IO_LINK;

    const sqe_fsync = try ring.fsync(0xeeeeeeee, fd, 0);
    try testing.expectEqual(linux.IORING_OP.FSYNC, sqe_fsync.opcode);
    try testing.expectEqual(fd, sqe_fsync.fd);
    sqe_fsync.flags |= linux.IOSQE_IO_LINK;

    const sqe_readv = try ring.readv(0xffffffff, fd, iovecs_read[0..], 17);
    try testing.expectEqual(linux.IORING_OP.READV, sqe_readv.opcode);
    try testing.expectEqual(@as(u64, 17), sqe_readv.off);

    try testing.expectEqual(@as(u32, 3), ring.sq_ready());
    try testing.expectEqual(@as(u32, 3), try ring.submit_and_wait(3));
    try testing.expectEqual(@as(u32, 0), ring.sq_ready());
    try testing.expectEqual(@as(u32, 3), ring.cq_ready());

    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xdddddddd,
        .res = buffer_write.len,
        .flags = 0,
    }, try ring.copy_cqe());
    try testing.expectEqual(@as(u32, 2), ring.cq_ready());

    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xeeeeeeee,
        .res = 0,
        .flags = 0,
    }, try ring.copy_cqe());
    try testing.expectEqual(@as(u32, 1), ring.cq_ready());

    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xffffffff,
        .res = buffer_read.len,
        .flags = 0,
    }, try ring.copy_cqe());
    try testing.expectEqual(@as(u32, 0), ring.cq_ready());

    try testing.expectEqualSlices(u8, buffer_write[0..], buffer_read[0..]);
}

test "write/read" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(2, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const path = "test_io_uring_write_read";
    const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = true });
    defer file.close();
    defer std.fs.cwd().deleteFile(path) catch {};
    const fd = file.handle;

    const buffer_write = [_]u8{97} ** 20;
    var buffer_read = [_]u8{98} ** 20;
    const sqe_write = try ring.write(0x11111111, fd, buffer_write[0..], 10);
    try testing.expectEqual(linux.IORING_OP.WRITE, sqe_write.opcode);
    try testing.expectEqual(@as(u64, 10), sqe_write.off);
    sqe_write.flags |= linux.IOSQE_IO_LINK;
    const sqe_read = try ring.read(0x22222222, fd, buffer_read[0..], 10);
    try testing.expectEqual(linux.IORING_OP.READ, sqe_read.opcode);
    try testing.expectEqual(@as(u64, 10), sqe_read.off);
    try testing.expectEqual(@as(u32, 2), try ring.submit());

    const cqe_write = try ring.copy_cqe();
    const cqe_read = try ring.copy_cqe();
    // Prior to Linux Kernel 5.6 this is the only way to test for read/write support:
    // https://lwn.net/Articles/809820/
    if (cqe_write.res == -linux.EINVAL) return error.SkipZigTest;
    if (cqe_read.res == -linux.EINVAL) return error.SkipZigTest;
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x11111111,
        .res = buffer_write.len,
        .flags = 0,
    }, cqe_write);
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x22222222,
        .res = buffer_read.len,
        .flags = 0,
    }, cqe_read);
    try testing.expectEqualSlices(u8, buffer_write[0..], buffer_read[0..]);
}

test "openat" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const path = "test_io_uring_openat";
    defer std.fs.cwd().deleteFile(path) catch {};

    const flags: u32 = os.O_CLOEXEC | os.O_RDWR | os.O_CREAT;
    const mode: os.mode_t = 0o666;
    const sqe_openat = try ring.openat(0x33333333, linux.AT_FDCWD, path, flags, mode);
    try testing.expectEqual(io_uring_sqe{
        .opcode = .OPENAT,
        .flags = 0,
        .ioprio = 0,
        .fd = linux.AT_FDCWD,
        .off = 0,
        .addr = @ptrToInt(path),
        .len = mode,
        .rw_flags = flags,
        .user_data = 0x33333333,
        .buf_index = 0,
        .personality = 0,
        .splice_fd_in = 0,
        .__pad2 = [2]u64{ 0, 0 },
    }, sqe_openat.*);
    try testing.expectEqual(@as(u32, 1), try ring.submit());

    const cqe_openat = try ring.copy_cqe();
    try testing.expectEqual(@as(u64, 0x33333333), cqe_openat.user_data);
    if (cqe_openat.res == -linux.EINVAL) return error.SkipZigTest;
    // AT_FDCWD is not fully supported before kernel 5.6:
    // See https://lore.kernel.org/io-uring/20200207155039.12819-1-axboe@kernel.dk/T/
    // We use IORING_FEAT_RW_CUR_POS to know if we are pre-5.6 since that feature was added in 5.6.
    if (cqe_openat.res == -linux.EBADF and (ring.features & linux.IORING_FEAT_RW_CUR_POS) == 0) {
        return error.SkipZigTest;
    }
    if (cqe_openat.res <= 0) std.debug.print("\ncqe_openat.res={}\n", .{cqe_openat.res});
    try testing.expect(cqe_openat.res > 0);
    try testing.expectEqual(@as(u32, 0), cqe_openat.flags);

    os.close(cqe_openat.res);
}

test "close" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const path = "test_io_uring_close";
    const file = try std.fs.cwd().createFile(path, .{});
    errdefer file.close();
    defer std.fs.cwd().deleteFile(path) catch {};

    const sqe_close = try ring.close(0x44444444, file.handle);
    try testing.expectEqual(linux.IORING_OP.CLOSE, sqe_close.opcode);
    try testing.expectEqual(file.handle, sqe_close.fd);
    try testing.expectEqual(@as(u32, 1), try ring.submit());

    const cqe_close = try ring.copy_cqe();
    if (cqe_close.res == -linux.EINVAL) return error.SkipZigTest;
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x44444444,
        .res = 0,
        .flags = 0,
    }, cqe_close);
}

test "accept/connect/send/recv" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(16, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const address = try net.Address.parseIp4("127.0.0.1", 3131);
    const kernel_backlog = 1;
    const server = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
    defer os.close(server);
    try os.setsockopt(server, os.SOL_SOCKET, os.SO_REUSEADDR, &mem.toBytes(@as(c_int, 1)));
    try os.bind(server, &address.any, address.getOsSockLen());
    try os.listen(server, kernel_backlog);

    const buffer_send = [_]u8{ 1, 0, 1, 0, 1, 0, 1, 0, 1, 0 };
    var buffer_recv = [_]u8{ 0, 1, 0, 1, 0 };

    var accept_addr: os.sockaddr = undefined;
    var accept_addr_len: os.socklen_t = @sizeOf(@TypeOf(accept_addr));
    _ = try ring.accept(0xaaaaaaaa, server, &accept_addr, &accept_addr_len, 0);
    try testing.expectEqual(@as(u32, 1), try ring.submit());

    const client = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
    defer os.close(client);
    _ = try ring.connect(0xcccccccc, client, &address.any, address.getOsSockLen());
    try testing.expectEqual(@as(u32, 1), try ring.submit());

    var cqe_accept = try ring.copy_cqe();
    if (cqe_accept.res == -linux.EINVAL) return error.SkipZigTest;
    var cqe_connect = try ring.copy_cqe();
    if (cqe_connect.res == -linux.EINVAL) return error.SkipZigTest;

    // The accept/connect CQEs may arrive in any order, the connect CQE will sometimes come first:
    if (cqe_accept.user_data == 0xcccccccc and cqe_connect.user_data == 0xaaaaaaaa) {
        const a = cqe_accept;
        const b = cqe_connect;
        cqe_accept = b;
        cqe_connect = a;
    }

    try testing.expectEqual(@as(u64, 0xaaaaaaaa), cqe_accept.user_data);
    if (cqe_accept.res <= 0) std.debug.print("\ncqe_accept.res={}\n", .{cqe_accept.res});
    try testing.expect(cqe_accept.res > 0);
    try testing.expectEqual(@as(u32, 0), cqe_accept.flags);
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xcccccccc,
        .res = 0,
        .flags = 0,
    }, cqe_connect);

    const send = try ring.send(0xeeeeeeee, client, buffer_send[0..], 0);
    send.flags |= linux.IOSQE_IO_LINK;
    _ = try ring.recv(0xffffffff, cqe_accept.res, buffer_recv[0..], 0);
    try testing.expectEqual(@as(u32, 2), try ring.submit());

    const cqe_send = try ring.copy_cqe();
    if (cqe_send.res == -linux.EINVAL) return error.SkipZigTest;
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xeeeeeeee,
        .res = buffer_send.len,
        .flags = 0,
    }, cqe_send);

    const cqe_recv = try ring.copy_cqe();
    if (cqe_recv.res == -linux.EINVAL) return error.SkipZigTest;
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xffffffff,
        .res = buffer_recv.len,
        .flags = 0,
    }, cqe_recv);

    try testing.expectEqualSlices(u8, buffer_send[0..buffer_recv.len], buffer_recv[0..]);
}

test "timeout (after a relative time)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const ms = 10;
    const margin = 5;
    const ts = os.__kernel_timespec{ .tv_sec = 0, .tv_nsec = ms * 1000000 };

    const started = std.time.milliTimestamp();
    const sqe = try ring.timeout(0x55555555, &ts, 0, 0);
    try testing.expectEqual(linux.IORING_OP.TIMEOUT, sqe.opcode);
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    const cqe = try ring.copy_cqe();
    const stopped = std.time.milliTimestamp();

    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x55555555,
        .res = -linux.ETIME,
        .flags = 0,
    }, cqe);

    // Tests should not depend on timings: skip test if outside margin.
    if (!std.math.approxEqAbs(f64, ms, @intToFloat(f64, stopped - started), margin)) return error.SkipZigTest;
}

test "timeout (after a number of completions)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(2, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const ts = os.__kernel_timespec{ .tv_sec = 3, .tv_nsec = 0 };
    const count_completions: u64 = 1;
    const sqe_timeout = try ring.timeout(0x66666666, &ts, count_completions, 0);
    try testing.expectEqual(linux.IORING_OP.TIMEOUT, sqe_timeout.opcode);
    try testing.expectEqual(count_completions, sqe_timeout.off);
    _ = try ring.nop(0x77777777);
    try testing.expectEqual(@as(u32, 2), try ring.submit());

    const cqe_nop = try ring.copy_cqe();
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x77777777,
        .res = 0,
        .flags = 0,
    }, cqe_nop);

    const cqe_timeout = try ring.copy_cqe();
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x66666666,
        .res = 0,
        .flags = 0,
    }, cqe_timeout);
}

test "timeout_remove" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(2, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const ts = os.__kernel_timespec{ .tv_sec = 3, .tv_nsec = 0 };
    const sqe_timeout = try ring.timeout(0x88888888, &ts, 0, 0);
    try testing.expectEqual(linux.IORING_OP.TIMEOUT, sqe_timeout.opcode);
    try testing.expectEqual(@as(u64, 0x88888888), sqe_timeout.user_data);

    const sqe_timeout_remove = try ring.timeout_remove(0x99999999, 0x88888888, 0);
    try testing.expectEqual(linux.IORING_OP.TIMEOUT_REMOVE, sqe_timeout_remove.opcode);
    try testing.expectEqual(@as(u64, 0x88888888), sqe_timeout_remove.addr);
    try testing.expectEqual(@as(u64, 0x99999999), sqe_timeout_remove.user_data);

    try testing.expectEqual(@as(u32, 2), try ring.submit());

    const cqe_timeout = try ring.copy_cqe();
    // IORING_OP_TIMEOUT_REMOVE is not supported by this kernel version:
    // Timeout remove operations set the fd to -1, which results in EBADF before EINVAL.
    // We use IORING_FEAT_RW_CUR_POS as a safety check here to make sure we are at least pre-5.6.
    // We don't want to skip this test for newer kernels.
    if (cqe_timeout.user_data == 0x99999999 and
        cqe_timeout.res == -linux.EBADF and
        (ring.features & linux.IORING_FEAT_RW_CUR_POS) == 0)
    {
        return error.SkipZigTest;
    }
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x88888888,
        .res = -linux.ECANCELED,
        .flags = 0,
    }, cqe_timeout);

    const cqe_timeout_remove = try ring.copy_cqe();
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0x99999999,
        .res = 0,
        .flags = 0,
    }, cqe_timeout_remove);
}

test "fallocate" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ring = IO_Uring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const path = "test_io_uring_fallocate";
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true, .mode = 0o666 });
    defer file.close();
    defer std.fs.cwd().deleteFile(path) catch {};

    try testing.expectEqual(@as(u64, 0), (try file.stat()).size);

    const len: u64 = 65536;
    const sqe = try ring.fallocate(0xaaaaaaaa, file.handle, 0, 0, len);
    try testing.expectEqual(linux.IORING_OP.FALLOCATE, sqe.opcode);
    try testing.expectEqual(file.handle, sqe.fd);
    try testing.expectEqual(@as(u32, 1), try ring.submit());

    const cqe = try ring.copy_cqe();
    switch (-cqe.res) {
        0 => {},
        // This kernel's io_uring does not yet implement fallocate():
        linux.EINVAL => return error.SkipZigTest,
        // This kernel does not implement fallocate():
        linux.ENOSYS => return error.SkipZigTest,
        // The filesystem containing the file referred to by fd does not support this operation;
        // or the mode is not supported by the filesystem containing the file referred to by fd:
        linux.EOPNOTSUPP => return error.SkipZigTest,
        else => |errno| std.debug.panic("unhandled errno: {}", .{errno}),
    }
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xaaaaaaaa,
        .res = 0,
        .flags = 0,
    }, cqe);

    try testing.expectEqual(len, (try file.stat()).size);
}
