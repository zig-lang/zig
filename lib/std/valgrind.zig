// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const builtin = @import("builtin");
const std = @import("std.zig");
const math = std.math;

pub fn doClientRequest(default: usize, request: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    if (!builtin.valgrind_support) {
        return default;
    }

    switch (builtin.cpu.arch) {
        .i386 => {
            return asm volatile (
                \\ roll $3,  %%edi ; roll $13, %%edi
                \\ roll $29, %%edi ; roll $19, %%edi
                \\ xchgl %%ebx,%%ebx
                : [_] "={edx}" (-> usize)
                : [_] "{eax}" (&[_]usize{ request, a1, a2, a3, a4, a5 }),
                  [_] "0" (default)
                : "cc", "memory"
            );
        },
        .x86_64 => {
            return asm volatile (
                \\ rolq $3,  %%rdi ; rolq $13, %%rdi
                \\ rolq $61, %%rdi ; rolq $51, %%rdi
                \\ xchgq %%rbx,%%rbx
                : [_] "={rdx}" (-> usize)
                : [_] "{rax}" (&[_]usize{ request, a1, a2, a3, a4, a5 }),
                  [_] "0" (default)
                : "cc", "memory"
            );
        },
        // ppc32
        // ppc64
        // arm
        // arm64
        // s390x
        // mips32
        // mips64
        else => {
            return default;
        },
    }
}

pub const ClientRequest = enum(u32) {
    RunningOnValgrind = 4097,
    DiscardTranslations = 4098,
    ClientCall0 = 4353,
    ClientCall1 = 4354,
    ClientCall2 = 4355,
    ClientCall3 = 4356,
    CountErrors = 4609,
    GdbMonitorCommand = 4610,
    MalloclikeBlock = 4865,
    ResizeinplaceBlock = 4875,
    FreelikeBlock = 4866,
    CreateMempool = 4867,
    DestroyMempool = 4868,
    MempoolAlloc = 4869,
    MempoolFree = 4870,
    MempoolTrim = 4871,
    MoveMempool = 4872,
    MempoolChange = 4873,
    MempoolExists = 4874,
    Printf = 5121,
    PrintfBacktrace = 5122,
    PrintfValistByRef = 5123,
    PrintfBacktraceValistByRef = 5124,
    StackRegister = 5377,
    StackDeregister = 5378,
    StackChange = 5379,
    LoadPdbDebuginfo = 5633,
    MapIpToSrcloc = 5889,
    ChangeErrDisablement = 6145,
    VexInitForIri = 6401,
    InnerThreads = 6402,
};
pub fn ToolBase(base: [2]u8) u32 {
    return (@as(u32, base[0] & 0xff) << 24) | (@as(u32, base[1] & 0xff) << 16);
}
pub fn IsTool(base: [2]u8, code: usize) bool {
    return ToolBase(base) == (code & 0xffff0000);
}

fn doClientRequestExpr(default: usize, request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) usize {
    return doClientRequest(default, @intCast(usize, @enumToInt(request)), a1, a2, a3, a4, a5);
}

fn doClientRequestStmt(request: ClientRequest, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) void {
    _ = doClientRequestExpr(0, request, a1, a2, a3, a4, a5);
}

/// Returns the number of Valgrinds this code is running under.  That
/// is, 0 if running natively, 1 if running under Valgrind, 2 if
/// running under Valgrind which is running under another Valgrind,
/// etc.
pub fn runningOnValgrind() usize {
    return doClientRequestExpr(0, .RunningOnValgrind, 0, 0, 0, 0, 0);
}

test "works whether running on valgrind or not" {
    _ = runningOnValgrind();
}

/// Discard translation of code in the slice qzz.  Useful if you are debugging
/// a JITter or some such, since it provides a way to make sure valgrind will
/// retranslate the invalidated area.  Returns no value.
pub fn discardTranslations(qzz: []const u8) void {
    doClientRequestStmt(.DiscardTranslations, @ptrToInt(qzz.ptr), qzz.len, 0, 0, 0);
}

pub fn innerThreads(qzz: [*]u8) void {
    doClientRequestStmt(.InnerThreads, qzz, 0, 0, 0, 0);
}

pub fn nonSIMDCall0(func: fn (usize) usize) usize {
    return doClientRequestExpr(0, .ClientCall0, @ptrToInt(func), 0, 0, 0, 0);
}

pub fn nonSIMDCall1(func: fn (usize, usize) usize, a1: usize) usize {
    return doClientRequestExpr(0, .ClientCall1, @ptrToInt(func), a1, 0, 0, 0);
}

pub fn nonSIMDCall2(func: fn (usize, usize, usize) usize, a1: usize, a2: usize) usize {
    return doClientRequestExpr(0, .ClientCall2, @ptrToInt(func), a1, a2, 0, 0);
}

pub fn nonSIMDCall3(func: fn (usize, usize, usize, usize) usize, a1: usize, a2: usize, a3: usize) usize {
    return doClientRequestExpr(0, .ClientCall3, @ptrToInt(func), a1, a2, a3, 0);
}

/// Counts the number of errors that have been recorded by a tool.  Nb:
/// the tool must record the errors with VG_(maybe_record_error)() or
/// VG_(unique_error)() for them to be counted.
pub fn countErrors() usize {
    return doClientRequestExpr(0, // default return
        .CountErrors, 0, 0, 0, 0, 0);
}

pub fn mallocLikeBlock(mem: []u8, rzB: usize, is_zeroed: bool) void {
    doClientRequestStmt(.MalloclikeBlock, @ptrToInt(mem.ptr), mem.len, rzB, @boolToInt(is_zeroed), 0);
}

pub fn resizeInPlaceBlock(oldmem: []u8, newsize: usize, rzB: usize) void {
    doClientRequestStmt(.ResizeinplaceBlock, @ptrToInt(oldmem.ptr), oldmem.len, newsize, rzB, 0);
}

pub fn freeLikeBlock(addr: [*]u8, rzB: usize) void {
    doClientRequestStmt(.FreelikeBlock, @ptrToInt(addr), rzB, 0, 0, 0);
}

/// Create a memory pool.
pub const MempoolFlags = struct {
    pub const AutoFree = 1;
    pub const MetaPool = 2;
};
pub fn createMempool(pool: [*]u8, rzB: usize, is_zeroed: bool, flags: usize) void {
    doClientRequestStmt(.CreateMempool, @ptrToInt(pool), rzB, @boolToInt(is_zeroed), flags, 0);
}

/// Destroy a memory pool.
pub fn destroyMempool(pool: [*]u8) void {
    doClientRequestStmt(.DestroyMempool, pool, 0, 0, 0, 0);
}

/// Associate a piece of memory with a memory pool.
pub fn mempoolAlloc(pool: [*]u8, mem: []u8) void {
    doClientRequestStmt(.MempoolAlloc, @ptrToInt(pool), @ptrToInt(mem.ptr), mem.len, 0, 0);
}

/// Disassociate a piece of memory from a memory pool.
pub fn mempoolFree(pool: [*]u8, addr: [*]u8) void {
    doClientRequestStmt(.MempoolFree, @ptrToInt(pool), @ptrToInt(addr), 0, 0, 0);
}

/// Disassociate any pieces outside a particular range.
pub fn mempoolTrim(pool: [*]u8, mem: []u8) void {
    doClientRequestStmt(.MempoolTrim, @ptrToInt(pool), @ptrToInt(mem.ptr), mem.len, 0, 0);
}

/// Resize and/or move a piece associated with a memory pool.
pub fn moveMempool(poolA: [*]u8, poolB: [*]u8) void {
    doClientRequestStmt(.MoveMempool, @ptrToInt(poolA), @ptrToInt(poolB), 0, 0, 0);
}

/// Resize and/or move a piece associated with a memory pool.
pub fn mempoolChange(pool: [*]u8, addrA: [*]u8, mem: []u8) void {
    doClientRequestStmt(.MempoolChange, @ptrToInt(pool), @ptrToInt(addrA), @ptrToInt(mem.ptr), mem.len, 0);
}

/// Return if a mempool exists.
pub fn mempoolExists(pool: [*]u8) bool {
    return doClientRequestExpr(0, .MempoolExists, @ptrToInt(pool), 0, 0, 0, 0) != 0;
}

/// Mark a piece of memory as being a stack. Returns a stack id.
/// start is the lowest addressable stack byte, end is the highest
/// addressable stack byte.
pub fn stackRegister(stack: []u8) usize {
    return doClientRequestExpr(0, .StackRegister, @ptrToInt(stack.ptr), @ptrToInt(stack.ptr) + stack.len, 0, 0, 0);
}

/// Unmark the piece of memory associated with a stack id as being a stack.
pub fn stackDeregister(id: usize) void {
    doClientRequestStmt(.StackDeregister, id, 0, 0, 0, 0);
}

/// Change the start and end address of the stack id.
/// start is the new lowest addressable stack byte, end is the new highest
/// addressable stack byte.
pub fn stackChange(id: usize, newstack: []u8) void {
    doClientRequestStmt(.StackChange, id, @ptrToInt(newstack.ptr), @ptrToInt(newstack.ptr) + newstack.len, 0, 0);
}

// Load PDB debug info for Wine PE image_map.
// pub fn loadPdbDebuginfo(fd, ptr, total_size, delta) void {
//     doClientRequestStmt(.LoadPdbDebuginfo,
//         fd, ptr, total_size, delta,
//         0);
// }

/// Map a code address to a source file name and line number.  buf64
/// must point to a 64-byte buffer in the caller's address space. The
/// result will be dumped in there and is guaranteed to be zero
/// terminated.  If no info is found, the first byte is set to zero.
pub fn mapIpToSrcloc(addr: *const u8, buf64: [64]u8) usize {
    return doClientRequestExpr(0, .MapIpToSrcloc, @ptrToInt(addr), @ptrToInt(&buf64[0]), 0, 0, 0);
}

/// Disable error reporting for this thread.  Behaves in a stack like
/// way, so you can safely call this multiple times provided that
/// enableErrorReporting() is called the same number of times
/// to re-enable reporting.  The first call of this macro disables
/// reporting.  Subsequent calls have no effect except to increase the
/// number of enableErrorReporting() calls needed to re-enable
/// reporting.  Child threads do not inherit this setting from their
/// parents -- they are always created with reporting enabled.
pub fn disableErrorReporting() void {
    doClientRequestStmt(.ChangeErrDisablement, 1, 0, 0, 0, 0);
}

/// Re-enable error reporting, (see disableErrorReporting())
pub fn enableErrorReporting() void {
    doClientRequestStmt(.ChangeErrDisablement, math.maxInt(usize), 0, 0, 0, 0);
}

/// Execute a monitor command from the client program.
/// If a connection is opened with GDB, the output will be sent
/// according to the output mode set for vgdb.
/// If no connection is opened, output will go to the log output.
/// Returns 1 if command not recognised, 0 otherwise.
pub fn monitorCommand(command: [*]u8) bool {
    return doClientRequestExpr(0, .GdbMonitorCommand, @ptrToInt(command.ptr), 0, 0, 0, 0) != 0;
}

pub const memcheck = @import("valgrind/memcheck.zig");
pub const callgrind = @import("valgrind/callgrind.zig");

test {
    _ = @import("valgrind/memcheck.zig");
    _ = @import("valgrind/callgrind.zig");
}
