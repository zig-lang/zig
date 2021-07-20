// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
// This is Zig's multi-target implementation of libc.
// When builtin.link_libc is true, we need to export all the functions and
// provide an entire C API.
// Otherwise, only the functions which LLVM generates calls to need to be generated,
// such as memcpy, memset, and some math functions.

const std = @import("std");
const builtin = @import("builtin");
const maxInt = std.math.maxInt;
const isNan = std.math.isNan;
const native_arch = builtin.cpu.arch;
const native_abi = builtin.abi;
const native_os = builtin.os.tag;

const is_wasm = switch (native_arch) {
    .wasm32, .wasm64 => true,
    else => false,
};
const is_msvc = switch (native_abi) {
    .msvc => true,
    else => false,
};
const is_freestanding = switch (native_os) {
    .freestanding => true,
    else => false,
};
comptime {
    if (is_freestanding and is_wasm and builtin.link_libc) {
        @export(wasm_start, .{ .name = "_start", .linkage = .Strong });
    }
    if (builtin.link_libc) {
        @export(strcmp, .{ .name = "strcmp", .linkage = .Strong });
        @export(strncmp, .{ .name = "strncmp", .linkage = .Strong });
        @export(strerror, .{ .name = "strerror", .linkage = .Strong });
        @export(strlen, .{ .name = "strlen", .linkage = .Strong });
        @export(strcpy, .{ .name = "strcpy", .linkage = .Strong });
        @export(strncpy, .{ .name = "strncpy", .linkage = .Strong });
        @export(strcat, .{ .name = "strcat", .linkage = .Strong });
        @export(strncat, .{ .name = "strncat", .linkage = .Strong });
    } else if (is_msvc) {
        @export(_fltused, .{ .name = "_fltused", .linkage = .Strong });
    }
}

var _fltused: c_int = 1;

extern fn main(argc: c_int, argv: [*:null]?[*:0]u8) c_int;
fn wasm_start() callconv(.C) void {
    _ = main(0, undefined);
}

fn strcpy(dest: [*:0]u8, src: [*:0]const u8) callconv(.C) [*:0]u8 {
    var i: usize = 0;
    while (src[i] != 0) : (i += 1) {
        dest[i] = src[i];
    }
    dest[i] = 0;

    return dest;
}

test "strcpy" {
    var s1: [9:0]u8 = undefined;

    s1[0] = 0;
    _ = strcpy(&s1, "foobarbaz");
    try std.testing.expectEqualSlices(u8, "foobarbaz", std.mem.spanZ(&s1));
}

fn strncpy(dest: [*:0]u8, src: [*:0]const u8, n: usize) callconv(.C) [*:0]u8 {
    var i: usize = 0;
    while (i < n and src[i] != 0) : (i += 1) {
        dest[i] = src[i];
    }
    while (i < n) : (i += 1) {
        dest[i] = 0;
    }

    return dest;
}

test "strncpy" {
    var s1: [9:0]u8 = undefined;

    s1[0] = 0;
    _ = strncpy(&s1, "foobarbaz", @sizeOf(@TypeOf(s1)));
    try std.testing.expectEqualSlices(u8, "foobarbaz", std.mem.spanZ(&s1));
}

fn strcat(dest: [*:0]u8, src: [*:0]const u8) callconv(.C) [*:0]u8 {
    var dest_end: usize = 0;
    while (dest[dest_end] != 0) : (dest_end += 1) {}

    var i: usize = 0;
    while (src[i] != 0) : (i += 1) {
        dest[dest_end + i] = src[i];
    }
    dest[dest_end + i] = 0;

    return dest;
}

test "strcat" {
    var s1: [9:0]u8 = undefined;

    s1[0] = 0;
    _ = strcat(&s1, "foo");
    _ = strcat(&s1, "bar");
    _ = strcat(&s1, "baz");
    try std.testing.expectEqualSlices(u8, "foobarbaz", std.mem.spanZ(&s1));
}

fn strncat(dest: [*:0]u8, src: [*:0]const u8, avail: usize) callconv(.C) [*:0]u8 {
    var dest_end: usize = 0;
    while (dest[dest_end] != 0) : (dest_end += 1) {}

    var i: usize = 0;
    while (i < avail and src[i] != 0) : (i += 1) {
        dest[dest_end + i] = src[i];
    }
    dest[dest_end + i] = 0;

    return dest;
}

test "strncat" {
    var s1: [9:0]u8 = undefined;

    s1[0] = 0;
    _ = strncat(&s1, "foo1111", 3);
    _ = strncat(&s1, "bar1111", 3);
    _ = strncat(&s1, "baz1111", 3);
    try std.testing.expectEqualSlices(u8, "foobarbaz", std.mem.spanZ(&s1));
}

fn strcmp(s1: [*:0]const u8, s2: [*:0]const u8) callconv(.C) c_int {
    return std.cstr.cmp(s1, s2);
}

fn strlen(s: [*:0]const u8) callconv(.C) usize {
    return std.mem.len(s);
}

fn strncmp(_l: [*:0]const u8, _r: [*:0]const u8, _n: usize) callconv(.C) c_int {
    if (_n == 0) return 0;
    var l = _l;
    var r = _r;
    var n = _n - 1;
    while (l[0] != 0 and r[0] != 0 and n != 0 and l[0] == r[0]) {
        l += 1;
        r += 1;
        n -= 1;
    }
    return @as(c_int, l[0]) - @as(c_int, r[0]);
}

fn strerror(errnum: c_int) callconv(.C) [*:0]const u8 {
    _ = errnum;
    return "TODO strerror implementation";
}

test "strncmp" {
    try std.testing.expect(strncmp("a", "b", 1) == -1);
    try std.testing.expect(strncmp("a", "c", 1) == -2);
    try std.testing.expect(strncmp("b", "a", 1) == 1);
    try std.testing.expect(strncmp("\xff", "\x02", 1) == 253);
}

// Avoid dragging in the runtime safety mechanisms into this .o file,
// unless we're trying to test this file.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace) noreturn {
    _ = error_return_trace;
    if (builtin.is_test) {
        @setCold(true);
        std.debug.panic("{s}", .{msg});
    }
    if (native_os != .freestanding and native_os != .other) {
        std.os.abort();
    }
    while (true) {}
}

export fn memset(dest: ?[*]u8, c: u8, n: usize) callconv(.C) ?[*]u8 {
    @setRuntimeSafety(false);

    var index: usize = 0;
    while (index != n) : (index += 1)
        dest.?[index] = c;

    return dest;
}

export fn __memset(dest: ?[*]u8, c: u8, n: usize, dest_n: usize) callconv(.C) ?[*]u8 {
    if (dest_n < n)
        @panic("buffer overflow");
    return memset(dest, c, n);
}

export fn memcpy(noalias dest: ?[*]u8, noalias src: ?[*]const u8, n: usize) callconv(.C) ?[*]u8 {
    @setRuntimeSafety(false);

    var index: usize = 0;
    while (index != n) : (index += 1)
        dest.?[index] = src.?[index];

    return dest;
}

export fn memmove(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(.C) ?[*]u8 {
    @setRuntimeSafety(false);

    if (@ptrToInt(dest) < @ptrToInt(src)) {
        var index: usize = 0;
        while (index != n) : (index += 1) {
            dest.?[index] = src.?[index];
        }
    } else {
        var index = n;
        while (index != 0) {
            index -= 1;
            dest.?[index] = src.?[index];
        }
    }

    return dest;
}

export fn memcmp(vl: ?[*]const u8, vr: ?[*]const u8, n: usize) callconv(.C) c_int {
    @setRuntimeSafety(false);

    var index: usize = 0;
    while (index != n) : (index += 1) {
        const compare_val = @bitCast(i8, vl.?[index] -% vr.?[index]);
        if (compare_val != 0) {
            return compare_val;
        }
    }

    return 0;
}

test "memcmp" {
    const base_arr = &[_]u8{ 1, 1, 1 };
    const arr1 = &[_]u8{ 1, 1, 1 };
    const arr2 = &[_]u8{ 1, 0, 1 };
    const arr3 = &[_]u8{ 1, 2, 1 };

    try std.testing.expect(memcmp(base_arr[0..], arr1[0..], base_arr.len) == 0);
    try std.testing.expect(memcmp(base_arr[0..], arr2[0..], base_arr.len) > 0);
    try std.testing.expect(memcmp(base_arr[0..], arr3[0..], base_arr.len) < 0);
}

export fn bcmp(vl: [*]allowzero const u8, vr: [*]allowzero const u8, n: usize) callconv(.C) c_int {
    @setRuntimeSafety(false);

    var index: usize = 0;
    while (index != n) : (index += 1) {
        if (vl[index] != vr[index]) {
            return 1;
        }
    }

    return 0;
}

test "bcmp" {
    const base_arr = &[_]u8{ 1, 1, 1 };
    const arr1 = &[_]u8{ 1, 1, 1 };
    const arr2 = &[_]u8{ 1, 0, 1 };
    const arr3 = &[_]u8{ 1, 2, 1 };

    try std.testing.expect(bcmp(base_arr[0..], arr1[0..], base_arr.len) == 0);
    try std.testing.expect(bcmp(base_arr[0..], arr2[0..], base_arr.len) != 0);
    try std.testing.expect(bcmp(base_arr[0..], arr3[0..], base_arr.len) != 0);
}

comptime {
    if (native_os == .linux) {
        @export(clone, .{ .name = "clone" });
    }
}

// TODO we should be able to put this directly in std/linux/x86_64.zig but
// it causes a segfault in release mode. this is a workaround of calling it
// across .o file boundaries. fix comptime @ptrCast of nakedcc functions.
fn clone() callconv(.Naked) void {
    switch (native_arch) {
        .i386 => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //         +8,   +12,   +16,   +20, +24,  +28, +32
            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //         eax,       ebx,   ecx,   edx,  esi, edi
            asm volatile (
                \\  push %%ebp
                \\  mov %%esp,%%ebp
                \\  push %%ebx
                \\  push %%esi
                \\  push %%edi
                \\  // Setup the arguments
                \\  mov 16(%%ebp),%%ebx
                \\  mov 12(%%ebp),%%ecx
                \\  and $-16,%%ecx
                \\  sub $20,%%ecx
                \\  mov 20(%%ebp),%%eax
                \\  mov %%eax,4(%%ecx)
                \\  mov 8(%%ebp),%%eax
                \\  mov %%eax,0(%%ecx)
                \\  mov 24(%%ebp),%%edx
                \\  mov 28(%%ebp),%%esi
                \\  mov 32(%%ebp),%%edi
                \\  mov $120,%%eax
                \\  int $128
                \\  test %%eax,%%eax
                \\  jnz 1f
                \\  pop %%eax
                \\  xor %%ebp,%%ebp
                \\  call *%%eax
                \\  mov %%eax,%%ebx
                \\  xor %%eax,%%eax
                \\  inc %%eax
                \\  int $128
                \\  hlt
                \\1:
                \\  pop %%edi
                \\  pop %%esi
                \\  pop %%ebx
                \\  pop %%ebp
                \\  ret
            );
        },
        .x86_64 => {
            asm volatile (
                \\      xor %%eax,%%eax
                \\      mov $56,%%al // SYS_clone
                \\      mov %%rdi,%%r11
                \\      mov %%rdx,%%rdi
                \\      mov %%r8,%%rdx
                \\      mov %%r9,%%r8
                \\      mov 8(%%rsp),%%r10
                \\      mov %%r11,%%r9
                \\      and $-16,%%rsi
                \\      sub $8,%%rsi
                \\      mov %%rcx,(%%rsi)
                \\      syscall
                \\      test %%eax,%%eax
                \\      jnz 1f
                \\      xor %%ebp,%%ebp
                \\      pop %%rdi
                \\      call *%%r9
                \\      mov %%eax,%%edi
                \\      xor %%eax,%%eax
                \\      mov $60,%%al // SYS_exit
                \\      syscall
                \\      hlt
                \\1:    ret
                \\
            );
        },
        .aarch64 => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //         x0,   x1,    w2,    x3,  x4,   x5,  x6

            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //         x8,        x0,    x1,    x2,   x3,  x4
            asm volatile (
                \\      // align stack and save func,arg
                \\      and x1,x1,#-16
                \\      stp x0,x3,[x1,#-16]!
                \\
                \\      // syscall
                \\      uxtw x0,w2
                \\      mov x2,x4
                \\      mov x3,x5
                \\      mov x4,x6
                \\      mov x8,#220 // SYS_clone
                \\      svc #0
                \\
                \\      cbz x0,1f
                \\      // parent
                \\      ret
                \\      // child
                \\1:    ldp x1,x0,[sp],#16
                \\      blr x1
                \\      mov x8,#93 // SYS_exit
                \\      svc #0
            );
        },
        .arm, .thumb => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //           r0,    r1,    r2,  r3,   +0,  +4,   +8

            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //                r7     r0,    r1,   r2,  r3,   r4
            asm volatile (
                \\    stmfd sp!,{r4,r5,r6,r7}
                \\    mov r7,#120
                \\    mov r6,r3
                \\    mov r5,r0
                \\    mov r0,r2
                \\    and r1,r1,#-16
                \\    ldr r2,[sp,#16]
                \\    ldr r3,[sp,#20]
                \\    ldr r4,[sp,#24]
                \\    svc 0
                \\    tst r0,r0
                \\    beq 1f
                \\    ldmfd sp!,{r4,r5,r6,r7}
                \\    bx lr
                \\
                \\1:  mov r0,r6
                \\    bl 3f
                \\2:  mov r7,#1
                \\    svc 0
                \\    b 2b
                \\3:  bx r5
            );
        },
        .riscv64 => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //           a0,    a1,    a2,  a3,   a4,  a5,   a6

            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //                a7     a0,    a1,   a2,  a3,   a4
            asm volatile (
                \\    # Save func and arg to stack
                \\    addi a1, a1, -16
                \\    sd a0, 0(a1)
                \\    sd a3, 8(a1)
                \\
                \\    # Call SYS_clone
                \\    mv a0, a2
                \\    mv a2, a4
                \\    mv a3, a5
                \\    mv a4, a6
                \\    li a7, 220 # SYS_clone
                \\    ecall
                \\
                \\    beqz a0, 1f
                \\    # Parent
                \\    ret
                \\
                \\    # Child
                \\1:  ld a1, 0(sp)
                \\    ld a0, 8(sp)
                \\    jalr a1
                \\
                \\    # Exit
                \\    li a7, 93 # SYS_exit
                \\    ecall
            );
        },
        .mips, .mipsel => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //            3,     4,     5,   6,    7,   8,    9

            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //                 2      4,     5,    6,   7,    8
            asm volatile (
                \\  # Save function pointer and argument pointer on new thread stack
                \\  and $5, $5, -8
                \\  subu $5, $5, 16
                \\  sw $4, 0($5)
                \\  sw $7, 4($5)
                \\  # Shuffle (fn,sp,fl,arg,ptid,tls,ctid) to (fl,sp,ptid,tls,ctid)
                \\  move $4, $6
                \\  lw $6, 16($sp)
                \\  lw $7, 20($sp)
                \\  lw $9, 24($sp)
                \\  subu $sp, $sp, 16
                \\  sw $9, 16($sp)
                \\  li $2, 4120
                \\  syscall
                \\  beq $7, $0, 1f
                \\  nop
                \\  addu $sp, $sp, 16
                \\  jr $ra
                \\  subu $2, $0, $2
                \\1:
                \\  beq $2, $0, 1f
                \\  nop
                \\  addu $sp, $sp, 16
                \\  jr $ra
                \\  nop
                \\1:
                \\  lw $25, 0($sp)
                \\  lw $4, 4($sp)
                \\  jalr $25
                \\  nop
                \\  move $4, $2
                \\  li $2, 4001
                \\  syscall
            );
        },
        .powerpc => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //            3,     4,     5,   6,    7,   8,    9

            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //                 0      3,     4,    5,   6,    7
            asm volatile (
                \\# store non-volatile regs r30, r31 on stack in order to put our
                \\# start func and its arg there
                \\stwu 30, -16(1)
                \\stw 31, 4(1)
                \\
                \\# save r3 (func) into r30, and r6(arg) into r31
                \\mr 30, 3
                \\mr 31, 6
                \\
                \\# create initial stack frame for new thread
                \\clrrwi 4, 4, 4
                \\li 0, 0
                \\stwu 0, -16(4)
                \\
                \\#move c into first arg
                \\mr 3, 5
                \\#mr 4, 4
                \\mr 5, 7
                \\mr 6, 8
                \\mr 7, 9
                \\
                \\# move syscall number into r0
                \\li 0, 120
                \\
                \\sc
                \\
                \\# check for syscall error
                \\bns+ 1f # jump to label 1 if no summary overflow.
                \\#else
                \\neg 3, 3 #negate the result (errno)
                \\1:
                \\# compare sc result with 0
                \\cmpwi cr7, 3, 0
                \\
                \\# if not 0, jump to end
                \\bne cr7, 2f
                \\
                \\#else: we're the child
                \\#call funcptr: move arg (d) into r3
                \\mr 3, 31
                \\#move r30 (funcptr) into CTR reg
                \\mtctr 30
                \\# call CTR reg
                \\bctrl
                \\# mov SYS_exit into r0 (the exit param is already in r3)
                \\li 0, 1
                \\sc
                \\
                \\2:
                \\
                \\# restore stack
                \\lwz 30, 0(1)
                \\lwz 31, 4(1)
                \\addi 1, 1, 16
                \\
                \\blr
            );
        },
        .powerpc64, .powerpc64le => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //            3,     4,     5,   6,    7,   8,    9

            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //                 0      3,     4,    5,   6,    7
            asm volatile (
                \\  # create initial stack frame for new thread
                \\  clrrdi 4, 4, 4
                \\  li     0, 0
                \\  stdu   0,-32(4)
                \\
                \\  # save fn and arg to child stack
                \\  std    3,  8(4)
                \\  std    6, 16(4)
                \\
                \\  # shuffle args into correct registers and call SYS_clone
                \\  mr    3, 5
                \\  #mr   4, 4
                \\  mr    5, 7
                \\  mr    6, 8
                \\  mr    7, 9
                \\  li    0, 120  # SYS_clone = 120
                \\  sc
                \\
                \\  # if error, negate return (errno)
                \\  bns+  1f
                \\  neg   3, 3
                \\
                \\1:
                \\  # if we're the parent, return
                \\  cmpwi cr7, 3, 0
                \\  bnelr cr7
                \\
                \\  # we're the child. call fn(arg)
                \\  ld     3, 16(1)
                \\  ld    12,  8(1)
                \\  mtctr 12
                \\  bctrl
                \\
                \\  # call SYS_exit. exit code is already in r3 from fn return value
                \\  li    0, 1    # SYS_exit = 1
                \\  sc
            );
        },
        .sparcv9 => {
            // __clone(func, stack, flags, arg, ptid, tls, ctid)
            //           i0,    i1,    i2,  i3,   i4,  i5,   sp
            // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
            //                g1     o0,    o1,   o2,  o3,   o4
            asm volatile (
                \\ save %%sp, -192, %%sp
                \\ # Save the func pointer and the arg pointer
                \\ mov %%i0, %%g2
                \\ mov %%i3, %%g3
                \\ # Shuffle the arguments
                \\ mov 217, %%g1
                \\ mov %%i2, %%o0
                \\ # Add some extra space for the initial frame
                \\ sub %%i1, 176 + 2047, %%o1
                \\ mov %%i4, %%o2
                \\ mov %%i5, %%o3
                \\ ldx [%%fp + 0x8af], %%o4
                \\ t 0x6d
                \\ bcs,pn %%xcc, 2f
                \\ nop
                \\ # The child pid is returned in o0 while o1 tells if this
                \\ # process is # the child (=1) or the parent (=0).
                \\ brnz %%o1, 1f
                \\ nop
                \\ # Parent process, return the child pid
                \\ mov %%o0, %%i0
                \\ ret
                \\ restore
                \\1:
                \\ # Child process, call func(arg)
                \\ mov %%g0, %%fp
                \\ call %%g2
                \\ mov %%g3, %%o0
                \\ # Exit
                \\ mov 1, %%g1
                \\ t 0x6d
                \\2:
                \\ # The syscall failed
                \\ sub %%g0, %%o0, %%i0
                \\ ret
                \\ restore
            );
        },
        else => @compileError("Implement clone() for this arch."),
    }
}

const math = std.math;

export fn fmodf(x: f32, y: f32) f32 {
    return generic_fmod(f32, x, y);
}
export fn fmod(x: f64, y: f64) f64 {
    return generic_fmod(f64, x, y);
}

// TODO add intrinsics for these (and probably the double version too)
// and have the math stuff use the intrinsic. same as @mod and @rem
export fn floorf(x: f32) f32 {
    return math.floor(x);
}

export fn ceilf(x: f32) f32 {
    return math.ceil(x);
}

export fn floor(x: f64) f64 {
    return math.floor(x);
}

export fn ceil(x: f64) f64 {
    return math.ceil(x);
}

export fn fma(a: f64, b: f64, c: f64) f64 {
    return math.fma(f64, a, b, c);
}

export fn fmaf(a: f32, b: f32, c: f32) f32 {
    return math.fma(f32, a, b, c);
}

export fn sin(a: f64) f64 {
    return math.sin(a);
}

export fn sinf(a: f32) f32 {
    return math.sin(a);
}

export fn cos(a: f64) f64 {
    return math.cos(a);
}

export fn cosf(a: f32) f32 {
    return math.cos(a);
}

export fn sincos(a: f64, r_sin: *f64, r_cos: *f64) void {
    r_sin.* = math.sin(a);
    r_cos.* = math.cos(a);
}

export fn sincosf(a: f32, r_sin: *f32, r_cos: *f32) void {
    r_sin.* = math.sin(a);
    r_cos.* = math.cos(a);
}

export fn exp(a: f64) f64 {
    return math.exp(a);
}

export fn expf(a: f32) f32 {
    return math.exp(a);
}

export fn exp2(a: f64) f64 {
    return math.exp2(a);
}

export fn exp2f(a: f32) f32 {
    return math.exp2(a);
}

export fn log(a: f64) f64 {
    return math.ln(a);
}

export fn logf(a: f32) f32 {
    return math.ln(a);
}

export fn log2(a: f64) f64 {
    return math.log2(a);
}

export fn log2f(a: f32) f32 {
    return math.log2(a);
}

export fn log10(a: f64) f64 {
    return math.log10(a);
}

export fn log10f(a: f32) f32 {
    return math.log10(a);
}

export fn fabs(a: f64) f64 {
    return math.fabs(a);
}

export fn fabsf(a: f32) f32 {
    return math.fabs(a);
}

export fn trunc(a: f64) f64 {
    return math.trunc(a);
}

export fn truncf(a: f32) f32 {
    return math.trunc(a);
}

export fn round(a: f64) f64 {
    return math.round(a);
}

export fn roundf(a: f32) f32 {
    return math.round(a);
}

fn generic_fmod(comptime T: type, x: T, y: T) T {
    @setRuntimeSafety(false);

    const bits = @typeInfo(T).Float.bits;
    const uint = std.meta.Int(.unsigned, bits);
    const log2uint = math.Log2Int(uint);
    const digits = if (T == f32) 23 else 52;
    const exp_bits = if (T == f32) 9 else 12;
    const bits_minus_1 = bits - 1;
    const mask = if (T == f32) 0xff else 0x7ff;
    var ux = @bitCast(uint, x);
    var uy = @bitCast(uint, y);
    var ex = @intCast(i32, (ux >> digits) & mask);
    var ey = @intCast(i32, (uy >> digits) & mask);
    const sx = if (T == f32) @intCast(u32, ux & 0x80000000) else @intCast(i32, ux >> bits_minus_1);
    var i: uint = undefined;

    if (uy << 1 == 0 or isNan(@bitCast(T, uy)) or ex == mask)
        return (x * y) / (x * y);

    if (ux << 1 <= uy << 1) {
        if (ux << 1 == uy << 1)
            return 0 * x;
        return x;
    }

    // normalize x and y
    if (ex == 0) {
        i = ux << exp_bits;
        while (i >> bits_minus_1 == 0) : ({
            ex -= 1;
            i <<= 1;
        }) {}
        ux <<= @intCast(log2uint, @bitCast(u32, -ex + 1));
    } else {
        ux &= maxInt(uint) >> exp_bits;
        ux |= 1 << digits;
    }
    if (ey == 0) {
        i = uy << exp_bits;
        while (i >> bits_minus_1 == 0) : ({
            ey -= 1;
            i <<= 1;
        }) {}
        uy <<= @intCast(log2uint, @bitCast(u32, -ey + 1));
    } else {
        uy &= maxInt(uint) >> exp_bits;
        uy |= 1 << digits;
    }

    // x mod y
    while (ex > ey) : (ex -= 1) {
        i = ux -% uy;
        if (i >> bits_minus_1 == 0) {
            if (i == 0)
                return 0 * x;
            ux = i;
        }
        ux <<= 1;
    }
    i = ux -% uy;
    if (i >> bits_minus_1 == 0) {
        if (i == 0)
            return 0 * x;
        ux = i;
    }
    while (ux >> digits == 0) : ({
        ux <<= 1;
        ex -= 1;
    }) {}

    // scale result up
    if (ex > 0) {
        ux -%= 1 << digits;
        ux |= @as(uint, @bitCast(u32, ex)) << digits;
    } else {
        ux >>= @intCast(log2uint, @bitCast(u32, -ex + 1));
    }
    if (T == f32) {
        ux |= sx;
    } else {
        ux |= @intCast(uint, sx) << bits_minus_1;
    }
    return @bitCast(T, ux);
}

test "fmod, fmodf" {
    inline for ([_]type{ f32, f64 }) |T| {
        const nan_val = math.nan(T);
        const inf_val = math.inf(T);

        try std.testing.expect(isNan(generic_fmod(T, nan_val, 1.0)));
        try std.testing.expect(isNan(generic_fmod(T, 1.0, nan_val)));
        try std.testing.expect(isNan(generic_fmod(T, inf_val, 1.0)));
        try std.testing.expect(isNan(generic_fmod(T, 0.0, 0.0)));
        try std.testing.expect(isNan(generic_fmod(T, 1.0, 0.0)));

        try std.testing.expectEqual(@as(T, 0.0), generic_fmod(T, 0.0, 2.0));
        try std.testing.expectEqual(@as(T, -0.0), generic_fmod(T, -0.0, 2.0));

        try std.testing.expectEqual(@as(T, -2.0), generic_fmod(T, -32.0, 10.0));
        try std.testing.expectEqual(@as(T, -2.0), generic_fmod(T, -32.0, -10.0));
        try std.testing.expectEqual(@as(T, 2.0), generic_fmod(T, 32.0, 10.0));
        try std.testing.expectEqual(@as(T, 2.0), generic_fmod(T, 32.0, -10.0));
    }
}

fn generic_fmin(comptime T: type, x: T, y: T) T {
    if (isNan(x))
        return y;
    if (isNan(y))
        return x;
    return if (x < y) x else y;
}

export fn fminf(x: f32, y: f32) callconv(.C) f32 {
    return generic_fmin(f32, x, y);
}

export fn fmin(x: f64, y: f64) callconv(.C) f64 {
    return generic_fmin(f64, x, y);
}

test "fmin, fminf" {
    inline for ([_]type{ f32, f64 }) |T| {
        const nan_val = math.nan(T);

        try std.testing.expect(isNan(generic_fmin(T, nan_val, nan_val)));
        try std.testing.expectEqual(@as(T, 1.0), generic_fmin(T, nan_val, 1.0));
        try std.testing.expectEqual(@as(T, 1.0), generic_fmin(T, 1.0, nan_val));

        try std.testing.expectEqual(@as(T, 1.0), generic_fmin(T, 1.0, 10.0));
        try std.testing.expectEqual(@as(T, -1.0), generic_fmin(T, 1.0, -1.0));
    }
}

fn generic_fmax(comptime T: type, x: T, y: T) T {
    if (isNan(x))
        return y;
    if (isNan(y))
        return x;
    return if (x < y) y else x;
}

export fn fmaxf(x: f32, y: f32) callconv(.C) f32 {
    return generic_fmax(f32, x, y);
}

export fn fmax(x: f64, y: f64) callconv(.C) f64 {
    return generic_fmax(f64, x, y);
}

test "fmax, fmaxf" {
    inline for ([_]type{ f32, f64 }) |T| {
        const nan_val = math.nan(T);

        try std.testing.expect(isNan(generic_fmax(T, nan_val, nan_val)));
        try std.testing.expectEqual(@as(T, 1.0), generic_fmax(T, nan_val, 1.0));
        try std.testing.expectEqual(@as(T, 1.0), generic_fmax(T, 1.0, nan_val));

        try std.testing.expectEqual(@as(T, 10.0), generic_fmax(T, 1.0, 10.0));
        try std.testing.expectEqual(@as(T, 1.0), generic_fmax(T, 1.0, -1.0));
    }
}

// NOTE: The original code is full of implicit signed -> unsigned assumptions and u32 wraparound
// behaviour. Most intermediate i32 values are changed to u32 where appropriate but there are
// potentially some edge cases remaining that are not handled in the same way.
export fn sqrt(x: f64) f64 {
    const tiny: f64 = 1.0e-300;
    const sign: u32 = 0x80000000;
    const u = @bitCast(u64, x);

    var ix0 = @intCast(u32, u >> 32);
    var ix1 = @intCast(u32, u & 0xFFFFFFFF);

    // sqrt(nan) = nan, sqrt(+inf) = +inf, sqrt(-inf) = nan
    if (ix0 & 0x7FF00000 == 0x7FF00000) {
        return x * x + x;
    }

    // sqrt(+-0) = +-0
    if (x == 0.0) {
        return x;
    }
    // sqrt(-ve) = snan
    if (ix0 & sign != 0) {
        return math.snan(f64);
    }

    // normalize x
    var m = @intCast(i32, ix0 >> 20);
    if (m == 0) {
        // subnormal
        while (ix0 == 0) {
            m -= 21;
            ix0 |= ix1 >> 11;
            ix1 <<= 21;
        }

        // subnormal
        var i: u32 = 0;
        while (ix0 & 0x00100000 == 0) : (i += 1) {
            ix0 <<= 1;
        }
        m -= @intCast(i32, i) - 1;
        ix0 |= ix1 >> @intCast(u5, 32 - i);
        ix1 <<= @intCast(u5, i);
    }

    // unbias exponent
    m -= 1023;
    ix0 = (ix0 & 0x000FFFFF) | 0x00100000;
    if (m & 1 != 0) {
        ix0 += ix0 + (ix1 >> 31);
        ix1 = ix1 +% ix1;
    }
    m >>= 1;

    // sqrt(x) bit by bit
    ix0 += ix0 + (ix1 >> 31);
    ix1 = ix1 +% ix1;

    var q: u32 = 0;
    var q1: u32 = 0;
    var s0: u32 = 0;
    var s1: u32 = 0;
    var r: u32 = 0x00200000;
    var t: u32 = undefined;
    var t1: u32 = undefined;

    while (r != 0) {
        t = s0 +% r;
        if (t <= ix0) {
            s0 = t + r;
            ix0 -= t;
            q += r;
        }
        ix0 = ix0 +% ix0 +% (ix1 >> 31);
        ix1 = ix1 +% ix1;
        r >>= 1;
    }

    r = sign;
    while (r != 0) {
        t1 = s1 +% r;
        t = s0;
        if (t < ix0 or (t == ix0 and t1 <= ix1)) {
            s1 = t1 +% r;
            if (t1 & sign == sign and s1 & sign == 0) {
                s0 += 1;
            }
            ix0 -= t;
            if (ix1 < t1) {
                ix0 -= 1;
            }
            ix1 = ix1 -% t1;
            q1 += r;
        }
        ix0 = ix0 +% ix0 +% (ix1 >> 31);
        ix1 = ix1 +% ix1;
        r >>= 1;
    }

    // rounding direction
    if (ix0 | ix1 != 0) {
        var z = 1.0 - tiny; // raise inexact
        if (z >= 1.0) {
            z = 1.0 + tiny;
            if (q1 == 0xFFFFFFFF) {
                q1 = 0;
                q += 1;
            } else if (z > 1.0) {
                if (q1 == 0xFFFFFFFE) {
                    q += 1;
                }
                q1 += 2;
            } else {
                q1 += q1 & 1;
            }
        }
    }

    ix0 = (q >> 1) + 0x3FE00000;
    ix1 = q1 >> 1;
    if (q & 1 != 0) {
        ix1 |= 0x80000000;
    }

    // NOTE: musl here appears to rely on signed twos-complement wraparound. +% has the same
    // behaviour at least.
    var iix0 = @intCast(i32, ix0);
    iix0 = iix0 +% (m << 20);

    const uz = (@intCast(u64, iix0) << 32) | ix1;
    return @bitCast(f64, uz);
}

test "sqrt" {
    const V = [_]f64{
        0.0,
        4.089288054930154,
        7.538757127071935,
        8.97780793672623,
        5.304443821913729,
        5.682408965311888,
        0.5846878579110049,
        3.650338664297043,
        0.3178091951800732,
        7.1505232436382835,
        3.6589165881946464,
    };

    // Note that @sqrt will either generate the sqrt opcode (if supported by the
    // target ISA) or a call to `sqrtf` otherwise.
    for (V) |val|
        try std.testing.expectEqual(@sqrt(val), sqrt(val));
}

test "sqrt special" {
    try std.testing.expect(std.math.isPositiveInf(sqrt(std.math.inf(f64))));
    try std.testing.expect(sqrt(0.0) == 0.0);
    try std.testing.expect(sqrt(-0.0) == -0.0);
    try std.testing.expect(isNan(sqrt(-1.0)));
    try std.testing.expect(isNan(sqrt(std.math.nan(f64))));
}

export fn sqrtf(x: f32) f32 {
    const tiny: f32 = 1.0e-30;
    const sign: i32 = @bitCast(i32, @as(u32, 0x80000000));
    var ix: i32 = @bitCast(i32, x);

    if ((ix & 0x7F800000) == 0x7F800000) {
        return x * x + x; // sqrt(nan) = nan, sqrt(+inf) = +inf, sqrt(-inf) = snan
    }

    // zero
    if (ix <= 0) {
        if (ix & ~sign == 0) {
            return x; // sqrt (+-0) = +-0
        }
        if (ix < 0) {
            return math.snan(f32);
        }
    }

    // normalize
    var m = ix >> 23;
    if (m == 0) {
        // subnormal
        var i: i32 = 0;
        while (ix & 0x00800000 == 0) : (i += 1) {
            ix <<= 1;
        }
        m -= i - 1;
    }

    m -= 127; // unbias exponent
    ix = (ix & 0x007FFFFF) | 0x00800000;

    if (m & 1 != 0) { // odd m, double x to even
        ix += ix;
    }

    m >>= 1; // m = [m / 2]

    // sqrt(x) bit by bit
    ix += ix;
    var q: i32 = 0; // q = sqrt(x)
    var s: i32 = 0;
    var r: i32 = 0x01000000; // r = moving bit right -> left

    while (r != 0) {
        const t = s + r;
        if (t <= ix) {
            s = t + r;
            ix -= t;
            q += r;
        }
        ix += ix;
        r >>= 1;
    }

    // floating add to find rounding direction
    if (ix != 0) {
        var z = 1.0 - tiny; // inexact
        if (z >= 1.0) {
            z = 1.0 + tiny;
            if (z > 1.0) {
                q += 2;
            } else {
                if (q & 1 != 0) {
                    q += 1;
                }
            }
        }
    }

    ix = (q >> 1) + 0x3f000000;
    ix += m << 23;
    return @bitCast(f32, ix);
}

test "sqrtf" {
    const V = [_]f32{
        0.0,
        4.089288054930154,
        7.538757127071935,
        8.97780793672623,
        5.304443821913729,
        5.682408965311888,
        0.5846878579110049,
        3.650338664297043,
        0.3178091951800732,
        7.1505232436382835,
        3.6589165881946464,
    };

    // Note that @sqrt will either generate the sqrt opcode (if supported by the
    // target ISA) or a call to `sqrtf` otherwise.
    for (V) |val|
        try std.testing.expectEqual(@sqrt(val), sqrtf(val));
}

test "sqrtf special" {
    try std.testing.expect(std.math.isPositiveInf(sqrtf(std.math.inf(f32))));
    try std.testing.expect(sqrtf(0.0) == 0.0);
    try std.testing.expect(sqrtf(-0.0) == -0.0);
    try std.testing.expect(isNan(sqrtf(-1.0)));
    try std.testing.expect(isNan(sqrtf(std.math.nan(f32))));
}
