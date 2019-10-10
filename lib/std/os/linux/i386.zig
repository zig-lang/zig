usingnamespace @import("../bits.zig");

pub fn syscall0(number: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize)
        : [number] "{eax}" (number)
        : "memory"
    );
}

pub fn syscall1(number: usize, arg1: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize)
        : [number] "{eax}" (number),
          [arg1] "{ebx}" (arg1)
        : "memory"
    );
}

pub fn syscall2(number: usize, arg1: usize, arg2: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize)
        : [number] "{eax}" (number),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2)
        : "memory"
    );
}

pub fn syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize)
        : [number] "{eax}" (number),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3)
        : "memory"
    );
}

pub fn syscall4(number: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize)
        : [number] "{eax}" (number),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4)
        : "memory"
    );
}

pub fn syscall5(number: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize)
        : [number] "{eax}" (number),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4),
          [arg5] "{edi}" (arg5)
        : "memory"
    );
}

pub fn syscall6(
    number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile (
        \\  push %[arg6]
        \\  push %[arg5]
        \\  push %%ebp
        \\  mov 4(%%esp), %%edi
        \\  mov 8(%%esp), %%ebp
        \\  int $0x80
        \\  pop %%ebp
        \\  add $8, %%esp
        : [ret] "={eax}" (-> usize)
        : [number] "{eax}" (number),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4),
          [arg5] "r" (arg5),
          [arg6] "r" (arg6)
        : "memory"
    );
}

pub const restore = restore_rt;

pub nakedcc fn restore_rt() void {
    _ = syscall0(SYS_rt_sigreturn);
}

// Source: libc/linux/clone.c
pub extern fn clone(func: extern fn (arg: usize) i32, stack: usize, flags: u32, arg: usize, ptid: *i32, tls: usize, ctid: *i32) i32;
