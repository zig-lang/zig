const std = @import("std");
const TestContext = @import("../../src-self-hosted/test.zig").TestContext;

pub fn addCases(ctx: *TestContext) !void {
    if (std.Target.current.os.tag != .linux or
        std.Target.current.cpu.arch != .x86_64)
    {
        // TODO implement self-hosted PE (.exe file) linking
        // TODO implement more ZIR so we don't depend on x86_64-linux
        return;
    }

    // self-hosted does not yet support PE executable files / COFF object files
    // or mach-o files. So we do these test cases cross compiling for x86_64-linux.
    // case_target affects cases added; changing its value after adding a case
    // does nothing.
    ctx.case_target = std.zig.CrossTarget{
        .cpu_arch = .x86_64,
        .os_tag = .linux,
    };

    {
        var case = ctx.exe("hello world with updates");
        // Regular old hello world
        case.addCompareOutput(
            \\export fn _start() noreturn {
            \\    print();
            \\
            \\    exit();
            \\}
            \\
            \\fn print() void {
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (1),
            \\          [arg1] "{rdi}" (1),
            \\          [arg2] "{rsi}" (@ptrToInt("Hello, World!\n")),
            \\          [arg3] "{rdx}" (14)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    return;
            \\}
            \\
            \\fn exit() noreturn {
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (231),
            \\          [arg1] "{rdi}" (0)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    unreachable;
            \\}
        ,
            "Hello, World!\n",
        );
        // Now change the message only
        case.addCompareOutput(
            \\export fn _start() noreturn {
            \\    print();
            \\
            \\    exit();
            \\}
            \\
            \\fn print() void {
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (1),
            \\          [arg1] "{rdi}" (1),
            \\          [arg2] "{rsi}" (@ptrToInt("What is up? This is a longer message that will force the data to be relocated in virtual address space.\n")),
            \\          [arg3] "{rdx}" (104)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    return;
            \\}
            \\
            \\fn exit() noreturn {
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (231),
            \\          [arg1] "{rdi}" (0)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    unreachable;
            \\}
        ,
            "What is up? This is a longer message that will force the data to be relocated in virtual address space.\n",
        );
        // Now we print it twice.
        case.addCompareOutput(
            \\export fn _start() noreturn {
            \\    print();
            \\    print();
            \\
            \\    exit();
            \\}
            \\
            \\fn print() void {
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (1),
            \\          [arg1] "{rdi}" (1),
            \\          [arg2] "{rsi}" (@ptrToInt("What is up? This is a longer message that will force the data to be relocated in virtual address space.\n")),
            \\          [arg3] "{rdx}" (104)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    return;
            \\}
            \\
            \\fn exit() noreturn {
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (231),
            \\          [arg1] "{rdi}" (0)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    unreachable;
            \\}
        ,
            \\What is up? This is a longer message that will force the data to be relocated in virtual address space.
            \\What is up? This is a longer message that will force the data to be relocated in virtual address space.
            \\
        );
    }

    {
        var case = ctx.exe("adding numbers");
        case.addCompareOutput(
            \\export fn _start() noreturn {
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (1),
            \\          [arg1] "{rdi}" (1),
            \\          [arg2] "{rsi}" (@ptrToInt("Hello, World!\n")),
            \\          [arg3] "{rdx}" (10 + 4)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    asm volatile ("syscall"
            \\        :
            \\        : [number] "{rax}" (@as(usize, 230) + @as(usize, 1)),
            \\          [arg1] "{rdi}" (0)
            \\        : "rcx", "r11", "memory"
            \\    );
            \\    unreachable;
            \\}
        ,
            "Hello, World!\n",
        );
    }
}
