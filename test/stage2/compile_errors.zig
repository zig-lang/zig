const TestContext = @import("../../src-self-hosted/test.zig").TestContext;
const std = @import("std");

const ErrorMsg = @import("../../src-self-hosted/Module.zig").ErrorMsg;

const linux_x64 = std.zig.CrossTarget{
    .cpu_arch = .x86_64,
    .os_tag = .linux,
};

pub fn addCases(ctx: *TestContext) !void {
    ctx.compileErrorZIR("call undefined local", linux_x64,
        \\@noreturn = primitive(noreturn)
        \\
        \\@start_fnty = fntype([], @noreturn, cc=Naked)
        \\@start = fn(@start_fnty, {
        \\  %0 = call(%test, [])
        \\})
 // TODO: address inconsistency in this message and the one in the next test
            , &[_][]const u8{":5:13: error: unrecognized identifier: %test"});

    ctx.compileErrorZIR("call with non-existent target", linux_x64,
        \\@noreturn = primitive(noreturn)
        \\
        \\@start_fnty = fntype([], @noreturn, cc=Naked)
        \\@start = fn(@start_fnty, {
        \\  %0 = call(@notafunc, [])
        \\})
        \\@0 = str("_start")
        \\@1 = export(@0, "start")
    , &[_][]const u8{":5:13: error: decl 'notafunc' not found"});

    // TODO: this error should occur at the call site, not the fntype decl
    ctx.compileErrorZIR("call naked function", linux_x64,
        \\@noreturn = primitive(noreturn)
        \\
        \\@start_fnty = fntype([], @noreturn, cc=Naked)
        \\@s = fn(@start_fnty, {})
        \\@start = fn(@start_fnty, {
        \\  %0 = call(@s, [])
        \\})
        \\@0 = str("_start")
        \\@1 = export(@0, "start")
    , &[_][]const u8{":4:9: error: unable to call function with naked calling convention"});

    ctx.incrementalFailureZIR("exported symbol collision", linux_x64,
        \\@noreturn = primitive(noreturn)
        \\
        \\@start_fnty = fntype([], @noreturn)
        \\@start = fn(@start_fnty, {})
        \\
        \\@0 = str("_start")
        \\@1 = export(@0, "start")
        \\@2 = export(@0, "start")
    , &[_][]const u8{":8:13: error: exported symbol collision: _start"},
        \\@noreturn = primitive(noreturn)
        \\
        \\@start_fnty = fntype([], @noreturn)
        \\@start = fn(@start_fnty, {})
        \\
        \\@0 = str("_start")
        \\@1 = export(@0, "start")
    );

    ctx.compileError("function redefinition", linux_x64,
        \\fn entry() void {}
        \\fn entry() void {}
    , &[_][]const u8{":2:4: error: redefinition of 'entry'"});

    //ctx.incrementalFailure("function redefinition", linux_x64,
    //    \\fn entry() void {}
    //    \\fn entry() void {}
    //, &[_][]const u8{":2:4: error: redefinition of 'entry'"},
    //    \\fn entry() void {}
    //);

    //// TODO: need to make sure this works with other variants of export.
    //ctx.incrementalFailure("exported symbol collision", linux_x64,
    //    \\export fn entry() void {}
    //    \\export fn entry() void {}
    //, &[_][]const u8{":2:11: error: redefinition of 'entry'"},
    //    \\export fn entry() void {}
    //);

    // ctx.incrementalFailure("missing function name", linux_x64,
    //     \\fn() void {}
    // , &[_][]const u8{":1:3: error: missing function name"},
    //     \\fn a() void {}
    // );

    ctx.compileErrorZIR("function call with args", linux_x64,
        \\@noreturn = primitive(noreturn)
        \\@void = primitive(void)
        \\@usize = primitive(usize)
        \\
        \\@0 = int(0)
        \\@1 = int(1)
        \\@2 = int(2)
        \\@3 = int(3)
        \\
        \\@rax = str("{rax}")
        \\@rdi = str("{rdi}")
        \\@rcx = str("rcx")
        \\@rdx = str("{rdx}")
        \\@rsi = str("{rsi}")
        \\@r11 = str("r11")
        \\@memory = str("memory")
        \\
        \\@sysoutreg = str("={rax}")
        \\
        \\@syscall = str("syscall")
        \\
        \\@write_fnty = fntype([@usize, @usize], @void, cc=C)
        \\@write = fn(@write_fnty, {
        \\  %0 = arg(0)
        \\  %1 = arg(1)
        \\
        \\  %SYS_write = as(@usize, @1)
        \\  %STDOUT_FILENO = as(@usize, @1)
        \\
        \\  %rc_write = asm(@syscall, @usize,
        \\    volatile=1,
        \\    output=@sysoutreg,
        \\    inputs=[@rax, @rdi, @rsi, @rdx],
        \\    clobbers=[@rcx, @r11, @memory],
        \\    args=[%SYS_write, %STDOUT_FILENO, %0, %1])
        \\})
        \\
        \\@start_fnty = fntype([], @noreturn, cc=Naked)
        \\@start = fn(@start_fnty, {
        \\  %SYS_exit_group = int(231)
        \\  %exit_code = as(@usize, @0)
        \\
        \\  %msg = str("Hello, world!\n")
        \\  %msg_addr = ptrtoint(%msg)
        \\  %len_name = str("len")
        \\  %msg_len_ptr = fieldptr(%msg, %len_name)
        \\  %msg_len = deref(%msg_len_ptr)
        \\
        \\  %nothing = call(@write, [%msg, %msg_len])
        \\
        \\  %rc_exit = asm(@syscall, @usize,
        \\    volatile=1,
        \\    output=@sysoutreg,
        \\    inputs=[@rax, @rdi],
        \\    clobbers=[@rcx, @r11, @memory],
        \\    args=[%SYS_exit_group, %exit_code])
        \\
        \\  %99 = unreachable()
        \\});
        \\
        \\@9 = str("_start")
        \\@11 = export(@9, "start")
    , &[_][]const u8{":49:19: error: expected usize, found *const [14:0]u8"});

    // TODO: re-enable these tests.
    // https://github.com/ziglang/zig/issues/1364

    //ctx.testCompileError(
    //    \\comptime {
    //    \\    return;
    //    \\}
    //, "1.zig", 2, 5, "return expression outside function definition");

    //ctx.testCompileError(
    //    \\export fn entry() void {
    //    \\    defer return;
    //    \\}
    //, "1.zig", 2, 11, "cannot return from defer expression");

    //ctx.testCompileError(
    //    \\export fn entry() c_int {
    //    \\    return 36893488147419103232;
    //    \\}
    //, "1.zig", 2, 12, "integer value '36893488147419103232' cannot be stored in type 'c_int'");

    //ctx.testCompileError(
    //    \\comptime {
    //    \\    var a: *align(4) align(4) i32 = 0;
    //    \\}
    //, "1.zig", 2, 22, "Extra align qualifier");

    //ctx.testCompileError(
    //    \\comptime {
    //    \\    var b: *const const i32 = 0;
    //    \\}
    //, "1.zig", 2, 19, "Extra align qualifier");

    //ctx.testCompileError(
    //    \\comptime {
    //    \\    var c: *volatile volatile i32 = 0;
    //    \\}
    //, "1.zig", 2, 22, "Extra align qualifier");

    //ctx.testCompileError(
    //    \\comptime {
    //    \\    var d: *allowzero allowzero i32 = 0;
    //    \\}
    //, "1.zig", 2, 23, "Extra align qualifier");
}
