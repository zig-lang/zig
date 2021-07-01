const std = @import("std");
const TestContext = @import("../../src/test.zig").TestContext;

const archs = [2]std.Target.Cpu.Arch{
    .aarch64, .x86_64,
};

pub fn addCases(ctx: *TestContext) !void {
    for (archs) |arch| {
        const target: std.zig.CrossTarget = .{
            .cpu_arch = arch,
            .os_tag = .macos,
        };
        {
            var case = ctx.exe("hello world with updates", target);
            case.addError("", &[_][]const u8{
                ":95:9: error: struct 'test_case.test_case' has no member named 'main'",
            });

            // Incorrect return type
            case.addError(
                \\pub export fn main() noreturn {
                \\}
            , &[_][]const u8{
                ":2:1: error: expected noreturn, found void",
            });

            // Regular old hello world
            case.addCompareOutput(
                \\extern "c" fn write(usize, usize, usize) usize;
                \\extern "c" fn exit(usize) noreturn;
                \\
                \\pub export fn main() noreturn {
                \\    print();
                \\
                \\    exit(0);
                \\}
                \\
                \\fn print() void {
                \\    const msg = @ptrToInt("Hello, World!\n");
                \\    const len = 14;
                \\    _ = write(1, msg, len);
                \\}
            ,
                "Hello, World!\n",
            );

            // Print it 4 times and force growth and realloc.
            case.addCompareOutput(
                \\extern "c" fn write(usize, usize, usize) usize;
                \\extern "c" fn exit(usize) noreturn;
                \\
                \\pub export fn main() noreturn {
                \\    print();
                \\    print();
                \\    print();
                \\    print();
                \\
                \\    exit(0);
                \\}
                \\
                \\fn print() void {
                \\    const msg = @ptrToInt("Hello, World!\n");
                \\    const len = 14;
                \\    _ = write(1, msg, len);
                \\}
            ,
                \\Hello, World!
                \\Hello, World!
                \\Hello, World!
                \\Hello, World!
                \\
            );

            // Print it once, and change the message.
            case.addCompareOutput(
                \\extern "c" fn write(usize, usize, usize) usize;
                \\extern "c" fn exit(usize) noreturn;
                \\
                \\pub export fn main() noreturn {
                \\    print();
                \\
                \\    exit(0);
                \\}
                \\
                \\fn print() void {
                \\    const msg = @ptrToInt("What is up? This is a longer message that will force the data to be relocated in virtual address space.\n");
                \\    const len = 104;
                \\    _ = write(1, msg, len);
                \\}
            ,
                "What is up? This is a longer message that will force the data to be relocated in virtual address space.\n",
            );

            // Now we print it twice.
            case.addCompareOutput(
                \\extern "c" fn write(usize, usize, usize) usize;
                \\extern "c" fn exit(usize) noreturn;
                \\
                \\pub export fn main() noreturn {
                \\    print();
                \\    print();
                \\
                \\    exit(0);
                \\}
                \\
                \\fn print() void {
                \\    const msg = @ptrToInt("What is up? This is a longer message that will force the data to be relocated in virtual address space.\n");
                \\    const len = 104;
                \\    _ = write(1, msg, len);
                \\}
            ,
                \\What is up? This is a longer message that will force the data to be relocated in virtual address space.
                \\What is up? This is a longer message that will force the data to be relocated in virtual address space.
                \\
            );
        }
        {
            var case = ctx.exe("corner case - update existing, singular TextBlock", target);

            // This test case also covers an infrequent scenarion where the string table *may* be relocated
            // into the position preceeding the symbol table which results in a dyld error.
            case.addCompareOutput(
                \\extern "c" fn exit(usize) noreturn;
                \\
                \\pub export fn main() noreturn {
                \\    exit(0);
                \\}
            ,
                "",
            );

            case.addCompareOutput(
                \\extern "c" fn exit(usize) noreturn;
                \\extern "c" fn write(usize, usize, usize) usize;
                \\
                \\pub export fn main() noreturn {
                \\    _ = write(1, @ptrToInt("Hey!\n"), 5);
                \\    exit(0);
                \\}
            ,
                "Hey!\n",
            );
        }
    }
}
