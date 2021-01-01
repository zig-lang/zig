const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const target = .{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .msvc,
    };
    _ = b.standardReleaseOptions();
    const obj = b.addObject("issue_5825", "main.zig");
    obj.setTarget(target);

    const exe = b.addExecutable("issue_5825", null);
    exe.subsystem = .Console;
    exe.linkSystemLibrary("kernel32");
    exe.linkSystemLibrary("ntdll");
    exe.setTarget(target);
    exe.addObject(obj);

    const test_step = b.step("test", "Test the program");
    test_step.dependOn(&exe.step);
}
