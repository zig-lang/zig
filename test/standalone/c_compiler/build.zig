const std = @import("std");
const builtin = @import("builtin");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;

fn isRunnableTarget(t: CrossTarget) bool {
    if (t.isNative()) return true;

    return (t.getOsTag() == builtin.os.tag and
        t.getCpuArch() == builtin.cpu.arch);
}

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const test_step = b.step("test", "Test the program");

    const exe_c = b.addExecutable("test_c", null);
    b.default_step.dependOn(&exe_c.step);
    exe_c.addCSourceFile("test.c", &[0][]const u8{});
    exe_c.setBuildMode(mode);
    exe_c.setTarget(target);
    exe_c.linkLibC();

    const exe_cpp = b.addExecutable("test_cpp", null);
    b.default_step.dependOn(&exe_cpp.step);
    exe_cpp.addCSourceFile("test.cpp", &[0][]const u8{});
    exe_cpp.setBuildMode(mode);
    exe_cpp.setTarget(target);
    exe_cpp.linkSystemLibrary("c++");

    // disable broken LTO links:
    switch (target.getOsTag()) {
        .windows => {
            exe_cpp.want_lto = false;
        },
        .macos => {
            exe_cpp.want_lto = false;
            exe_c.want_lto = false;
        },
        else => {},
    }

    if (isRunnableTarget(target)) {
        const run_c_cmd = exe_c.run();
        test_step.dependOn(&run_c_cmd.step);
        const run_cpp_cmd = exe_cpp.run();
        test_step.dependOn(&run_cpp_cmd.step);
    } else {
        test_step.dependOn(&exe_c.step);
        test_step.dependOn(&exe_cpp.step);
    }
}
