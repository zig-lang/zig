const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) !void {
    if (b.option(bool, "android", "build for android") orelse false) {
        if (comptime @import("std").builtin.hasPkg("androidbuild")) {
            std.log.info("we have and need the 'androidbuild' package", .{});
            const androidbuild = @import("androidbuild");
            const options = androidbuild.getApkOptions(b);
            std.log.info("options = {}\n", .{options});
            try androidbuild.makeApk(b, options);
        } else {
            std.log.err("missing package 'androidbuild'", .{});
            return error.MissingPackage;
        }
    } else {
        std.log.info("android not enabled, 'androidbuild' package not needed", .{});
    }
}
