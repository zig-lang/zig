const std = @import("std");
const expect = std.testing.expect;

test "namespace depends on compile var" {
    if (some_namespace.a_bool) {
        try expect(some_namespace.a_bool);
    } else {
        try expect(!some_namespace.a_bool);
    }
}
const some_namespace = switch (@import("builtin").os.tag) {
    .linux => @import("namespace_depends_on_compile_var/a.zig"),
    else => @import("namespace_depends_on_compile_var/b.zig"),
};
