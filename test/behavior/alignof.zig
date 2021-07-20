const std = @import("std");
const expect = std.testing.expect;
const builtin = @import("builtin");
const native_arch = builtin.cpu.arch;
const maxInt = std.math.maxInt;

const Foo = struct {
    x: u32,
    y: u32,
    z: u32,
};

test "@alignOf(T) before referencing T" {
    comptime try expect(@alignOf(Foo) != maxInt(usize));
    if (native_arch == .x86_64) {
        comptime try expect(@alignOf(Foo) == 4);
    }
}

test "comparison of @alignOf(T) against zero" {
    {
        const T = struct { x: u32 };
        try expect(!(@alignOf(T) == 0));
        try expect(@alignOf(T) != 0);
        try expect(!(@alignOf(T) < 0));
        try expect(!(@alignOf(T) <= 0));
        try expect(@alignOf(T) > 0);
        try expect(@alignOf(T) >= 0);
    }
    {
        const T = struct {};
        try expect(@alignOf(T) == 0);
        try expect(!(@alignOf(T) != 0));
        try expect(!(@alignOf(T) < 0));
        try expect(@alignOf(T) <= 0);
        try expect(!(@alignOf(T) > 0));
        try expect(@alignOf(T) >= 0);
    }
}
