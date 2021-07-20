const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;

const TypeInfo = std.builtin.TypeInfo;
const TypeId = std.builtin.TypeId;

const expect = std.testing.expect;
const expectEqualStrings = std.testing.expectEqualStrings;

test "type info: tag type, void info" {
    try testBasic();
    comptime try testBasic();
}

fn testBasic() !void {
    try expect(@typeInfo(TypeInfo).Union.tag_type == TypeId);
    const void_info = @typeInfo(void);
    try expect(void_info == TypeId.Void);
    try expect(void_info.Void == {});
}

test "type info: integer, floating point type info" {
    try testIntFloat();
    comptime try testIntFloat();
}

fn testIntFloat() !void {
    const u8_info = @typeInfo(u8);
    try expect(u8_info == .Int);
    try expect(u8_info.Int.signedness == .unsigned);
    try expect(u8_info.Int.bits == 8);

    const f64_info = @typeInfo(f64);
    try expect(f64_info == .Float);
    try expect(f64_info.Float.bits == 64);
}

test "type info: pointer type info" {
    try testPointer();
    comptime try testPointer();
}

fn testPointer() !void {
    const u32_ptr_info = @typeInfo(*u32);
    try expect(u32_ptr_info == .Pointer);
    try expect(u32_ptr_info.Pointer.size == TypeInfo.Pointer.Size.One);
    try expect(u32_ptr_info.Pointer.is_const == false);
    try expect(u32_ptr_info.Pointer.is_volatile == false);
    try expect(u32_ptr_info.Pointer.alignment == @alignOf(u32));
    try expect(u32_ptr_info.Pointer.child == u32);
    try expect(u32_ptr_info.Pointer.sentinel == null);
}

test "type info: unknown length pointer type info" {
    try testUnknownLenPtr();
    comptime try testUnknownLenPtr();
}

fn testUnknownLenPtr() !void {
    const u32_ptr_info = @typeInfo([*]const volatile f64);
    try expect(u32_ptr_info == .Pointer);
    try expect(u32_ptr_info.Pointer.size == TypeInfo.Pointer.Size.Many);
    try expect(u32_ptr_info.Pointer.is_const == true);
    try expect(u32_ptr_info.Pointer.is_volatile == true);
    try expect(u32_ptr_info.Pointer.sentinel == null);
    try expect(u32_ptr_info.Pointer.alignment == @alignOf(f64));
    try expect(u32_ptr_info.Pointer.child == f64);
}

test "type info: null terminated pointer type info" {
    try testNullTerminatedPtr();
    comptime try testNullTerminatedPtr();
}

fn testNullTerminatedPtr() !void {
    const ptr_info = @typeInfo([*:0]u8);
    try expect(ptr_info == .Pointer);
    try expect(ptr_info.Pointer.size == TypeInfo.Pointer.Size.Many);
    try expect(ptr_info.Pointer.is_const == false);
    try expect(ptr_info.Pointer.is_volatile == false);
    try expect(ptr_info.Pointer.sentinel.? == 0);

    try expect(@typeInfo([:0]u8).Pointer.sentinel != null);
}

test "type info: C pointer type info" {
    try testCPtr();
    comptime try testCPtr();
}

fn testCPtr() !void {
    const ptr_info = @typeInfo([*c]align(4) const i8);
    try expect(ptr_info == .Pointer);
    try expect(ptr_info.Pointer.size == .C);
    try expect(ptr_info.Pointer.is_const);
    try expect(!ptr_info.Pointer.is_volatile);
    try expect(ptr_info.Pointer.alignment == 4);
    try expect(ptr_info.Pointer.child == i8);
}

test "type info: slice type info" {
    try testSlice();
    comptime try testSlice();
}

fn testSlice() !void {
    const u32_slice_info = @typeInfo([]u32);
    try expect(u32_slice_info == .Pointer);
    try expect(u32_slice_info.Pointer.size == .Slice);
    try expect(u32_slice_info.Pointer.is_const == false);
    try expect(u32_slice_info.Pointer.is_volatile == false);
    try expect(u32_slice_info.Pointer.alignment == 4);
    try expect(u32_slice_info.Pointer.child == u32);
}

test "type info: array type info" {
    try testArray();
    comptime try testArray();
}

fn testArray() !void {
    {
        const info = @typeInfo([42]u8);
        try expect(info == .Array);
        try expect(info.Array.len == 42);
        try expect(info.Array.child == u8);
        try expect(info.Array.sentinel == null);
    }

    {
        const info = @typeInfo([10:0]u8);
        try expect(info.Array.len == 10);
        try expect(info.Array.child == u8);
        try expect(info.Array.sentinel.? == @as(u8, 0));
        try expect(@sizeOf([10:0]u8) == info.Array.len + 1);
    }
}

test "type info: optional type info" {
    try testOptional();
    comptime try testOptional();
}

fn testOptional() !void {
    const null_info = @typeInfo(?void);
    try expect(null_info == .Optional);
    try expect(null_info.Optional.child == void);
}

test "type info: error set, error union info" {
    try testErrorSet();
    comptime try testErrorSet();
}

fn testErrorSet() !void {
    const TestErrorSet = error{
        First,
        Second,
        Third,
    };

    const error_set_info = @typeInfo(TestErrorSet);
    try expect(error_set_info == .ErrorSet);
    try expect(error_set_info.ErrorSet.?.len == 3);
    try expect(mem.eql(u8, error_set_info.ErrorSet.?[0].name, "First"));

    const error_union_info = @typeInfo(TestErrorSet!usize);
    try expect(error_union_info == .ErrorUnion);
    try expect(error_union_info.ErrorUnion.error_set == TestErrorSet);
    try expect(error_union_info.ErrorUnion.payload == usize);

    const global_info = @typeInfo(anyerror);
    try expect(global_info == .ErrorSet);
    try expect(global_info.ErrorSet == null);
}

test "type info: enum info" {
    try testEnum();
    comptime try testEnum();
}

fn testEnum() !void {
    const Os = enum {
        Windows,
        Macos,
        Linux,
        FreeBSD,
    };

    const os_info = @typeInfo(Os);
    try expect(os_info == .Enum);
    try expect(os_info.Enum.layout == .Auto);
    try expect(os_info.Enum.fields.len == 4);
    try expect(mem.eql(u8, os_info.Enum.fields[1].name, "Macos"));
    try expect(os_info.Enum.fields[3].value == 3);
    try expect(os_info.Enum.tag_type == u2);
    try expect(os_info.Enum.decls.len == 0);
}

test "type info: union info" {
    try testUnion();
    comptime try testUnion();
}

fn testUnion() !void {
    const typeinfo_info = @typeInfo(TypeInfo);
    try expect(typeinfo_info == .Union);
    try expect(typeinfo_info.Union.layout == .Auto);
    try expect(typeinfo_info.Union.tag_type.? == TypeId);
    try expect(typeinfo_info.Union.fields.len == 25);
    try expect(typeinfo_info.Union.fields[4].field_type == @TypeOf(@typeInfo(u8).Int));
    try expect(typeinfo_info.Union.decls.len == 22);

    const TestNoTagUnion = union {
        Foo: void,
        Bar: u32,
    };

    const notag_union_info = @typeInfo(TestNoTagUnion);
    try expect(notag_union_info == .Union);
    try expect(notag_union_info.Union.tag_type == null);
    try expect(notag_union_info.Union.layout == .Auto);
    try expect(notag_union_info.Union.fields.len == 2);
    try expect(notag_union_info.Union.fields[0].alignment == @alignOf(void));
    try expect(notag_union_info.Union.fields[1].field_type == u32);
    try expect(notag_union_info.Union.fields[1].alignment == @alignOf(u32));

    const TestExternUnion = extern union {
        foo: *c_void,
    };

    const extern_union_info = @typeInfo(TestExternUnion);
    try expect(extern_union_info.Union.layout == .Extern);
    try expect(extern_union_info.Union.tag_type == null);
    try expect(extern_union_info.Union.fields[0].field_type == *c_void);
}

test "type info: struct info" {
    try testStruct();
    comptime try testStruct();
}

fn testStruct() !void {
    const unpacked_struct_info = @typeInfo(TestUnpackedStruct);
    try expect(unpacked_struct_info.Struct.is_tuple == false);
    try expect(unpacked_struct_info.Struct.fields[0].alignment == @alignOf(u32));
    try expect(unpacked_struct_info.Struct.fields[0].default_value.? == 4);
    try expectEqualStrings("foobar", unpacked_struct_info.Struct.fields[1].default_value.?);

    const struct_info = @typeInfo(TestStruct);
    try expect(struct_info == .Struct);
    try expect(struct_info.Struct.is_tuple == false);
    try expect(struct_info.Struct.layout == .Packed);
    try expect(struct_info.Struct.fields.len == 4);
    try expect(struct_info.Struct.fields[0].alignment == 2 * @alignOf(usize));
    try expect(struct_info.Struct.fields[2].field_type == *TestStruct);
    try expect(struct_info.Struct.fields[2].default_value == null);
    try expect(struct_info.Struct.fields[3].default_value.? == 4);
    try expect(struct_info.Struct.fields[3].alignment == 1);
    try expect(struct_info.Struct.decls.len == 2);
    try expect(struct_info.Struct.decls[0].is_pub);
    try expect(!struct_info.Struct.decls[0].data.Fn.is_extern);
    try expect(struct_info.Struct.decls[0].data.Fn.lib_name == null);
    try expect(struct_info.Struct.decls[0].data.Fn.return_type == void);
    try expect(struct_info.Struct.decls[0].data.Fn.fn_type == fn (*const TestStruct) void);
}

const TestUnpackedStruct = struct {
    fieldA: u32 = 4,
    fieldB: *const [6:0]u8 = "foobar",
};

const TestStruct = packed struct {
    fieldA: usize align(2 * @alignOf(usize)),
    fieldB: void,
    fieldC: *Self,
    fieldD: u32 = 4,

    pub fn foo(self: *const Self) void {
        _ = self;
    }
    const Self = @This();
};

test "type info: opaque info" {
    try testOpaque();
    comptime try testOpaque();
}

fn testOpaque() !void {
    const Foo = opaque {
        const A = 1;
        fn b() void {}
    };

    const foo_info = @typeInfo(Foo);
    try expect(foo_info.Opaque.decls.len == 2);
}

test "type info: function type info" {
    // wasm doesn't support align attributes on functions
    if (builtin.cpu.arch == .wasm32 or builtin.cpu.arch == .wasm64) return error.SkipZigTest;
    try testFunction();
    comptime try testFunction();
}

fn testFunction() !void {
    const fn_info = @typeInfo(@TypeOf(foo));
    try expect(fn_info == .Fn);
    try expect(fn_info.Fn.alignment > 0);
    try expect(fn_info.Fn.calling_convention == .C);
    try expect(!fn_info.Fn.is_generic);
    try expect(fn_info.Fn.args.len == 2);
    try expect(fn_info.Fn.is_var_args);
    try expect(fn_info.Fn.return_type.? == usize);
    const fn_aligned_info = @typeInfo(@TypeOf(fooAligned));
    try expect(fn_aligned_info.Fn.alignment == 4);

    const test_instance: TestStruct = undefined;
    const bound_fn_info = @typeInfo(@TypeOf(test_instance.foo));
    try expect(bound_fn_info == .BoundFn);
    try expect(bound_fn_info.BoundFn.args[0].arg_type.? == *const TestStruct);
}

extern fn foo(a: usize, b: bool, ...) callconv(.C) usize;
extern fn fooAligned(a: usize, b: bool, ...) align(4) callconv(.C) usize;

test "typeInfo with comptime parameter in struct fn def" {
    const S = struct {
        pub fn func(comptime x: f32) void {
            _ = x;
        }
    };
    comptime var info = @typeInfo(S);
    _ = info;
}

test "type info: vectors" {
    try testVector();
    comptime try testVector();
}

fn testVector() !void {
    const vec_info = @typeInfo(std.meta.Vector(4, i32));
    try expect(vec_info == .Vector);
    try expect(vec_info.Vector.len == 4);
    try expect(vec_info.Vector.child == i32);
}

test "type info: anyframe and anyframe->T" {
    try testAnyFrame();
    comptime try testAnyFrame();
}

fn testAnyFrame() !void {
    {
        const anyframe_info = @typeInfo(anyframe->i32);
        try expect(anyframe_info == .AnyFrame);
        try expect(anyframe_info.AnyFrame.child.? == i32);
    }

    {
        const anyframe_info = @typeInfo(anyframe);
        try expect(anyframe_info == .AnyFrame);
        try expect(anyframe_info.AnyFrame.child == null);
    }
}

test "type info: pass to function" {
    _ = passTypeInfo(@typeInfo(void));
    _ = comptime passTypeInfo(@typeInfo(void));
}

fn passTypeInfo(comptime info: TypeInfo) type {
    _ = info;
    return void;
}

test "type info: TypeId -> TypeInfo impl cast" {
    _ = passTypeInfo(TypeId.Void);
    _ = comptime passTypeInfo(TypeId.Void);
}

test "type info: extern fns with and without lib names" {
    const S = struct {
        extern fn bar1() void;
        extern "cool" fn bar2() void;
    };
    const info = @typeInfo(S);
    comptime {
        for (info.Struct.decls) |decl| {
            if (std.mem.eql(u8, decl.name, "bar1")) {
                try expect(decl.data.Fn.lib_name == null);
            } else {
                try expectEqualStrings("cool", decl.data.Fn.lib_name.?);
            }
        }
    }
}

test "data field is a compile-time value" {
    const S = struct {
        const Bar = @as(isize, -1);
    };
    comptime try expect(@typeInfo(S).Struct.decls[0].data.Var == isize);
}

test "sentinel of opaque pointer type" {
    const c_void_info = @typeInfo(*c_void);
    try expect(c_void_info.Pointer.sentinel == null);
}

test "@typeInfo does not force declarations into existence" {
    const S = struct {
        x: i32,

        fn doNotReferenceMe() void {
            @compileError("test failed");
        }
    };
    comptime try expect(@typeInfo(S).Struct.fields.len == 1);
}

test "defaut value for a var-typed field" {
    const S = struct { x: anytype };
    try expect(@typeInfo(S).Struct.fields[0].default_value == null);
}

fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "type info for async frames" {
    switch (@typeInfo(@Frame(add))) {
        .Frame => |frame| {
            try expect(frame.function == add);
        },
        else => unreachable,
    }
}

test "type info: value is correctly copied" {
    comptime {
        var ptrInfo = @typeInfo([]u32);
        ptrInfo.Pointer.size = .One;
        try expect(@typeInfo([]u32).Pointer.size == .Slice);
    }
}

test "Declarations are returned in declaration order" {
    const S = struct {
        const a = 1;
        const b = 2;
        const c = 3;
        const d = 4;
        const e = 5;
    };
    const d = @typeInfo(S).Struct.decls;
    try expect(std.mem.eql(u8, d[0].name, "a"));
    try expect(std.mem.eql(u8, d[1].name, "b"));
    try expect(std.mem.eql(u8, d[2].name, "c"));
    try expect(std.mem.eql(u8, d[3].name, "d"));
    try expect(std.mem.eql(u8, d[4].name, "e"));
}

test "Struct.is_tuple" {
    try expect(@typeInfo(@TypeOf(.{0})).Struct.is_tuple);
    try expect(!@typeInfo(@TypeOf(.{ .a = 0 })).Struct.is_tuple);
}

test "StructField.is_comptime" {
    const info = @typeInfo(struct { x: u8 = 3, comptime y: u32 = 5 }).Struct;
    try expect(!info.fields[0].is_comptime);
    try expect(info.fields[1].is_comptime);
}

test "typeInfo resolves usingnamespace declarations" {
    const A = struct {
        pub const f1 = 42;
    };

    const B = struct {
        const f0 = 42;
        usingnamespace A;
    };

    try expect(@typeInfo(B).Struct.decls.len == 2);
    //a
}
