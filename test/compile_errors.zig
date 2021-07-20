const std = @import("std");
const builtin = @import("builtin");
const TestContext = @import("../src/test.zig").TestContext;

pub fn addCases(ctx: *TestContext) !void {
    ctx.objErrStage1("issue #9346: return outside of function scope",
        \\pub const empty = return 1;
    , &.{"tmp.zig:1:19: error: 'return' outside function scope"});

    ctx.exeErrStage1("std.fmt error for unused arguments",
        \\pub fn main() !void {
        \\    @import("std").debug.print("{d} {d} {d} {d} {d}", .{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
        \\}
    , &.{
        "?:?:?: error: 10 unused arguments in '{d} {d} {d} {d} {d}'",
    });

    ctx.objErrStage1("lazy pointer with undefined element type",
        \\export fn foo() void {
        \\    comptime var T: type = undefined;
        \\    const S = struct { x: *T };
        \\    const I = @typeInfo(S);
        \\    _ = I;
        \\}
    , &[_][]const u8{
        ":3:28: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("pointer arithmetic on pointer-to-array",
        \\export fn foo() void {
        \\    var x: [10]u8 = undefined;
        \\    var y = &x;
        \\    var z = y + 1;
        \\    _ = z;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:17: error: integer value 1 cannot be coerced to type '*[10]u8'",
    });

    ctx.objErrStage1("pointer attributes checked when coercing pointer to anon literal",
        \\comptime {
        \\    const c: [][]const u8 = &.{"hello", "world" };
        \\    _ = c;
        \\}
        \\comptime {
        \\    const c: *[2][]const u8 = &.{"hello", "world" };
        \\    _ = c;
        \\}
        \\const S = struct {a: u8 = 1, b: u32 = 2};
        \\comptime {
        \\    const c: *S = &.{};
        \\    _ = c;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:31: error: expected type '[][]const u8', found '*const struct:2:31'",
        "tmp.zig:6:33: error: expected type '*[2][]const u8', found '*const struct:6:33'",
        "tmp.zig:11:21: error: expected type '*S', found '*const struct:11:21'",
    });

    ctx.objErrStage1("@Type() union payload is undefined",
        \\const Foo = @Type(@import("std").builtin.TypeInfo{
        \\    .Struct = undefined,
        \\});
        \\comptime { _ = Foo; }
    , &[_][]const u8{
        "tmp.zig:1:50: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("wrong initializer for union payload of type 'type'",
        \\const U = union(enum) {
        \\    A: type,
        \\};
        \\const S = struct {
        \\    u: U,
        \\};
        \\export fn entry() void {
        \\    comptime var v: S = undefined;
        \\    v.u.A = U{ .A = i32 };
        \\}
    , &[_][]const u8{
        "tmp.zig:9:8: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("union with too small explicit signed tag type",
        \\const U = union(enum(i2)) {
        \\    A: u8,
        \\    B: u8,
        \\    C: u8,
        \\    D: u8,
        \\};
        \\export fn entry() void {
        \\    _ = U{ .D = 1 };
        \\}
    , &[_][]const u8{
        "tmp.zig:1:22: error: specified integer tag type cannot represent every field",
        "tmp.zig:1:22: note: type i2 cannot fit values in range 0...3",
    });

    ctx.objErrStage1("union with too small explicit unsigned tag type",
        \\const U = union(enum(u2)) {
        \\    A: u8,
        \\    B: u8,
        \\    C: u8,
        \\    D: u8,
        \\    E: u8,
        \\};
        \\export fn entry() void {
        \\    _ = U{ .E = 1 };
        \\}
    , &[_][]const u8{
        "tmp.zig:1:22: error: specified integer tag type cannot represent every field",
        "tmp.zig:1:22: note: type u2 cannot fit values in range 0...4",
    });

    {
        const case = ctx.obj("callconv(.Interrupt) on unsupported platform", .{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\export fn entry() callconv(.Interrupt) void {}
        , &[_][]const u8{
            "tmp.zig:1:28: error: callconv 'Interrupt' is only available on x86, x86_64, AVR, and MSP430, not aarch64",
        });
    }
    {
        var case = ctx.obj("callconv(.Signal) on unsupported platform", .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\export fn entry() callconv(.Signal) void {}
        , &[_][]const u8{
            "tmp.zig:1:28: error: callconv 'Signal' is only available on AVR, not x86_64",
        });
    }
    {
        const case = ctx.obj("callconv(.Stdcall, .Fastcall, .Thiscall) on unsupported platform", .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\const F1 = fn () callconv(.Stdcall) void;
            \\const F2 = fn () callconv(.Fastcall) void;
            \\const F3 = fn () callconv(.Thiscall) void;
            \\export fn entry1() void { var a: F1 = undefined; _ = a; }
            \\export fn entry2() void { var a: F2 = undefined; _ = a; }
            \\export fn entry3() void { var a: F3 = undefined; _ = a; }
        , &[_][]const u8{
            "tmp.zig:1:27: error: callconv 'Stdcall' is only available on x86, not x86_64",
            "tmp.zig:2:27: error: callconv 'Fastcall' is only available on x86, not x86_64",
            "tmp.zig:3:27: error: callconv 'Thiscall' is only available on x86, not x86_64",
        });
    }
    {
        const case = ctx.obj("callconv(.Stdcall, .Fastcall, .Thiscall) on unsupported platform", .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\export fn entry1() callconv(.Stdcall) void {}
            \\export fn entry2() callconv(.Fastcall) void {}
            \\export fn entry3() callconv(.Thiscall) void {}
        , &[_][]const u8{
            "tmp.zig:1:29: error: callconv 'Stdcall' is only available on x86, not x86_64",
            "tmp.zig:2:29: error: callconv 'Fastcall' is only available on x86, not x86_64",
            "tmp.zig:3:29: error: callconv 'Thiscall' is only available on x86, not x86_64",
        });
    }
    {
        const case = ctx.obj("callconv(.Vectorcall) on unsupported platform", .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\export fn entry() callconv(.Vectorcall) void {}
        , &[_][]const u8{
            "tmp.zig:1:28: error: callconv 'Vectorcall' is only available on x86 and AArch64, not x86_64",
        });
    }
    {
        const case = ctx.obj("callconv(.APCS, .AAPCS, .AAPCSVFP) on unsupported platform", .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\export fn entry1() callconv(.APCS) void {}
            \\export fn entry2() callconv(.AAPCS) void {}
            \\export fn entry3() callconv(.AAPCSVFP) void {}
        , &[_][]const u8{
            "tmp.zig:1:29: error: callconv 'APCS' is only available on ARM, not x86_64",
            "tmp.zig:2:29: error: callconv 'AAPCS' is only available on ARM, not x86_64",
            "tmp.zig:3:29: error: callconv 'AAPCSVFP' is only available on ARM, not x86_64",
        });
    }

    ctx.objErrStage1("unreachable executed at comptime",
        \\fn foo(comptime x: i32) i32 {
        \\    comptime {
        \\        if (x >= 0) return -x;
        \\        unreachable;
        \\    }
        \\}
        \\export fn entry() void {
        \\    _ = foo(-42);
        \\}
    , &[_][]const u8{
        "tmp.zig:4:9: error: reached unreachable code",
        "tmp.zig:8:12: note: called from here",
    });

    ctx.objErrStage1("@Type with TypeInfo.Int",
        \\const builtin = @import("std").builtin;
        \\export fn entry() void {
        \\    _ = @Type(builtin.TypeInfo.Int {
        \\        .signedness = .signed,
        \\        .bits = 8,
        \\    });
        \\}
    , &[_][]const u8{
        "tmp.zig:3:36: error: expected type 'std.builtin.TypeInfo', found 'std.builtin.Int'",
    });

    ctx.objErrStage1("indexing a undefined slice at comptime",
        \\comptime {
        \\    var slice: []u8 = undefined;
        \\    slice[0] = 2;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:10: error: index 0 outside slice of size 0",
    });

    ctx.objErrStage1("array in c exported function",
        \\export fn zig_array(x: [10]u8) void {
        \\try expect(std.mem.eql(u8, &x, "1234567890"));
        \\}
        \\
        \\export fn zig_return_array() [10]u8 {
        \\    return "1234567890".*;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:24: error: parameter of type '[10]u8' not allowed in function with calling convention 'C'",
        "tmp.zig:5:30: error: return type '[10]u8' not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("@Type for exhaustive enum with undefined tag type",
        \\const TypeInfo = @import("std").builtin.TypeInfo;
        \\const Tag = @Type(.{
        \\    .Enum = .{
        \\        .layout = .Auto,
        \\        .tag_type = undefined,
        \\        .fields = &[_]TypeInfo.EnumField{},
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\        .is_exhaustive = false,
        \\    },
        \\});
        \\export fn entry() void {
        \\    _ = @intToEnum(Tag, 0);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:20: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("extern struct with non-extern-compatible integer tag type",
        \\pub const E = enum(u31) { A, B, C };
        \\pub const S = extern struct {
        \\    e: E,
        \\};
        \\export fn entry() void {
        \\    const s: S = undefined;
        \\    _ = s;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: extern structs cannot contain fields of type 'E'",
    });

    ctx.objErrStage1("@Type for exhaustive enum with non-integer tag type",
        \\const TypeInfo = @import("std").builtin.TypeInfo;
        \\const Tag = @Type(.{
        \\    .Enum = .{
        \\        .layout = .Auto,
        \\        .tag_type = bool,
        \\        .fields = &[_]TypeInfo.EnumField{},
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\        .is_exhaustive = false,
        \\    },
        \\});
        \\export fn entry() void {
        \\    _ = @intToEnum(Tag, 0);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:20: error: TypeInfo.Enum.tag_type must be an integer type, not 'bool'",
    });

    ctx.objErrStage1("extern struct with extern-compatible but inferred integer tag type",
        \\pub const E = enum {
        \\@"0",@"1",@"2",@"3",@"4",@"5",@"6",@"7",@"8",@"9",@"10",@"11",@"12",
        \\@"13",@"14",@"15",@"16",@"17",@"18",@"19",@"20",@"21",@"22",@"23",
        \\@"24",@"25",@"26",@"27",@"28",@"29",@"30",@"31",@"32",@"33",@"34",
        \\@"35",@"36",@"37",@"38",@"39",@"40",@"41",@"42",@"43",@"44",@"45",
        \\@"46",@"47",@"48",@"49",@"50",@"51",@"52",@"53",@"54",@"55",@"56",
        \\@"57",@"58",@"59",@"60",@"61",@"62",@"63",@"64",@"65",@"66",@"67",
        \\@"68",@"69",@"70",@"71",@"72",@"73",@"74",@"75",@"76",@"77",@"78",
        \\@"79",@"80",@"81",@"82",@"83",@"84",@"85",@"86",@"87",@"88",@"89",
        \\@"90",@"91",@"92",@"93",@"94",@"95",@"96",@"97",@"98",@"99",@"100",
        \\@"101",@"102",@"103",@"104",@"105",@"106",@"107",@"108",@"109",
        \\@"110",@"111",@"112",@"113",@"114",@"115",@"116",@"117",@"118",
        \\@"119",@"120",@"121",@"122",@"123",@"124",@"125",@"126",@"127",
        \\@"128",@"129",@"130",@"131",@"132",@"133",@"134",@"135",@"136",
        \\@"137",@"138",@"139",@"140",@"141",@"142",@"143",@"144",@"145",
        \\@"146",@"147",@"148",@"149",@"150",@"151",@"152",@"153",@"154",
        \\@"155",@"156",@"157",@"158",@"159",@"160",@"161",@"162",@"163",
        \\@"164",@"165",@"166",@"167",@"168",@"169",@"170",@"171",@"172",
        \\@"173",@"174",@"175",@"176",@"177",@"178",@"179",@"180",@"181",
        \\@"182",@"183",@"184",@"185",@"186",@"187",@"188",@"189",@"190",
        \\@"191",@"192",@"193",@"194",@"195",@"196",@"197",@"198",@"199",
        \\@"200",@"201",@"202",@"203",@"204",@"205",@"206",@"207",@"208",
        \\@"209",@"210",@"211",@"212",@"213",@"214",@"215",@"216",@"217",
        \\@"218",@"219",@"220",@"221",@"222",@"223",@"224",@"225",@"226",
        \\@"227",@"228",@"229",@"230",@"231",@"232",@"233",@"234",@"235",
        \\@"236",@"237",@"238",@"239",@"240",@"241",@"242",@"243",@"244",
        \\@"245",@"246",@"247",@"248",@"249",@"250",@"251",@"252",@"253",
        \\@"254",@"255"
        \\};
        \\pub const S = extern struct {
        \\    e: E,
        \\};
        \\export fn entry() void {
        \\    if (@typeInfo(E).Enum.tag_type != u8) @compileError("did not infer u8 tag type");
        \\    const s: S = undefined;
        \\    _ = s;
        \\}
    , &[_][]const u8{
        "tmp.zig:31:5: error: extern structs cannot contain fields of type 'E'",
    });

    ctx.objErrStage1("@Type for tagged union with extra enum field",
        \\const TypeInfo = @import("std").builtin.TypeInfo;
        \\const Tag = @Type(.{
        \\    .Enum = .{
        \\        .layout = .Auto,
        \\        .tag_type = u2,
        \\        .fields = &[_]TypeInfo.EnumField{
        \\            .{ .name = "signed", .value = 0 },
        \\            .{ .name = "unsigned", .value = 1 },
        \\            .{ .name = "arst", .value = 2 },
        \\        },
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\        .is_exhaustive = true,
        \\    },
        \\});
        \\const Tagged = @Type(.{
        \\    .Union = .{
        \\        .layout = .Auto,
        \\        .tag_type = Tag,
        \\        .fields = &[_]TypeInfo.UnionField{
        \\            .{ .name = "signed", .field_type = i32, .alignment = @alignOf(i32) },
        \\            .{ .name = "unsigned", .field_type = u32, .alignment = @alignOf(u32) },
        \\        },
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\    },
        \\});
        \\export fn entry() void {
        \\    var tagged = Tagged{ .signed = -1 };
        \\    tagged = .{ .unsigned = 1 };
        \\}
    , &[_][]const u8{
        "tmp.zig:15:23: error: enum field missing: 'arst'",
        "tmp.zig:27:24: note: referenced here",
    });

    ctx.objErrStage1("field access of opaque type",
        \\const MyType = opaque {};
        \\
        \\export fn entry() bool {
        \\    var x: i32 = 1;
        \\    return bar(@ptrCast(*MyType, &x));
        \\}
        \\
        \\fn bar(x: *MyType) bool {
        \\    return x.blah;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:13: error: no member named 'blah' in opaque type 'MyType'",
    });

    ctx.objErrStage1("opaque type with field",
        \\const Opaque = opaque { foo: i32 };
        \\export fn entry() void {
        \\    const foo: ?*Opaque = null;
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:25: error: opaque types cannot have fields",
    });

    ctx.objErrStage1("@Type(.Fn) with is_generic = true",
        \\const Foo = @Type(.{
        \\    .Fn = .{
        \\        .calling_convention = .Unspecified,
        \\        .alignment = 0,
        \\        .is_generic = true,
        \\        .is_var_args = false,
        \\        .return_type = u0,
        \\        .args = &[_]@import("std").builtin.TypeInfo.FnArg{},
        \\    },
        \\});
        \\comptime { _ = Foo; }
    , &[_][]const u8{
        "tmp.zig:1:20: error: TypeInfo.Fn.is_generic must be false for @Type",
    });

    ctx.objErrStage1("@Type(.Fn) with is_var_args = true and non-C callconv",
        \\const Foo = @Type(.{
        \\    .Fn = .{
        \\        .calling_convention = .Unspecified,
        \\        .alignment = 0,
        \\        .is_generic = false,
        \\        .is_var_args = true,
        \\        .return_type = u0,
        \\        .args = &[_]@import("std").builtin.TypeInfo.FnArg{},
        \\    },
        \\});
        \\comptime { _ = Foo; }
    , &[_][]const u8{
        "tmp.zig:1:20: error: varargs functions must have C calling convention",
    });

    ctx.objErrStage1("@Type(.Fn) with return_type = null",
        \\const Foo = @Type(.{
        \\    .Fn = .{
        \\        .calling_convention = .Unspecified,
        \\        .alignment = 0,
        \\        .is_generic = false,
        \\        .is_var_args = false,
        \\        .return_type = null,
        \\        .args = &[_]@import("std").builtin.TypeInfo.FnArg{},
        \\    },
        \\});
        \\comptime { _ = Foo; }
    , &[_][]const u8{
        "tmp.zig:1:20: error: TypeInfo.Fn.return_type must be non-null for @Type",
    });

    ctx.objErrStage1("@Type for union with opaque field",
        \\const TypeInfo = @import("std").builtin.TypeInfo;
        \\const Untagged = @Type(.{
        \\    .Union = .{
        \\        .layout = .Auto,
        \\        .tag_type = null,
        \\        .fields = &[_]TypeInfo.UnionField{
        \\            .{ .name = "foo", .field_type = opaque {}, .alignment = 1 },
        \\        },
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\    },
        \\});
        \\export fn entry() void {
        \\    _ = Untagged{};
        \\}
    , &[_][]const u8{
        "tmp.zig:2:25: error: opaque types have unknown size and therefore cannot be directly embedded in unions",
        "tmp.zig:13:17: note: referenced here",
    });

    ctx.objErrStage1("slice sentinel mismatch",
        \\export fn entry() void {
        \\    const x = @import("std").meta.Vector(3, f32){ 25, 75, 5, 0 };
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:62: error: index 3 outside vector of size 3",
    });

    ctx.objErrStage1("slice sentinel mismatch",
        \\export fn entry() void {
        \\    const y: [:1]const u8 = &[_:2]u8{ 1, 2 };
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:37: error: expected type '[:1]const u8', found '*const [2:2]u8'",
    });

    ctx.objErrStage1("@Type for union with zero fields",
        \\const TypeInfo = @import("std").builtin.TypeInfo;
        \\const Untagged = @Type(.{
        \\    .Union = .{
        \\        .layout = .Auto,
        \\        .tag_type = null,
        \\        .fields = &[_]TypeInfo.UnionField{},
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\    },
        \\});
        \\export fn entry() void {
        \\    _ = Untagged{};
        \\}
    , &[_][]const u8{
        "tmp.zig:2:25: error: unions must have 1 or more fields",
        "tmp.zig:11:17: note: referenced here",
    });

    ctx.objErrStage1("@Type for exhaustive enum with zero fields",
        \\const TypeInfo = @import("std").builtin.TypeInfo;
        \\const Tag = @Type(.{
        \\    .Enum = .{
        \\        .layout = .Auto,
        \\        .tag_type = u1,
        \\        .fields = &[_]TypeInfo.EnumField{},
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\        .is_exhaustive = true,
        \\    },
        \\});
        \\export fn entry() void {
        \\    _ = @intToEnum(Tag, 0);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:20: error: enums must have 1 or more fields",
        "tmp.zig:12:9: note: referenced here",
    });

    ctx.objErrStage1("@Type for tagged union with extra union field",
        \\const TypeInfo = @import("std").builtin.TypeInfo;
        \\const Tag = @Type(.{
        \\    .Enum = .{
        \\        .layout = .Auto,
        \\        .tag_type = u1,
        \\        .fields = &[_]TypeInfo.EnumField{
        \\            .{ .name = "signed", .value = 0 },
        \\            .{ .name = "unsigned", .value = 1 },
        \\        },
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\        .is_exhaustive = true,
        \\    },
        \\});
        \\const Tagged = @Type(.{
        \\    .Union = .{
        \\        .layout = .Auto,
        \\        .tag_type = Tag,
        \\        .fields = &[_]TypeInfo.UnionField{
        \\            .{ .name = "signed", .field_type = i32, .alignment = @alignOf(i32) },
        \\            .{ .name = "unsigned", .field_type = u32, .alignment = @alignOf(u32) },
        \\            .{ .name = "arst", .field_type = f32, .alignment = @alignOf(f32) },
        \\        },
        \\        .decls = &[_]TypeInfo.Declaration{},
        \\    },
        \\});
        \\export fn entry() void {
        \\    var tagged = Tagged{ .signed = -1 };
        \\    tagged = .{ .unsigned = 1 };
        \\}
    , &[_][]const u8{
        "tmp.zig:14:23: error: enum field not found: 'arst'",
        "tmp.zig:2:20: note: enum declared here",
        "tmp.zig:27:24: note: referenced here",
    });

    ctx.objErrStage1("@Type with undefined",
        \\comptime {
        \\    _ = @Type(.{ .Array = .{ .len = 0, .child = u8, .sentinel = undefined } });
        \\}
        \\comptime {
        \\    _ = @Type(.{
        \\        .Struct = .{
        \\            .fields = undefined,
        \\            .decls = undefined,
        \\            .is_tuple = false,
        \\            .layout = .Auto,
        \\        },
        \\    });
        \\}
    , &[_][]const u8{
        "tmp.zig:2:16: error: use of undefined value here causes undefined behavior",
        "tmp.zig:5:16: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("struct with declarations unavailable for @Type",
        \\export fn entry() void {
        \\    _ = @Type(@typeInfo(struct { const foo = 1; }));
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: TypeInfo.Struct.decls must be empty for @Type",
    });

    ctx.objErrStage1("enum with declarations unavailable for @Type",
        \\export fn entry() void {
        \\    _ = @Type(@typeInfo(enum { foo, const bar = 1; }));
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: TypeInfo.Enum.decls must be empty for @Type",
    });

    ctx.testErrStage1("reject extern variables with initializers",
        \\extern var foo: int = 2;
    , &[_][]const u8{
        "tmp.zig:1:23: error: extern variables have no initializers",
    });

    ctx.testErrStage1("duplicate/unused labels",
        \\comptime {
        \\    blk: { blk: while (false) {} }
        \\}
        \\comptime {
        \\    blk: while (false) { blk: for (@as([0]void, undefined)) |_| {} }
        \\}
        \\comptime {
        \\    blk: for (@as([0]void, undefined)) |_| { blk: {} }
        \\}
        \\comptime {
        \\    blk: {}
        \\}
        \\comptime {
        \\    blk: while(false) {}
        \\}
        \\comptime {
        \\    blk: for(@as([0]void, undefined)) |_| {}
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: redefinition of label 'blk'",
        "tmp.zig:2:5: note: previous definition here",
        "tmp.zig:5:26: error: redefinition of label 'blk'",
        "tmp.zig:5:5: note: previous definition here",
        "tmp.zig:8:46: error: redefinition of label 'blk'",
        "tmp.zig:8:5: note: previous definition here",
        "tmp.zig:11:5: error: unused block label",
        "tmp.zig:14:5: error: unused while loop label",
        "tmp.zig:17:5: error: unused for loop label",
    });

    ctx.testErrStage1("@alignCast of zero sized types",
        \\export fn foo() void {
        \\    const a: *void = undefined;
        \\    _ = @alignCast(2, a);
        \\}
        \\export fn bar() void {
        \\    const a: ?*void = undefined;
        \\    _ = @alignCast(2, a);
        \\}
        \\export fn baz() void {
        \\    const a: []void = undefined;
        \\    _ = @alignCast(2, a);
        \\}
        \\export fn qux() void {
        \\    const a = struct {
        \\        fn a(comptime b: u32) void { _ = b; }
        \\    }.a;
        \\    _ = @alignCast(2, a);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:23: error: cannot adjust alignment of zero sized type '*void'",
        "tmp.zig:7:23: error: cannot adjust alignment of zero sized type '?*void'",
        "tmp.zig:11:23: error: cannot adjust alignment of zero sized type '[]void'",
        "tmp.zig:17:23: error: cannot adjust alignment of zero sized type 'fn(u32) anytype'",
    });

    ctx.testErrStage1("invalid non-exhaustive enum to union",
        \\const E = enum(u8) {
        \\    a,
        \\    b,
        \\    _,
        \\};
        \\const U = union(E) {
        \\    a,
        \\    b,
        \\};
        \\export fn foo() void {
        \\    var e = @intToEnum(E, 15);
        \\    var u: U = e;
        \\    _ = u;
        \\}
        \\export fn bar() void {
        \\    const e = @intToEnum(E, 15);
        \\    var u: U = e;
        \\    _ = u;
        \\}
    , &[_][]const u8{
        "tmp.zig:12:16: error: runtime cast to union 'U' from non-exhustive enum",
        "tmp.zig:17:16: error: no tag by value 15",
    });

    ctx.testErrStage1("switching with exhaustive enum has '_' prong ",
        \\const E = enum{
        \\    a,
        \\    b,
        \\};
        \\pub export fn entry() void {
        \\    var e: E = .b;
        \\    switch (e) {
        \\        .a => {},
        \\        .b => {},
        \\        _ => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:7:5: error: switch on exhaustive enum has `_` prong",
    });

    ctx.testErrStage1("invalid pointer with @Type",
        \\export fn entry() void {
        \\    _ = @Type(.{ .Pointer = .{
        \\        .size = .One,
        \\        .is_const = false,
        \\        .is_volatile = false,
        \\        .alignment = 1,
        \\        .child = u8,
        \\        .is_allowzero = false,
        \\        .sentinel = 0,
        \\    }});
        \\}
    , &[_][]const u8{
        "tmp.zig:2:16: error: sentinels are only allowed on slices and unknown-length pointers",
    });

    ctx.testErrStage1("helpful return type error message",
        \\export fn foo() u32 {
        \\    return error.Ohno;
        \\}
        \\fn bar() !u32 {
        \\    return error.Ohno;
        \\}
        \\export fn baz() void {
        \\    try bar();
        \\}
        \\export fn qux() u32 {
        \\    return bar();
        \\}
        \\export fn quux() u32 {
        \\    var buf: u32 = 0;
        \\    buf = bar();
        \\}
    , &[_][]const u8{
        "tmp.zig:2:17: error: expected type 'u32', found 'error{Ohno}'",
        "tmp.zig:1:17: note: function cannot return an error",
        "tmp.zig:8:5: error: expected type 'void', found '@typeInfo(@typeInfo(@TypeOf(bar)).Fn.return_type.?).ErrorUnion.error_set'",
        "tmp.zig:7:17: note: function cannot return an error",
        "tmp.zig:11:15: error: expected type 'u32', found '@typeInfo(@typeInfo(@TypeOf(bar)).Fn.return_type.?).ErrorUnion.error_set!u32'",
        "tmp.zig:10:17: note: function cannot return an error",
        "tmp.zig:15:14: error: expected type 'u32', found '@typeInfo(@typeInfo(@TypeOf(bar)).Fn.return_type.?).ErrorUnion.error_set!u32'",
        "tmp.zig:14:5: note: cannot store an error in type 'u32'",
    });

    ctx.testErrStage1("int/float conversion to comptime_int/float",
        \\export fn foo() void {
        \\    var a: f32 = 2;
        \\    _ = @floatToInt(comptime_int, a);
        \\}
        \\export fn bar() void {
        \\    var a: u32 = 2;
        \\    _ = @intToFloat(comptime_float, a);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:35: error: unable to evaluate constant expression",
        "tmp.zig:3:9: note: referenced here",
        "tmp.zig:7:37: error: unable to evaluate constant expression",
        "tmp.zig:7:9: note: referenced here",
    });

    ctx.objErrStage1("extern variable has no type",
        \\extern var foo;
        \\pub export fn entry() void {
        \\    foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:8: error: unable to infer variable type",
    });

    ctx.objErrStage1("@src outside function",
        \\comptime {
        \\    @src();
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: @src outside function",
    });

    ctx.objErrStage1("call assigned to constant",
        \\const Foo = struct {
        \\    x: i32,
        \\};
        \\fn foo() Foo {
        \\    return .{ .x = 42 };
        \\}
        \\fn bar(val: anytype) Foo {
        \\    return .{ .x = val };
        \\}
        \\export fn entry() void {
        \\    const baz: Foo = undefined;
        \\    baz = foo();
        \\}
        \\export fn entry1() void {
        \\    const baz: Foo = undefined;
        \\    baz = bar(42);
        \\}
    , &[_][]const u8{
        "tmp.zig:12:14: error: cannot assign to constant",
        "tmp.zig:16:14: error: cannot assign to constant",
    });

    ctx.objErrStage1("invalid pointer syntax",
        \\export fn foo() void {
        \\    var guid: *:0 const u8 = undefined;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:16: error: expected type expression, found ':'",
    });

    ctx.objErrStage1("declaration between fields",
        \\const S = struct {
        \\    const foo = 2;
        \\    const bar = 2;
        \\    const baz = 2;
        \\    a: usize,
        \\    const foo1 = 2;
        \\    const bar1 = 2;
        \\    const baz1 = 2;
        \\    b: usize,
        \\};
        \\comptime {
        \\    _ = S;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:5: error: declarations are not allowed between container fields",
    });

    ctx.objErrStage1("non-extern function with var args",
        \\fn foo(args: ...) void {}
        \\export fn entry() void {
        \\    foo();
        \\}
    , &[_][]const u8{
        "tmp.zig:1:14: error: expected type expression, found '...'",
    });

    ctx.testErrStage1("invalid int casts",
        \\export fn foo() void {
        \\    var a: u32 = 2;
        \\    _ = @intCast(comptime_int, a);
        \\}
        \\export fn bar() void {
        \\    var a: u32 = 2;
        \\    _ = @intToFloat(u32, a);
        \\}
        \\export fn baz() void {
        \\    var a: u32 = 2;
        \\    _ = @floatToInt(u32, a);
        \\}
        \\export fn qux() void {
        \\    var a: f32 = 2;
        \\    _ = @intCast(u32, a);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:32: error: unable to evaluate constant expression",
        "tmp.zig:3:9: note: referenced here",
        "tmp.zig:7:21: error: expected float type, found 'u32'",
        "tmp.zig:7:9: note: referenced here",
        "tmp.zig:11:26: error: expected float type, found 'u32'",
        "tmp.zig:11:9: note: referenced here",
        "tmp.zig:15:23: error: expected integer type, found 'f32'",
        "tmp.zig:15:9: note: referenced here",
    });

    ctx.testErrStage1("invalid float casts",
        \\export fn foo() void {
        \\    var a: f32 = 2;
        \\    _ = @floatCast(comptime_float, a);
        \\}
        \\export fn bar() void {
        \\    var a: f32 = 2;
        \\    _ = @floatToInt(f32, a);
        \\}
        \\export fn baz() void {
        \\    var a: f32 = 2;
        \\    _ = @intToFloat(f32, a);
        \\}
        \\export fn qux() void {
        \\    var a: u32 = 2;
        \\    _ = @floatCast(f32, a);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:36: error: unable to evaluate constant expression",
        "tmp.zig:3:9: note: referenced here",
        "tmp.zig:7:21: error: expected integer type, found 'f32'",
        "tmp.zig:7:9: note: referenced here",
        "tmp.zig:11:26: error: expected int type, found 'f32'",
        "tmp.zig:11:9: note: referenced here",
        "tmp.zig:15:25: error: expected float type, found 'u32'",
        "tmp.zig:15:9: note: referenced here",
    });

    ctx.testErrStage1("invalid assignments",
        \\export fn entry1() void {
        \\    var a: []const u8 = "foo";
        \\    a[0..2] = "bar";
        \\}
        \\export fn entry2() void {
        \\    var a: u8 = 2;
        \\    a + 2 = 3;
        \\}
        \\export fn entry4() void {
        \\    2 + 2 = 3;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:6: error: invalid left-hand side to assignment",
        "tmp.zig:7:7: error: invalid left-hand side to assignment",
        "tmp.zig:10:7: error: invalid left-hand side to assignment",
    });

    ctx.testErrStage1("reassign to array parameter",
        \\fn reassign(a: [3]f32) void {
        \\    a = [3]f32{4, 5, 6};
        \\}
        \\export fn entry() void {
        \\    reassign(.{1, 2, 3});
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: cannot assign to constant",
    });

    ctx.testErrStage1("reassign to slice parameter",
        \\pub fn reassign(s: []const u8) void {
        \\    s = s[0..];
        \\}
        \\export fn entry() void {
        \\    reassign("foo");
        \\}
    , &[_][]const u8{
        "tmp.zig:2:10: error: cannot assign to constant",
    });

    ctx.testErrStage1("reassign to struct parameter",
        \\const S = struct {
        \\    x: u32,
        \\};
        \\fn reassign(s: S) void {
        \\    s = S{.x = 2};
        \\}
        \\export fn entry() void {
        \\    reassign(S{.x = 3});
        \\}
    , &[_][]const u8{
        "tmp.zig:5:10: error: cannot assign to constant",
    });

    ctx.testErrStage1("reference to const data",
        \\export fn foo() void {
        \\    var ptr = &[_]u8{0,0,0,0};
        \\    ptr[1] = 2;
        \\}
        \\export fn bar() void {
        \\    var ptr = &@as(u32, 2);
        \\    ptr.* = 2;
        \\}
        \\export fn baz() void {
        \\    var ptr = &true;
        \\    ptr.* = false;
        \\}
        \\export fn qux() void {
        \\    const S = struct{
        \\        x: usize,
        \\        y: usize,
        \\    };
        \\    var ptr = &S{.x=1,.y=2};
        \\    ptr.x = 2;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:14: error: cannot assign to constant",
        "tmp.zig:7:13: error: cannot assign to constant",
        "tmp.zig:11:13: error: cannot assign to constant",
        "tmp.zig:19:13: error: cannot assign to constant",
    });

    ctx.testErrStage1("cast between ?T where T is not a pointer",
        \\pub const fnty1 = ?fn (i8) void;
        \\pub const fnty2 = ?fn (u64) void;
        \\export fn entry() void {
        \\    var a: fnty1 = undefined;
        \\    var b: fnty2 = undefined;
        \\    a = b;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:9: error: expected type '?fn(i8) void', found '?fn(u64) void'",
        "tmp.zig:6:9: note: optional type child 'fn(u64) void' cannot cast into optional type child 'fn(i8) void'",
    });

    ctx.testErrStage1("unused variable error on errdefer",
        \\fn foo() !void {
        \\    errdefer |a| unreachable;
        \\    return error.A;
        \\}
        \\export fn entry() void {
        \\    foo() catch unreachable;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: unused variable: 'a'",
    });

    ctx.testErrStage1("comparison of non-tagged union and enum literal",
        \\export fn entry() void {
        \\    const U = union { A: u32, B: u64 };
        \\    var u = U{ .A = 42 };
        \\    var ok = u == .A;
        \\    _ = ok;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:16: error: comparison of union and enum literal is only valid for tagged union types",
        "tmp.zig:2:15: note: type U is not a tagged union",
    });

    ctx.testErrStage1("shift on type with non-power-of-two size",
        \\export fn entry() void {
        \\    const S = struct {
        \\        fn a() void {
        \\            var x: u24 = 42;
        \\            _ = x >> 24;
        \\        }
        \\        fn b() void {
        \\            var x: u24 = 42;
        \\            _ = x << 24;
        \\        }
        \\        fn c() void {
        \\            var x: u24 = 42;
        \\            _ = @shlExact(x, 24);
        \\        }
        \\        fn d() void {
        \\            var x: u24 = 42;
        \\            _ = @shrExact(x, 24);
        \\        }
        \\    };
        \\    S.a();
        \\    S.b();
        \\    S.c();
        \\    S.d();
        \\}
    , &[_][]const u8{
        "tmp.zig:5:19: error: RHS of shift is too large for LHS type",
        "tmp.zig:9:19: error: RHS of shift is too large for LHS type",
        "tmp.zig:13:17: error: RHS of shift is too large for LHS type",
        "tmp.zig:17:17: error: RHS of shift is too large for LHS type",
    });

    ctx.testErrStage1("combination of nosuspend and async",
        \\export fn entry() void {
        \\    nosuspend {
        \\        const bar = async foo();
        \\        suspend {}
        \\        resume bar;
        \\    }
        \\}
        \\fn foo() void {}
    , &[_][]const u8{
        "tmp.zig:4:9: error: suspend inside nosuspend block",
        "tmp.zig:2:5: note: nosuspend block here",
    });

    ctx.objErrStage1("atomicrmw with bool op not .Xchg",
        \\export fn entry() void {
        \\    var x = false;
        \\    _ = @atomicRmw(bool, &x, .Add, true, .SeqCst);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:30: error: @atomicRmw with bool only allowed with .Xchg",
    });

    ctx.testErrStage1("@TypeOf with no arguments",
        \\export fn entry() void {
        \\    _ = @TypeOf();
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: expected at least 1 argument, found 0",
    });

    ctx.testErrStage1("@TypeOf with incompatible arguments",
        \\export fn entry() void {
        \\    var var_1: f32 = undefined;
        \\    var var_2: u32 = undefined;
        \\    _ = @TypeOf(var_1, var_2);
        \\}
    , &[_][]const u8{
        "tmp.zig:4:9: error: incompatible types: 'f32' and 'u32'",
    });

    ctx.testErrStage1("type mismatch with tuple concatenation",
        \\export fn entry() void {
        \\    var x = .{};
        \\    x = x ++ .{ 1, 2, 3 };
        \\}
    , &[_][]const u8{
        "tmp.zig:3:11: error: expected type 'struct:2:14', found 'struct:3:11'",
    });

    ctx.testErrStage1("@tagName on invalid value of non-exhaustive enum",
        \\test "enum" {
        \\    const E = enum(u8) {A, B, _};
        \\    _ = @tagName(@intToEnum(E, 5));
        \\}
    , &[_][]const u8{
        "tmp.zig:3:18: error: no tag by value 5",
    });

    ctx.testErrStage1("@ptrToInt with pointer to zero-sized type",
        \\export fn entry() void {
        \\    var pointer: ?*u0 = null;
        \\    var x = @ptrToInt(pointer);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:23: error: pointer to size 0 type has no address",
    });

    ctx.testErrStage1("access invalid @typeInfo decl",
        \\const A = B;
        \\test "Crash" {
        \\    _ = @typeInfo(@This()).Struct.decls[0];
        \\}
    , &[_][]const u8{
        "tmp.zig:1:11: error: use of undeclared identifier 'B'",
    });

    ctx.testErrStage1("reject extern function definitions with body",
        \\extern "c" fn definitelyNotInLibC(a: i32, b: i32) i32 {
        \\    return a + b;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: extern functions have no body",
    });

    ctx.testErrStage1("duplicate field in anonymous struct literal",
        \\export fn entry() void {
        \\    const anon = .{
        \\        .inner = .{
        \\            .a = .{
        \\                .something = "text",
        \\            },
        \\            .a = .{},
        \\        },
        \\    };
        \\    _ = anon;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:13: error: duplicate field",
        "tmp.zig:4:13: note: other field here",
    });

    ctx.testErrStage1("type mismatch in C prototype with varargs",
        \\const fn_ty = ?fn ([*c]u8, ...) callconv(.C) void;
        \\extern fn fn_decl(fmt: [*:0]u8, ...) void;
        \\
        \\export fn main() void {
        \\    const x: fn_ty = fn_decl;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:22: error: expected type 'fn([*c]u8, ...) callconv(.C) void', found 'fn([*:0]u8, ...) callconv(.C) void'",
    });

    ctx.testErrStage1("dependency loop in top-level decl with @TypeInfo when accessing the decls",
        \\export const foo = @typeInfo(@This()).Struct.decls;
    , &[_][]const u8{
        "tmp.zig:1:20: error: dependency loop detected",
        "tmp.zig:1:45: note: referenced here",
    });

    ctx.objErrStage1("function call assigned to incorrect type",
        \\export fn entry() void {
        \\    var arr: [4]f32 = undefined;
        \\    arr = concat();
        \\}
        \\fn concat() [16]f32 {
        \\    return [1]f32{0}**16;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:17: error: expected type '[4]f32', found '[16]f32'",
    });

    ctx.objErrStage1("generic function call assigned to incorrect type",
        \\pub export fn entry() void {
        \\    var res: []i32 = undefined;
        \\    res = myAlloc(i32);
        \\}
        \\fn myAlloc(comptime arg: type) anyerror!arg{
        \\    unreachable;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:18: error: expected type '[]i32', found 'anyerror!i32",
    });

    ctx.testErrStage1("non-exhaustive enum marker assigned a value",
        \\const A = enum {
        \\    a,
        \\    b,
        \\    _ = 1,
        \\};
        \\const B = enum {
        \\    a,
        \\    b,
        \\    _,
        \\};
        \\comptime { _ = A; _ = B; }
    , &[_][]const u8{
        "tmp.zig:4:9: error: '_' is used to mark an enum as non-exhaustive and cannot be assigned a value",
        "tmp.zig:6:11: error: non-exhaustive enum missing integer tag type",
        "tmp.zig:9:5: note: marked non-exhaustive here",
    });

    ctx.testErrStage1("non-exhaustive enums",
        \\const B = enum(u1) {
        \\    a,
        \\    _,
        \\    b,
        \\};
        \\const C = enum(u1) {
        \\    a,
        \\    b,
        \\    _,
        \\};
        \\pub export fn entry() void {
        \\    _ = B;
        \\    _ = C;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: '_' field of non-exhaustive enum must be last",
        "tmp.zig:6:11: error: non-exhaustive enum specifies every value",
    });

    ctx.testErrStage1("switching with non-exhaustive enums",
        \\const E = enum(u8) {
        \\    a,
        \\    b,
        \\    _,
        \\};
        \\const U = union(E) {
        \\    a: i32,
        \\    b: u32,
        \\};
        \\pub export fn entry() void {
        \\    var e: E = .b;
        \\    switch (e) { // error: switch not handling the tag `b`
        \\        .a => {},
        \\        _ => {},
        \\    }
        \\    switch (e) { // error: switch on non-exhaustive enum must include `else` or `_` prong
        \\        .a => {},
        \\        .b => {},
        \\    }
        \\    var u = U{.a = 2};
        \\    switch (u) { // error: `_` prong not allowed when switching on tagged union
        \\        .a => {},
        \\        .b => {},
        \\        _ => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:12:5: error: enumeration value 'E.b' not handled in switch",
        "tmp.zig:16:5: error: switch on non-exhaustive enum must include `else` or `_` prong",
        "tmp.zig:21:5: error: `_` prong not allowed when switching on tagged union",
    });

    ctx.objErrStage1("switch expression - unreachable else prong (bool)",
        \\fn foo(x: bool) void {
        \\    switch (x) {
        \\        true => {},
        \\        false => {},
        \\        else => {},
        \\    }
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:5:9: error: unreachable else prong, all cases already handled",
    });

    ctx.objErrStage1("switch expression - unreachable else prong (u1)",
        \\fn foo(x: u1) void {
        \\    switch (x) {
        \\        0 => {},
        \\        1 => {},
        \\        else => {},
        \\    }
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:5:9: error: unreachable else prong, all cases already handled",
    });

    ctx.objErrStage1("switch expression - unreachable else prong (u2)",
        \\fn foo(x: u2) void {
        \\    switch (x) {
        \\        0 => {},
        \\        1 => {},
        \\        2 => {},
        \\        3 => {},
        \\        else => {},
        \\    }
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:7:9: error: unreachable else prong, all cases already handled",
    });

    ctx.objErrStage1("switch expression - unreachable else prong (range u8)",
        \\fn foo(x: u8) void {
        \\    switch (x) {
        \\        0 => {},
        \\        1 => {},
        \\        2 => {},
        \\        3 => {},
        \\        4...255 => {},
        \\        else => {},
        \\    }
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:8:9: error: unreachable else prong, all cases already handled",
    });

    ctx.objErrStage1("switch expression - unreachable else prong (range i8)",
        \\fn foo(x: i8) void {
        \\    switch (x) {
        \\        -128...0 => {},
        \\        1 => {},
        \\        2 => {},
        \\        3 => {},
        \\        4...127 => {},
        \\        else => {},
        \\    }
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:8:9: error: unreachable else prong, all cases already handled",
    });

    ctx.objErrStage1("switch expression - unreachable else prong (enum)",
        \\const TestEnum = enum{ T1, T2 };
        \\
        \\fn err(x: u8) TestEnum {
        \\    switch (x) {
        \\        0 => return TestEnum.T1,
        \\        else => return TestEnum.T2,
        \\    }
        \\}
        \\
        \\fn foo(x: u8) void {
        \\    switch (err(x)) {
        \\        TestEnum.T1 => {},
        \\        TestEnum.T2 => {},
        \\        else => {},
        \\    }
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:14:9: error: unreachable else prong, all cases already handled",
    });

    ctx.testErrStage1("@export with empty name string",
        \\pub export fn entry() void { }
        \\comptime {
        \\    @export(entry, .{ .name = "" });
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: exported symbol name cannot be empty",
    });

    ctx.testErrStage1("switch ranges endpoints are validated",
        \\pub export fn entry() void {
        \\    var x: i32 = 0;
        \\    switch (x) {
        \\        6...1 => {},
        \\        -1...-5 => {},
        \\        else => unreachable,
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:4:9: error: range start value is greater than the end value",
        "tmp.zig:5:9: error: range start value is greater than the end value",
    });

    ctx.testErrStage1("errors in for loop bodies are propagated",
        \\pub export fn entry() void {
        \\    var arr: [100]u8 = undefined;
        \\    for (arr) |bits| _ = @popCount(bits);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:26: error: expected 2 arguments, found 1",
    });

    ctx.testErrStage1("@call rejects non comptime-known fn - always_inline",
        \\pub export fn entry() void {
        \\    var call_me: fn () void = undefined;
        \\    @call(.{ .modifier = .always_inline }, call_me, .{});
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: the specified modifier requires a comptime-known function",
    });

    ctx.testErrStage1("@call rejects non comptime-known fn - compile_time",
        \\pub export fn entry() void {
        \\    var call_me: fn () void = undefined;
        \\    @call(.{ .modifier = .compile_time }, call_me, .{});
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: the specified modifier requires a comptime-known function",
    });

    ctx.testErrStage1("error in struct initializer doesn't crash the compiler",
        \\pub export fn entry() void {
        \\    const bitfield = struct {
        \\        e: u8,
        \\        e: u8,
        \\    };
        \\    var a = .{@sizeOf(bitfield)};
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:9: error: duplicate struct field: 'e'",
    });

    ctx.testErrStage1("repeated invalid field access to generic function returning type crashes compiler. #2655",
        \\pub fn A() type {
        \\    return Q;
        \\}
        \\test "1" {
        \\    _ = A().a;
        \\    _ = A().a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: use of undeclared identifier 'Q'",
    });

    ctx.objErrStage1("bitCast to enum type",
        \\export fn entry() void {
        \\    const y = @bitCast(enum(u32) { a, b }, @as(u32, 3));
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:24: error: cannot cast a value of type 'y'",
    });

    ctx.objErrStage1("comparing against undefined produces undefined value",
        \\export fn entry() void {
        \\    if (2 == undefined) {}
        \\}
    , &[_][]const u8{
        "tmp.zig:2:11: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("comptime ptrcast of zero-sized type",
        \\fn foo() void {
        \\    const node: struct {} = undefined;
        \\    const vla_ptr = @ptrCast([*]const u8, &node);
        \\    _ = vla_ptr;
        \\}
        \\comptime { foo(); }
    , &[_][]const u8{
        "tmp.zig:3:21: error: '*const struct:2:17' and '[*]const u8' do not have the same in-memory representation",
    });

    ctx.objErrStage1("slice sentinel mismatch",
        \\fn foo() [:0]u8 {
        \\    var x: []u8 = undefined;
        \\    return x;
        \\}
        \\comptime { _ = foo; }
    , &[_][]const u8{
        "tmp.zig:3:12: error: expected type '[:0]u8', found '[]u8'",
        "tmp.zig:3:12: note: destination pointer requires a terminating '0' sentinel",
    });

    ctx.objErrStage1("cmpxchg with float",
        \\export fn entry() void {
        \\    var x: f32 = 0;
        \\    _ = @cmpxchgWeak(f32, &x, 1, 2, .SeqCst, .SeqCst);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:22: error: expected bool, integer, enum or pointer type, found 'f32'",
    });

    ctx.objErrStage1("atomicrmw with float op not .Xchg, .Add or .Sub",
        \\export fn entry() void {
        \\    var x: f32 = 0;
        \\    _ = @atomicRmw(f32, &x, .And, 2, .SeqCst);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:29: error: @atomicRmw with float only allowed with .Xchg, .Add and .Sub",
    });

    ctx.objErrStage1("intToPtr with misaligned address",
        \\pub fn main() void {
        \\    var y = @intToPtr([*]align(4) u8, 5);
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:13: error: pointer type '[*]align(4) u8' requires aligned address",
    });

    ctx.objErrStage1("invalid float literal",
        \\const std = @import("std");
        \\
        \\pub fn main() void {
        \\    var bad_float :f32 = 0.0;
        \\    bad_float = bad_float + .20;
        \\    std.debug.assert(bad_float < 1.0);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:29: error: invalid token: '.'",
    });

    ctx.objErrStage1("invalid exponent in float literal - 1",
        \\fn main() void {
        \\    var bad: f128 = 0x1.0p1ab1;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:28: note: invalid byte: 'a'",
    });

    ctx.objErrStage1("invalid exponent in float literal - 2",
        \\fn main() void {
        \\    var bad: f128 = 0x1.0p50F;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:29: note: invalid byte: 'F'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 1",
        \\fn main() void {
        \\    var bad: f128 = 0._0;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:23: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 2",
        \\fn main() void {
        \\    var bad: f128 = 0_.0;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:23: note: invalid byte: '.'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 3",
        \\fn main() void {
        \\    var bad: f128 = 0.0_;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:25: note: invalid byte: ';'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 4",
        \\fn main() void {
        \\    var bad: f128 = 1.0e_1;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:25: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 5",
        \\fn main() void {
        \\    var bad: f128 = 1.0e+_1;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:26: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 6",
        \\fn main() void {
        \\    var bad: f128 = 1.0e-_1;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:26: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 7",
        \\fn main() void {
        \\    var bad: f128 = 1.0e-1_;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:28: note: invalid byte: ';'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 9",
        \\fn main() void {
        \\    var bad: f128 = 1__0.0e-1;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:23: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 10",
        \\fn main() void {
        \\    var bad: f128 = 1.0__0e-1;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:25: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 11",
        \\fn main() void {
        \\    var bad: f128 = 1.0e-1__0;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:28: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 12",
        \\fn main() void {
        \\    var bad: f128 = 0_x0.0;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:23: note: invalid byte: 'x'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 13",
        \\fn main() void {
        \\    var bad: f128 = 0x_0.0;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:23: note: invalid byte: '_'",
    });

    ctx.objErrStage1("invalid underscore placement in float literal - 14",
        \\fn main() void {
        \\    var bad: f128 = 0x0.0_p1;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:27: note: invalid byte: 'p'",
    });

    ctx.objErrStage1("invalid underscore placement in int literal - 1",
        \\fn main() void {
        \\    var bad: u128 = 0010_;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:26: note: invalid byte: ';'",
    });

    ctx.objErrStage1("invalid underscore placement in int literal - 2",
        \\fn main() void {
        \\    var bad: u128 = 0b0010_;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:28: note: invalid byte: ';'",
    });

    ctx.objErrStage1("invalid underscore placement in int literal - 3",
        \\fn main() void {
        \\    var bad: u128 = 0o0010_;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:28: note: invalid byte: ';'",
    });

    ctx.objErrStage1("invalid underscore placement in int literal - 4",
        \\fn main() void {
        \\    var bad: u128 = 0x0010_;
        \\    _ = bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected expression, found 'invalid'",
        "tmp.zig:2:28: note: invalid byte: ';'",
    });

    ctx.objErrStage1("comptime struct field, no init value",
        \\const Foo = struct {
        \\    comptime b: i32,
        \\};
        \\export fn entry() void {
        \\    var f: Foo = undefined;
        \\    _ = f;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: comptime field without default initialization value",
    });

    ctx.objErrStage1("bad usage of @call",
        \\export fn entry1() void {
        \\    @call(.{}, foo, {});
        \\}
        \\export fn entry2() void {
        \\    comptime @call(.{ .modifier = .never_inline }, foo, .{});
        \\}
        \\export fn entry3() void {
        \\    comptime @call(.{ .modifier = .never_tail }, foo, .{});
        \\}
        \\export fn entry4() void {
        \\    @call(.{ .modifier = .never_inline }, bar, .{});
        \\}
        \\export fn entry5(c: bool) void {
        \\    var baz = if (c) baz1 else baz2;
        \\    @call(.{ .modifier = .compile_time }, baz, .{});
        \\}
        \\fn foo() void {}
        \\fn bar() callconv(.Inline) void {}
        \\fn baz1() void {}
        \\fn baz2() void {}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected tuple or struct, found 'void'",
        "tmp.zig:5:14: error: unable to perform 'never_inline' call at compile-time",
        "tmp.zig:8:14: error: unable to perform 'never_tail' call at compile-time",
        "tmp.zig:11:5: error: no-inline call of inline function",
        "tmp.zig:15:5: error: the specified modifier requires a comptime-known function",
    });

    ctx.objErrStage1("exported async function",
        \\export fn foo() callconv(.Async) void {}
    , &[_][]const u8{
        "tmp.zig:1:1: error: exported function cannot be async",
    });

    ctx.exeErrStage1("main missing name",
        \\pub fn (main) void {}
    , &[_][]const u8{
        "tmp.zig:1:5: error: missing function name",
    });

    {
        const case = ctx.obj("call with new stack on unsupported target", .{
            .cpu_arch = .wasm32,
            .os_tag = .wasi,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\var buf: [10]u8 align(16) = undefined;
            \\export fn entry() void {
            \\    @call(.{.stack = &buf}, foo, .{});
            \\}
            \\fn foo() void {}
        , &[_][]const u8{
            "tmp.zig:3:5: error: target arch 'wasm32' does not support calling with a new stack",
        });
    }

    // Note: One of the error messages here is backwards. It would be nice to fix, but that's not
    // going to stop me from merging this branch which fixes a bunch of other stuff.
    ctx.objErrStage1("incompatible sentinels",
        \\export fn entry1(ptr: [*:255]u8) [*:0]u8 {
        \\    return ptr;
        \\}
        \\export fn entry2(ptr: [*]u8) [*:0]u8 {
        \\    return ptr;
        \\}
        \\export fn entry3() void {
        \\    var array: [2:0]u8 = [_:255]u8{1, 2};
        \\    _ = array;
        \\}
        \\export fn entry4() void {
        \\    var array: [2:0]u8 = [_]u8{1, 2};
        \\    _ = array;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: expected type '[*:0]u8', found '[*:255]u8'",
        "tmp.zig:2:12: note: destination pointer requires a terminating '0' sentinel, but source pointer has a terminating '255' sentinel",
        "tmp.zig:5:12: error: expected type '[*:0]u8', found '[*]u8'",
        "tmp.zig:5:12: note: destination pointer requires a terminating '0' sentinel",

        "tmp.zig:8:35: error: expected type '[2:255]u8', found '[2:0]u8'",
        "tmp.zig:8:35: note: destination array requires a terminating '255' sentinel, but source array has a terminating '0' sentinel",
        "tmp.zig:12:31: error: expected type '[2:0]u8', found '[2]u8'",
        "tmp.zig:12:31: note: destination array requires a terminating '0' sentinel",
    });

    ctx.objErrStage1("empty switch on an integer",
        \\export fn entry() void {
        \\    var x: u32 = 0;
        \\    switch(x) {}
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: switch must handle all possibilities",
    });

    ctx.objErrStage1("incorrect return type",
        \\ pub export fn entry() void{
        \\     _ = foo();
        \\ }
        \\ const A = struct {
        \\     a: u32,
        \\ };
        \\ fn foo() A {
        \\     return bar();
        \\ }
        \\ const B = struct {
        \\     a: u32,
        \\ };
        \\ fn bar() B {
        \\     unreachable;
        \\ }
    , &[_][]const u8{
        "tmp.zig:8:16: error: expected type 'A', found 'B'",
    });

    ctx.objErrStage1("regression test #2980: base type u32 is not type checked properly when assigning a value within a struct",
        \\const Foo = struct {
        \\    ptr: ?*usize,
        \\    uval: u32,
        \\};
        \\fn get_uval(x: u32) !u32 {
        \\    _ = x;
        \\    return error.NotFound;
        \\}
        \\export fn entry() void {
        \\    const afoo = Foo{
        \\        .ptr = null,
        \\        .uval = get_uval(42),
        \\    };
        \\    _ = afoo;
        \\}
    , &[_][]const u8{
        "tmp.zig:12:25: error: expected type 'u32', found '@typeInfo(@typeInfo(@TypeOf(get_uval)).Fn.return_type.?).ErrorUnion.error_set!u32'",
    });

    ctx.objErrStage1("assigning to struct or union fields that are not optionals with a function that returns an optional",
        \\fn maybe(is: bool) ?u8 {
        \\    if (is) return @as(u8, 10) else return null;
        \\}
        \\const U = union {
        \\    Ye: u8,
        \\};
        \\const S = struct {
        \\    num: u8,
        \\};
        \\export fn entry() void {
        \\    var u = U{ .Ye = maybe(false) };
        \\    var s = S{ .num = maybe(false) };
        \\    _ = u;
        \\    _ = s;
        \\}
    , &[_][]const u8{
        "tmp.zig:11:27: error: expected type 'u8', found '?u8'",
    });

    ctx.objErrStage1("missing result type for phi node",
        \\fn foo() !void {
        \\    return anyerror.Foo;
        \\}
        \\export fn entry() void {
        \\    foo() catch 0;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:17: error: integer value 0 cannot be coerced to type 'void'",
    });

    ctx.objErrStage1("atomicrmw with enum op not .Xchg",
        \\export fn entry() void {
        \\    const E = enum(u8) {
        \\        a,
        \\        b,
        \\        c,
        \\        d,
        \\    };
        \\    var x: E = .a;
        \\    _ = @atomicRmw(E, &x, .Add, .b, .SeqCst);
        \\}
    , &[_][]const u8{
        "tmp.zig:9:27: error: @atomicRmw with enum only allowed with .Xchg",
    });

    ctx.objErrStage1("disallow coercion from non-null-terminated pointer to null-terminated pointer",
        \\extern fn puts(s: [*:0]const u8) c_int;
        \\pub fn main() void {
        \\    const no_zero_array = [_]u8{'h', 'e', 'l', 'l', 'o'};
        \\    const no_zero_ptr: [*]const u8 = &no_zero_array;
        \\    _ = puts(no_zero_ptr);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:14: error: expected type '[*:0]const u8', found '[*]const u8'",
    });

    ctx.objErrStage1("atomic orderings of atomicStore Acquire or AcqRel",
        \\export fn entry() void {
        \\    var x: u32 = 0;
        \\    @atomicStore(u32, &x, 1, .Acquire);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:30: error: @atomicStore atomic ordering must not be Acquire or AcqRel",
    });

    ctx.objErrStage1("missing const in slice with nested array type",
        \\const Geo3DTex2D = struct { vertices: [][2]f32 };
        \\pub fn getGeo3DTex2D() Geo3DTex2D {
        \\    return Geo3DTex2D{
        \\        .vertices = [_][2]f32{
        \\            [_]f32{ -0.5, -0.5},
        \\        },
        \\    };
        \\}
        \\export fn entry() void {
        \\    var geo_data = getGeo3DTex2D();
        \\    _ = geo_data;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:30: error: array literal requires address-of operator to coerce to slice type '[][2]f32'",
    });

    ctx.objErrStage1("slicing of global undefined pointer",
        \\var buf: *[1]u8 = undefined;
        \\export fn entry() void {
        \\    _ = buf[0..1];
        \\}
    , &[_][]const u8{
        "tmp.zig:3:12: error: non-zero length slice of undefined pointer",
    });

    ctx.objErrStage1("using invalid types in function call raises an error",
        \\const MenuEffect = enum {};
        \\fn func(effect: MenuEffect) void { _ = effect; }
        \\export fn entry() void {
        \\    func(MenuEffect.ThisDoesNotExist);
        \\}
    , &[_][]const u8{
        "tmp.zig:1:20: error: enum declarations must have at least one tag",
    });

    ctx.objErrStage1("store vector pointer with unknown runtime index",
        \\export fn entry() void {
        \\    var v: @import("std").meta.Vector(4, i32) = [_]i32{ 1, 5, 3, undefined };
        \\
        \\    var i: u32 = 0;
        \\    storev(&v[i], 42);
        \\}
        \\
        \\fn storev(ptr: anytype, val: i32) void {
        \\    ptr.* = val;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:8: error: unable to determine vector element index of type '*align(16:0:4:?) i32",
    });

    ctx.objErrStage1("load vector pointer with unknown runtime index",
        \\export fn entry() void {
        \\    var v: @import("std").meta.Vector(4, i32) = [_]i32{ 1, 5, 3, undefined };
        \\
        \\    var i: u32 = 0;
        \\    var x = loadv(&v[i]);
        \\    _ = x;
        \\}
        \\
        \\fn loadv(ptr: anytype) i32 {
        \\    return ptr.*;
        \\}
    , &[_][]const u8{
        "tmp.zig:10:12: error: unable to determine vector element index of type '*align(16:0:4:?) i32",
    });

    ctx.objErrStage1("using an unknown len ptr type instead of array",
        \\const resolutions = [*][*]const u8{
        \\    "[320 240  ]",
        \\    null,
        \\};
        \\comptime {
        \\    _ = resolutions;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:21: error: expected array type or [_], found '[*][*]const u8'",
    });

    ctx.objErrStage1("comparison with error union and error value",
        \\export fn entry() void {
        \\    var number_or_error: anyerror!i32 = error.SomethingAwful;
        \\    _ = number_or_error == error.SomethingAwful;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:25: error: operator not allowed for type 'anyerror!i32'",
    });

    ctx.objErrStage1("switch with overlapping case ranges",
        \\export fn entry() void {
        \\    var q: u8 = 0;
        \\    switch (q) {
        \\        1...2 => {},
        \\        0...255 => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:9: error: duplicate switch value",
    });

    ctx.objErrStage1("invalid optional type in extern struct",
        \\const stroo = extern struct {
        \\    moo: ?[*c]u8,
        \\};
        \\export fn testf(fluff: *stroo) void { _ = fluff; }
    , &[_][]const u8{
        "tmp.zig:2:5: error: extern structs cannot contain fields of type '?[*c]u8'",
    });

    ctx.objErrStage1("attempt to negate a non-integer, non-float or non-vector type",
        \\fn foo() anyerror!u32 {
        \\    return 1;
        \\}
        \\
        \\export fn entry() void {
        \\    const x = -foo();
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:15: error: negation of type 'anyerror!u32'",
    });

    ctx.objErrStage1("attempt to create 17 bit float type",
        \\const builtin = @import("std").builtin;
        \\comptime {
        \\    _ = @Type(builtin.TypeInfo { .Float = std.builtin.TypeInfo.Float { .bits = 17 } });
        \\}
    , &[_][]const u8{
        "tmp.zig:3:32: error: 17-bit float unsupported",
    });

    ctx.objErrStage1("wrong type for @Type",
        \\export fn entry() void {
        \\    _ = @Type(0);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected type 'std.builtin.TypeInfo', found 'comptime_int'",
    });

    ctx.objErrStage1("@Type with non-constant expression",
        \\const builtin = @import("std").builtin;
        \\var globalTypeInfo : std.builtin.TypeInfo = undefined;
        \\export fn entry() void {
        \\    _ = @Type(globalTypeInfo);
        \\}
    , &[_][]const u8{
        "tmp.zig:4:15: error: unable to evaluate constant expression",
    });

    ctx.objErrStage1("wrong type for argument tuple to @asyncCall",
        \\export fn entry1() void {
        \\    var frame: @Frame(foo) = undefined;
        \\    @asyncCall(&frame, {}, foo, {});
        \\}
        \\
        \\fn foo() i32 {
        \\    return 0;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:33: error: expected tuple or struct, found 'void'",
    });

    ctx.objErrStage1("wrong type for result ptr to @asyncCall",
        \\export fn entry() void {
        \\    _ = async amain();
        \\}
        \\fn amain() i32 {
        \\    var frame: @Frame(foo) = undefined;
        \\    return await @asyncCall(&frame, false, foo, .{});
        \\}
        \\fn foo() i32 {
        \\    return 1234;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:37: error: expected type '*i32', found 'bool'",
    });

    ctx.objErrStage1("shift amount has to be an integer type",
        \\export fn entry() void {
        \\    const x = 1 << &@as(u8, 10);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: shift amount has to be an integer type, but found '*const u8'",
        "tmp.zig:2:17: note: referenced here",
    });

    ctx.objErrStage1("bit shifting only works on integer types",
        \\export fn entry() void {
        \\    const x = &@as(u8, 1) << 10;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:16: error: bit shifting operation expected integer type, found '*const u8'",
        "tmp.zig:2:27: note: referenced here",
    });

    ctx.objErrStage1("struct depends on itself via optional field",
        \\const LhsExpr = struct {
        \\    rhsExpr: ?AstObject,
        \\};
        \\const AstObject = union {
        \\    lhsExpr: LhsExpr,
        \\};
        \\export fn entry() void {
        \\    const lhsExpr = LhsExpr{ .rhsExpr = null };
        \\    const obj = AstObject{ .lhsExpr = lhsExpr };
        \\    _ = obj;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:17: error: struct 'LhsExpr' depends on itself",
        "tmp.zig:5:5: note: while checking this field",
        "tmp.zig:2:5: note: while checking this field",
    });

    ctx.objErrStage1("alignment of enum field specified",
        \\const Number = enum {
        \\    a,
        \\    b align(i32),
        \\};
        \\export fn entry1() void {
        \\    var x: Number = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:7: error: expected ',', found 'align'",
    });

    ctx.objErrStage1("bad alignment type",
        \\export fn entry1() void {
        \\    var x: []align(true) i32 = undefined;
        \\    _ = x;
        \\}
        \\export fn entry2() void {
        \\    var x: *align(@as(f64, 12.34)) i32 = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:20: error: expected type 'u29', found 'bool'",
        "tmp.zig:6:19: error: fractional component prevents float value 12.340000 from being casted to type 'u29'",
    });

    {
        const case = ctx.obj("variable in inline assembly template cannot be found", .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .gnu,
        });
        case.backend = .stage1;
        case.addError(
            \\export fn entry() void {
            \\    var sp = asm volatile (
            \\        "mov %[foo], sp"
            \\        : [bar] "=r" (-> usize)
            \\    );
            \\    _ = sp;
            \\}
        , &[_][]const u8{
            "tmp.zig:2:14: error: could not find 'foo' in the inputs or outputs",
        });
    }

    ctx.objErrStage1("indirect recursion of async functions detected",
        \\var frame: ?anyframe = null;
        \\
        \\export fn a() void {
        \\    _ = async rangeSum(10);
        \\    while (frame) |f| resume f;
        \\}
        \\
        \\fn rangeSum(x: i32) i32 {
        \\    suspend {
        \\        frame = @frame();
        \\    }
        \\    frame = null;
        \\
        \\    if (x == 0) return 0;
        \\    var child = rangeSumIndirect(x - 1);
        \\    return child + 1;
        \\}
        \\
        \\fn rangeSumIndirect(x: i32) i32 {
        \\    suspend {
        \\        frame = @frame();
        \\    }
        \\    frame = null;
        \\
        \\    if (x == 0) return 0;
        \\    var child = rangeSum(x - 1);
        \\    return child + 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:8:1: error: '@Frame(rangeSum)' depends on itself",
        "tmp.zig:15:33: note: when analyzing type '@Frame(rangeSum)' here",
        "tmp.zig:26:25: note: when analyzing type '@Frame(rangeSumIndirect)' here",
    });

    ctx.objErrStage1("non-async function pointer eventually is inferred to become async",
        \\export fn a() void {
        \\    var non_async_fn: fn () void = undefined;
        \\    non_async_fn = func;
        \\}
        \\fn func() void {
        \\    suspend {}
        \\}
    , &[_][]const u8{
        "tmp.zig:5:1: error: 'func' cannot be async",
        "tmp.zig:3:20: note: required to be non-async here",
        "tmp.zig:6:5: note: suspends here",
    });

    {
        const case = ctx.obj("bad alignment in @asyncCall", .{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
            .abi = .none,
        });
        case.backend = .stage1;
        case.addError(
            \\export fn entry() void {
            \\    var ptr: fn () callconv(.Async) void = func;
            \\    var bytes: [64]u8 = undefined;
            \\    _ = @asyncCall(&bytes, {}, ptr, .{});
            \\}
            \\fn func() callconv(.Async) void {}
        , &[_][]const u8{
            "tmp.zig:4:21: error: expected type '[]align(8) u8', found '*[64]u8'",
        });
    }

    ctx.objErrStage1("atomic orderings of fence Acquire or stricter",
        \\export fn entry() void {
        \\    @fence(.Monotonic);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: atomic ordering must be Acquire or stricter",
    });

    ctx.objErrStage1("bad alignment in implicit cast from array pointer to slice",
        \\export fn a() void {
        \\    var x: [10]u8 = undefined;
        \\    var y: []align(16) u8 = &x;
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:30: error: expected type '[]align(16) u8', found '*[10]u8'",
    });

    ctx.objErrStage1("result location incompatibility mismatching handle_is_ptr (generic call)",
        \\export fn entry() void {
        \\    var damn = Container{
        \\        .not_optional = getOptional(i32),
        \\    };
        \\    _ = damn;
        \\}
        \\pub fn getOptional(comptime T: type) ?T {
        \\    return 0;
        \\}
        \\pub const Container = struct {
        \\    not_optional: i32,
        \\};
    , &[_][]const u8{
        "tmp.zig:3:36: error: expected type 'i32', found '?i32'",
    });

    ctx.objErrStage1("result location incompatibility mismatching handle_is_ptr",
        \\export fn entry() void {
        \\    var damn = Container{
        \\        .not_optional = getOptional(),
        \\    };
        \\    _ = damn;
        \\}
        \\pub fn getOptional() ?i32 {
        \\    return 0;
        \\}
        \\pub const Container = struct {
        \\    not_optional: i32,
        \\};
    , &[_][]const u8{
        "tmp.zig:3:36: error: expected type 'i32', found '?i32'",
    });

    ctx.objErrStage1("const frame cast to anyframe",
        \\export fn a() void {
        \\    const f = async func();
        \\    resume f;
        \\}
        \\export fn b() void {
        \\    const f = async func();
        \\    var x: anyframe = &f;
        \\    _ = x;
        \\}
        \\fn func() void {
        \\    suspend {}
        \\}
    , &[_][]const u8{
        "tmp.zig:3:12: error: expected type 'anyframe', found '*const @Frame(func)'",
        "tmp.zig:7:24: error: expected type 'anyframe', found '*const @Frame(func)'",
    });

    ctx.objErrStage1("prevent bad implicit casting of anyframe types",
        \\export fn a() void {
        \\    var x: anyframe = undefined;
        \\    var y: anyframe->i32 = x;
        \\    _ = y;
        \\}
        \\export fn b() void {
        \\    var x: i32 = undefined;
        \\    var y: anyframe->i32 = x;
        \\    _ = y;
        \\}
        \\export fn c() void {
        \\    var x: @Frame(func) = undefined;
        \\    var y: anyframe->i32 = &x;
        \\    _ = y;
        \\}
        \\fn func() void {}
    , &[_][]const u8{
        "tmp.zig:3:28: error: expected type 'anyframe->i32', found 'anyframe'",
        "tmp.zig:8:28: error: expected type 'anyframe->i32', found 'i32'",
        "tmp.zig:13:29: error: expected type 'anyframe->i32', found '*@Frame(func)'",
    });

    ctx.objErrStage1("wrong frame type used for async call",
        \\export fn entry() void {
        \\    var frame: @Frame(foo) = undefined;
        \\    frame = async bar();
        \\}
        \\fn foo() void {
        \\    suspend {}
        \\}
        \\fn bar() void {
        \\    suspend {}
        \\}
    , &[_][]const u8{
        "tmp.zig:3:13: error: expected type '*@Frame(bar)', found '*@Frame(foo)'",
    });

    ctx.objErrStage1("@Frame() of generic function",
        \\export fn entry() void {
        \\    var frame: @Frame(func) = undefined;
        \\    _ = frame;
        \\}
        \\fn func(comptime T: type) void {
        \\    var x: T = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:16: error: @Frame() of generic function",
    });

    ctx.objErrStage1("@frame() causes function to be async",
        \\export fn entry() void {
        \\    func();
        \\}
        \\fn func() void {
        \\    _ = @frame();
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: function with calling convention 'C' cannot be async",
        "tmp.zig:5:9: note: @frame() causes function to be async",
    });

    ctx.objErrStage1("invalid suspend in exported function",
        \\export fn entry() void {
        \\    var frame = async func();
        \\    var result = await frame;
        \\    _ = result;
        \\}
        \\fn func() void {
        \\    suspend {}
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: function with calling convention 'C' cannot be async",
        "tmp.zig:3:18: note: await here is a suspend point",
    });

    ctx.objErrStage1("async function indirectly depends on its own frame",
        \\export fn entry() void {
        \\    _ = async amain();
        \\}
        \\fn amain() callconv(.Async) void {
        \\    other();
        \\}
        \\fn other() void {
        \\    var x: [@sizeOf(@Frame(amain))]u8 = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:1: error: unable to determine async function frame of 'amain'",
        "tmp.zig:5:10: note: analysis of function 'other' depends on the frame",
        "tmp.zig:8:13: note: referenced here",
    });

    ctx.objErrStage1("async function depends on its own frame",
        \\export fn entry() void {
        \\    _ = async amain();
        \\}
        \\fn amain() callconv(.Async) void {
        \\    var x: [@sizeOf(@Frame(amain))]u8 = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:1: error: cannot resolve '@Frame(amain)': function not fully analyzed yet",
        "tmp.zig:5:13: note: referenced here",
    });

    ctx.objErrStage1("non async function pointer passed to @asyncCall",
        \\export fn entry() void {
        \\    var ptr = afunc;
        \\    var bytes: [100]u8 align(16) = undefined;
        \\    _ = @asyncCall(&bytes, {}, ptr, .{});
        \\}
        \\fn afunc() void { }
    , &[_][]const u8{
        "tmp.zig:4:32: error: expected async function, found 'fn() void'",
    });

    ctx.objErrStage1("runtime-known async function called",
        \\export fn entry() void {
        \\    _ = async amain();
        \\}
        \\fn amain() void {
        \\    var ptr = afunc;
        \\    _ = ptr();
        \\}
        \\fn afunc() callconv(.Async) void {}
    , &[_][]const u8{
        "tmp.zig:6:12: error: function is not comptime-known; @asyncCall required",
    });

    ctx.objErrStage1("runtime-known function called with async keyword",
        \\export fn entry() void {
        \\    var ptr = afunc;
        \\    _ = async ptr();
        \\}
        \\
        \\fn afunc() callconv(.Async) void { }
    , &[_][]const u8{
        "tmp.zig:3:15: error: function is not comptime-known; @asyncCall required",
    });

    ctx.objErrStage1("function with ccc indirectly calling async function",
        \\export fn entry() void {
        \\    foo();
        \\}
        \\fn foo() void {
        \\    bar();
        \\}
        \\fn bar() void {
        \\    suspend {}
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: function with calling convention 'C' cannot be async",
        "tmp.zig:2:8: note: async function call here",
        "tmp.zig:5:8: note: async function call here",
        "tmp.zig:8:5: note: suspends here",
    });

    ctx.objErrStage1("capture group on switch prong with incompatible payload types",
        \\const Union = union(enum) {
        \\    A: usize,
        \\    B: isize,
        \\};
        \\comptime {
        \\    var u = Union{ .A = 8 };
        \\    switch (u) {
        \\        .A, .B => |e| {
        \\            _ = e;
        \\            unreachable;
        \\        },
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:8:20: error: capture group with incompatible types",
        "tmp.zig:8:9: note: type 'usize' here",
        "tmp.zig:8:13: note: type 'isize' here",
    });

    ctx.objErrStage1("wrong type to @hasField",
        \\export fn entry() bool {
        \\    return @hasField(i32, "hi");
        \\}
    , &[_][]const u8{
        "tmp.zig:2:22: error: type 'i32' does not support @hasField",
    });

    ctx.objErrStage1("slice passed as array init type with elems",
        \\export fn entry() void {
        \\    const x = []u8{1, 2};
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: array literal requires address-of operator to coerce to slice type '[]u8'",
    });

    ctx.objErrStage1("slice passed as array init type",
        \\export fn entry() void {
        \\    const x = []u8{};
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: array literal requires address-of operator to coerce to slice type '[]u8'",
    });

    ctx.objErrStage1("inferred array size invalid here",
        \\export fn entry() void {
        \\    const x = [_]u8;
        \\    _ = x;
        \\}
        \\export fn entry2() void {
        \\    const S = struct { a: *const [_]u8 };
        \\    var a = .{ S{} };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:16: error: unable to infer array size",
        "tmp.zig:6:35: error: unable to infer array size",
    });

    ctx.objErrStage1("initializing array with struct syntax",
        \\export fn entry() void {
        \\    const x = [_]u8{ .y = 2 };
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: initializing array with struct syntax",
    });

    ctx.objErrStage1("compile error in struct init expression",
        \\const Foo = struct {
        \\    a: i32 = crap,
        \\    b: i32,
        \\};
        \\export fn entry() void {
        \\    var x = Foo{
        \\        .b = 5,
        \\    };
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:14: error: use of undeclared identifier 'crap'",
    });

    ctx.objErrStage1("undefined as field type is rejected",
        \\const Foo = struct {
        \\    a: undefined,
        \\};
        \\export fn entry1() void {
        \\    const foo: Foo = undefined;
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:8: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("@hasDecl with non-container",
        \\export fn entry() void {
        \\    _ = @hasDecl(i32, "hi");
        \\}
    , &[_][]const u8{
        "tmp.zig:2:18: error: expected struct, enum, or union; found 'i32'",
    });

    ctx.objErrStage1("field access of slices",
        \\export fn entry() void {
        \\    var slice: []i32 = undefined;
        \\    const info = @TypeOf(slice).unknown;
        \\    _ = info;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:32: error: type 'type' does not support field access",
    });

    ctx.objErrStage1("peer cast then implicit cast const pointer to mutable C pointer",
        \\export fn func() void {
        \\    var strValue: [*c]u8 = undefined;
        \\    strValue = strValue orelse "";
        \\}
    , &[_][]const u8{
        "tmp.zig:3:32: error: expected type '[*c]u8', found '*const [0:0]u8'",
        "tmp.zig:3:32: note: cast discards const qualifier",
    });

    ctx.objErrStage1("overflow in enum value allocation",
        \\const Moo = enum(u8) {
        \\    Last = 255,
        \\    Over,
        \\};
        \\pub fn main() void {
        \\  var y = Moo.Last;
        \\  _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: enumeration value 256 too large for type 'u8'",
    });

    ctx.objErrStage1("attempt to cast enum literal to error",
        \\export fn entry() void {
        \\    switch (error.Hi) {
        \\        .Hi => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: expected type 'error{Hi}', found '(enum literal)'",
    });

    ctx.objErrStage1("@sizeOf bad type",
        \\export fn entry() usize {
        \\    return @sizeOf(@TypeOf(null));
        \\}
    , &[_][]const u8{
        "tmp.zig:2:20: error: no size available for type '(null)'",
    });

    ctx.objErrStage1("generic function where return type is self-referenced",
        \\fn Foo(comptime T: type) Foo(T) {
        \\    return struct{ x: T };
        \\}
        \\export fn entry() void {
        \\    const t = Foo(u32) {
        \\      .x = 1
        \\    };
        \\    _ = t;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:29: error: evaluation exceeded 1000 backwards branches",
        "tmp.zig:5:18: note: referenced here",
    });

    ctx.objErrStage1("@ptrToInt 0 to non optional pointer",
        \\export fn entry() void {
        \\    var b = @intToPtr(*i32, 0);
        \\    _ = b;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:13: error: pointer type '*i32' does not allow address zero",
    });

    ctx.objErrStage1("cast enum literal to enum but it doesn't match",
        \\const Foo = enum {
        \\    a,
        \\    b,
        \\};
        \\export fn entry() void {
        \\    const x: Foo = .c;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:20: error: enum 'Foo' has no field named 'c'",
        "tmp.zig:1:13: note: 'Foo' declared here",
    });

    ctx.objErrStage1("discarding error value",
        \\export fn entry() void {
        \\    _ = foo();
        \\}
        \\fn foo() !void {
        \\    return error.OutOfMemory;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: error is discarded. consider using `try`, `catch`, or `if`",
    });

    ctx.objErrStage1("volatile on global assembly",
        \\comptime {
        \\    asm volatile ("");
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: volatile is meaningless on global assembly",
    });

    ctx.objErrStage1("invalid multiple dereferences",
        \\export fn a() void {
        \\    var box = Box{ .field = 0 };
        \\    box.*.field = 1;
        \\}
        \\export fn b() void {
        \\    var box = Box{ .field = 0 };
        \\    var boxPtr = &box;
        \\    boxPtr.*.*.field = 1;
        \\}
        \\pub const Box = struct {
        \\    field: i32,
        \\};
    , &[_][]const u8{
        "tmp.zig:3:8: error: attempt to dereference non-pointer type 'Box'",
        "tmp.zig:8:13: error: attempt to dereference non-pointer type 'Box'",
    });

    ctx.objErrStage1("usingnamespace with wrong type",
        \\usingnamespace void;
    , &[_][]const u8{
        "tmp.zig:1:1: error: expected struct, enum, or union; found 'void'",
    });

    ctx.objErrStage1("ignored expression in while continuation",
        \\export fn a() void {
        \\    while (true) : (bad()) {}
        \\}
        \\export fn b() void {
        \\    var x: anyerror!i32 = 1234;
        \\    while (x) |_| : (bad()) {} else |_| {}
        \\}
        \\export fn c() void {
        \\    var x: ?i32 = 1234;
        \\    while (x) |_| : (bad()) {}
        \\}
        \\fn bad() anyerror!void {
        \\    return error.Bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:24: error: error is ignored. consider using `try`, `catch`, or `if`",
        "tmp.zig:6:25: error: error is ignored. consider using `try`, `catch`, or `if`",
        "tmp.zig:10:25: error: error is ignored. consider using `try`, `catch`, or `if`",
    });

    ctx.objErrStage1("empty while loop body",
        \\export fn a() void {
        \\    while(true);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:16: error: expected block or assignment, found ';'",
    });

    ctx.objErrStage1("empty for loop body",
        \\export fn a() void {
        \\    for(undefined) |x|;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:23: error: expected block or assignment, found ';'",
    });

    ctx.objErrStage1("empty if body",
        \\export fn a() void {
        \\    if(true);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:13: error: expected block or assignment, found ';'",
    });

    ctx.objErrStage1("import outside package path",
        \\comptime{
        \\    _ = @import("../a.zig");
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: import of file outside package path: '../a.zig'",
    });

    ctx.objErrStage1("bogus compile var",
        \\const x = @import("builtin").bogus;
        \\export fn entry() usize { return @sizeOf(@TypeOf(x)); }
    , &[_][]const u8{
        "tmp.zig:1:29: error: container 'builtin' has no member called 'bogus'",
    });

    ctx.objErrStage1("wrong panic signature, runtime function",
        \\test "" {}
        \\
        \\pub fn panic() void {}
        \\
    , &[_][]const u8{
        "error: expected type 'fn([]const u8, ?*std.builtin.StackTrace) noreturn', found 'fn() void'",
    });

    ctx.objErrStage1("wrong panic signature, generic function",
        \\pub fn panic(comptime msg: []const u8, error_return_trace: ?*builtin.StackTrace) noreturn {
        \\    _ = msg; _ = error_return_trace;
        \\    while (true) {}
        \\}
    , &[_][]const u8{
        "error: expected type 'fn([]const u8, ?*std.builtin.StackTrace) noreturn', found 'fn([]const u8,anytype) anytype'",
        "note: only one of the functions is generic",
    });

    ctx.objErrStage1("direct struct loop",
        \\const A = struct { a : A, };
        \\export fn entry() usize { return @sizeOf(A); }
    , &[_][]const u8{
        "tmp.zig:1:11: error: struct 'A' depends on itself",
    });

    ctx.objErrStage1("indirect struct loop",
        \\const A = struct { b : B, };
        \\const B = struct { c : C, };
        \\const C = struct { a : A, };
        \\export fn entry() usize { return @sizeOf(A); }
    , &[_][]const u8{
        "tmp.zig:1:11: error: struct 'A' depends on itself",
    });

    ctx.objErrStage1("instantiating an undefined value for an invalid struct that contains itself",
        \\const Foo = struct {
        \\    x: Foo,
        \\};
        \\
        \\var foo: Foo = undefined;
        \\
        \\export fn entry() usize {
        \\    return @sizeOf(@TypeOf(foo.x));
        \\}
    , &[_][]const u8{
        "tmp.zig:1:13: error: struct 'Foo' depends on itself",
        "tmp.zig:8:28: note: referenced here",
    });

    ctx.objErrStage1("enum field value references enum",
        \\pub const Foo = enum(c_int) {
        \\    A = Foo.B,
        \\    C = D,
        \\};
        \\export fn entry() void {
        \\    var s: Foo = Foo.E;
        \\    _ = s;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:17: error: enum 'Foo' depends on itself",
    });

    ctx.objErrStage1("top level decl dependency loop",
        \\const a : @TypeOf(b) = 0;
        \\const b : @TypeOf(a) = 0;
        \\export fn entry() void {
        \\    const c = a + b;
        \\    _ = c;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:19: error: dependency loop detected",
        "tmp.zig:1:19: note: referenced here",
        "tmp.zig:4:15: note: referenced here",
    });

    ctx.testErrStage1("not an enum type",
        \\export fn entry() void {
        \\    var self: Error = undefined;
        \\    switch (self) {
        \\        InvalidToken => |x| return x.token,
        \\        ExpectedVarDeclOrFn => |x| return x.token,
        \\    }
        \\}
        \\const Error = union(enum) {
        \\    A: InvalidToken,
        \\    B: ExpectedVarDeclOrFn,
        \\};
        \\const InvalidToken = struct {};
        \\const ExpectedVarDeclOrFn = struct {};
    , &[_][]const u8{
        "tmp.zig:4:9: error: expected type '@typeInfo(Error).Union.tag_type.?', found 'type'",
    });

    ctx.testErrStage1("binary OR operator on error sets",
        \\pub const A = error.A;
        \\pub const AB = A | error.B;
        \\export fn entry() void {
        \\    var x: AB = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:18: error: invalid operands to binary expression: 'error{A}' and 'error{B}'",
    });

    if (builtin.os.tag == .linux) {
        ctx.testErrStage1("implicit dependency on libc",
            \\extern "c" fn exit(u8) void;
            \\export fn entry() void {
            \\    exit(0);
            \\}
        , &[_][]const u8{
            "tmp.zig:3:5: error: dependency on libc must be explicitly specified in the build command",
        });

        ctx.testErrStage1("libc headers note",
            \\const c = @cImport(@cInclude("stdio.h"));
            \\export fn entry() void {
            \\    _ = c.printf("hello, world!\n");
            \\}
        , &[_][]const u8{
            "tmp.zig:1:11: error: C import failed",
            "tmp.zig:1:11: note: libc headers not available; compilation does not link against libc",
        });
    }

    ctx.testErrStage1("comptime vector overflow shows the index",
        \\comptime {
        \\    var a: @import("std").meta.Vector(4, u8) = [_]u8{ 1, 2, 255, 4 };
        \\    var b: @import("std").meta.Vector(4, u8) = [_]u8{ 5, 6, 1, 8 };
        \\    var x = a + b;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:15: error: operation caused overflow",
        "tmp.zig:4:15: note: when computing vector element at index 2",
    });

    ctx.testErrStage1("packed struct with fields of not allowed types",
        \\const A = packed struct {
        \\    x: anyerror,
        \\};
        \\const B = packed struct {
        \\    x: [2]u24,
        \\};
        \\const C = packed struct {
        \\    x: [1]anyerror,
        \\};
        \\const D = packed struct {
        \\    x: [1]S,
        \\};
        \\const E = packed struct {
        \\    x: [1]U,
        \\};
        \\const F = packed struct {
        \\    x: ?anyerror,
        \\};
        \\const G = packed struct {
        \\    x: Enum,
        \\};
        \\export fn entry1() void {
        \\    var a: A = undefined;
        \\    _ = a;
        \\}
        \\export fn entry2() void {
        \\    var b: B = undefined;
        \\    _ = b;
        \\}
        \\export fn entry3() void {
        \\    var r: C = undefined;
        \\    _ = r;
        \\}
        \\export fn entry4() void {
        \\    var d: D = undefined;
        \\    _ = d;
        \\}
        \\export fn entry5() void {
        \\    var e: E = undefined;
        \\    _ = e;
        \\}
        \\export fn entry6() void {
        \\    var f: F = undefined;
        \\    _ = f;
        \\}
        \\export fn entry7() void {
        \\    var g: G = undefined;
        \\    _ = g;
        \\}
        \\const S = struct {
        \\    x: i32,
        \\};
        \\const U = struct {
        \\    A: i32,
        \\    B: u32,
        \\};
        \\const Enum = enum {
        \\    A,
        \\    B,
        \\};
    , &[_][]const u8{
        "tmp.zig:2:5: error: type 'anyerror' not allowed in packed struct; no guaranteed in-memory representation",
        "tmp.zig:5:5: error: array of 'u24' not allowed in packed struct due to padding bits",
        "tmp.zig:8:5: error: type 'anyerror' not allowed in packed struct; no guaranteed in-memory representation",
        "tmp.zig:11:5: error: non-packed, non-extern struct 'S' not allowed in packed struct; no guaranteed in-memory representation",
        "tmp.zig:14:5: error: non-packed, non-extern struct 'U' not allowed in packed struct; no guaranteed in-memory representation",
        "tmp.zig:17:5: error: type '?anyerror' not allowed in packed struct; no guaranteed in-memory representation",
        "tmp.zig:20:5: error: type 'Enum' not allowed in packed struct; no guaranteed in-memory representation",
        "tmp.zig:57:14: note: enum declaration does not specify an integer tag type",
    });

    ctx.objErrStage1("deduplicate undeclared identifier",
        \\export fn a() void {
        \\    x += 1;
        \\}
        \\export fn b() void {
        \\    x += 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: use of undeclared identifier 'x'",
    });

    ctx.objErrStage1("export generic function",
        \\export fn foo(num: anytype) i32 {
        \\    _ = num;
        \\    return 0;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:15: error: parameter of type 'anytype' not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("C pointer to c_void",
        \\export fn a() void {
        \\    var x: *c_void = undefined;
        \\    var y: [*c]c_void = x;
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:16: error: C pointers cannot point to opaque types",
    });

    ctx.objErrStage1("directly embedding opaque type in struct and union",
        \\const O = opaque {};
        \\const Foo = struct {
        \\    o: O,
        \\};
        \\const Bar = union {
        \\    One: i32,
        \\    Two: O,
        \\};
        \\export fn a() void {
        \\    var foo: Foo = undefined;
        \\    _ = foo;
        \\}
        \\export fn b() void {
        \\    var bar: Bar = undefined;
        \\    _ = bar;
        \\}
        \\export fn c() void {
        \\    var baz: *opaque {} = undefined;
        \\    const qux = .{baz.*};
        \\    _ = qux;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: opaque types have unknown size and therefore cannot be directly embedded in structs",
        "tmp.zig:7:5: error: opaque types have unknown size and therefore cannot be directly embedded in unions",
        "tmp.zig:19:22: error: opaque types have unknown size and therefore cannot be directly embedded in structs",
    });

    ctx.objErrStage1("implicit cast between C pointer and Zig pointer - bad const/align/child",
        \\export fn a() void {
        \\    var x: [*c]u8 = undefined;
        \\    var y: *align(4) u8 = x;
        \\    _ = y;
        \\}
        \\export fn b() void {
        \\    var x: [*c]const u8 = undefined;
        \\    var y: *u8 = x;
        \\    _ = y;
        \\}
        \\export fn c() void {
        \\    var x: [*c]u8 = undefined;
        \\    var y: *u32 = x;
        \\    _ = y;
        \\}
        \\export fn d() void {
        \\    var y: *align(1) u32 = undefined;
        \\    var x: [*c]u32 = y;
        \\    _ = x;
        \\}
        \\export fn e() void {
        \\    var y: *const u8 = undefined;
        \\    var x: [*c]u8 = y;
        \\    _ = x;
        \\}
        \\export fn f() void {
        \\    var y: *u8 = undefined;
        \\    var x: [*c]u32 = y;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:27: error: cast increases pointer alignment",
        "tmp.zig:8:18: error: cast discards const qualifier",
        "tmp.zig:13:19: error: expected type '*u32', found '[*c]u8'",
        "tmp.zig:13:19: note: pointer type child 'u8' cannot cast into pointer type child 'u32'",
        "tmp.zig:18:22: error: cast increases pointer alignment",
        "tmp.zig:23:21: error: cast discards const qualifier",
        "tmp.zig:28:22: error: expected type '[*c]u32', found '*u8'",
    });

    ctx.objErrStage1("implicit casting null c pointer to zig pointer",
        \\comptime {
        \\    var c_ptr: [*c]u8 = 0;
        \\    var zig_ptr: *u8 = c_ptr;
        \\    _ = zig_ptr;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:24: error: null pointer casted to type '*u8'",
    });

    ctx.objErrStage1("implicit casting undefined c pointer to zig pointer",
        \\comptime {
        \\    var c_ptr: [*c]u8 = undefined;
        \\    var zig_ptr: *u8 = c_ptr;
        \\    _ = zig_ptr;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:24: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("implicit casting C pointers which would mess up null semantics",
        \\export fn entry() void {
        \\    var slice: []const u8 = "aoeu";
        \\    const opt_many_ptr: [*]const u8 = slice.ptr;
        \\    var ptr_opt_many_ptr = &opt_many_ptr;
        \\    var c_ptr: [*c]const [*c]const u8 = ptr_opt_many_ptr;
        \\    ptr_opt_many_ptr = c_ptr;
        \\}
        \\export fn entry2() void {
        \\    var buf: [4]u8 = "aoeu".*;
        \\    var slice: []u8 = &buf;
        \\    var opt_many_ptr: [*]u8 = slice.ptr;
        \\    var ptr_opt_many_ptr = &opt_many_ptr;
        \\    var c_ptr: [*c][*c]const u8 = ptr_opt_many_ptr;
        \\    _ = c_ptr;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:24: error: expected type '*const [*]const u8', found '[*c]const [*c]const u8'",
        "tmp.zig:6:24: note: pointer type child '[*c]const u8' cannot cast into pointer type child '[*]const u8'",
        "tmp.zig:6:24: note: '[*c]const u8' could have null values which are illegal in type '[*]const u8'",
        "tmp.zig:13:35: error: expected type '[*c][*c]const u8', found '*[*]u8'",
        "tmp.zig:13:35: note: pointer type child '[*]u8' cannot cast into pointer type child '[*c]const u8'",
        "tmp.zig:13:35: note: mutable '[*c]const u8' allows illegal null values stored to type '[*]u8'",
    });

    ctx.objErrStage1("implicit casting too big integers to C pointers",
        \\export fn a() void {
        \\    var ptr: [*c]u8 = (1 << 64) + 1;
        \\    _ = ptr;
        \\}
        \\export fn b() void {
        \\    var x: u65 = 0x1234;
        \\    var ptr: [*c]u8 = x;
        \\    _ = ptr;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:33: error: integer value 18446744073709551617 cannot be coerced to type 'usize'",
        "tmp.zig:7:23: error: integer type 'u65' too big for implicit @intToPtr to type '[*c]u8'",
    });

    ctx.objErrStage1("C pointer pointing to non C ABI compatible type or has align attr",
        \\const Foo = struct {};
        \\export fn a() void {
        \\    const T = [*c]Foo;
        \\    var t: T = undefined;
        \\    _ = t;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:19: error: C pointers cannot point to non-C-ABI-compatible type 'Foo'",
    });

    ctx.objErrStage1("compile log statement warning deduplication in generic fn",
        \\export fn entry() void {
        \\    inner(1);
        \\    inner(2);
        \\}
        \\fn inner(comptime n: usize) void {
        \\    comptime var i = 0;
        \\    inline while (i < n) : (i += 1) { @compileLog("!@#$"); }
        \\}
    , &[_][]const u8{
        "tmp.zig:7:39: error: found compile log statement",
    });

    ctx.objErrStage1("assign to invalid dereference",
        \\export fn entry() void {
        \\    'a'.* = 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:8: error: attempt to dereference non-pointer type 'comptime_int'",
    });

    ctx.objErrStage1("take slice of invalid dereference",
        \\export fn entry() void {
        \\    const x = 'a'.*[0..];
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:18: error: attempt to dereference non-pointer type 'comptime_int'",
    });

    ctx.objErrStage1("@truncate undefined value",
        \\export fn entry() void {
        \\    var z = @truncate(u8, @as(u16, undefined));
        \\    _ = z;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:27: error: use of undefined value here causes undefined behavior",
    });

    ctx.testErrStage1("return invalid type from test",
        \\test "example" { return 1; }
    , &[_][]const u8{
        "tmp.zig:1:25: error: expected type 'void', found 'comptime_int'",
    });

    ctx.objErrStage1("threadlocal qualifier on const",
        \\threadlocal const x: i32 = 1234;
        \\export fn entry() i32 {
        \\    return x;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: threadlocal variable cannot be constant",
    });

    ctx.objErrStage1("@bitCast same size but bit count mismatch",
        \\export fn entry(byte: u8) void {
        \\    var oops = @bitCast(u7, byte);
        \\    _ = oops;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:25: error: destination type 'u7' has 7 bits but source type 'u8' has 8 bits",
    });

    ctx.objErrStage1("@bitCast with different sizes inside an expression",
        \\export fn entry() void {
        \\    var foo = (@bitCast(u8, @as(f32, 1.0)) == 0xf);
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:25: error: destination type 'u8' has size 1 but source type 'f32' has size 4",
    });

    ctx.objErrStage1("attempted `&&`",
        \\export fn entry(a: bool, b: bool) i32 {
        \\    if (a && b) {
        \\        return 1234;
        \\    }
        \\    return 5678;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:11: error: `&&` is invalid; note that `and` is boolean AND",
    });

    ctx.objErrStage1("attempted `||` on boolean values",
        \\export fn entry(a: bool, b: bool) i32 {
        \\    if (a || b) {
        \\        return 1234;
        \\    }
        \\    return 5678;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: expected error set type, found 'bool'",
        "tmp.zig:2:11: note: `||` merges error sets; `or` performs boolean OR",
    });

    ctx.objErrStage1("compile log a pointer to an opaque value",
        \\export fn entry() void {
        \\    @compileLog(@ptrCast(*const c_void, &entry));
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: found compile log statement",
    });

    ctx.objErrStage1("duplicate boolean switch value",
        \\comptime {
        \\    const x = switch (true) {
        \\        true => false,
        \\        false => true,
        \\        true => false,
        \\    };
        \\    _ = x;
        \\}
        \\comptime {
        \\    const x = switch (true) {
        \\        false => true,
        \\        true => false,
        \\        false => true,
        \\    };
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:9: error: duplicate switch value",
        "tmp.zig:13:9: error: duplicate switch value",
    });

    ctx.objErrStage1("missing boolean switch value",
        \\comptime {
        \\    const x = switch (true) {
        \\        true => false,
        \\    };
        \\    _ = x;
        \\}
        \\comptime {
        \\    const x = switch (true) {
        \\        false => true,
        \\    };
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: switch must handle all possibilities",
        "tmp.zig:8:15: error: switch must handle all possibilities",
    });

    ctx.objErrStage1("reading past end of pointer casted array",
        \\comptime {
        \\    const array: [4]u8 = "aoeu".*;
        \\    const sub_array = array[1..];
        \\    const int_ptr = @ptrCast(*const u24, sub_array);
        \\    const deref = int_ptr.*;
        \\    _ = deref;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:26: error: attempt to read 4 bytes from [4]u8 at index 1 which is 3 bytes",
    });

    ctx.objErrStage1("error note for function parameter incompatibility",
        \\fn do_the_thing(func: fn (arg: i32) void) void { _ = func; }
        \\fn bar(arg: bool) void { _ = arg; }
        \\export fn entry() void {
        \\    do_the_thing(bar);
        \\}
    , &[_][]const u8{
        "tmp.zig:4:18: error: expected type 'fn(i32) void', found 'fn(bool) void",
        "tmp.zig:4:18: note: parameter 0: 'bool' cannot cast into 'i32'",
    });
    ctx.objErrStage1("cast negative value to unsigned integer",
        \\comptime {
        \\    const value: i32 = -1;
        \\    const unsigned = @intCast(u32, value);
        \\    _ = unsigned;
        \\}
        \\export fn entry1() void {
        \\    const value: i32 = -1;
        \\    const unsigned: u32 = value;
        \\    _ = unsigned;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:22: error: attempt to cast negative value to unsigned integer",
        "tmp.zig:8:27: error: cannot cast negative value -1 to unsigned integer type 'u32'",
    });

    ctx.objErrStage1("integer cast truncates bits",
        \\export fn entry1() void {
        \\    const spartan_count: u16 = 300;
        \\    const byte = @intCast(u8, spartan_count);
        \\    _ = byte;
        \\}
        \\export fn entry2() void {
        \\    const spartan_count: u16 = 300;
        \\    const byte: u8 = spartan_count;
        \\    _ = byte;
        \\}
        \\export fn entry3() void {
        \\    var spartan_count: u16 = 300;
        \\    var byte: u8 = spartan_count;
        \\    _ = byte;
        \\}
        \\export fn entry4() void {
        \\    var signed: i8 = -1;
        \\    var unsigned: u64 = signed;
        \\    _ = unsigned;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:18: error: cast from 'u16' to 'u8' truncates bits",
        "tmp.zig:8:22: error: integer value 300 cannot be coerced to type 'u8'",
        "tmp.zig:13:20: error: expected type 'u8', found 'u16'",
        "tmp.zig:13:20: note: unsigned 8-bit int cannot represent all possible unsigned 16-bit values",
        "tmp.zig:18:25: error: expected type 'u64', found 'i8'",
        "tmp.zig:18:25: note: unsigned 64-bit int cannot represent all possible signed 8-bit values",
    });

    ctx.objErrStage1("comptime implicit cast f64 to f32",
        \\export fn entry() void {
        \\    const x: f64 = 16777217;
        \\    const y: f32 = x;
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:20: error: cast of value 16777217.000000 to type 'f32' loses information",
    });

    ctx.objErrStage1("implicit cast from f64 to f32",
        \\var x: f64 = 1.0;
        \\var y: f32 = x;
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(y)); }
    , &[_][]const u8{
        "tmp.zig:2:14: error: expected type 'f32', found 'f64'",
    });

    ctx.objErrStage1("exceeded maximum bit width of integer",
        \\export fn entry1() void {
        \\    const T = u65536;
        \\    _ = T;
        \\}
        \\export fn entry2() void {
        \\    var x: i65536 = 1;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: primitive integer type 'u65536' exceeds maximum bit width of 65535",
        "tmp.zig:6:12: error: primitive integer type 'i65536' exceeds maximum bit width of 65535",
    });

    ctx.objErrStage1("compile error when evaluating return type of inferred error set",
        \\const Car = struct {
        \\    foo: *SymbolThatDoesNotExist,
        \\    pub fn init() !Car {}
        \\};
        \\export fn entry() void {
        \\    const car = Car.init();
        \\    _ = car;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:11: error: use of undeclared identifier 'SymbolThatDoesNotExist'",
    });

    ctx.objErrStage1("don't implicit cast double pointer to *c_void",
        \\export fn entry() void {
        \\    var a: u32 = 1;
        \\    var ptr: *align(@alignOf(u32)) c_void = &a;
        \\    var b: *u32 = @ptrCast(*u32, ptr);
        \\    var ptr2: *c_void = &b;
        \\    _ = ptr2;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:26: error: expected type '*c_void', found '**u32'",
    });

    ctx.objErrStage1("runtime index into comptime type slice",
        \\const Struct = struct {
        \\    a: u32,
        \\};
        \\fn getIndex() usize {
        \\    return 2;
        \\}
        \\export fn entry() void {
        \\    const index = getIndex();
        \\    const field = @typeInfo(Struct).Struct.fields[index];
        \\    _ = field;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:51: error: values of type 'std.builtin.StructField' must be comptime known, but index value is runtime known",
    });

    ctx.objErrStage1("compile log statement inside function which must be comptime evaluated",
        \\fn Foo(comptime T: type) type {
        \\    @compileLog(@typeName(T));
        \\    return T;
        \\}
        \\export fn entry() void {
        \\    _ = Foo(i32);
        \\    _ = @typeName(Foo(i32));
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: found compile log statement",
    });

    ctx.objErrStage1("comptime slice of an undefined slice",
        \\comptime {
        \\    var a: []u8 = undefined;
        \\    var b = a[0..10];
        \\    _ = b;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:14: error: slice of undefined",
    });

    ctx.objErrStage1("implicit cast const array to mutable slice",
        \\export fn entry() void {
        \\    const buffer: [1]u8 = [_]u8{8};
        \\    const sliceA: []u8 = &buffer;
        \\    _ = sliceA;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:27: error: expected type '[]u8', found '*const [1]u8'",
    });

    ctx.objErrStage1("deref slice and get len field",
        \\export fn entry() void {
        \\    var a: []u8 = undefined;
        \\    _ = a.*.len;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:10: error: attempt to dereference non-pointer type '[]u8'",
    });

    ctx.objErrStage1("@ptrCast a 0 bit type to a non- 0 bit type",
        \\export fn entry() bool {
        \\    var x: u0 = 0;
        \\    const p = @ptrCast(?*u0, &x);
        \\    return p == null;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:15: error: '*u0' and '?*u0' do not have the same in-memory representation",
        "tmp.zig:3:31: note: '*u0' has no in-memory bits",
        "tmp.zig:3:24: note: '?*u0' has in-memory bits",
    });

    ctx.objErrStage1("comparing a non-optional pointer against null",
        \\export fn entry() void {
        \\    var x: i32 = 1;
        \\    _ = &x == null;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:12: error: comparison of '*i32' with null",
    });

    ctx.objErrStage1("non error sets used in merge error sets operator",
        \\export fn foo() void {
        \\    const Errors = u8 || u16;
        \\    _ = Errors;
        \\}
        \\export fn bar() void {
        \\    const Errors = error{} || u16;
        \\    _ = Errors;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:20: error: expected error set type, found type 'u8'",
        "tmp.zig:2:23: note: `||` merges error sets; `or` performs boolean OR",
        "tmp.zig:6:31: error: expected error set type, found type 'u16'",
        "tmp.zig:6:28: note: `||` merges error sets; `or` performs boolean OR",
    });

    ctx.objErrStage1("variable initialization compile error then referenced",
        \\fn Undeclared() type {
        \\    return T;
        \\}
        \\fn Gen() type {
        \\    const X = Undeclared();
        \\    return struct {
        \\        x: X,
        \\    };
        \\}
        \\export fn entry() void {
        \\    const S = Gen();
        \\    _ = S;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: use of undeclared identifier 'T'",
    });

    ctx.objErrStage1("refer to the type of a generic function",
        \\export fn entry() void {
        \\    const Func = fn (type) void;
        \\    const f: Func = undefined;
        \\    f(i32);
        \\}
    , &[_][]const u8{
        "tmp.zig:4:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("accessing runtime parameter from outer function",
        \\fn outer(y: u32) fn (u32) u32 {
        \\    const st = struct {
        \\        fn get(z: u32) u32 {
        \\            return z + y;
        \\        }
        \\    };
        \\    return st.get;
        \\}
        \\export fn entry() void {
        \\    var func = outer(10);
        \\    var x = func(3);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:24: error: 'y' not accessible from inner function",
        "tmp.zig:3:28: note: crossed function definition here",
        "tmp.zig:1:10: note: declared here",
    });

    ctx.objErrStage1("non int passed to @intToFloat",
        \\export fn entry() void {
        \\    const x = @intToFloat(f32, 1.1);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:32: error: expected int type, found 'comptime_float'",
    });

    ctx.objErrStage1("non float passed to @floatToInt",
        \\export fn entry() void {
        \\    const x = @floatToInt(i32, @as(i32, 54));
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:32: error: expected float type, found 'i32'",
    });

    ctx.objErrStage1("out of range comptime_int passed to @floatToInt",
        \\export fn entry() void {
        \\    const x = @floatToInt(i8, 200);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:31: error: integer value 200 cannot be coerced to type 'i8'",
    });

    ctx.objErrStage1("load too many bytes from comptime reinterpreted pointer",
        \\export fn entry() void {
        \\    const float: f32 = 5.99999999999994648725e-01;
        \\    const float_ptr = &float;
        \\    const int_ptr = @ptrCast(*const i64, float_ptr);
        \\    const int_val = int_ptr.*;
        \\    _ = int_val;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:28: error: attempt to read 8 bytes from pointer to f32 which is 4 bytes",
    });

    ctx.objErrStage1("invalid type used in array type",
        \\const Item = struct {
        \\    field: SomeNonexistentType,
        \\};
        \\var items: [100]Item = undefined;
        \\export fn entry() void {
        \\    const a = items[0];
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: use of undeclared identifier 'SomeNonexistentType'",
    });

    ctx.objErrStage1("comptime continue inside runtime catch",
        \\export fn entry() void {
        \\    const ints = [_]u8{ 1, 2 };
        \\    inline for (ints) |_| {
        \\        bad() catch continue;
        \\    }
        \\}
        \\fn bad() !void {
        \\    return error.Bad;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:21: error: comptime control flow inside runtime block",
        "tmp.zig:4:15: note: runtime block created here",
    });

    ctx.objErrStage1("comptime continue inside runtime switch",
        \\export fn entry() void {
        \\    var p: i32 = undefined;
        \\    comptime var q = true;
        \\    inline while (q) {
        \\        switch (p) {
        \\            11 => continue,
        \\            else => {},
        \\        }
        \\        q = false;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:6:19: error: comptime control flow inside runtime block",
        "tmp.zig:5:9: note: runtime block created here",
    });

    ctx.objErrStage1("comptime continue inside runtime while error",
        \\export fn entry() void {
        \\    var p: anyerror!usize = undefined;
        \\    comptime var q = true;
        \\    outer: inline while (q) {
        \\        while (p) |_| {
        \\            continue :outer;
        \\        } else |_| {}
        \\        q = false;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:6:13: error: comptime control flow inside runtime block",
        "tmp.zig:5:9: note: runtime block created here",
    });

    ctx.objErrStage1("comptime continue inside runtime while optional",
        \\export fn entry() void {
        \\    var p: ?usize = undefined;
        \\    comptime var q = true;
        \\    outer: inline while (q) {
        \\        while (p) |_| continue :outer;
        \\        q = false;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:23: error: comptime control flow inside runtime block",
        "tmp.zig:5:9: note: runtime block created here",
    });

    ctx.objErrStage1("comptime continue inside runtime while bool",
        \\export fn entry() void {
        \\    var p: usize = undefined;
        \\    comptime var q = true;
        \\    outer: inline while (q) {
        \\        while (p == 11) continue :outer;
        \\        q = false;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:25: error: comptime control flow inside runtime block",
        "tmp.zig:5:9: note: runtime block created here",
    });

    ctx.objErrStage1("comptime continue inside runtime if error",
        \\export fn entry() void {
        \\    var p: anyerror!i32 = undefined;
        \\    comptime var q = true;
        \\    inline while (q) {
        \\        if (p) |_| continue else |_| {}
        \\        q = false;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:20: error: comptime control flow inside runtime block",
        "tmp.zig:5:9: note: runtime block created here",
    });

    ctx.objErrStage1("comptime continue inside runtime if optional",
        \\export fn entry() void {
        \\    var p: ?i32 = undefined;
        \\    comptime var q = true;
        \\    inline while (q) {
        \\        if (p) |_| continue;
        \\        q = false;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:20: error: comptime control flow inside runtime block",
        "tmp.zig:5:9: note: runtime block created here",
    });

    ctx.objErrStage1("comptime continue inside runtime if bool",
        \\export fn entry() void {
        \\    var p: usize = undefined;
        \\    comptime var q = true;
        \\    inline while (q) {
        \\        if (p == 11) continue;
        \\        q = false;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:22: error: comptime control flow inside runtime block",
        "tmp.zig:5:9: note: runtime block created here",
    });

    ctx.objErrStage1("switch with invalid expression parameter",
        \\export fn entry() void {
        \\    Test(i32);
        \\}
        \\fn Test(comptime T: type) void {
        \\    const x = switch (T) {
        \\        []u8 => |x| x,
        \\        i32 => |x| x,
        \\        else => unreachable,
        \\    };
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:17: error: switch on type 'type' provides no expression parameter",
    });

    ctx.objErrStage1("function prototype with no body",
        \\fn foo() void;
        \\export fn entry() void {
        \\    foo();
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: non-extern function has no body",
    });

    ctx.objErrStage1("@frame() called outside of function definition",
        \\var handle_undef: anyframe = undefined;
        \\var handle_dummy: anyframe = @frame();
        \\export fn entry() bool {
        \\    return handle_undef == handle_dummy;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:30: error: @frame() called outside of function definition",
    });

    ctx.objErrStage1("`_` is not a declarable symbol",
        \\export fn f1() usize {
        \\    var _: usize = 2;
        \\    return _;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: '_' used as an identifier without @\"_\" syntax",
    });

    ctx.objErrStage1("`_` should not be usable inside for",
        \\export fn returns() void {
        \\    for ([_]void{}) |_, i| {
        \\        for ([_]void{}) |_, j| {
        \\            return _;
        \\        }
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:4:20: error: '_' used as an identifier without @\"_\" syntax",
    });

    ctx.objErrStage1("`_` should not be usable inside while",
        \\export fn returns() void {
        \\    while (optionalReturn()) |_| {
        \\        while (optionalReturn()) |_| {
        \\            return _;
        \\        }
        \\    }
        \\}
        \\fn optionalReturn() ?u32 {
        \\    return 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:20: error: '_' used as an identifier without @\"_\" syntax",
    });

    ctx.objErrStage1("`_` should not be usable inside while else",
        \\export fn returns() void {
        \\    while (optionalReturnError()) |_| {
        \\        while (optionalReturnError()) |_| {
        \\            return;
        \\        } else |_| {
        \\            if (_ == error.optionalReturnError) return;
        \\        }
        \\    }
        \\}
        \\fn optionalReturnError() !?u32 {
        \\    return error.optionalReturnError;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:17: error: '_' used as an identifier without @\"_\" syntax",
    });

    ctx.objErrStage1("while loop body expression ignored",
        \\fn returns() usize {
        \\    return 2;
        \\}
        \\export fn f1() void {
        \\    while (true) returns();
        \\}
        \\export fn f2() void {
        \\    var x: ?i32 = null;
        \\    while (x) |_| returns();
        \\}
        \\export fn f3() void {
        \\    var x: anyerror!i32 = error.Bad;
        \\    while (x) |_| returns() else |_| unreachable;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:25: error: expression value is ignored",
        "tmp.zig:9:26: error: expression value is ignored",
        "tmp.zig:13:26: error: expression value is ignored",
    });

    ctx.objErrStage1("missing parameter name of generic function",
        \\fn dump(anytype) void {}
        \\export fn entry() void {
        \\    var a: u8 = 9;
        \\    dump(a);
        \\}
    , &[_][]const u8{
        "tmp.zig:1:9: error: missing parameter name",
    });

    ctx.objErrStage1("non-inline for loop on a type that requires comptime",
        \\const Foo = struct {
        \\    name: []const u8,
        \\    T: type,
        \\};
        \\export fn entry() void {
        \\    const xx: [2]Foo = undefined;
        \\    for (xx) |f| { _ = f;}
        \\}
    , &[_][]const u8{
        "tmp.zig:7:5: error: values of type 'Foo' must be comptime known, but index value is runtime known",
    });

    ctx.objErrStage1("generic fn as parameter without comptime keyword",
        \\fn f(_: fn (anytype) void) void {}
        \\fn g(_: anytype) void {}
        \\export fn entry() void {
        \\    f(g);
        \\}
    , &[_][]const u8{
        "tmp.zig:1:9: error: parameter of type 'fn(anytype) anytype' must be declared comptime",
    });

    ctx.objErrStage1("optional pointer to void in extern struct",
        \\const Foo = extern struct {
        \\    x: ?*const void,
        \\};
        \\const Bar = extern struct {
        \\    foo: Foo,
        \\    y: i32,
        \\};
        \\export fn entry(bar: *Bar) void {_ = bar;}
    , &[_][]const u8{
        "tmp.zig:2:5: error: extern structs cannot contain fields of type '?*const void'",
    });

    ctx.objErrStage1("use of comptime-known undefined function value",
        \\const Cmd = struct {
        \\    exec: fn () void,
        \\};
        \\export fn entry() void {
        \\    const command = Cmd{ .exec = undefined };
        \\    command.exec();
        \\}
    , &[_][]const u8{
        "tmp.zig:6:12: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("use of comptime-known undefined function value",
        \\const Cmd = struct {
        \\    exec: fn () void,
        \\};
        \\export fn entry() void {
        \\    const command = Cmd{ .exec = undefined };
        \\    command.exec();
        \\}
    , &[_][]const u8{
        "tmp.zig:6:12: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bad @alignCast at comptime",
        \\comptime {
        \\    const ptr = @intToPtr(*align(1) i32, 0x1);
        \\    const aligned = @alignCast(4, ptr);
        \\    _ = aligned;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:35: error: pointer address 0x1 is not aligned to 4 bytes",
    });

    ctx.objErrStage1("@ptrToInt on *void",
        \\export fn entry() bool {
        \\    return @ptrToInt(&{}) == @ptrToInt(&{});
        \\}
    , &[_][]const u8{
        "tmp.zig:2:23: error: pointer to size 0 type has no address",
    });

    ctx.objErrStage1("@popCount - non-integer",
        \\export fn entry(x: f32) u32 {
        \\    return @popCount(f32, x);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:22: error: expected integer type, found 'f32'",
    });

    {
        const case = ctx.obj("wrong same named struct", .{});
        case.backend = .stage1;

        case.addSourceFile("a.zig",
            \\pub const Foo = struct {
            \\    x: i32,
            \\};
        );

        case.addSourceFile("b.zig",
            \\pub const Foo = struct {
            \\    z: f64,
            \\};
        );

        case.addError(
            \\const a = @import("a.zig");
            \\const b = @import("b.zig");
            \\
            \\export fn entry() void {
            \\    var a1: a.Foo = undefined;
            \\    bar(&a1);
            \\}
            \\
            \\fn bar(x: *b.Foo) void {_ = x;}
        , &[_][]const u8{
            "tmp.zig:6:10: error: expected type '*b.Foo', found '*a.Foo'",
            "tmp.zig:6:10: note: pointer type child 'a.Foo' cannot cast into pointer type child 'b.Foo'",
            "a.zig:1:17: note: a.Foo declared here",
            "b.zig:1:17: note: b.Foo declared here",
        });
    }

    ctx.objErrStage1("@floatToInt comptime safety",
        \\comptime {
        \\    _ = @floatToInt(i8, @as(f32, -129.1));
        \\}
        \\comptime {
        \\    _ = @floatToInt(u8, @as(f32, -1.1));
        \\}
        \\comptime {
        \\    _ = @floatToInt(u8, @as(f32, 256.1));
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: integer value '-129' cannot be stored in type 'i8'",
        "tmp.zig:5:9: error: integer value '-1' cannot be stored in type 'u8'",
        "tmp.zig:8:9: error: integer value '256' cannot be stored in type 'u8'",
    });

    ctx.objErrStage1("use c_void as return type of fn ptr",
        \\export fn entry() void {
        \\    const a: fn () c_void = undefined;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:20: error: return type cannot be opaque",
    });

    ctx.objErrStage1("use implicit casts to assign null to non-nullable pointer",
        \\export fn entry() void {
        \\    var x: i32 = 1234;
        \\    var p: *i32 = &x;
        \\    var pp: *?*i32 = &p;
        \\    pp.* = null;
        \\    var y = p.*;
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:23: error: expected type '*?*i32', found '**i32'",
    });

    ctx.objErrStage1("attempted implicit cast from T to [*]const T",
        \\export fn entry() void {
        \\    const x: [*]const bool = true;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:30: error: expected type '[*]const bool', found 'bool'",
    });

    ctx.objErrStage1("dereference unknown length pointer",
        \\export fn entry(x: [*]i32) i32 {
        \\    return x.*;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:13: error: index syntax required for unknown-length pointer type '[*]i32'",
    });

    ctx.objErrStage1("field access of unknown length pointer",
        \\const Foo = extern struct {
        \\    a: i32,
        \\};
        \\
        \\export fn entry(foo: [*]Foo) void {
        \\    foo.a += 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:8: error: type '[*]Foo' does not support field access",
    });

    ctx.objErrStage1("unknown length pointer to opaque",
        \\export const T = [*]opaque {};
    , &[_][]const u8{
        "tmp.zig:1:21: error: unknown-length pointer to opaque",
    });

    ctx.objErrStage1("error when evaluating return type",
        \\const Foo = struct {
        \\    map: @as(i32, i32),
        \\
        \\    fn init() Foo {
        \\        return undefined;
        \\    }
        \\};
        \\export fn entry() void {
        \\    var rule_set = try Foo.init();
        \\    _ = rule_set;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:19: error: expected type 'i32', found 'type'",
    });

    ctx.objErrStage1("slicing single-item pointer",
        \\export fn entry(ptr: *i32) void {
        \\    const slice = ptr[0..2];
        \\    _ = slice;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:22: error: slice of single-item pointer",
    });

    ctx.objErrStage1("indexing single-item pointer",
        \\export fn entry(ptr: *i32) i32 {
        \\    return ptr[1];
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: index of single-item pointer",
    });

    ctx.objErrStage1("nested error set mismatch",
        \\const NextError = error{NextError};
        \\const OtherError = error{OutOfMemory};
        \\
        \\export fn entry() void {
        \\    const a: ?NextError!i32 = foo();
        \\    _ = a;
        \\}
        \\
        \\fn foo() ?OtherError!i32 {
        \\    return null;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:34: error: expected type '?NextError!i32', found '?OtherError!i32'",
        "tmp.zig:5:34: note: optional type child 'OtherError!i32' cannot cast into optional type child 'NextError!i32'",
        "tmp.zig:5:34: note: error set 'OtherError' cannot cast into error set 'NextError'",
        "tmp.zig:2:26: note: 'error.OutOfMemory' not a member of destination error set",
    });

    ctx.objErrStage1("invalid deref on switch target",
        \\comptime {
        \\    var tile = Tile.Empty;
        \\    switch (tile.*) {
        \\        Tile.Empty => {},
        \\        Tile.Filled => {},
        \\    }
        \\}
        \\const Tile = enum {
        \\    Empty,
        \\    Filled,
        \\};
    , &[_][]const u8{
        "tmp.zig:3:17: error: attempt to dereference non-pointer type 'Tile'",
    });

    ctx.objErrStage1("invalid field access in comptime",
        \\comptime { var x = doesnt_exist.whatever; _ = x; }
    , &[_][]const u8{
        "tmp.zig:1:20: error: use of undeclared identifier 'doesnt_exist'",
    });

    ctx.objErrStage1("suspend inside suspend block",
        \\export fn entry() void {
        \\    _ = async foo();
        \\}
        \\fn foo() void {
        \\    suspend {
        \\        suspend {
        \\        }
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:6:9: error: cannot suspend inside suspend block",
        "tmp.zig:5:5: note: other suspend block here",
    });

    ctx.objErrStage1("assign inline fn to non-comptime var",
        \\export fn entry() void {
        \\    var a = b;
        \\    _ = a;
        \\}
        \\fn b() callconv(.Inline) void { }
    , &[_][]const u8{
        "tmp.zig:2:5: error: functions marked inline must be stored in const or comptime var",
        "tmp.zig:5:1: note: declared here",
    });

    ctx.objErrStage1("wrong type passed to @panic",
        \\export fn entry() void {
        \\    var e = error.Foo;
        \\    @panic(e);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:12: error: expected type '[]const u8', found 'error{Foo}'",
    });

    ctx.objErrStage1("@tagName used on union with no associated enum tag",
        \\const FloatInt = extern union {
        \\    Float: f32,
        \\    Int: i32,
        \\};
        \\export fn entry() void {
        \\    var fi = FloatInt{.Float = 123.45};
        \\    var tagName = @tagName(fi);
        \\    _ = tagName;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:19: error: union has no associated enum",
        "tmp.zig:1:18: note: declared here",
    });

    ctx.objErrStage1("returning error from void async function",
        \\export fn entry() void {
        \\    _ = async amain();
        \\}
        \\fn amain() callconv(.Async) void {
        \\    return error.ShouldBeCompileError;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:17: error: expected type 'void', found 'error{ShouldBeCompileError}'",
    });

    ctx.objErrStage1("var makes structs required to be comptime known",
        \\export fn entry() void {
        \\   const S = struct{v: anytype};
        \\   var s = S{.v=@as(i32, 10)};
        \\   _ = s;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:4: error: variable of type 'S' must be const or comptime",
    });

    ctx.objErrStage1("@ptrCast discards const qualifier",
        \\export fn entry() void {
        \\    const x: i32 = 1234;
        \\    const y = @ptrCast(*i32, &x);
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:15: error: cast discards const qualifier",
    });

    ctx.objErrStage1("comptime slice of undefined pointer non-zero len",
        \\export fn entry() void {
        \\    const slice = @as([*]i32, undefined)[0..1];
        \\    _ = slice;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:41: error: non-zero length slice of undefined pointer",
    });

    ctx.objErrStage1("type checking function pointers",
        \\fn a(b: fn (*const u8) void) void {
        \\    b('a');
        \\}
        \\fn c(d: u8) void {_ = d;}
        \\export fn entry() void {
        \\    a(c);
        \\}
    , &[_][]const u8{
        "tmp.zig:6:7: error: expected type 'fn(*const u8) void', found 'fn(u8) void'",
    });

    ctx.objErrStage1("no else prong on switch on global error set",
        \\export fn entry() void {
        \\    foo(error.A);
        \\}
        \\fn foo(a: anyerror) void {
        \\    switch (a) {
        \\        error.A => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: else prong required when switching on type 'anyerror'",
    });

    ctx.objErrStage1("error not handled in switch",
        \\export fn entry() void {
        \\    foo(452) catch |err| switch (err) {
        \\        error.Foo => {},
        \\    };
        \\}
        \\fn foo(x: i32) !void {
        \\    switch (x) {
        \\        0 ... 10 => return error.Foo,
        \\        11 ... 20 => return error.Bar,
        \\        21 ... 30 => return error.Baz,
        \\        else => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:2:26: error: error.Baz not handled in switch",
        "tmp.zig:2:26: error: error.Bar not handled in switch",
    });

    ctx.objErrStage1("duplicate error in switch",
        \\export fn entry() void {
        \\    foo(452) catch |err| switch (err) {
        \\        error.Foo => {},
        \\        error.Bar => {},
        \\        error.Foo => {},
        \\        else => {},
        \\    };
        \\}
        \\fn foo(x: i32) !void {
        \\    switch (x) {
        \\        0 ... 10 => return error.Foo,
        \\        11 ... 20 => return error.Bar,
        \\        else => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:14: error: duplicate switch value: '@typeInfo(@typeInfo(@TypeOf(foo)).Fn.return_type.?).ErrorUnion.error_set.Foo'",
        "tmp.zig:3:14: note: other value here",
    });

    ctx.objErrStage1("invalid cast from integral type to enum",
        \\const E = enum(usize) { One, Two };
        \\
        \\export fn entry() void {
        \\    foo(1);
        \\}
        \\
        \\fn foo(x: usize) void {
        \\    switch (x) {
        \\        E.One => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:9:10: error: expected type 'usize', found 'E'",
    });

    ctx.objErrStage1("range operator in switch used on error set",
        \\export fn entry() void {
        \\    try foo(452) catch |err| switch (err) {
        \\        error.A ... error.B => {},
        \\        else => {},
        \\    };
        \\}
        \\fn foo(x: i32) !void {
        \\    switch (x) {
        \\        0 ... 10 => return error.Foo,
        \\        11 ... 20 => return error.Bar,
        \\        else => {},
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:3:17: error: operator not allowed for errors",
    });

    ctx.objErrStage1("inferring error set of function pointer",
        \\comptime {
        \\    const z: ?fn()!void = null;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:19: error: function prototype may not have inferred error set",
    });

    ctx.objErrStage1("access non-existent member of error set",
        \\const Foo = error{A};
        \\comptime {
        \\    const z = Foo.Bar;
        \\    _ = z;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:18: error: no error named 'Bar' in 'Foo'",
    });

    ctx.objErrStage1("error union operator with non error set LHS",
        \\comptime {
        \\    const z = i32!i32;
        \\    var x: z = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected error set type, found type 'i32'",
    });

    ctx.objErrStage1("error equality but sets have no common members",
        \\const Set1 = error{A, C};
        \\const Set2 = error{B, D};
        \\export fn entry() void {
        \\    foo(Set1.A);
        \\}
        \\fn foo(x: Set1) void {
        \\    if (x == Set2.B) {
        \\
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:7:11: error: error sets 'Set1' and 'Set2' have no common errors",
    });

    ctx.objErrStage1("only equality binary operator allowed for error sets",
        \\comptime {
        \\    const z = error.A > error.B;
        \\    _ = z;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:23: error: operator not allowed for errors",
    });

    ctx.objErrStage1("explicit error set cast known at comptime violates error sets",
        \\const Set1 = error {A, B};
        \\const Set2 = error {A, C};
        \\comptime {
        \\    var x = Set1.B;
        \\    var y = @errSetCast(Set2, x);
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:13: error: error.B not a member of error set 'Set2'",
    });

    ctx.objErrStage1("cast error union of global error set to error union of smaller error set",
        \\const SmallErrorSet = error{A};
        \\export fn entry() void {
        \\    var x: SmallErrorSet!i32 = foo();
        \\    _ = x;
        \\}
        \\fn foo() anyerror!i32 {
        \\    return error.B;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:35: error: expected type 'SmallErrorSet!i32', found 'anyerror!i32'",
        "tmp.zig:3:35: note: error set 'anyerror' cannot cast into error set 'SmallErrorSet'",
        "tmp.zig:3:35: note: cannot cast global error set into smaller set",
    });

    ctx.objErrStage1("cast global error set to error set",
        \\const SmallErrorSet = error{A};
        \\export fn entry() void {
        \\    var x: SmallErrorSet = foo();
        \\    _ = x;
        \\}
        \\fn foo() anyerror {
        \\    return error.B;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:31: error: expected type 'SmallErrorSet', found 'anyerror'",
        "tmp.zig:3:31: note: cannot cast global error set into smaller set",
    });
    ctx.objErrStage1("recursive inferred error set",
        \\export fn entry() void {
        \\    foo() catch unreachable;
        \\}
        \\fn foo() !void {
        \\    try foo();
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: cannot resolve inferred error set '@typeInfo(@typeInfo(@TypeOf(foo)).Fn.return_type.?).ErrorUnion.error_set': function 'foo' not fully analyzed yet",
    });

    ctx.objErrStage1("implicit cast of error set not a subset",
        \\const Set1 = error{A, B};
        \\const Set2 = error{A, C};
        \\export fn entry() void {
        \\    foo(Set1.B);
        \\}
        \\fn foo(set1: Set1) void {
        \\    var x: Set2 = set1;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:19: error: expected type 'Set2', found 'Set1'",
        "tmp.zig:1:23: note: 'error.B' not a member of destination error set",
    });

    ctx.objErrStage1("int to err global invalid number",
        \\const Set1 = error{
        \\    A,
        \\    B,
        \\};
        \\comptime {
        \\    var x: u16 = 3;
        \\    var y = @intToError(x);
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:13: error: integer value 3 represents no error",
    });

    ctx.objErrStage1("int to err non global invalid number",
        \\const Set1 = error{
        \\    A,
        \\    B,
        \\};
        \\const Set2 = error{
        \\    A,
        \\    C,
        \\};
        \\comptime {
        \\    var x = @errorToInt(Set1.B);
        \\    var y = @errSetCast(Set2, @intToError(x));
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:11:13: error: error.B not a member of error set 'Set2'",
    });

    ctx.objErrStage1("duplicate error value in error set",
        \\const Foo = error {
        \\    Bar,
        \\    Bar,
        \\};
        \\export fn entry() void {
        \\    const a: Foo = undefined;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: duplicate error: 'Bar'",
        "tmp.zig:2:5: note: other error here",
    });

    ctx.objErrStage1("cast negative integer literal to usize",
        \\export fn entry() void {
        \\    const x = @as(usize, -10);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:26: error: cannot cast negative value -10 to unsigned integer type 'usize'",
    });

    ctx.objErrStage1("use invalid number literal as array index",
        \\var v = 25;
        \\export fn entry() void {
        \\    var arr: [v]u8 = undefined;
        \\    _ = arr;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: unable to infer variable type",
    });

    ctx.objErrStage1("duplicate struct field",
        \\const Foo = struct {
        \\    Bar: i32,
        \\    Bar: usize,
        \\};
        \\export fn entry() void {
        \\    const a: Foo = undefined;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: duplicate struct field: 'Bar'",
        "tmp.zig:2:5: note: other field here",
    });

    ctx.objErrStage1("duplicate union field",
        \\const Foo = union {
        \\    Bar: i32,
        \\    Bar: usize,
        \\};
        \\export fn entry() void {
        \\    const a: Foo = undefined;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: duplicate union field: 'Bar'",
        "tmp.zig:2:5: note: other field here",
    });

    ctx.objErrStage1("duplicate enum field",
        \\const Foo = enum {
        \\    Bar,
        \\    Bar,
        \\};
        \\
        \\export fn entry() void {
        \\    const a: Foo = undefined;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: duplicate enum field: 'Bar'",
        "tmp.zig:2:5: note: other field here",
    });

    ctx.objErrStage1("calling function with naked calling convention",
        \\export fn entry() void {
        \\    foo();
        \\}
        \\fn foo() callconv(.Naked) void { }
    , &[_][]const u8{
        "tmp.zig:2:5: error: unable to call function with naked calling convention",
        "tmp.zig:4:1: note: declared here",
    });

    ctx.objErrStage1("function with invalid return type",
        \\export fn foo() boid {}
    , &[_][]const u8{
        "tmp.zig:1:17: error: use of undeclared identifier 'boid'",
    });

    ctx.objErrStage1("function with non-extern non-packed enum parameter",
        \\const Foo = enum { A, B, C };
        \\export fn entry(foo: Foo) void { _ = foo; }
    , &[_][]const u8{
        "tmp.zig:2:22: error: parameter of type 'Foo' not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("function with non-extern non-packed struct parameter",
        \\const Foo = struct {
        \\    A: i32,
        \\    B: f32,
        \\    C: bool,
        \\};
        \\export fn entry(foo: Foo) void { _ = foo; }
    , &[_][]const u8{
        "tmp.zig:6:22: error: parameter of type 'Foo' not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("function with non-extern non-packed union parameter",
        \\const Foo = union {
        \\    A: i32,
        \\    B: f32,
        \\    C: bool,
        \\};
        \\export fn entry(foo: Foo) void { _ = foo; }
    , &[_][]const u8{
        "tmp.zig:6:22: error: parameter of type 'Foo' not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("switch on enum with 1 field with no prongs",
        \\const Foo = enum { M };
        \\
        \\export fn entry() void {
        \\    var f = Foo.M;
        \\    switch (f) {}
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: enumeration value 'Foo.M' not handled in switch",
    });

    ctx.objErrStage1("shift by negative comptime integer",
        \\comptime {
        \\    var a = 1 >> -1;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:18: error: shift by negative value -1",
    });

    ctx.objErrStage1("@panic called at compile time",
        \\export fn entry() void {
        \\    comptime {
        \\        @panic("aoeu",);
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: encountered @panic at compile-time",
    });

    ctx.objErrStage1("wrong return type for main",
        \\pub fn main() f32 { }
    , &[_][]const u8{
        "error: expected return type of main to be 'void', '!void', 'noreturn', 'u8', or '!u8'",
    });

    ctx.objErrStage1("double ?? on main return value",
        \\pub fn main() ??void {
        \\}
    , &[_][]const u8{
        "error: expected return type of main to be 'void', '!void', 'noreturn', 'u8', or '!u8'",
    });

    ctx.objErrStage1("bad identifier in function with struct defined inside function which references local const",
        \\export fn entry() void {
        \\    const BlockKind = u32;
        \\
        \\    const Block = struct {
        \\        kind: BlockKind,
        \\    };
        \\
        \\    bogus;
        \\
        \\    _ = Block;
        \\}
    , &[_][]const u8{
        "tmp.zig:8:5: error: use of undeclared identifier 'bogus'",
    });

    ctx.objErrStage1("labeled break not found",
        \\export fn entry() void {
        \\    blah: while (true) {
        \\        while (true) {
        \\            break :outer;
        \\        }
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:4:20: error: label not found: 'outer'",
    });

    ctx.objErrStage1("labeled continue not found",
        \\export fn entry() void {
        \\    var i: usize = 0;
        \\    blah: while (i < 10) : (i += 1) {
        \\        while (true) {
        \\            continue :outer;
        \\        }
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:5:23: error: label not found: 'outer'",
    });

    ctx.objErrStage1("attempt to use 0 bit type in extern fn",
        \\extern fn foo(ptr: fn(*void) callconv(.C) void) void;
        \\
        \\export fn entry() void {
        \\    foo(bar);
        \\}
        \\
        \\fn bar(x: *void) callconv(.C) void { _ = x; }
        \\export fn entry2() void {
        \\    bar(&{});
        \\}
    , &[_][]const u8{
        "tmp.zig:1:23: error: parameter of type '*void' has 0 bits; not allowed in function with calling convention 'C'",
        "tmp.zig:7:11: error: parameter of type '*void' has 0 bits; not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("implicit semicolon - block statement",
        \\export fn entry() void {
        \\    {}
        \\    var good = {};
        \\    ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - block expr",
        \\export fn entry() void {
        \\    _ = {};
        \\    var good = {};
        \\    _ = {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - comptime statement",
        \\export fn entry() void {
        \\    comptime {}
        \\    var good = {};
        \\    comptime ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - comptime expression",
        \\export fn entry() void {
        \\    _ = comptime {};
        \\    var good = {};
        \\    _ = comptime {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - defer",
        \\export fn entry() void {
        \\    defer {}
        \\    var good = {};
        \\    defer ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if statement",
        \\export fn entry() void {
        \\    if(true) {}
        \\    var good = {};
        \\    if(true) ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';' or 'else', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if expression",
        \\export fn entry() void {
        \\    _ = if(true) {};
        \\    var good = {};
        \\    _ = if(true) {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if-else statement",
        \\export fn entry() void {
        \\    if(true) {} else {}
        \\    var good = {};
        \\    if(true) ({}) else ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if-else expression",
        \\export fn entry() void {
        \\    _ = if(true) {} else {};
        \\    var good = {};
        \\    _ = if(true) {} else {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if-else-if statement",
        \\export fn entry() void {
        \\    if(true) {} else if(true) {}
        \\    var good = {};
        \\    if(true) ({}) else if(true) ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';' or 'else', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if-else-if expression",
        \\export fn entry() void {
        \\    _ = if(true) {} else if(true) {};
        \\    var good = {};
        \\    _ = if(true) {} else if(true) {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if-else-if-else statement",
        \\export fn entry() void {
        \\    if(true) {} else if(true) {} else {}
        \\    var good = {};
        \\    if(true) ({}) else if(true) ({}) else ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - if-else-if-else expression",
        \\export fn entry() void {
        \\    _ = if(true) {} else if(true) {} else {};
        \\    var good = {};
        \\    _ = if(true) {} else if(true) {} else {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - test statement",
        \\export fn entry() void {
        \\    if (foo()) |_| {}
        \\    var good = {};
        \\    if (foo()) |_| ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';' or 'else', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - test expression",
        \\export fn entry() void {
        \\    _ = if (foo()) |_| {};
        \\    var good = {};
        \\    _ = if (foo()) |_| {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - while statement",
        \\export fn entry() void {
        \\    while(true) {}
        \\    var good = {};
        \\    while(true) ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';' or 'else', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - while expression",
        \\export fn entry() void {
        \\    _ = while(true) {};
        \\    var good = {};
        \\    _ = while(true) {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - while-continue statement",
        \\export fn entry() void {
        \\    while(true):({}) {}
        \\    var good = {};
        \\    while(true):({}) ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';' or 'else', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - while-continue expression",
        \\export fn entry() void {
        \\    _ = while(true):({}) {};
        \\    var good = {};
        \\    _ = while(true):({}) {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - for statement",
        \\export fn entry() void {
        \\    for(foo()) |_| {}
        \\    var good = {};
        \\    for(foo()) |_| ({})
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';' or 'else', found 'var'",
    });

    ctx.objErrStage1("implicit semicolon - for expression",
        \\export fn entry() void {
        \\    _ = for(foo()) |_| {};
        \\    var good = {};
        \\    _ = for(foo()) |_| {}
        \\    var bad = {};
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: expected ';', found 'var'",
    });

    ctx.objErrStage1("multiple function definitions",
        \\fn a() void {}
        \\fn a() void {}
        \\export fn entry() void { a(); }
    , &[_][]const u8{
        "tmp.zig:2:1: error: redeclaration of 'a'",
        "tmp.zig:1:1: note: other declaration here",
    });

    ctx.objErrStage1("unreachable with return",
        \\fn a() noreturn {return;}
        \\export fn entry() void { a(); }
    , &[_][]const u8{
        "tmp.zig:1:18: error: expected type 'noreturn', found 'void'",
    });

    ctx.objErrStage1("control reaches end of non-void function",
        \\fn a() i32 {}
        \\export fn entry() void { _ = a(); }
    , &[_][]const u8{
        "tmp.zig:1:12: error: expected type 'i32', found 'void'",
    });

    ctx.objErrStage1("undefined function call",
        \\export fn a() void {
        \\    b();
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: use of undeclared identifier 'b'",
    });

    ctx.objErrStage1("wrong number of arguments",
        \\export fn a() void {
        \\    c(1);
        \\}
        \\fn c(d: i32, e: i32, f: i32) void { _ = d; _ = e; _ = f; }
    , &[_][]const u8{
        "tmp.zig:2:6: error: expected 3 argument(s), found 1",
    });

    ctx.objErrStage1("invalid type",
        \\fn a() bogus {}
        \\export fn entry() void { _ = a(); }
    , &[_][]const u8{
        "tmp.zig:1:8: error: use of undeclared identifier 'bogus'",
    });

    ctx.objErrStage1("pointer to noreturn",
        \\fn a() *noreturn {}
        \\export fn entry() void { _ = a(); }
    , &[_][]const u8{
        "tmp.zig:1:9: error: pointer to noreturn not allowed",
    });

    ctx.objErrStage1("unreachable code",
        \\export fn a() void {
        \\    return;
        \\    b();
        \\}
        \\
        \\fn b() void {}
    , &[_][]const u8{
        "tmp.zig:3:6: error: unreachable code",
        "tmp.zig:2:5: note: control flow is diverted here",
    });

    ctx.objErrStage1("bad import",
        \\const bogus = @import("bogus-does-not-exist.zig",);
    , &[_][]const u8{
        "tmp.zig:1:23: error: unable to load '${DIR}bogus-does-not-exist.zig': FileNotFound",
    });

    ctx.objErrStage1("undeclared identifier",
        \\export fn a() void {
        \\    return
        \\    b +
        \\    c;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undeclared identifier 'b'",
    });

    ctx.objErrStage1("parameter redeclaration",
        \\fn f(a : i32, a : i32) void {
        \\}
        \\export fn entry() void { f(1, 2); }
    , &[_][]const u8{
        "tmp.zig:1:15: error: redeclaration of function parameter 'a'",
        "tmp.zig:1:6: note: previous declaration here",
    });

    ctx.objErrStage1("local variable redeclaration",
        \\export fn f() void {
        \\    const a : i32 = 0;
        \\    var a = 0;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: redeclaration of local constant 'a'",
        "tmp.zig:2:11: note: previous declaration here",
    });

    ctx.objErrStage1("local variable redeclares parameter",
        \\fn f(a : i32) void {
        \\    const a = 0;
        \\}
        \\export fn entry() void { f(1); }
    , &[_][]const u8{
        "tmp.zig:2:11: error: redeclaration of function parameter 'a'",
        "tmp.zig:1:6: note: previous declaration here",
    });

    ctx.objErrStage1("variable has wrong type",
        \\export fn f() i32 {
        \\    const a = "a";
        \\    return a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:12: error: expected type 'i32', found '*const [1:0]u8'",
    });

    ctx.objErrStage1("if condition is bool, not int",
        \\export fn f() void {
        \\    if (0) {}
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: expected type 'bool', found 'comptime_int'",
    });

    ctx.objErrStage1("assign unreachable",
        \\export fn f() void {
        \\    const a = return;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: unreachable code",
        "tmp.zig:2:15: note: control flow is diverted here",
    });

    ctx.objErrStage1("unreachable variable",
        \\export fn f() void {
        \\    const a: noreturn = {};
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:25: error: expected type 'noreturn', found 'void'",
    });

    ctx.objErrStage1("unreachable parameter",
        \\fn f(a: noreturn) void { _ = a; }
        \\export fn entry() void { f(); }
    , &[_][]const u8{
        "tmp.zig:1:9: error: parameter of type 'noreturn' not allowed",
    });

    ctx.objErrStage1("assign to constant variable",
        \\export fn f() void {
        \\    const a = 3;
        \\    a = 4;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: cannot assign to constant",
    });

    ctx.objErrStage1("use of undeclared identifier",
        \\export fn f() void {
        \\    b = 3;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: use of undeclared identifier 'b'",
    });

    ctx.objErrStage1("const is a statement, not an expression",
        \\export fn f() void {
        \\    (const a = 0);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:6: error: expected expression, found 'const'",
    });

    ctx.objErrStage1("array access of undeclared identifier",
        \\export fn f() void {
        \\    i[i] = i[i];
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: use of undeclared identifier 'i'",
    });

    ctx.objErrStage1("array access of non array",
        \\export fn f() void {
        \\    var bad : bool = undefined;
        \\    bad[0] = bad[0];
        \\}
        \\export fn g() void {
        \\    var bad : bool = undefined;
        \\    _ = bad[0];
        \\}
    , &[_][]const u8{
        "tmp.zig:3:8: error: array access of non-array type 'bool'",
        "tmp.zig:7:12: error: array access of non-array type 'bool'",
    });

    ctx.objErrStage1("array access with non integer index",
        \\export fn f() void {
        \\    var array = "aoeu";
        \\    var bad = false;
        \\    array[bad] = array[bad];
        \\}
        \\export fn g() void {
        \\    var array = "aoeu";
        \\    var bad = false;
        \\    _ = array[bad];
        \\}
    , &[_][]const u8{
        "tmp.zig:4:11: error: expected type 'usize', found 'bool'",
        "tmp.zig:9:15: error: expected type 'usize', found 'bool'",
    });

    ctx.objErrStage1("write to const global variable",
        \\const x : i32 = 99;
        \\fn f() void {
        \\    x = 1;
        \\}
        \\export fn entry() void { f(); }
    , &[_][]const u8{
        "tmp.zig:3:9: error: cannot assign to constant",
    });

    ctx.objErrStage1("missing else clause",
        \\fn f(b: bool) void {
        \\    const x : i32 = if (b) h: { break :h 1; };
        \\    _ = x;
        \\}
        \\fn g(b: bool) void {
        \\    const y = if (b) h: { break :h @as(i32, 1); };
        \\    _ = y;
        \\}
        \\export fn entry() void { f(true); g(true); }
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected type 'i32', found 'void'",
        "tmp.zig:6:15: error: incompatible types: 'i32' and 'void'",
    });

    ctx.objErrStage1("invalid struct field",
        \\const A = struct { x : i32, };
        \\export fn f() void {
        \\    var a : A = undefined;
        \\    a.foo = 1;
        \\    const y = a.bar;
        \\    _ = y;
        \\}
        \\export fn g() void {
        \\    var a : A = undefined;
        \\    const y = a.bar;
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:6: error: no member named 'foo' in struct 'A'",
        "tmp.zig:10:16: error: no member named 'bar' in struct 'A'",
    });

    ctx.objErrStage1("redefinition of struct",
        \\const A = struct { x : i32, };
        \\const A = struct { y : i32, };
    , &[_][]const u8{
        "tmp.zig:2:1: error: redeclaration of 'A'",
        "tmp.zig:1:1: note: other declaration here",
    });

    ctx.objErrStage1("redefinition of enums",
        \\const A = enum {x};
        \\const A = enum {x};
    , &[_][]const u8{
        "tmp.zig:2:1: error: redeclaration of 'A'",
        "tmp.zig:1:1: note: other declaration here",
    });

    ctx.objErrStage1("redefinition of global variables",
        \\var a : i32 = 1;
        \\var a : i32 = 2;
    , &[_][]const u8{
        "tmp.zig:2:1: error: redeclaration of 'a'",
        "tmp.zig:1:1: note: other declaration here",
    });

    ctx.objErrStage1("duplicate field in struct value expression",
        \\const A = struct {
        \\    x : i32,
        \\    y : i32,
        \\    z : i32,
        \\};
        \\export fn f() void {
        \\    const a = A {
        \\        .z = 1,
        \\        .y = 2,
        \\        .x = 3,
        \\        .z = 4,
        \\    };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:11:9: error: duplicate field",
    });

    ctx.objErrStage1("missing field in struct value expression",
        \\const A = struct {
        \\    x : i32,
        \\    y : i32,
        \\    z : i32,
        \\};
        \\export fn f() void {
        \\    // we want the error on the '{' not the 'A' because
        \\    // the A could be a complicated expression
        \\    const a = A {
        \\        .z = 4,
        \\        .y = 2,
        \\    };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:17: error: missing field: 'x'",
    });

    ctx.objErrStage1("invalid field in struct value expression",
        \\const A = struct {
        \\    x : i32,
        \\    y : i32,
        \\    z : i32,
        \\};
        \\export fn f() void {
        \\    const a = A {
        \\        .z = 4,
        \\        .y = 2,
        \\        .foo = 42,
        \\    };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:10:9: error: no member named 'foo' in struct 'A'",
    });

    ctx.objErrStage1("invalid break expression",
        \\export fn f() void {
        \\    break;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: break expression outside loop",
    });

    ctx.objErrStage1("invalid continue expression",
        \\export fn f() void {
        \\    continue;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: continue expression outside loop",
    });

    ctx.objErrStage1("invalid maybe type",
        \\export fn f() void {
        \\    if (true) |x| { _ = x; }
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: expected optional type, found 'bool'",
    });

    ctx.objErrStage1("cast unreachable",
        \\fn f() i32 {
        \\    return @as(i32, return 1);
        \\}
        \\export fn entry() void { _ = f(); }
    , &[_][]const u8{
        "tmp.zig:2:12: error: unreachable code",
        "tmp.zig:2:21: note: control flow is diverted here",
    });

    ctx.objErrStage1("invalid builtin fn",
        \\fn f() @bogus(foo) {
        \\}
        \\export fn entry() void { _ = f(); }
    , &[_][]const u8{
        "tmp.zig:1:8: error: invalid builtin function: '@bogus'",
    });

    ctx.objErrStage1("noalias on non pointer param",
        \\fn f(noalias x: i32) void { _ = x; }
        \\export fn entry() void { f(1234); }
    , &[_][]const u8{
        "tmp.zig:1:6: error: noalias on non-pointer parameter",
    });

    ctx.objErrStage1("struct init syntax for array",
        \\const foo = [3]u16{ .x = 1024 };
        \\comptime {
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:13: error: initializing array with struct syntax",
    });

    ctx.objErrStage1("type variables must be constant",
        \\var foo = u8;
        \\export fn entry() foo {
        \\    return 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: variable of type 'type' must be constant",
    });

    ctx.objErrStage1("parameter shadowing global",
        \\const Foo = struct {};
        \\fn f(Foo: i32) void {}
        \\export fn entry() void {
        \\    f(1234);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:6: error: local shadows declaration of 'Foo'",
        "tmp.zig:1:1: note: declared here",
    });

    ctx.objErrStage1("local variable shadowing global",
        \\const Foo = struct {};
        \\const Bar = struct {};
        \\
        \\export fn entry() void {
        \\    var Bar : i32 = undefined;
        \\    _ = Bar;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:9: error: local shadows declaration of 'Bar'",
        "tmp.zig:2:1: note: declared here",
    });

    ctx.objErrStage1("switch expression - missing enumeration prong",
        \\const Number = enum {
        \\    One,
        \\    Two,
        \\    Three,
        \\    Four,
        \\};
        \\fn f(n: Number) i32 {
        \\    switch (n) {
        \\        Number.One => 1,
        \\        Number.Two => 2,
        \\        Number.Three => @as(i32, 3),
        \\    }
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:8:5: error: enumeration value 'Number.Four' not handled in switch",
    });

    ctx.objErrStage1("switch expression - duplicate enumeration prong",
        \\const Number = enum {
        \\    One,
        \\    Two,
        \\    Three,
        \\    Four,
        \\};
        \\fn f(n: Number) i32 {
        \\    switch (n) {
        \\        Number.One => 1,
        \\        Number.Two => 2,
        \\        Number.Three => @as(i32, 3),
        \\        Number.Four => 4,
        \\        Number.Two => 2,
        \\    }
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:13:15: error: duplicate switch value",
        "tmp.zig:10:15: note: other value here",
    });

    ctx.objErrStage1("switch expression - duplicate enumeration prong when else present",
        \\const Number = enum {
        \\    One,
        \\    Two,
        \\    Three,
        \\    Four,
        \\};
        \\fn f(n: Number) i32 {
        \\    switch (n) {
        \\        Number.One => 1,
        \\        Number.Two => 2,
        \\        Number.Three => @as(i32, 3),
        \\        Number.Four => 4,
        \\        Number.Two => 2,
        \\        else => 10,
        \\    }
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:13:15: error: duplicate switch value",
        "tmp.zig:10:15: note: other value here",
    });

    ctx.objErrStage1("switch expression - multiple else prongs",
        \\fn f(x: u32) void {
        \\    const value: bool = switch (x) {
        \\        1234 => false,
        \\        else => true,
        \\        else => true,
        \\    };
        \\}
        \\export fn entry() void {
        \\    f(1234);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:9: error: multiple else prongs in switch expression",
    });

    ctx.objErrStage1("switch expression - non exhaustive integer prongs",
        \\fn foo(x: u8) void {
        \\    switch (x) {
        \\        0 => {},
        \\    }
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:2:5: error: switch must handle all possibilities",
    });

    ctx.objErrStage1("switch expression - duplicate or overlapping integer value",
        \\fn foo(x: u8) u8 {
        \\    return switch (x) {
        \\        0 ... 100 => @as(u8, 0),
        \\        101 ... 200 => 1,
        \\        201, 203 ... 207 => 2,
        \\        206 ... 255 => 3,
        \\    };
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:6:9: error: duplicate switch value",
        "tmp.zig:5:14: note: previous value here",
    });

    ctx.objErrStage1("switch expression - duplicate type",
        \\fn foo(comptime T: type, x: T) u8 {
        \\    _ = x;
        \\    return switch (T) {
        \\        u32 => 0,
        \\        u64 => 1,
        \\        u32 => 2,
        \\        else => 3,
        \\    };
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo(u32, 0))); }
    , &[_][]const u8{
        "tmp.zig:6:9: error: duplicate switch value",
        "tmp.zig:4:9: note: previous value here",
    });

    ctx.objErrStage1("switch expression - duplicate type (struct alias)",
        \\const Test = struct {
        \\    bar: i32,
        \\};
        \\const Test2 = Test;
        \\fn foo(comptime T: type, x: T) u8 {
        \\    _ = x;
        \\    return switch (T) {
        \\        Test => 0,
        \\        u64 => 1,
        \\        Test2 => 2,
        \\        else => 3,
        \\    };
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo(u32, 0))); }
    , &[_][]const u8{
        "tmp.zig:10:9: error: duplicate switch value",
        "tmp.zig:8:9: note: previous value here",
    });

    ctx.objErrStage1("switch expression - switch on pointer type with no else",
        \\fn foo(x: *u8) void {
        \\    switch (x) {
        \\        &y => {},
        \\    }
        \\}
        \\const y: u8 = 100;
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:2:5: error: else prong required when switching on type '*u8'",
    });

    ctx.objErrStage1("global variable initializer must be constant expression",
        \\extern fn foo() i32;
        \\const x = foo();
        \\export fn entry() i32 { return x; }
    , &[_][]const u8{
        "tmp.zig:2:11: error: unable to evaluate constant expression",
    });

    ctx.objErrStage1("array concatenation with wrong type",
        \\const src = "aoeu";
        \\const derp: usize = 1234;
        \\const a = derp ++ "foo";
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(a)); }
    , &[_][]const u8{
        "tmp.zig:3:11: error: expected array, found 'usize'",
    });

    ctx.objErrStage1("non compile time array concatenation",
        \\fn f() []u8 {
        \\    return s ++ "foo";
        \\}
        \\var s: [10]u8 = undefined;
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:2:12: error: unable to evaluate constant expression",
    });

    ctx.objErrStage1("@cImport with bogus include",
        \\const c = @cImport(@cInclude("bogus.h"));
        \\export fn entry() usize { return @sizeOf(@TypeOf(c.bogo)); }
    , &[_][]const u8{
        "tmp.zig:1:11: error: C import failed",
        ".h:1:10: note: 'bogus.h' file not found",
    });

    ctx.objErrStage1("address of number literal",
        \\const x = 3;
        \\const y = &x;
        \\fn foo() *const i32 { return y; }
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:3:30: error: expected type '*const i32', found '*const comptime_int'",
    });

    ctx.objErrStage1("integer overflow error",
        \\const x : u8 = 300;
        \\export fn entry() usize { return @sizeOf(@TypeOf(x)); }
    , &[_][]const u8{
        "tmp.zig:1:16: error: integer value 300 cannot be coerced to type 'u8'",
    });

    ctx.objErrStage1("invalid shift amount error",
        \\const x : u8 = 2;
        \\fn f() u16 {
        \\    return x << 8;
        \\}
        \\export fn entry() u16 { return f(); }
    , &[_][]const u8{
        "tmp.zig:3:17: error: integer value 8 cannot be coerced to type 'u3'",
    });

    ctx.objErrStage1("missing function call param",
        \\const Foo = struct {
        \\    a: i32,
        \\    b: i32,
        \\
        \\    fn member_a(foo: *const Foo) i32 {
        \\        return foo.a;
        \\    }
        \\    fn member_b(foo: *const Foo) i32 {
        \\        return foo.b;
        \\    }
        \\};
        \\
        \\const member_fn_type = @TypeOf(Foo.member_a);
        \\const members = [_]member_fn_type {
        \\    Foo.member_a,
        \\    Foo.member_b,
        \\};
        \\
        \\fn f(foo: *const Foo, index: usize) void {
        \\    const result = members[index]();
        \\    _ = foo;
        \\    _ = result;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:20:34: error: expected 1 argument(s), found 0",
    });

    ctx.objErrStage1("missing function name",
        \\fn () void {}
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:1:1: error: missing function name",
    });

    ctx.objErrStage1("missing param name",
        \\fn f(i32) void {}
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:1:6: error: missing parameter name",
    });

    ctx.objErrStage1("wrong function type",
        \\const fns = [_]fn() void { a, b, c };
        \\fn a() i32 {return 0;}
        \\fn b() i32 {return 1;}
        \\fn c() i32 {return 2;}
        \\export fn entry() usize { return @sizeOf(@TypeOf(fns)); }
    , &[_][]const u8{
        "tmp.zig:1:28: error: expected type 'fn() void', found 'fn() i32'",
    });

    ctx.objErrStage1("extern function pointer mismatch",
        \\const fns = [_](fn(i32)i32) { a, b, c };
        \\pub fn a(x: i32) i32 {return x + 0;}
        \\pub fn b(x: i32) i32 {return x + 1;}
        \\export fn c(x: i32) i32 {return x + 2;}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(fns)); }
    , &[_][]const u8{
        "tmp.zig:1:37: error: expected type 'fn(i32) i32', found 'fn(i32) callconv(.C) i32'",
    });

    ctx.objErrStage1("colliding invalid top level functions",
        \\fn func() bogus {}
        \\fn func() bogus {}
        \\export fn entry() usize { return @sizeOf(@TypeOf(func)); }
    , &[_][]const u8{
        "tmp.zig:2:1: error: redeclaration of 'func'",
        "tmp.zig:1:1: note: other declaration here",
    });

    ctx.objErrStage1("non constant expression in array size",
        \\const Foo = struct {
        \\    y: [get()]u8,
        \\};
        \\var global_var: usize = 1;
        \\fn get() usize { return global_var; }
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(Foo)); }
    , &[_][]const u8{
        "tmp.zig:5:25: error: cannot store runtime value in compile time variable",
        "tmp.zig:2:12: note: called from here",
    });

    ctx.objErrStage1("addition with non numbers",
        \\const Foo = struct {
        \\    field: i32,
        \\};
        \\const x = Foo {.field = 1} + Foo {.field = 2};
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(x)); }
    , &[_][]const u8{
        "tmp.zig:4:28: error: invalid operands to binary expression: 'Foo' and 'Foo'",
    });

    ctx.objErrStage1("division by zero",
        \\const lit_int_x = 1 / 0;
        \\const lit_float_x = 1.0 / 0.0;
        \\const int_x = @as(u32, 1) / @as(u32, 0);
        \\const float_x = @as(f32, 1.0) / @as(f32, 0.0);
        \\
        \\export fn entry1() usize { return @sizeOf(@TypeOf(lit_int_x)); }
        \\export fn entry2() usize { return @sizeOf(@TypeOf(lit_float_x)); }
        \\export fn entry3() usize { return @sizeOf(@TypeOf(int_x)); }
        \\export fn entry4() usize { return @sizeOf(@TypeOf(float_x)); }
    , &[_][]const u8{
        "tmp.zig:1:21: error: division by zero",
        "tmp.zig:2:25: error: division by zero",
        "tmp.zig:3:27: error: division by zero",
        "tmp.zig:4:31: error: division by zero",
    });

    ctx.objErrStage1("normal string with newline",
        \\const foo = "a
        \\b";
    , &[_][]const u8{
        "tmp.zig:1:13: error: expected expression, found 'invalid'",
        "tmp.zig:1:15: note: invalid byte: '\\n'",
    });

    ctx.objErrStage1("invalid comparison for function pointers",
        \\fn foo() void {}
        \\const invalid = foo > foo;
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(invalid)); }
    , &[_][]const u8{
        "tmp.zig:2:21: error: operator not allowed for type 'fn() void'",
    });

    ctx.objErrStage1("generic function instance with non-constant expression",
        \\fn foo(comptime x: i32, y: i32) i32 { return x + y; }
        \\fn test1(a: i32, b: i32) i32 {
        \\    return foo(a, b);
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(test1)); }
    , &[_][]const u8{
        "tmp.zig:3:16: error: runtime value cannot be passed to comptime arg",
    });

    ctx.objErrStage1("assign null to non-optional pointer",
        \\const a: *u8 = null;
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(a)); }
    , &[_][]const u8{
        "tmp.zig:1:16: error: expected type '*u8', found '(null)'",
    });

    ctx.objErrStage1("indexing an array of size zero",
        \\const array = [_]u8{};
        \\export fn foo() void {
        \\    const pointer = &array[0];
        \\    _ = pointer;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:27: error: accessing a zero length array is not allowed",
    });

    ctx.objErrStage1("indexing an array of size zero with runtime index",
        \\const array = [_]u8{};
        \\export fn foo() void {
        \\    var index: usize = 0;
        \\    const pointer = &array[index];
        \\    _ = pointer;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:27: error: accessing a zero length array is not allowed",
    });

    ctx.objErrStage1("compile time division by zero",
        \\const y = foo(0);
        \\fn foo(x: u32) u32 {
        \\    return 1 / x;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(y)); }
    , &[_][]const u8{
        "tmp.zig:3:14: error: division by zero",
        "tmp.zig:1:14: note: referenced here",
    });

    ctx.objErrStage1("branch on undefined value",
        \\const x = if (undefined) true else false;
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(x)); }
    , &[_][]const u8{
        "tmp.zig:1:15: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("div on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a / a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("div assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a /= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("mod on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a % a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("mod assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a %= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("add on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a + a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("add assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a += a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("add wrap on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a +% a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("add wrap assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a +%= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("sub on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a - a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("sub assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a -= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("sub wrap on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a -% a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("sub wrap assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a -%= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("mult on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a * a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("mult assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a *= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("mult wrap on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a *% a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("mult wrap assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a *%= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("shift left on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a << 2;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("shift left assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a <<= 2;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("shift right on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a >> 2;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("shift left assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a >>= 2;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bin and on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a & a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bin and assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a &= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bin or on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a | a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bin or assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a |= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bin xor on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = a ^ a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bin xor assign on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    a ^= a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("comparison operators with undefined value",
        \\// operator ==
        \\comptime {
        \\    var a: i64 = undefined;
        \\    var x: i32 = 0;
        \\    if (a == a) x += 1;
        \\}
        \\// operator !=
        \\comptime {
        \\    var a: i64 = undefined;
        \\    var x: i32 = 0;
        \\    if (a != a) x += 1;
        \\}
        \\// operator >
        \\comptime {
        \\    var a: i64 = undefined;
        \\    var x: i32 = 0;
        \\    if (a > a) x += 1;
        \\}
        \\// operator <
        \\comptime {
        \\    var a: i64 = undefined;
        \\    var x: i32 = 0;
        \\    if (a < a) x += 1;
        \\}
        \\// operator >=
        \\comptime {
        \\    var a: i64 = undefined;
        \\    var x: i32 = 0;
        \\    if (a >= a) x += 1;
        \\}
        \\// operator <=
        \\comptime {
        \\    var a: i64 = undefined;
        \\    var x: i32 = 0;
        \\    if (a <= a) x += 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:11: error: use of undefined value here causes undefined behavior",
        "tmp.zig:11:11: error: use of undefined value here causes undefined behavior",
        "tmp.zig:17:11: error: use of undefined value here causes undefined behavior",
        "tmp.zig:23:11: error: use of undefined value here causes undefined behavior",
        "tmp.zig:29:11: error: use of undefined value here causes undefined behavior",
        "tmp.zig:35:11: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("and on undefined value",
        \\comptime {
        \\    var a: bool = undefined;
        \\    _ = a and a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("or on undefined value",
        \\comptime {
        \\    var a: bool = undefined;
        \\    _ = a or a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("negate on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = -a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:10: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("negate wrap on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = -%a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:11: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bin not on undefined value",
        \\comptime {
        \\    var a: i64 = undefined;
        \\    _ = ~a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:10: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("bool not on undefined value",
        \\comptime {
        \\    var a: bool = undefined;
        \\    _ = !a;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:10: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("orelse on undefined value",
        \\comptime {
        \\    var a: ?bool = undefined;
        \\    _ = a orelse false;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:11: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("catch on undefined value",
        \\comptime {
        \\    var a: anyerror!bool = undefined;
        \\    _ = a catch false;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:11: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("deref on undefined value",
        \\comptime {
        \\    var a: *u8 = undefined;
        \\    _ = a.*;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:9: error: attempt to dereference undefined value",
    });

    ctx.objErrStage1("endless loop in function evaluation",
        \\const seventh_fib_number = fibbonaci(7);
        \\fn fibbonaci(x: i32) i32 {
        \\    return fibbonaci(x - 1) + fibbonaci(x - 2);
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(seventh_fib_number)); }
    , &[_][]const u8{
        "tmp.zig:3:21: error: evaluation exceeded 1000 backwards branches",
        "tmp.zig:1:37: note: referenced here",
        "tmp.zig:6:50: note: referenced here",
    });

    ctx.objErrStage1("@embedFile with bogus file",
        \\const resource = @embedFile("bogus.txt",);
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(resource)); }
    , &[_][]const u8{
        "tmp.zig:1:29: error: unable to find '",
    });

    ctx.objErrStage1("non-const expression in struct literal outside function",
        \\const Foo = struct {
        \\    x: i32,
        \\};
        \\const a = Foo {.x = get_it()};
        \\extern fn get_it() i32;
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(a)); }
    , &[_][]const u8{
        "tmp.zig:4:21: error: unable to evaluate constant expression",
    });

    ctx.objErrStage1("non-const expression function call with struct return value outside function",
        \\const Foo = struct {
        \\    x: i32,
        \\};
        \\const a = get_it();
        \\fn get_it() Foo {
        \\    global_side_effect = true;
        \\    return Foo {.x = 13};
        \\}
        \\var global_side_effect = false;
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(a)); }
    , &[_][]const u8{
        "tmp.zig:6:26: error: unable to evaluate constant expression",
        "tmp.zig:4:17: note: referenced here",
    });

    ctx.objErrStage1("undeclared identifier error should mark fn as impure",
        \\export fn foo() void {
        \\    test_a_thing();
        \\}
        \\fn test_a_thing() void {
        \\    bad_fn_call();
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: use of undeclared identifier 'bad_fn_call'",
    });

    ctx.objErrStage1("illegal comparison of types",
        \\fn bad_eql_1(a: []u8, b: []u8) bool {
        \\    return a == b;
        \\}
        \\const EnumWithData = union(enum) {
        \\    One: void,
        \\    Two: i32,
        \\};
        \\fn bad_eql_2(a: *const EnumWithData, b: *const EnumWithData) bool {
        \\    return a.* == b.*;
        \\}
        \\
        \\export fn entry1() usize { return @sizeOf(@TypeOf(bad_eql_1)); }
        \\export fn entry2() usize { return @sizeOf(@TypeOf(bad_eql_2)); }
    , &[_][]const u8{
        "tmp.zig:2:14: error: operator not allowed for type '[]u8'",
        "tmp.zig:9:16: error: operator not allowed for type 'EnumWithData'",
    });

    ctx.objErrStage1("non-const switch number literal",
        \\export fn foo() void {
        \\    const x = switch (bar()) {
        \\        1, 2 => 1,
        \\        3, 4 => 2,
        \\        else => 3,
        \\    };
        \\    _ = x;
        \\}
        \\fn bar() i32 {
        \\    return 2;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:17: error: cannot store runtime value in type 'comptime_int'",
    });

    ctx.objErrStage1("atomic orderings of cmpxchg - failure stricter than success",
        \\const AtomicOrder = @import("std").builtin.AtomicOrder;
        \\export fn f() void {
        \\    var x: i32 = 1234;
        \\    while (!@cmpxchgWeak(i32, &x, 1234, 5678, AtomicOrder.Monotonic, AtomicOrder.SeqCst)) {}
        \\}
    , &[_][]const u8{
        "tmp.zig:4:81: error: failure atomic ordering must be no stricter than success",
    });

    ctx.objErrStage1("atomic orderings of cmpxchg - success Monotonic or stricter",
        \\const AtomicOrder = @import("std").builtin.AtomicOrder;
        \\export fn f() void {
        \\    var x: i32 = 1234;
        \\    while (!@cmpxchgWeak(i32, &x, 1234, 5678, AtomicOrder.Unordered, AtomicOrder.Unordered)) {}
        \\}
    , &[_][]const u8{
        "tmp.zig:4:58: error: success atomic ordering must be Monotonic or stricter",
    });

    ctx.objErrStage1("negation overflow in function evaluation",
        \\const y = neg(-128);
        \\fn neg(x: i8) i8 {
        \\    return -x;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(y)); }
    , &[_][]const u8{
        "tmp.zig:3:12: error: negation caused overflow",
        "tmp.zig:1:14: note: referenced here",
    });

    ctx.objErrStage1("add overflow in function evaluation",
        \\const y = add(65530, 10);
        \\fn add(a: u16, b: u16) u16 {
        \\    return a + b;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(y)); }
    , &[_][]const u8{
        "tmp.zig:3:14: error: operation caused overflow",
        "tmp.zig:1:14: note: referenced here",
    });

    ctx.objErrStage1("sub overflow in function evaluation",
        \\const y = sub(10, 20);
        \\fn sub(a: u16, b: u16) u16 {
        \\    return a - b;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(y)); }
    , &[_][]const u8{
        "tmp.zig:3:14: error: operation caused overflow",
        "tmp.zig:1:14: note: referenced here",
    });

    ctx.objErrStage1("mul overflow in function evaluation",
        \\const y = mul(300, 6000);
        \\fn mul(a: u16, b: u16) u16 {
        \\    return a * b;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(y)); }
    , &[_][]const u8{
        "tmp.zig:3:14: error: operation caused overflow",
        "tmp.zig:1:14: note: referenced here",
    });

    ctx.objErrStage1("truncate sign mismatch",
        \\export fn entry1() i8 {
        \\    var x: u32 = 10;
        \\    return @truncate(i8, x);
        \\}
        \\export fn entry2() u8 {
        \\    var x: i32 = -10;
        \\    return @truncate(u8, x);
        \\}
        \\export fn entry3() i8 {
        \\    comptime var x: u32 = 10;
        \\    return @truncate(i8, x);
        \\}
        \\export fn entry4() u8 {
        \\    comptime var x: i32 = -10;
        \\    return @truncate(u8, x);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:26: error: expected signed integer type, found 'u32'",
        "tmp.zig:7:26: error: expected unsigned integer type, found 'i32'",
        "tmp.zig:11:26: error: expected signed integer type, found 'u32'",
        "tmp.zig:15:26: error: expected unsigned integer type, found 'i32'",
    });

    ctx.objErrStage1("try in function with non error return type",
        \\export fn f() void {
        \\    try something();
        \\}
        \\fn something() anyerror!void { }
    , &[_][]const u8{
        "tmp.zig:2:5: error: expected type 'void', found 'anyerror'",
    });

    ctx.objErrStage1("invalid pointer for var type",
        \\extern fn ext() usize;
        \\var bytes: [ext()]u8 = undefined;
        \\export fn f() void {
        \\    for (bytes) |*b, i| {
        \\        b.* = @as(u8, i);
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:2:13: error: unable to evaluate constant expression",
    });

    ctx.objErrStage1("export function with comptime parameter",
        \\export fn foo(comptime x: i32, y: i32) i32{
        \\    return x + y;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:15: error: comptime parameter not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("extern function with comptime parameter",
        \\extern fn foo(comptime x: i32, y: i32) i32;
        \\fn f() i32 {
        \\    return foo(1, 2);
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:1:15: error: comptime parameter not allowed in function with calling convention 'C'",
    });

    ctx.objErrStage1("non-pure function returns type",
        \\var a: u32 = 0;
        \\pub fn List(comptime T: type) type {
        \\    a += 1;
        \\    return SmallList(T, 8);
        \\}
        \\
        \\pub fn SmallList(comptime T: type, comptime STATIC_SIZE: usize) type {
        \\    return struct {
        \\        items: []T,
        \\        length: usize,
        \\        prealloc_items: [STATIC_SIZE]T,
        \\    };
        \\}
        \\
        \\export fn function_with_return_type_type() void {
        \\    var list: List(i32) = undefined;
        \\    list.length = 10;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:7: error: unable to evaluate constant expression",
        "tmp.zig:16:19: note: referenced here",
    });

    ctx.objErrStage1("bogus method call on slice",
        \\var self = "aoeu";
        \\fn f(m: []const u8) void {
        \\    m.copy(u8, self[0..], m);
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:3:6: error: no member named 'copy' in '[]const u8'",
    });

    ctx.objErrStage1("wrong number of arguments for method fn call",
        \\const Foo = struct {
        \\    fn method(self: *const Foo, a: i32) void {_ = self; _ = a;}
        \\};
        \\fn f(foo: *const Foo) void {
        \\
        \\    foo.method(1, 2);
        \\}
        \\export fn entry() usize { return @sizeOf(@TypeOf(f)); }
    , &[_][]const u8{
        "tmp.zig:6:15: error: expected 2 argument(s), found 3",
    });

    ctx.objErrStage1("assign through constant pointer",
        \\export fn f() void {
        \\  var cstr = "Hat";
        \\  cstr[0] = 'W';
        \\}
    , &[_][]const u8{
        "tmp.zig:3:13: error: cannot assign to constant",
    });

    ctx.objErrStage1("assign through constant slice",
        \\export fn f() void {
        \\  var cstr: []const u8 = "Hat";
        \\  cstr[0] = 'W';
        \\}
    , &[_][]const u8{
        "tmp.zig:3:13: error: cannot assign to constant",
    });

    ctx.objErrStage1("main function with bogus args type",
        \\pub fn main(args: [][]bogus) !void {_ = args;}
    , &[_][]const u8{
        "tmp.zig:1:23: error: use of undeclared identifier 'bogus'",
    });

    ctx.objErrStage1("misspelled type with pointer only reference",
        \\const JasonHM = u8;
        \\const JasonList = *JsonNode;
        \\
        \\const JsonOA = union(enum) {
        \\    JSONArray: JsonList,
        \\    JSONObject: JasonHM,
        \\};
        \\
        \\const JsonType = union(enum) {
        \\    JSONNull: void,
        \\    JSONInteger: isize,
        \\    JSONDouble: f64,
        \\    JSONBool: bool,
        \\    JSONString: []u8,
        \\    JSONArray: void,
        \\    JSONObject: void,
        \\};
        \\
        \\pub const JsonNode = struct {
        \\    kind: JsonType,
        \\    jobject: ?JsonOA,
        \\};
        \\
        \\fn foo() void {
        \\    var jll: JasonList = undefined;
        \\    jll.init(1234);
        \\    var jd = JsonNode {.kind = JsonType.JSONArray , .jobject = JsonOA.JSONArray {jll} };
        \\    _ = jd;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:5:16: error: use of undeclared identifier 'JsonList'",
    });

    ctx.objErrStage1("method call with first arg type primitive",
        \\const Foo = struct {
        \\    x: i32,
        \\
        \\    fn init(x: i32) Foo {
        \\        return Foo {
        \\            .x = x,
        \\        };
        \\    }
        \\};
        \\
        \\export fn f() void {
        \\    const derp = Foo.init(3);
        \\
        \\    derp.init();
        \\}
    , &[_][]const u8{
        "tmp.zig:14:5: error: expected type 'i32', found 'Foo'",
    });

    ctx.objErrStage1("method call with first arg type wrong container",
        \\pub const List = struct {
        \\    len: usize,
        \\    allocator: *Allocator,
        \\
        \\    pub fn init(allocator: *Allocator) List {
        \\        return List {
        \\            .len = 0,
        \\            .allocator = allocator,
        \\        };
        \\    }
        \\};
        \\
        \\pub var global_allocator = Allocator {
        \\    .field = 1234,
        \\};
        \\
        \\pub const Allocator = struct {
        \\    field: i32,
        \\};
        \\
        \\export fn foo() void {
        \\    var x = List.init(&global_allocator);
        \\    x.init();
        \\}
    , &[_][]const u8{
        "tmp.zig:23:5: error: expected type '*Allocator', found '*List'",
    });

    ctx.objErrStage1("binary not on number literal",
        \\const TINY_QUANTUM_SHIFT = 4;
        \\const TINY_QUANTUM_SIZE = 1 << TINY_QUANTUM_SHIFT;
        \\var block_aligned_stuff: usize = (4 + TINY_QUANTUM_SIZE) & ~(TINY_QUANTUM_SIZE - 1);
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(block_aligned_stuff)); }
    , &[_][]const u8{
        "tmp.zig:3:60: error: unable to perform binary not operation on type 'comptime_int'",
    });

    {
        const case = ctx.obj("multiple files with private function error", .{});
        case.backend = .stage1;

        case.addSourceFile("foo.zig",
            \\fn privateFunction() void { }
        );

        case.addError(
            \\const foo = @import("foo.zig",);
            \\
            \\export fn callPrivFunction() void {
            \\    foo.privateFunction();
            \\}
        , &[_][]const u8{
            "tmp.zig:4:8: error: 'privateFunction' is private",
            "foo.zig:1:1: note: declared here",
        });
    }

    {
        const case = ctx.obj("multiple files with private member instance function (canonical invocation) error", .{});
        case.backend = .stage1;

        case.addSourceFile("foo.zig",
            \\pub const Foo = struct {
            \\    fn privateFunction(self: *Foo) void { _ = self; }
            \\};
        );

        case.addError(
            \\const Foo = @import("foo.zig",).Foo;
            \\
            \\export fn callPrivFunction() void {
            \\    var foo = Foo{};
            \\    Foo.privateFunction(foo);
            \\}
        , &[_][]const u8{
            "tmp.zig:5:8: error: 'privateFunction' is private",
            "foo.zig:2:5: note: declared here",
        });
    }

    {
        const case = ctx.obj("multiple files with private member instance function error", .{});
        case.backend = .stage1;

        case.addSourceFile("foo.zig",
            \\pub const Foo = struct {
            \\    fn privateFunction(self: *Foo) void { _ = self; }
            \\};
        );

        case.addError(
            \\const Foo = @import("foo.zig",).Foo;
            \\
            \\export fn callPrivFunction() void {
            \\    var foo = Foo{};
            \\    foo.privateFunction();
            \\}
        , &[_][]const u8{
            "tmp.zig:5:8: error: 'privateFunction' is private",
            "foo.zig:2:5: note: declared here",
        });
    }

    ctx.objErrStage1("container init with non-type",
        \\const zero: i32 = 0;
        \\const a = zero{1};
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(a)); }
    , &[_][]const u8{
        "tmp.zig:2:11: error: expected type 'type', found 'i32'",
    });

    ctx.objErrStage1("assign to constant field",
        \\const Foo = struct {
        \\    field: i32,
        \\};
        \\export fn derp() void {
        \\    const f = Foo {.field = 1234,};
        \\    f.field = 0;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:15: error: cannot assign to constant",
    });

    ctx.objErrStage1("return from defer expression",
        \\pub fn testTrickyDefer() !void {
        \\    defer canFail() catch {};
        \\
        \\    defer try canFail();
        \\
        \\    const a = maybeInt() orelse return;
        \\}
        \\
        \\fn canFail() anyerror!void { }
        \\
        \\pub fn maybeInt() ?i32 {
        \\    return 0;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(testTrickyDefer)); }
    , &[_][]const u8{
        "tmp.zig:4:11: error: 'try' not allowed inside defer expression",
    });

    ctx.objErrStage1("assign too big number to u16",
        \\export fn foo() void {
        \\    var vga_mem: u16 = 0xB8000;
        \\    _ = vga_mem;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:24: error: integer value 753664 cannot be coerced to type 'u16'",
    });

    ctx.objErrStage1("global variable alignment non power of 2",
        \\const some_data: [100]u8 align(3) = undefined;
        \\export fn entry() usize { return @sizeOf(@TypeOf(some_data)); }
    , &[_][]const u8{
        "tmp.zig:1:32: error: alignment value 3 is not a power of 2",
    });

    ctx.objErrStage1("function alignment non power of 2",
        \\extern fn foo() align(3) void;
        \\export fn entry() void { return foo(); }
    , &[_][]const u8{
        "tmp.zig:1:23: error: alignment value 3 is not a power of 2",
    });

    ctx.objErrStage1("compile log",
        \\export fn foo() void {
        \\    comptime bar(12, "hi",);
        \\}
        \\fn bar(a: i32, b: []const u8) void {
        \\    @compileLog("begin",);
        \\    @compileLog("a", a, "b", b);
        \\    @compileLog("end",);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: found compile log statement",
        "tmp.zig:6:5: error: found compile log statement",
        "tmp.zig:7:5: error: found compile log statement",
    });

    ctx.objErrStage1("casting bit offset pointer to regular pointer",
        \\const BitField = packed struct {
        \\    a: u3,
        \\    b: u3,
        \\    c: u2,
        \\};
        \\
        \\fn foo(bit_field: *const BitField) u3 {
        \\    return bar(&bit_field.b);
        \\}
        \\
        \\fn bar(x: *const u3) u3 {
        \\    return x.*;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:8:26: error: expected type '*const u3', found '*align(:3:1) const u3'",
    });

    ctx.objErrStage1("referring to a struct that is invalid",
        \\const UsbDeviceRequest = struct {
        \\    Type: u8,
        \\};
        \\
        \\export fn foo() void {
        \\    comptime assert(@sizeOf(UsbDeviceRequest) == 0x8);
        \\}
        \\
        \\fn assert(ok: bool) void {
        \\    if (!ok) unreachable;
        \\}
    , &[_][]const u8{
        "tmp.zig:10:14: error: reached unreachable code",
        "tmp.zig:6:20: note: referenced here",
    });

    ctx.objErrStage1("control flow uses comptime var at runtime",
        \\export fn foo() void {
        \\    comptime var i = 0;
        \\    while (i < 5) : (i += 1) {
        \\        bar();
        \\    }
        \\}
        \\
        \\fn bar() void { }
    , &[_][]const u8{
        "tmp.zig:3:5: error: control flow attempts to use compile-time variable at runtime",
        "tmp.zig:3:24: note: compile-time variable assigned here",
    });

    ctx.objErrStage1("ignored return value",
        \\export fn foo() void {
        \\    bar();
        \\}
        \\fn bar() i32 { return 0; }
    , &[_][]const u8{
        "tmp.zig:2:8: error: expression value is ignored",
    });

    ctx.objErrStage1("ignored assert-err-ok return value",
        \\export fn foo() void {
        \\    bar() catch unreachable;
        \\}
        \\fn bar() anyerror!i32 { return 0; }
    , &[_][]const u8{
        "tmp.zig:2:11: error: expression value is ignored",
    });

    ctx.objErrStage1("ignored statement value",
        \\export fn foo() void {
        \\    1;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: expression value is ignored",
    });

    ctx.objErrStage1("ignored comptime statement value",
        \\export fn foo() void {
        \\    comptime {1;}
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: expression value is ignored",
    });

    ctx.objErrStage1("ignored comptime value",
        \\export fn foo() void {
        \\    comptime 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: expression value is ignored",
    });

    ctx.objErrStage1("ignored defered statement value",
        \\export fn foo() void {
        \\    defer {1;}
        \\}
    , &[_][]const u8{
        "tmp.zig:2:12: error: expression value is ignored",
    });

    ctx.objErrStage1("ignored defered function call",
        \\export fn foo() void {
        \\    defer bar();
        \\}
        \\fn bar() anyerror!i32 { return 0; }
    , &[_][]const u8{
        "tmp.zig:2:14: error: error is ignored. consider using `try`, `catch`, or `if`",
    });

    ctx.objErrStage1("dereference an array",
        \\var s_buffer: [10]u8 = undefined;
        \\pub fn pass(in: []u8) []u8 {
        \\    var out = &s_buffer;
        \\    out.*.* = in[0];
        \\    return out.*[0..1];
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(pass)); }
    , &[_][]const u8{
        "tmp.zig:4:10: error: attempt to dereference non-pointer type '[10]u8'",
    });

    ctx.objErrStage1("pass const ptr to mutable ptr fn",
        \\fn foo() bool {
        \\    const a = @as([]const u8, "a",);
        \\    const b = &a;
        \\    return ptrEql(b, b);
        \\}
        \\fn ptrEql(a: *[]const u8, b: *[]const u8) bool {
        \\    _ = a; _ = b;
        \\    return true;
        \\}
        \\
        \\export fn entry() usize { return @sizeOf(@TypeOf(foo)); }
    , &[_][]const u8{
        "tmp.zig:4:19: error: expected type '*[]const u8', found '*const []const u8'",
    });

    {
        const case = ctx.obj("export collision", .{});
        case.backend = .stage1;

        case.addSourceFile("foo.zig",
            \\export fn bar() void {}
            \\pub const baz = 1234;
        );

        case.addError(
            \\const foo = @import("foo.zig",);
            \\
            \\export fn bar() usize {
            \\    return foo.baz;
            \\}
        , &[_][]const u8{
            "foo.zig:1:1: error: exported symbol collision: 'bar'",
            "tmp.zig:3:1: note: other symbol here",
        });
    }

    ctx.objErrStage1("implicit cast from array to mutable slice",
        \\var global_array: [10]i32 = undefined;
        \\fn foo(param: []i32) void {_ = param;}
        \\export fn entry() void {
        \\    foo(global_array);
        \\}
    , &[_][]const u8{
        "tmp.zig:4:9: error: expected type '[]i32', found '[10]i32'",
    });

    ctx.objErrStage1("ptrcast to non-pointer",
        \\export fn entry(a: *i32) usize {
        \\    return @ptrCast(usize, a);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: expected pointer, found 'usize'",
    });

    ctx.objErrStage1("asm at compile time",
        \\comptime {
        \\    doSomeAsm();
        \\}
        \\
        \\fn doSomeAsm() void {
        \\    asm volatile (
        \\        \\.globl aoeu;
        \\        \\.type aoeu, @function;
        \\        \\.set aoeu, derp;
        \\    );
        \\}
    , &[_][]const u8{
        "tmp.zig:6:5: error: unable to evaluate constant expression",
    });

    ctx.objErrStage1("invalid member of builtin enum",
        \\const builtin = @import("std").builtin;
        \\export fn entry() void {
        \\    const foo = std.builtin.Mode.x86;
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:29: error: container 'std.builtin.Mode' has no member called 'x86'",
    });

    ctx.objErrStage1("int to ptr of 0 bits",
        \\export fn foo() void {
        \\    var x: usize = 0x1000;
        \\    var y: *void = @intToPtr(*void, x);
        \\    _ = y;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:30: error: type '*void' has 0 bits and cannot store information",
    });

    ctx.objErrStage1("@fieldParentPtr - non struct",
        \\const Foo = i32;
        \\export fn foo(a: *i32) *Foo {
        \\    return @fieldParentPtr(Foo, "a", a);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:28: error: expected struct type, found 'i32'",
    });

    ctx.objErrStage1("@fieldParentPtr - bad field name",
        \\const Foo = extern struct {
        \\    derp: i32,
        \\};
        \\export fn foo(a: *i32) *Foo {
        \\    return @fieldParentPtr(Foo, "a", a);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:33: error: struct 'Foo' has no field 'a'",
    });

    ctx.objErrStage1("@fieldParentPtr - field pointer is not pointer",
        \\const Foo = extern struct {
        \\    a: i32,
        \\};
        \\export fn foo(a: i32) *Foo {
        \\    return @fieldParentPtr(Foo, "a", a);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:38: error: expected pointer, found 'i32'",
    });

    ctx.objErrStage1("@fieldParentPtr - comptime field ptr not based on struct",
        \\const Foo = struct {
        \\    a: i32,
        \\    b: i32,
        \\};
        \\const foo = Foo { .a = 1, .b = 2, };
        \\
        \\comptime {
        \\    const field_ptr = @intToPtr(*i32, 0x1234);
        \\    const another_foo_ptr = @fieldParentPtr(Foo, "b", field_ptr);
        \\    _ = another_foo_ptr;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:55: error: pointer value not based on parent struct",
    });

    ctx.objErrStage1("@fieldParentPtr - comptime wrong field index",
        \\const Foo = struct {
        \\    a: i32,
        \\    b: i32,
        \\};
        \\const foo = Foo { .a = 1, .b = 2, };
        \\
        \\comptime {
        \\    const another_foo_ptr = @fieldParentPtr(Foo, "b", &foo.a);
        \\    _ = another_foo_ptr;
        \\}
    , &[_][]const u8{
        "tmp.zig:8:29: error: field 'b' has index 1 but pointer value is index 0 of struct 'Foo'",
    });

    ctx.objErrStage1("@offsetOf - non struct",
        \\const Foo = i32;
        \\export fn foo() usize {
        \\    return @offsetOf(Foo, "a",);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:22: error: expected struct type, found 'i32'",
    });

    ctx.objErrStage1("@offsetOf - bad field name",
        \\const Foo = struct {
        \\    derp: i32,
        \\};
        \\export fn foo() usize {
        \\    return @offsetOf(Foo, "a",);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:27: error: struct 'Foo' has no field 'a'",
    });

    ctx.exeErrStage1("missing main fn in executable",
        \\
    , &[_][]const u8{
        "error: root source file has no member called 'main'",
    });

    ctx.exeErrStage1("private main fn",
        \\fn main() void {}
    , &[_][]const u8{
        "error: 'main' is private",
        "tmp.zig:1:1: note: declared here",
    });

    ctx.objErrStage1("setting a section on a local variable",
        \\export fn entry() i32 {
        \\    var foo: i32 linksection(".text2") = 1234;
        \\    return foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:30: error: cannot set section of local variable 'foo'",
    });

    ctx.objErrStage1("inner struct member shadowing outer struct member",
        \\fn A() type {
        \\    return struct {
        \\        b: B(),
        \\
        \\        const Self = @This();
        \\
        \\        fn B() type {
        \\            return struct {
        \\                const Self = @This();
        \\            };
        \\        }
        \\    };
        \\}
        \\comptime {
        \\    assert(A().B().Self != A().Self);
        \\}
        \\fn assert(ok: bool) void {
        \\    if (!ok) unreachable;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:17: error: redefinition of 'Self'",
        "tmp.zig:5:9: note: previous definition here",
    });

    ctx.objErrStage1("while expected bool, got optional",
        \\export fn foo() void {
        \\    while (bar()) {}
        \\}
        \\fn bar() ?i32 { return 1; }
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected type 'bool', found '?i32'",
    });

    ctx.objErrStage1("while expected bool, got error union",
        \\export fn foo() void {
        \\    while (bar()) {}
        \\}
        \\fn bar() anyerror!i32 { return 1; }
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected type 'bool', found 'anyerror!i32'",
    });

    ctx.objErrStage1("while expected optional, got bool",
        \\export fn foo() void {
        \\    while (bar()) |x| {_ = x;}
        \\}
        \\fn bar() bool { return true; }
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected optional type, found 'bool'",
    });

    ctx.objErrStage1("while expected optional, got error union",
        \\export fn foo() void {
        \\    while (bar()) |x| {_ = x;}
        \\}
        \\fn bar() anyerror!i32 { return 1; }
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected optional type, found 'anyerror!i32'",
    });

    ctx.objErrStage1("while expected error union, got bool",
        \\export fn foo() void {
        \\    while (bar()) |x| {_ = x;} else |err| {_ = err;}
        \\}
        \\fn bar() bool { return true; }
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected error union type, found 'bool'",
    });

    ctx.objErrStage1("while expected error union, got optional",
        \\export fn foo() void {
        \\    while (bar()) |x| {_ = x;} else |err| {_ = err;}
        \\}
        \\fn bar() ?i32 { return 1; }
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected error union type, found '?i32'",
    });

    // TODO test this in stage2, but we won't even try in stage1
    //ctx.objErrStage1("inline fn calls itself indirectly",
    //    \\export fn foo() void {
    //    \\    bar();
    //    \\}
    //    \\fn bar() callconv(.Inline) void {
    //    \\    baz();
    //    \\    quux();
    //    \\}
    //    \\fn baz() callconv(.Inline) void {
    //    \\    bar();
    //    \\    quux();
    //    \\}
    //    \\extern fn quux() void;
    //, &[_][]const u8{
    //    "tmp.zig:4:1: error: unable to inline function",
    //});

    //ctx.objErrStage1("save reference to inline function",
    //    \\export fn foo() void {
    //    \\    quux(@ptrToInt(bar));
    //    \\}
    //    \\fn bar() callconv(.Inline) void { }
    //    \\extern fn quux(usize) void;
    //, &[_][]const u8{
    //    "tmp.zig:4:1: error: unable to inline function",
    //});

    ctx.objErrStage1("signed integer division",
        \\export fn foo(a: i32, b: i32) i32 {
        \\    return a / b;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:14: error: division with 'i32' and 'i32': signed integers must use @divTrunc, @divFloor, or @divExact",
    });

    ctx.objErrStage1("signed integer remainder division",
        \\export fn foo(a: i32, b: i32) i32 {
        \\    return a % b;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:14: error: remainder division with 'i32' and 'i32': signed integers and floats must use @rem or @mod",
    });

    ctx.objErrStage1("compile-time division by zero",
        \\comptime {
        \\    const a: i32 = 1;
        \\    const b: i32 = 0;
        \\    const c = a / b;
        \\    _ = c;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:17: error: division by zero",
    });

    ctx.objErrStage1("compile-time remainder division by zero",
        \\comptime {
        \\    const a: i32 = 1;
        \\    const b: i32 = 0;
        \\    const c = a % b;
        \\    _ = c;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:17: error: division by zero",
    });

    ctx.objErrStage1("@setRuntimeSafety twice for same scope",
        \\export fn foo() void {
        \\    @setRuntimeSafety(false);
        \\    @setRuntimeSafety(false);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: runtime safety set twice for same scope",
        "tmp.zig:2:5: note: first set here",
    });

    ctx.objErrStage1("@setFloatMode twice for same scope",
        \\export fn foo() void {
        \\    @setFloatMode(@import("std").builtin.FloatMode.Optimized);
        \\    @setFloatMode(@import("std").builtin.FloatMode.Optimized);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: float mode set twice for same scope",
        "tmp.zig:2:5: note: first set here",
    });

    ctx.objErrStage1("array access of type",
        \\export fn foo() void {
        \\    var b: u8[40] = undefined;
        \\    _ = b;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:14: error: array access of non-array type 'type'",
    });

    ctx.objErrStage1("cannot break out of defer expression",
        \\export fn foo() void {
        \\    while (true) {
        \\        defer {
        \\            break;
        \\        }
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:4:13: error: cannot break out of defer expression",
    });

    ctx.objErrStage1("cannot continue out of defer expression",
        \\export fn foo() void {
        \\    while (true) {
        \\        defer {
        \\            continue;
        \\        }
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:4:13: error: cannot continue out of defer expression",
    });

    ctx.objErrStage1("calling a generic function only known at runtime",
        \\var foos = [_]fn(anytype) void { foo1, foo2 };
        \\
        \\fn foo1(arg: anytype) void {_ = arg;}
        \\fn foo2(arg: anytype) void {_ = arg;}
        \\
        \\pub fn main() !void {
        \\    foos[0](true);
        \\}
    , &[_][]const u8{
        "tmp.zig:7:9: error: calling a generic function requires compile-time known function value",
    });

    ctx.objErrStage1("@compileError shows traceback of references that caused it",
        \\const foo = @compileError("aoeu",);
        \\
        \\const bar = baz + foo;
        \\const baz = 1;
        \\
        \\export fn entry() i32 {
        \\    return bar;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:13: error: aoeu",
        "tmp.zig:3:19: note: referenced here",
        "tmp.zig:7:12: note: referenced here",
    });

    ctx.objErrStage1("float literal too large error",
        \\comptime {
        \\    const a = 0x1.0p18495;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: float literal out of range of any type",
    });

    ctx.objErrStage1("float literal too small error (denormal)",
        \\comptime {
        \\    const a = 0x1.0p-19000;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: float literal out of range of any type",
    });

    ctx.objErrStage1("explicit cast float literal to integer when there is a fraction component",
        \\export fn entry() i32 {
        \\    return @as(i32, 12.34);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:21: error: fractional component prevents float value 12.340000 from being casted to type 'i32'",
    });

    ctx.objErrStage1("non pointer given to @ptrToInt",
        \\export fn entry(x: i32) usize {
        \\    return @ptrToInt(x);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:22: error: expected pointer, found 'i32'",
    });

    ctx.objErrStage1("@shlExact shifts out 1 bits",
        \\comptime {
        \\    const x = @shlExact(@as(u8, 0b01010101), 2);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: operation caused overflow",
    });

    ctx.objErrStage1("@shrExact shifts out 1 bits",
        \\comptime {
        \\    const x = @shrExact(@as(u8, 0b10101010), 2);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: exact shift shifted out 1 bits",
    });

    ctx.objErrStage1("shifting without int type or comptime known",
        \\export fn entry(x: u8) u8 {
        \\    return 0x11 << x;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:17: error: LHS of shift must be a fixed-width integer type, or RHS must be compile-time known",
    });

    ctx.objErrStage1("shifting RHS is log2 of LHS int bit width",
        \\export fn entry(x: u8, y: u8) u8 {
        \\    return x << y;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:17: error: expected type 'u3', found 'u8'",
    });

    ctx.objErrStage1("globally shadowing a primitive type",
        \\const u16 = u8;
        \\export fn entry() void {
        \\    const a: u16 = 300;
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:1: error: declaration shadows primitive type 'u16'",
    });

    ctx.objErrStage1("implicitly increasing pointer alignment",
        \\const Foo = packed struct {
        \\    a: u8,
        \\    b: u32,
        \\};
        \\
        \\export fn entry() void {
        \\    var foo = Foo { .a = 1, .b = 10 };
        \\    bar(&foo.b);
        \\}
        \\
        \\fn bar(x: *u32) void {
        \\    x.* += 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:8:13: error: expected type '*u32', found '*align(1) u32'",
    });

    ctx.objErrStage1("implicitly increasing slice alignment",
        \\const Foo = packed struct {
        \\    a: u8,
        \\    b: u32,
        \\};
        \\
        \\export fn entry() void {
        \\    var foo = Foo { .a = 1, .b = 10 };
        \\    foo.b += 1;
        \\    bar(@as(*[1]u32, &foo.b)[0..]);
        \\}
        \\
        \\fn bar(x: []u32) void {
        \\    x[0] += 1;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:26: error: cast increases pointer alignment",
        "tmp.zig:9:26: note: '*align(1) u32' has alignment 1",
        "tmp.zig:9:26: note: '*[1]u32' has alignment 4",
    });

    ctx.objErrStage1("increase pointer alignment in @ptrCast",
        \\export fn entry() u32 {
        \\    var bytes: [4]u8 = [_]u8{0x01, 0x02, 0x03, 0x04};
        \\    const ptr = @ptrCast(*u32, &bytes[0]);
        \\    return ptr.*;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:17: error: cast increases pointer alignment",
        "tmp.zig:3:38: note: '*u8' has alignment 1",
        "tmp.zig:3:26: note: '*u32' has alignment 4",
    });

    ctx.objErrStage1("@alignCast expects pointer or slice",
        \\export fn entry() void {
        \\    @alignCast(4, @as(u32, 3));
        \\}
    , &[_][]const u8{
        "tmp.zig:2:19: error: expected pointer or slice, found 'u32'",
    });

    ctx.objErrStage1("passing an under-aligned function pointer",
        \\export fn entry() void {
        \\    testImplicitlyDecreaseFnAlign(alignedSmall, 1234);
        \\}
        \\fn testImplicitlyDecreaseFnAlign(ptr: fn () align(8) i32, answer: i32) void {
        \\    if (ptr() != answer) unreachable;
        \\}
        \\fn alignedSmall() align(4) i32 { return 1234; }
    , &[_][]const u8{
        "tmp.zig:2:35: error: expected type 'fn() align(8) i32', found 'fn() align(4) i32'",
    });

    ctx.objErrStage1("passing a not-aligned-enough pointer to cmpxchg",
        \\const AtomicOrder = @import("std").builtin.AtomicOrder;
        \\export fn entry() bool {
        \\    var x: i32 align(1) = 1234;
        \\    while (!@cmpxchgWeak(i32, &x, 1234, 5678, AtomicOrder.SeqCst, AtomicOrder.SeqCst)) {}
        \\    return x == 5678;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:32: error: expected type '*i32', found '*align(1) i32'",
    });

    ctx.objErrStage1("wrong size to an array literal",
        \\comptime {
        \\    const array = [2]u8{1, 2, 3};
        \\    _ = array;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:31: error: index 2 outside array of size 2",
    });

    ctx.objErrStage1("wrong pointer coerced to pointer to opaque {}",
        \\const Derp = opaque {};
        \\extern fn bar(d: *Derp) void;
        \\export fn foo() void {
        \\    var x = @as(u8, 1);
        \\    bar(@ptrCast(*c_void, &x));
        \\}
    , &[_][]const u8{
        "tmp.zig:5:9: error: expected type '*Derp', found '*c_void'",
    });

    ctx.objErrStage1("non-const variables of things that require const variables",
        \\export fn entry1() void {
        \\   var m2 = &2;
        \\   _ = m2;
        \\}
        \\export fn entry2() void {
        \\   var a = undefined;
        \\   _ = a;
        \\}
        \\export fn entry3() void {
        \\   var b = 1;
        \\   _ = b;
        \\}
        \\export fn entry4() void {
        \\   var c = 1.0;
        \\   _ = c;
        \\}
        \\export fn entry5() void {
        \\   var d = null;
        \\   _ = d;
        \\}
        \\export fn entry6(opaque_: *Opaque) void {
        \\   var e = opaque_.*;
        \\   _ = e;
        \\}
        \\export fn entry7() void {
        \\   var f = i32;
        \\   _ = f;
        \\}
        \\export fn entry8() void {
        \\   var h = (Foo {}).bar;
        \\   _ = h;
        \\}
        \\const Opaque = opaque {};
        \\const Foo = struct {
        \\    fn bar(self: *const Foo) void {_ = self;}
        \\};
    , &[_][]const u8{
        "tmp.zig:2:4: error: variable of type '*const comptime_int' must be const or comptime",
        "tmp.zig:6:4: error: variable of type '(undefined)' must be const or comptime",
        "tmp.zig:10:4: error: variable of type 'comptime_int' must be const or comptime",
        "tmp.zig:10:4: note: to modify this variable at runtime, it must be given an explicit fixed-size number type",
        "tmp.zig:14:4: error: variable of type 'comptime_float' must be const or comptime",
        "tmp.zig:14:4: note: to modify this variable at runtime, it must be given an explicit fixed-size number type",
        "tmp.zig:18:4: error: variable of type '(null)' must be const or comptime",
        "tmp.zig:22:4: error: variable of type 'Opaque' not allowed",
        "tmp.zig:26:4: error: variable of type 'type' must be const or comptime",
        "tmp.zig:30:4: error: variable of type '(bound fn(*const Foo) void)' must be const or comptime",
    });

    ctx.objErrStage1("variable with type 'noreturn'",
        \\export fn entry9() void {
        \\    var z: noreturn = return;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: unreachable code",
        "tmp.zig:2:23: note: control flow is diverted here",
    });

    ctx.objErrStage1("wrong types given to atomic order args in cmpxchg",
        \\export fn entry() void {
        \\    var x: i32 = 1234;
        \\    while (!@cmpxchgWeak(i32, &x, 1234, 5678, @as(u32, 1234), @as(u32, 1234))) {}
        \\}
    , &[_][]const u8{
        "tmp.zig:3:47: error: expected type 'std.builtin.AtomicOrder', found 'u32'",
    });

    ctx.objErrStage1("wrong types given to @export",
        \\fn entry() callconv(.C) void { }
        \\comptime {
        \\    @export(entry, .{.name = "entry", .linkage = @as(u32, 1234) });
        \\}
    , &[_][]const u8{
        "tmp.zig:3:59: error: expected type 'std.builtin.GlobalLinkage', found 'comptime_int'",
    });

    ctx.objErrStage1("struct with invalid field",
        \\const std = @import("std",);
        \\const Allocator = std.mem.Allocator;
        \\const ArrayList = std.ArrayList;
        \\
        \\const HeaderWeight = enum {
        \\    H1, H2, H3, H4, H5, H6,
        \\};
        \\
        \\const MdText = ArrayList(u8);
        \\
        \\const MdNode = union(enum) {
        \\    Header: struct {
        \\        text: MdText,
        \\        weight: HeaderValue,
        \\    },
        \\};
        \\
        \\export fn entry() void {
        \\    const a = MdNode.Header {
        \\        .text = MdText.init(&std.testing.allocator),
        \\        .weight = HeaderWeight.H1,
        \\    };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:14:17: error: use of undeclared identifier 'HeaderValue'",
    });

    ctx.objErrStage1("@setAlignStack outside function",
        \\comptime {
        \\    @setAlignStack(16);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: @setAlignStack outside function",
    });

    ctx.objErrStage1("@setAlignStack in naked function",
        \\export fn entry() callconv(.Naked) void {
        \\    @setAlignStack(16);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: @setAlignStack in naked function",
    });

    ctx.objErrStage1("@setAlignStack in inline function",
        \\export fn entry() void {
        \\    foo();
        \\}
        \\fn foo() callconv(.Inline) void {
        \\    @setAlignStack(16);
        \\}
    , &[_][]const u8{
        "tmp.zig:5:5: error: @setAlignStack in inline function",
    });

    ctx.objErrStage1("@setAlignStack set twice",
        \\export fn entry() void {
        \\    @setAlignStack(16);
        \\    @setAlignStack(16);
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: alignstack set twice",
        "tmp.zig:2:5: note: first set here",
    });

    ctx.objErrStage1("@setAlignStack too big",
        \\export fn entry() void {
        \\    @setAlignStack(511 + 1);
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: attempt to @setAlignStack(512); maximum is 256",
    });

    ctx.objErrStage1("storing runtime value in compile time variable then using it",
        \\const Mode = @import("std").builtin.Mode;
        \\
        \\fn Free(comptime filename: []const u8) TestCase {
        \\    return TestCase {
        \\        .filename = filename,
        \\        .problem_type = ProblemType.Free,
        \\    };
        \\}
        \\
        \\fn LibC(comptime filename: []const u8) TestCase {
        \\    return TestCase {
        \\        .filename = filename,
        \\        .problem_type = ProblemType.LinkLibC,
        \\    };
        \\}
        \\
        \\const TestCase = struct {
        \\    filename: []const u8,
        \\    problem_type: ProblemType,
        \\};
        \\
        \\const ProblemType = enum {
        \\    Free,
        \\    LinkLibC,
        \\};
        \\
        \\export fn entry() void {
        \\    const tests = [_]TestCase {
        \\        Free("001"),
        \\        Free("002"),
        \\        LibC("078"),
        \\        Free("116"),
        \\        Free("117"),
        \\    };
        \\
        \\    for ([_]Mode { Mode.Debug, Mode.ReleaseSafe, Mode.ReleaseFast }) |mode| {
        \\        _ = mode;
        \\        inline for (tests) |test_case| {
        \\            const foo = test_case.filename ++ ".zig";
        \\            _ = foo;
        \\        }
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:38:29: error: cannot store runtime value in compile time variable",
    });

    ctx.objErrStage1("invalid legacy unicode escape",
        \\export fn entry() void {
        \\    const a = '\U1234';
        \\}
    , &[_][]const u8{
        "tmp.zig:2:15: error: expected expression, found 'invalid'",
        "tmp.zig:2:18: note: invalid byte: '1'",
    });

    ctx.objErrStage1("invalid empty unicode escape",
        \\export fn entry() void {
        \\    const a = '\u{}';
        \\}
    , &[_][]const u8{
        "tmp.zig:2:19: error: empty unicode escape sequence",
    });

    ctx.objErrStage1("non-printable invalid character", "\xff\xfe" ++
        "fn foo() bool {\r\n" ++
        "    return true;\r\n" ++
        "}\r\n", &[_][]const u8{
        "tmp.zig:1:1: error: expected test, comptime, var decl, or container field, found 'invalid'",
        "tmp.zig:1:1: note: invalid byte: '\\xff'",
    });

    ctx.objErrStage1("non-printable invalid character with escape alternative", "fn foo() bool {\n" ++
        "\treturn true;\n" ++
        "}\n", &[_][]const u8{
        "tmp.zig:2:1: error: invalid character: '\\t'",
    });

    ctx.objErrStage1("calling var args extern function, passing array instead of pointer",
        \\export fn entry() void {
        \\    foo("hello".*,);
        \\}
        \\pub extern fn foo(format: *const u8, ...) void;
    , &[_][]const u8{
        "tmp.zig:2:16: error: expected type '*const u8', found '[5:0]u8'",
    });

    ctx.objErrStage1("constant inside comptime function has compile error",
        \\const ContextAllocator = MemoryPool(usize);
        \\
        \\pub fn MemoryPool(comptime T: type) type {
        \\    const free_list_t = @compileError("aoeu",);
        \\
        \\    return struct {
        \\        free_list: free_list_t,
        \\    };
        \\}
        \\
        \\export fn entry() void {
        \\    var allocator: ContextAllocator = undefined;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:5: error: unreachable code",
        "tmp.zig:4:25: note: control flow is diverted here",
        "tmp.zig:12:9: error: unused local variable",
    });

    ctx.objErrStage1("specify enum tag type that is too small",
        \\const Small = enum (u2) {
        \\    One,
        \\    Two,
        \\    Three,
        \\    Four,
        \\    Five,
        \\};
        \\
        \\export fn entry() void {
        \\    var x = Small.One;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:5: error: enumeration value 4 too large for type 'u2'",
    });

    ctx.objErrStage1("specify non-integer enum tag type",
        \\const Small = enum (f32) {
        \\    One,
        \\    Two,
        \\    Three,
        \\};
        \\
        \\export fn entry() void {
        \\    var x = Small.One;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:21: error: expected integer, found 'f32'",
    });

    ctx.objErrStage1("implicitly casting enum to tag type",
        \\const Small = enum(u2) {
        \\    One,
        \\    Two,
        \\    Three,
        \\    Four,
        \\};
        \\
        \\export fn entry() void {
        \\    var x: u2 = Small.Two;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:9:22: error: expected type 'u2', found 'Small'",
    });

    ctx.objErrStage1("explicitly casting non tag type to enum",
        \\const Small = enum(u2) {
        \\    One,
        \\    Two,
        \\    Three,
        \\    Four,
        \\};
        \\
        \\export fn entry() void {
        \\    var y = @as(u3, 3);
        \\    var x = @intToEnum(Small, y);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:10:31: error: expected type 'u2', found 'u3'",
    });

    ctx.objErrStage1("union fields with value assignments",
        \\const MultipleChoice = union {
        \\    A: i32 = 20,
        \\};
        \\export fn entry() void {
        \\    var x: MultipleChoice = undefined;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:24: error: explicitly valued tagged union missing integer tag type",
        "tmp.zig:2:14: note: tag value specified here",
    });

    ctx.objErrStage1("enum with 0 fields",
        \\const Foo = enum {};
    , &[_][]const u8{
        "tmp.zig:1:13: error: enum declarations must have at least one tag",
    });

    ctx.objErrStage1("union with 0 fields",
        \\const Foo = union {};
    , &[_][]const u8{
        "tmp.zig:1:13: error: union declarations must have at least one tag",
    });

    ctx.objErrStage1("enum value already taken",
        \\const MultipleChoice = enum(u32) {
        \\    A = 20,
        \\    B = 40,
        \\    C = 60,
        \\    D = 1000,
        \\    E = 60,
        \\};
        \\export fn entry() void {
        \\    var x = MultipleChoice.C;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:5: error: enum tag value 60 already taken",
        "tmp.zig:4:5: note: other occurrence here",
    });

    ctx.objErrStage1("union with specified enum omits field",
        \\const Letter = enum {
        \\    A,
        \\    B,
        \\    C,
        \\};
        \\const Payload = union(Letter) {
        \\    A: i32,
        \\    B: f64,
        \\};
        \\export fn entry() usize {
        \\    return @sizeOf(Payload);
        \\}
    , &[_][]const u8{
        "tmp.zig:6:17: error: enum field missing: 'C'",
        "tmp.zig:4:5: note: declared here",
    });

    ctx.objErrStage1("non-integer tag type to automatic union enum",
        \\const Foo = union(enum(f32)) {
        \\    A: i32,
        \\};
        \\export fn entry() void {
        \\    const x = @typeInfo(Foo).Union.tag_type.?;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:24: error: expected integer tag type, found 'f32'",
    });

    ctx.objErrStage1("non-enum tag type passed to union",
        \\const Foo = union(u32) {
        \\    A: i32,
        \\};
        \\export fn entry() void {
        \\    const x = @typeInfo(Foo).Union.tag_type.?;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:1:19: error: expected enum tag type, found 'u32'",
    });

    ctx.objErrStage1("union auto-enum value already taken",
        \\const MultipleChoice = union(enum(u32)) {
        \\    A = 20,
        \\    B = 40,
        \\    C = 60,
        \\    D = 1000,
        \\    E = 60,
        \\};
        \\export fn entry() void {
        \\    var x = MultipleChoice { .C = {} };
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:9: error: enum tag value 60 already taken",
        "tmp.zig:4:9: note: other occurrence here",
    });

    ctx.objErrStage1("union enum field does not match enum",
        \\const Letter = enum {
        \\    A,
        \\    B,
        \\    C,
        \\};
        \\const Payload = union(Letter) {
        \\    A: i32,
        \\    B: f64,
        \\    C: bool,
        \\    D: bool,
        \\};
        \\export fn entry() void {
        \\    var a = Payload {.A = 1234};
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:10:5: error: enum field not found: 'D'",
        "tmp.zig:1:16: note: enum declared here",
    });

    ctx.objErrStage1("field type supplied in an enum",
        \\const Letter = enum {
        \\    A: void,
        \\    B,
        \\    C,
        \\};
    , &[_][]const u8{
        "tmp.zig:2:8: error: enum fields do not have types",
        "tmp.zig:1:16: note: consider 'union(enum)' here to make it a tagged union",
    });

    ctx.objErrStage1("struct field missing type",
        \\const Letter = struct {
        \\    A,
        \\};
        \\export fn entry() void {
        \\    var a = Letter { .A = {} };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: struct field missing type",
    });

    ctx.objErrStage1("extern union field missing type",
        \\const Letter = extern union {
        \\    A,
        \\};
        \\export fn entry() void {
        \\    var a = Letter { .A = {} };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: union field missing type",
    });

    ctx.objErrStage1("extern union given enum tag type",
        \\const Letter = enum {
        \\    A,
        \\    B,
        \\    C,
        \\};
        \\const Payload = extern union(Letter) {
        \\    A: i32,
        \\    B: f64,
        \\    C: bool,
        \\};
        \\export fn entry() void {
        \\    var a = Payload { .A = 1234 };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:30: error: extern union does not support enum tag type",
    });

    ctx.objErrStage1("packed union given enum tag type",
        \\const Letter = enum {
        \\    A,
        \\    B,
        \\    C,
        \\};
        \\const Payload = packed union(Letter) {
        \\    A: i32,
        \\    B: f64,
        \\    C: bool,
        \\};
        \\export fn entry() void {
        \\    var a = Payload { .A = 1234 };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:30: error: packed union does not support enum tag type",
    });

    ctx.objErrStage1("packed union with automatic layout field",
        \\const Foo = struct {
        \\    a: u32,
        \\    b: f32,
        \\};
        \\const Payload = packed union {
        \\    A: Foo,
        \\    B: bool,
        \\};
        \\export fn entry() void {
        \\    var a = Payload { .B = true };
        \\    _ = a;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:5: error: non-packed, non-extern struct 'Foo' not allowed in packed union; no guaranteed in-memory representation",
    });

    ctx.objErrStage1("switch on union with no attached enum",
        \\const Payload = union {
        \\    A: i32,
        \\    B: f64,
        \\    C: bool,
        \\};
        \\export fn entry() void {
        \\    const a = Payload { .A = 1234 };
        \\    foo(a);
        \\}
        \\fn foo(a: *const Payload) void {
        \\    switch (a.*) {
        \\        Payload.A => {},
        \\        else => unreachable,
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:11:14: error: switch on union which has no attached enum",
        "tmp.zig:1:17: note: consider 'union(enum)' here",
    });

    ctx.objErrStage1("enum in field count range but not matching tag",
        \\const Foo = enum(u32) {
        \\    A = 10,
        \\    B = 11,
        \\};
        \\export fn entry() void {
        \\    var x = @intToEnum(Foo, 0);
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:6:13: error: enum 'Foo' has no tag matching integer value 0",
        "tmp.zig:1:13: note: 'Foo' declared here",
    });

    ctx.objErrStage1("comptime cast enum to union but field has payload",
        \\const Letter = enum { A, B, C };
        \\const Value = union(Letter) {
        \\    A: i32,
        \\    B,
        \\    C,
        \\};
        \\export fn entry() void {
        \\    var x: Value = Letter.A;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:8:26: error: cast to union 'Value' must initialize 'i32' field 'A'",
        "tmp.zig:3:5: note: field 'A' declared here",
    });

    ctx.objErrStage1("runtime cast to union which has non-void fields",
        \\const Letter = enum { A, B, C };
        \\const Value = union(Letter) {
        \\    A: i32,
        \\    B,
        \\    C,
        \\};
        \\export fn entry() void {
        \\    foo(Letter.A);
        \\}
        \\fn foo(l: Letter) void {
        \\    var x: Value = l;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:11:20: error: runtime cast to union 'Value' which has non-void fields",
        "tmp.zig:3:5: note: field 'A' has type 'i32'",
    });

    ctx.objErrStage1("taking byte offset of void field in struct",
        \\const Empty = struct {
        \\    val: void,
        \\};
        \\export fn foo() void {
        \\    const fieldOffset = @offsetOf(Empty, "val",);
        \\    _ = fieldOffset;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:42: error: zero-bit field 'val' in struct 'Empty' has no offset",
    });

    ctx.objErrStage1("taking bit offset of void field in struct",
        \\const Empty = struct {
        \\    val: void,
        \\};
        \\export fn foo() void {
        \\    const fieldOffset = @bitOffsetOf(Empty, "val",);
        \\    _ = fieldOffset;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:45: error: zero-bit field 'val' in struct 'Empty' has no offset",
    });

    ctx.objErrStage1("invalid union field access in comptime",
        \\const Foo = union {
        \\    Bar: u8,
        \\    Baz: void,
        \\};
        \\comptime {
        \\    var foo = Foo {.Baz = {}};
        \\    const bar_val = foo.Bar;
        \\    _ = bar_val;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:24: error: accessing union field 'Bar' while field 'Baz' is set",
    });

    ctx.objErrStage1("unsupported modifier at start of asm output constraint",
        \\export fn foo() void {
        \\    var bar: u32 = 3;
        \\    asm volatile ("" : [baz]"+r"(bar) : : "");
        \\}
    , &[_][]const u8{
        "tmp.zig:3:5: error: invalid modifier starting output constraint for 'baz': '+', only '=' is supported. Compiler TODO: see https://github.com/ziglang/zig/issues/215",
    });

    ctx.objErrStage1("comptime_int in asm input",
        \\export fn foo() void {
        \\    asm volatile ("" : : [bar]"r"(3) : "");
        \\}
    , &[_][]const u8{
        "tmp.zig:2:35: error: expected sized integer or sized float, found comptime_int",
    });

    ctx.objErrStage1("comptime_float in asm input",
        \\export fn foo() void {
        \\    asm volatile ("" : : [bar]"r"(3.17) : "");
        \\}
    , &[_][]const u8{
        "tmp.zig:2:35: error: expected sized integer or sized float, found comptime_float",
    });

    ctx.objErrStage1("runtime assignment to comptime struct type",
        \\const Foo = struct {
        \\    Bar: u8,
        \\    Baz: type,
        \\};
        \\export fn f() void {
        \\    var x: u8 = 0;
        \\    const foo = Foo { .Bar = x, .Baz = u8 };
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:23: error: unable to evaluate constant expression",
    });

    ctx.objErrStage1("runtime assignment to comptime union type",
        \\const Foo = union {
        \\    Bar: u8,
        \\    Baz: type,
        \\};
        \\export fn f() void {
        \\    var x: u8 = 0;
        \\    const foo = Foo { .Bar = x };
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:7:23: error: unable to evaluate constant expression",
    });

    ctx.testErrStage1("@shuffle with selected index past first vector length",
        \\export fn entry() void {
        \\    const v: @import("std").meta.Vector(4, u32) = [4]u32{ 10, 11, 12, 13 };
        \\    const x: @import("std").meta.Vector(4, u32) = [4]u32{ 14, 15, 16, 17 };
        \\    var z = @shuffle(u32, v, x, [8]i32{ 0, 1, 2, 3, 7, 6, 5, 4 });
        \\    _ = z;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:39: error: mask index '4' has out-of-bounds selection",
        "tmp.zig:4:27: note: selected index '7' out of bounds of @Vector(4, u32)",
        "tmp.zig:4:30: note: selections from the second vector are specified with negative numbers",
    });

    ctx.testErrStage1("nested vectors",
        \\export fn entry() void {
        \\    const V1 = @import("std").meta.Vector(4, u8);
        \\    const V2 = @Type(@import("std").builtin.TypeInfo{ .Vector = .{ .len = 4, .child = V1 } });
        \\    var v: V2 = undefined;
        \\    _ = v;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:53: error: vector element type must be integer, float, bool, or pointer; '@Vector(4, u8)' is invalid",
        "tmp.zig:3:16: note: referenced here",
    });

    ctx.testErrStage1("bad @splat type",
        \\export fn entry() void {
        \\    const c = 4;
        \\    var v = @splat(4, c);
        \\    _ = v;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:23: error: vector element type must be integer, float, bool, or pointer; 'comptime_int' is invalid",
    });

    ctx.objErrStage1("compileLog of tagged enum doesn't crash the compiler",
        \\const Bar = union(enum(u32)) {
        \\    X: i32 = 1
        \\};
        \\
        \\fn testCompileLog(x: Bar) void {
        \\    @compileLog(x);
        \\}
        \\
        \\pub fn main () void {
        \\    comptime testCompileLog(Bar{.X = 123});
        \\}
    , &[_][]const u8{
        "tmp.zig:6:5: error: found compile log statement",
    });

    ctx.objErrStage1("attempted implicit cast from *const T to *[1]T",
        \\export fn entry(byte: u8) void {
        \\    const w: i32 = 1234;
        \\    var x: *const i32 = &w;
        \\    var y: *[1]i32 = x;
        \\    y[0] += 1;
        \\    _ = byte;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:22: error: expected type '*[1]i32', found '*const i32'",
        "tmp.zig:4:22: note: cast discards const qualifier",
    });

    ctx.objErrStage1("attempted implicit cast from *const T to []T",
        \\export fn entry() void {
        \\    const u: u32 = 42;
        \\    const x: []u32 = &u;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:23: error: expected type '[]u32', found '*const u32'",
    });

    ctx.objErrStage1("for loop body expression ignored",
        \\fn returns() usize {
        \\    return 2;
        \\}
        \\export fn f1() void {
        \\    for ("hello") |_| returns();
        \\}
        \\export fn f2() void {
        \\    var x: anyerror!i32 = error.Bad;
        \\    for ("hello") |_| returns() else unreachable;
        \\    _ = x;
        \\}
    , &[_][]const u8{
        "tmp.zig:5:30: error: expression value is ignored",
        "tmp.zig:9:30: error: expression value is ignored",
    });

    ctx.objErrStage1("aligned variable of zero-bit type",
        \\export fn f() void {
        \\    var s: struct {} align(4) = undefined;
        \\    _ = s;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:5: error: variable 's' of zero-bit type 'struct:2:12' has no in-memory representation, it cannot be aligned",
    });

    ctx.objErrStage1("function returning opaque type",
        \\const FooType = opaque {};
        \\export fn bar() !FooType {
        \\    return error.InvalidValue;
        \\}
        \\export fn bav() !@TypeOf(null) {
        \\    return error.InvalidValue;
        \\}
        \\export fn baz() !@TypeOf(undefined) {
        \\    return error.InvalidValue;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:18: error: Opaque return type 'FooType' not allowed",
        "tmp.zig:1:1: note: type declared here",
        "tmp.zig:5:18: error: Null return type '(null)' not allowed",
        "tmp.zig:8:18: error: Undefined return type '(undefined)' not allowed",
    });

    ctx.objErrStage1("generic function returning opaque type",
        \\const FooType = opaque {};
        \\fn generic(comptime T: type) !T {
        \\    return undefined;
        \\}
        \\export fn bar() void {
        \\    _ = generic(FooType);
        \\}
        \\export fn bav() void {
        \\    _ = generic(@TypeOf(null));
        \\}
        \\export fn baz() void {
        \\    _ = generic(@TypeOf(undefined));
        \\}
    , &[_][]const u8{
        "tmp.zig:6:16: error: call to generic function with Opaque return type 'FooType' not allowed",
        "tmp.zig:2:1: note: function declared here",
        "tmp.zig:1:1: note: type declared here",
        "tmp.zig:9:16: error: call to generic function with Null return type '(null)' not allowed",
        "tmp.zig:2:1: note: function declared here",
        "tmp.zig:12:16: error: call to generic function with Undefined return type '(undefined)' not allowed",
        "tmp.zig:2:1: note: function declared here",
    });

    ctx.objErrStage1("function parameter is opaque",
        \\const FooType = opaque {};
        \\export fn entry1() void {
        \\    const someFuncPtr: fn (FooType) void = undefined;
        \\    _ = someFuncPtr;
        \\}
        \\
        \\export fn entry2() void {
        \\    const someFuncPtr: fn (@TypeOf(null)) void = undefined;
        \\    _ = someFuncPtr;
        \\}
        \\
        \\fn foo(p: FooType) void {_ = p;}
        \\export fn entry3() void {
        \\    _ = foo;
        \\}
        \\
        \\fn bar(p: @TypeOf(null)) void {_ = p;}
        \\export fn entry4() void {
        \\    _ = bar;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:28: error: parameter of opaque type 'FooType' not allowed",
        "tmp.zig:8:28: error: parameter of type '(null)' not allowed",
        "tmp.zig:12:11: error: parameter of opaque type 'FooType' not allowed",
        "tmp.zig:17:11: error: parameter of type '(null)' not allowed",
    });

    ctx.objErrStage1( // fixed bug #2032
        "compile diagnostic string for top level decl type",
        \\export fn entry() void {
        \\    var foo: u32 = @This(){};
        \\    _ = foo;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:27: error: type 'u32' does not support array initialization",
    });

    ctx.objErrStage1("issue #2687: coerce from undefined array pointer to slice",
        \\export fn foo1() void {
        \\    const a: *[1]u8 = undefined;
        \\    var b: []u8 = a;
        \\    _ = b;
        \\}
        \\export fn foo2() void {
        \\    comptime {
        \\        var a: *[1]u8 = undefined;
        \\        var b: []u8 = a;
        \\        _ = b;
        \\    }
        \\}
        \\export fn foo3() void {
        \\    comptime {
        \\        const a: *[1]u8 = undefined;
        \\        var b: []u8 = a;
        \\        _ = b;
        \\    }
        \\}
    , &[_][]const u8{
        "tmp.zig:3:19: error: use of undefined value here causes undefined behavior",
        "tmp.zig:9:23: error: use of undefined value here causes undefined behavior",
        "tmp.zig:16:23: error: use of undefined value here causes undefined behavior",
    });

    ctx.objErrStage1("issue #3818: bitcast from parray/slice to u16",
        \\export fn foo1() void {
        \\    var bytes = [_]u8{1, 2};
        \\    const word: u16 = @bitCast(u16, bytes[0..]);
        \\    _ = word;
        \\}
        \\export fn foo2() void {
        \\    var bytes: []const u8 = &[_]u8{1, 2};
        \\    const word: u16 = @bitCast(u16, bytes);
        \\    _ = word;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:42: error: unable to @bitCast from pointer type '*[2]u8'",
        "tmp.zig:8:32: error: destination type 'u16' has size 2 but source type '[]const u8' has size 16",
        "tmp.zig:8:37: note: referenced here",
    });

    // issue #7810
    ctx.objErrStage1("comptime slice-len increment beyond bounds",
        \\export fn foo_slice_len_increment_beyond_bounds() void {
        \\    comptime {
        \\        var buf_storage: [8]u8 = undefined;
        \\        var buf: []const u8 = buf_storage[0..];
        \\        buf.len += 1;
        \\        buf[8] = 42;
        \\    }
        \\}
    , &[_][]const u8{
        ":6:12: error: out of bounds slice",
    });

    ctx.objErrStage1("comptime slice-sentinel is out of bounds (unterminated)",
        \\export fn foo_array() void {
        \\    comptime {
        \\        var target = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        const slice = target[0..14 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_ptr_array() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target = &buf;
        \\        const slice = target[0..14 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = &buf;
        \\        const slice = target[0..14 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = @ptrCast([*]u8, &buf);
        \\        const slice = target[0..14 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = &buf;
        \\        const slice = target[0..14 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = @ptrCast([*c]u8, &buf);
        \\        const slice = target[0..14 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_slice() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: []u8 = &buf;
        \\        const slice = target[0..14 :0];
        \\        _ = slice;
        \\    }
        \\}
    , &[_][]const u8{
        ":4:29: error: slice-sentinel is out of bounds",
        ":12:29: error: slice-sentinel is out of bounds",
        ":20:29: error: slice-sentinel is out of bounds",
        ":28:29: error: slice-sentinel is out of bounds",
        ":36:29: error: slice-sentinel is out of bounds",
        ":44:29: error: slice-sentinel is out of bounds",
        ":52:29: error: slice-sentinel is out of bounds",
    });

    ctx.objErrStage1("comptime slice-sentinel is out of bounds (terminated)",
        \\export fn foo_array() void {
        \\    comptime {
        \\        var target = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        const slice = target[0..15 :1];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_ptr_array() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target = &buf;
        \\        const slice = target[0..15 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = &buf;
        \\        const slice = target[0..15 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = @ptrCast([*]u8, &buf);
        \\        const slice = target[0..15 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = &buf;
        \\        const slice = target[0..15 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = @ptrCast([*c]u8, &buf);
        \\        const slice = target[0..15 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_slice() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: []u8 = &buf;
        \\        const slice = target[0..15 :0];
        \\        _ = slice;
        \\    }
        \\}
    , &[_][]const u8{
        ":4:29: error: out of bounds slice",
        ":12:29: error: out of bounds slice",
        ":20:29: error: out of bounds slice",
        ":28:29: error: out of bounds slice",
        ":36:29: error: out of bounds slice",
        ":44:29: error: out of bounds slice",
        ":52:29: error: out of bounds slice",
    });

    ctx.objErrStage1("comptime slice-sentinel does not match memory at target index (unterminated)",
        \\export fn foo_array() void {
        \\    comptime {
        \\        var target = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_ptr_array() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = @ptrCast([*]u8, &buf);
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = @ptrCast([*c]u8, &buf);
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_slice() void {
        \\    comptime {
        \\        var buf = [_]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: []u8 = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
    , &[_][]const u8{
        ":4:29: error: slice-sentinel does not match memory at target index",
        ":12:29: error: slice-sentinel does not match memory at target index",
        ":20:29: error: slice-sentinel does not match memory at target index",
        ":28:29: error: slice-sentinel does not match memory at target index",
        ":36:29: error: slice-sentinel does not match memory at target index",
        ":44:29: error: slice-sentinel does not match memory at target index",
        ":52:29: error: slice-sentinel does not match memory at target index",
    });

    ctx.objErrStage1("comptime slice-sentinel does not match memory at target index (terminated)",
        \\export fn foo_array() void {
        \\    comptime {
        \\        var target = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_ptr_array() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = @ptrCast([*]u8, &buf);
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = @ptrCast([*c]u8, &buf);
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_slice() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: []u8 = &buf;
        \\        const slice = target[0..3 :0];
        \\        _ = slice;
        \\    }
        \\}
    , &[_][]const u8{
        ":4:29: error: slice-sentinel does not match memory at target index",
        ":12:29: error: slice-sentinel does not match memory at target index",
        ":20:29: error: slice-sentinel does not match memory at target index",
        ":28:29: error: slice-sentinel does not match memory at target index",
        ":36:29: error: slice-sentinel does not match memory at target index",
        ":44:29: error: slice-sentinel does not match memory at target index",
        ":52:29: error: slice-sentinel does not match memory at target index",
    });

    ctx.objErrStage1("comptime slice-sentinel does not match target-sentinel",
        \\export fn foo_array() void {
        \\    comptime {
        \\        var target = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        const slice = target[0..14 :255];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_ptr_array() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target = &buf;
        \\        const slice = target[0..14 :255];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = &buf;
        \\        const slice = target[0..14 :255];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_vector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*]u8 = @ptrCast([*]u8, &buf);
        \\        const slice = target[0..14 :255];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialBaseArray() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = &buf;
        \\        const slice = target[0..14 :255];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_cvector_ConstPtrSpecialRef() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: [*c]u8 = @ptrCast([*c]u8, &buf);
        \\        const slice = target[0..14 :255];
        \\        _ = slice;
        \\    }
        \\}
        \\export fn foo_slice() void {
        \\    comptime {
        \\        var buf = [_:0]u8{ 'a', 'b', 'c', 'd' } ++ [_]u8{undefined} ** 10;
        \\        var target: []u8 = &buf;
        \\        const slice = target[0..14 :255];
        \\        _ = slice;
        \\    }
        \\}
    , &[_][]const u8{
        ":4:29: error: slice-sentinel does not match target-sentinel",
        ":12:29: error: slice-sentinel does not match target-sentinel",
        ":20:29: error: slice-sentinel does not match target-sentinel",
        ":28:29: error: slice-sentinel does not match target-sentinel",
        ":36:29: error: slice-sentinel does not match target-sentinel",
        ":44:29: error: slice-sentinel does not match target-sentinel",
        ":52:29: error: slice-sentinel does not match target-sentinel",
    });

    ctx.objErrStage1("issue #4207: coerce from non-terminated-slice to terminated-pointer",
        \\export fn foo() [*:0]const u8 {
        \\    var buffer: [64]u8 = undefined;
        \\    return buffer[0..];
        \\}
    , &[_][]const u8{
        ":3:18: error: expected type '[*:0]const u8', found '*[64]u8'",
        ":3:18: note: destination pointer requires a terminating '0' sentinel",
    });

    ctx.objErrStage1("issue #5221: invalid struct init type referenced by @typeInfo and passed into function",
        \\fn ignore(comptime param: anytype) void {_ = param;}
        \\
        \\export fn foo() void {
        \\    const MyStruct = struct {
        \\        wrong_type: []u8 = "foo",
        \\    };
        \\
        \\    comptime ignore(@typeInfo(MyStruct).Struct.fields[0]);
        \\}
    , &[_][]const u8{
        ":5:28: error: expected type '[]u8', found '*const [3:0]u8'",
    });

    ctx.objErrStage1("integer underflow error",
        \\export fn entry() void {
        \\    _ = @intToPtr(*c_void, ~@as(usize, @import("std").math.maxInt(usize)) - 1);
        \\}
    , &[_][]const u8{
        ":2:75: error: operation caused overflow",
    });

    {
        const case = ctx.obj("align(N) expr function pointers is a compile error", .{
            .cpu_arch = .wasm32,
            .os_tag = .freestanding,
            .abi = .none,
        });
        case.backend = .stage1;

        case.addError(
            \\export fn foo() align(1) void {
            \\    return;
            \\}
        , &[_][]const u8{
            "tmp.zig:1:23: error: align(N) expr is not allowed on function prototypes in wasm32/wasm64",
        });
    }

    ctx.objErrStage1("compare optional to non-optional with invalid types",
        \\export fn inconsistentChildType() void {
        \\    var x: ?i32 = undefined;
        \\    const y: comptime_int = 10;
        \\    _ = (x == y);
        \\}
        \\
        \\export fn optionalToOptional() void {
        \\    var x: ?i32 = undefined;
        \\    var y: ?i32 = undefined;
        \\    _ = (x == y);
        \\}
        \\
        \\export fn optionalVector() void {
        \\    var x: ?@Vector(10, i32) = undefined;
        \\    var y: @Vector(10, i32) = undefined;
        \\    _ = (x == y);
        \\}
        \\
        \\export fn invalidChildType() void {
        \\    var x: ?[3]i32 = undefined;
        \\    var y: [3]i32 = undefined;
        \\    _ = (x == y);
        \\}
    , &[_][]const u8{
        ":4:12: error: cannot compare types '?i32' and 'comptime_int'",
        ":4:12: note: optional child type 'i32' must be the same as non-optional type 'comptime_int'",
        ":10:12: error: cannot compare types '?i32' and '?i32'",
        ":10:12: note: optional to optional comparison is only supported for optional pointer types",
        ":16:12: error: TODO add comparison of optional vector",
        ":22:12: error: cannot compare types '?[3]i32' and '[3]i32'",
        ":22:12: note: operator not supported for type '[3]i32'",
    });

    ctx.objErrStage1("slice cannot have its bytes reinterpreted",
        \\export fn foo() void {
        \\    const bytes = [1]u8{ 0xfa } ** 16;
        \\    var value = @ptrCast(*const []const u8, &bytes).*;
        \\    _ = value;
        \\}
    , &[_][]const u8{
        ":3:52: error: slice '[]const u8' cannot have its bytes reinterpreted",
    });

    ctx.objErrStage1("wasmMemorySize is a compile error in non-Wasm targets",
        \\export fn foo() void {
        \\    _ = @wasmMemorySize(0);
        \\    return;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: @wasmMemorySize is a wasm32 feature only",
    });

    ctx.objErrStage1("wasmMemoryGrow is a compile error in non-Wasm targets",
        \\export fn foo() void {
        \\    _ = @wasmMemoryGrow(0, 1);
        \\    return;
        \\}
    , &[_][]const u8{
        "tmp.zig:2:9: error: @wasmMemoryGrow is a wasm32 feature only",
    });
    ctx.objErrStage1("Issue #5586: Make unary minus for unsigned types a compile error",
        \\export fn f1(x: u32) u32 {
        \\    const y = -%x;
        \\    return -y;
        \\}
        \\const V = @import("std").meta.Vector;
        \\export fn f2(x: V(4, u32)) V(4, u32) {
        \\    const y = -%x;
        \\    return -y;
        \\}
    , &[_][]const u8{
        "tmp.zig:3:12: error: negation of type 'u32'",
        "tmp.zig:8:12: error: negation of type 'u32'",
    });

    ctx.objErrStage1("Issue #5618: coercion of ?*c_void to *c_void must fail.",
        \\export fn foo() void {
        \\    var u: ?*c_void = null;
        \\    var v: *c_void = undefined;
        \\    v = u;
        \\}
    , &[_][]const u8{
        "tmp.zig:4:9: error: expected type '*c_void', found '?*c_void'",
    });

    ctx.objErrStage1("Issue #6823: don't allow .* to be followed by **",
        \\fn foo() void {
        \\    var sequence = "repeat".*** 10;
        \\    _ = sequence;
        \\}
    , &[_][]const u8{
        // Ideally this would be column 30 but it's not very important.
        "tmp.zig:2:28: error: '.*' cannot be followed by '*'. Are you missing a space?",
    });

    ctx.objErrStage1("Issue #9165: windows tcp server compilation error",
        \\const std = @import("std");
        \\const builtin = @import("builtin");
        \\pub const io_mode = .evented;
        \\pub fn main() !void {
        \\    if (builtin.os.tag == .windows) {
        \\        _ = try (std.net.StreamServer.init(.{})).accept();
        \\    } else {
        \\        @compileError("Unsupported OS");
        \\    }
        \\}
    , &[_][]const u8{
        "error: Unsupported OS",
    });
}
