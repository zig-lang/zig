pub const std = @import("std");
const builtin = @import("builtin");

pub const enable = if (builtin.is_test) false else @import("build_options").enable_tracy;

extern fn ___tracy_emit_zone_begin_callstack(
    srcloc: *const ___tracy_source_location_data,
    depth: c_int,
    active: c_int,
) ___tracy_c_zone_context;

extern fn ___tracy_emit_zone_end(ctx: ___tracy_c_zone_context) void;

pub const ___tracy_source_location_data = extern struct {
    name: ?[*:0]const u8,
    function: [*:0]const u8,
    file: [*:0]const u8,
    line: u32,
    color: u32,
};

pub const ___tracy_c_zone_context = extern struct {
    id: u32,
    active: c_int,

    pub fn end(self: ___tracy_c_zone_context) void {
        ___tracy_emit_zone_end(self);
    }
};

pub const Ctx = if (enable) ___tracy_c_zone_context else struct {
    pub fn end(self: Ctx) void {
        _ = self;
    }
};

pub inline fn trace(comptime src: std.builtin.SourceLocation) Ctx {
    if (!enable) return .{};

    const loc: ___tracy_source_location_data = .{
        .name = null,
        .function = src.fn_name.ptr,
        .file = src.file.ptr,
        .line = src.line,
        .color = 0,
    };
    return ___tracy_emit_zone_begin_callstack(&loc, 1, 1);
}
