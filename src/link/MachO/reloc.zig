const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.reloc);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

pub const aarch64 = @import("reloc/aarch64.zig");
pub const x86_64 = @import("reloc/x86_64.zig");

const Allocator = mem.Allocator;
const Symbol = @import("Symbol.zig");
const TextBlock = @import("Zld.zig").TextBlock;

pub const Relocation = struct {
    @"type": Type,
    offset: u32,
    block: *TextBlock,
    target: *Symbol,

    pub fn cast(base: *Relocation, comptime T: type) ?*T {
        if (base.@"type" != T.base_type)
            return null;

        return @fieldParentPtr(T, "base", base);
    }

    // pub fn resolve(base: *Relocation) !void {
    //     return switch (base.@"type") {
    //         .unsigned => @fieldParentPtr(Unsigned, "base", base).resolve(),
    //         .branch_aarch64 => @fieldParentPtr(aarch64.Branch, "base", base).resolve(),
    //         .page => @fieldParentPtr(aarch64.Page, "base", base).resolve(),
    //         .page_off => @fieldParentPtr(aarch64.PageOff, "base", base).resolve(),
    //         .got_page => @fieldParentPtr(aarch64.GotPage, "base", base).resolve(),
    //         .got_page_off => @fieldParentPtr(aarch64.GotPageOff, "base", base).resolve(),
    //         .pointer_to_got => @fieldParentPtr(aarch64.PointerToGot, "base", base).resolve(),
    //         .tlvp_page => @fieldParentPtr(aarch64.TlvpPage, "base", base).resolve(),
    //         .tlvp_page_off => @fieldParentPtr(aarch64.TlvpPageOff, "base", base).resolve(),
    //         .branch_x86_64 => @fieldParentPtr(x86_64.Branch, "base", base).resolve(),
    //         .signed => @fieldParentPtr(x86_64.Signed, "base", base).resolve(),
    //         .got_load => @fieldParentPtr(x86_64.GotLoad, "base", base).resolve(),
    //         .got => @fieldParentPtr(x86_64.Got, "base", base).resolve(),
    //         .tlv => @fieldParentPtr(x86_64.Tlv, "base", base).resolve(),
    //     };
    // }

    pub const Type = enum {
        branch_aarch64,
        unsigned,
        page,
        page_off,
        got_page,
        got_page_off,
        tlvp_page,
        pointer_to_got,
        tlvp_page_off,
        branch_x86_64,
        signed,
        got_load,
        got,
        tlv,
    };

    pub fn format(base: *const Relocation, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try std.fmt.format(writer, "Relocation {{ ", .{});
        try std.fmt.format(writer, ".type = {s}, ", .{base.@"type"});
        try std.fmt.format(writer, ".offset = {}, ", .{base.offset});
        try std.fmt.format(writer, ".block = {}", .{base.block.local_sym_index});
        try std.fmt.format(writer, ".target = {}, ", .{base.target});

        try switch (base.@"type") {
            .unsigned => @fieldParentPtr(Unsigned, "base", base).format(fmt, options, writer),
            .branch_aarch64 => @fieldParentPtr(aarch64.Branch, "base", base).format(fmt, options, writer),
            .page => @fieldParentPtr(aarch64.Page, "base", base).format(fmt, options, writer),
            .page_off => @fieldParentPtr(aarch64.PageOff, "base", base).format(fmt, options, writer),
            .got_page => @fieldParentPtr(aarch64.GotPage, "base", base).format(fmt, options, writer),
            .got_page_off => @fieldParentPtr(aarch64.GotPageOff, "base", base).format(fmt, options, writer),
            .pointer_to_got => @fieldParentPtr(aarch64.PointerToGot, "base", base).format(fmt, options, writer),
            .tlvp_page => @fieldParentPtr(aarch64.TlvpPage, "base", base).format(fmt, options, writer),
            .tlvp_page_off => @fieldParentPtr(aarch64.TlvpPageOff, "base", base).format(fmt, options, writer),
            .branch_x86_64 => @fieldParentPtr(x86_64.Branch, "base", base).format(fmt, options, writer),
            .signed => @fieldParentPtr(x86_64.Signed, "base", base).format(fmt, options, writer),
            .got_load => @fieldParentPtr(x86_64.GotLoad, "base", base).format(fmt, options, writer),
            .got => @fieldParentPtr(x86_64.Got, "base", base).format(fmt, options, writer),
            .tlv => @fieldParentPtr(x86_64.Tlv, "base", base).format(fmt, options, writer),
        };

        try std.fmt.format(writer, "}}", .{});
    }
};

pub const Unsigned = struct {
    base: Relocation,
    subtractor: ?*Symbol = null,
    /// Addend embedded directly in the relocation slot
    addend: i64,
    /// Extracted from r_length:
    /// => 3 implies true
    /// => 2 implies false
    /// => * is unreachable
    is_64bit: bool,

    pub const base_type: Relocation.Type = .unsigned;

    // pub fn resolve(unsigned: Unsigned) !void {
    //     const addend = if (unsigned.base.target == .section)
    //         unsigned.addend - @intCast(i64, args.source_target_sect_addr.?)
    //     else
    //         unsigned.addend;

    //     const result = if (args.subtractor) |subtractor|
    //         @intCast(i64, args.target_addr) - @intCast(i64, subtractor) + addend
    //     else
    //         @intCast(i64, args.target_addr) + addend;

    //     log.debug("    | calculated addend 0x{x}", .{addend});
    //     log.debug("    | calculated unsigned value 0x{x}", .{result});

    //     if (unsigned.is_64bit) {
    //         mem.writeIntLittle(
    //             u64,
    //             unsigned.base.code[0..8],
    //             @bitCast(u64, result),
    //         );
    //     } else {
    //         mem.writeIntLittle(
    //             u32,
    //             unsigned.base.code[0..4],
    //             @truncate(u32, @bitCast(u64, result)),
    //         );
    //     }
    // }

    pub fn format(self: Unsigned, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (self.subtractor) |sub| {
            try std.fmt.format(writer, ".subtractor = {}, ", .{sub});
        }
        try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
        const length: usize = if (self.is_64bit) 8 else 4;
        try std.fmt.format(writer, ".length = {}, ", .{length});
    }
};

pub const RelocIterator = struct {
    buffer: []const macho.relocation_info,
    index: i32 = -1,

    pub fn next(self: *RelocIterator) ?macho.relocation_info {
        self.index += 1;
        if (self.index < self.buffer.len) {
            return self.buffer[@intCast(u32, self.index)];
        }
        return null;
    }

    pub fn peek(self: RelocIterator) macho.relocation_info {
        assert(self.index + 1 < self.buffer.len);
        return self.buffer[@intCast(u32, self.index + 1)];
    }
};
