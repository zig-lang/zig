const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.reloc);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const aarch64 = @import("reloc/aarch64.zig");
const x86_64 = @import("reloc/x86_64.zig");

const Allocator = mem.Allocator;

pub const Relocation = struct {
    @"type": Type,
    code: []u8,
    offset: u32,
    target: Target,

    pub fn cast(base: *Relocation, comptime T: type) ?*T {
        if (base.@"type" != T.base_type)
            return null;

        return @fieldParentPtr(T, "base", base);
    }

    pub const ResolveArgs = struct {
        source_addr: u64,
        target_addr: u64,
        subtractor: ?u64 = null,
        source_source_sect_addr: ?u64 = null,
        source_target_sect_addr: ?u64 = null,
    };

    pub fn resolve(base: *Relocation, args: ResolveArgs) !void {
        log.debug("{s}", .{base.@"type"});
        log.debug("    | offset 0x{x}", .{base.offset});
        log.debug("    | source address 0x{x}", .{args.source_addr});
        log.debug("    | target address 0x{x}", .{args.target_addr});
        if (args.subtractor) |sub|
            log.debug("    | subtractor address 0x{x}", .{sub});
        if (args.source_source_sect_addr) |addr|
            log.debug("    | source source section address 0x{x}", .{addr});
        if (args.source_target_sect_addr) |addr|
            log.debug("    | source target section address 0x{x}", .{addr});

        return switch (base.@"type") {
            .unsigned => @fieldParentPtr(Unsigned, "base", base).resolve(args),
            .branch_aarch64 => @fieldParentPtr(aarch64.Branch, "base", base).resolve(args),
            .page => @fieldParentPtr(aarch64.Page, "base", base).resolve(args),
            .page_off => @fieldParentPtr(aarch64.PageOff, "base", base).resolve(args),
            .got_page => @fieldParentPtr(aarch64.GotPage, "base", base).resolve(args),
            .got_page_off => @fieldParentPtr(aarch64.GotPageOff, "base", base).resolve(args),
            .pointer_to_got => @fieldParentPtr(aarch64.PointerToGot, "base", base).resolve(args),
            .tlvp_page => @fieldParentPtr(aarch64.TlvpPage, "base", base).resolve(args),
            .tlvp_page_off => @fieldParentPtr(aarch64.TlvpPageOff, "base", base).resolve(args),
            .branch_x86_64 => @fieldParentPtr(x86_64.Branch, "base", base).resolve(args),
            .signed => @fieldParentPtr(x86_64.Signed, "base", base).resolve(args),
            .got_load => @fieldParentPtr(x86_64.GotLoad, "base", base).resolve(args),
            .got => @fieldParentPtr(x86_64.Got, "base", base).resolve(args),
            .tlv => @fieldParentPtr(x86_64.Tlv, "base", base).resolve(args),
        };
    }

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

    pub const Target = union(enum) {
        symbol: u32,
        section: u16,

        pub fn fromReloc(reloc: macho.relocation_info) Target {
            return if (reloc.r_extern == 1) .{
                .symbol = reloc.r_symbolnum,
            } else .{
                .section = @intCast(u16, reloc.r_symbolnum - 1),
            };
        }
    };
};

pub const Unsigned = struct {
    base: Relocation,
    subtractor: ?Relocation.Target = null,
    /// Addend embedded directly in the relocation slot
    addend: i64,
    /// Extracted from r_length:
    /// => 3 implies true
    /// => 2 implies false
    /// => * is unreachable
    is_64bit: bool,

    pub const base_type: Relocation.Type = .unsigned;

    pub fn resolve(unsigned: Unsigned, args: Relocation.ResolveArgs) !void {
        const addend = if (unsigned.base.target == .section)
            unsigned.addend - @intCast(i64, args.source_target_sect_addr.?)
        else
            unsigned.addend;

        const result = if (args.subtractor) |subtractor|
            @intCast(i64, args.target_addr) - @intCast(i64, subtractor) + addend
        else
            @intCast(i64, args.target_addr) + addend;

        log.debug("    | calculated addend 0x{x}", .{addend});
        log.debug("    | calculated unsigned value 0x{x}", .{result});

        if (unsigned.is_64bit) {
            mem.writeIntLittle(
                u64,
                unsigned.base.code[0..8],
                @bitCast(u64, result),
            );
        } else {
            mem.writeIntLittle(
                u32,
                unsigned.base.code[0..4],
                @truncate(u32, @bitCast(u64, result)),
            );
        }
    }
};

pub fn parse(
    allocator: *Allocator,
    arch: std.Target.Cpu.Arch,
    code: []u8,
    relocs: []const macho.relocation_info,
) ![]*Relocation {
    var it = RelocIterator{
        .buffer = relocs,
    };

    switch (arch) {
        .aarch64 => {
            var parser = aarch64.Parser{
                .allocator = allocator,
                .it = &it,
                .code = code,
                .parsed = std.ArrayList(*Relocation).init(allocator),
            };
            defer parser.deinit();
            try parser.parse();

            return parser.parsed.toOwnedSlice();
        },
        .x86_64 => {
            var parser = x86_64.Parser{
                .allocator = allocator,
                .it = &it,
                .code = code,
                .parsed = std.ArrayList(*Relocation).init(allocator),
            };
            defer parser.deinit();
            try parser.parse();

            return parser.parsed.toOwnedSlice();
        },
        else => unreachable,
    }
}

pub const RelocIterator = struct {
    buffer: []const macho.relocation_info,
    index: i32 = -1,

    pub fn next(self: *RelocIterator) ?macho.relocation_info {
        self.index += 1;
        if (self.index < self.buffer.len) {
            const reloc = self.buffer[@intCast(u32, self.index)];
            log.debug("relocation", .{});
            log.debug("    | type = {}", .{reloc.r_type});
            log.debug("    | offset = {}", .{reloc.r_address});
            log.debug("    | PC = {}", .{reloc.r_pcrel == 1});
            log.debug("    | length = {}", .{reloc.r_length});
            log.debug("    | symbolnum = {}", .{reloc.r_symbolnum});
            log.debug("    | extern = {}", .{reloc.r_extern == 1});
            return reloc;
        }
        return null;
    }

    pub fn peek(self: RelocIterator) macho.relocation_info {
        assert(self.index + 1 < self.buffer.len);
        return self.buffer[@intCast(u32, self.index + 1)];
    }
};
