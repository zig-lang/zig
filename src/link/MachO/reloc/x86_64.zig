const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.reloc);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const reloc = @import("../reloc.zig");

const Allocator = mem.Allocator;
const Object = @import("../Object.zig");
const Relocation = reloc.Relocation;
const Symbol = @import("../Symbol.zig");
const TextBlock = Zld.TextBlock;
const Zld = @import("../Zld.zig");

pub const Branch = struct {
    base: Relocation,

    pub const base_type: Relocation.Type = .branch_x86_64;

    // pub fn resolve(branch: Branch, args: Relocation.ResolveArgs) !void {
    //     const displacement = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4);
    //     log.debug("    | displacement 0x{x}", .{displacement});
    //     mem.writeIntLittle(u32, branch.base.code[0..4], @bitCast(u32, displacement));
    // }

    pub fn format(self: Branch, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const Signed = struct {
    base: Relocation,
    addend: i32,
    correction: i4,

    pub const base_type: Relocation.Type = .signed;

    // pub fn resolve(signed: Signed, args: Relocation.ResolveArgs) !void {
    //     const target_addr = target_addr: {
    //         if (signed.base.target == .section) {
    //             const source_target = @intCast(i64, args.source_source_sect_addr.?) + @intCast(i64, signed.base.offset) + signed.addend + 4;
    //             const source_disp = source_target - @intCast(i64, args.source_target_sect_addr.?);
    //             break :target_addr @intCast(i64, args.target_addr) + source_disp;
    //         }
    //         break :target_addr @intCast(i64, args.target_addr) + signed.addend;
    //     };
    //     const displacement = try math.cast(
    //         i32,
    //         target_addr - @intCast(i64, args.source_addr) - signed.correction - 4,
    //     );

    //     log.debug("    | addend 0x{x}", .{signed.addend});
    //     log.debug("    | correction 0x{x}", .{signed.correction});
    //     log.debug("    | displacement 0x{x}", .{displacement});

    //     mem.writeIntLittle(u32, signed.base.code[0..4], @bitCast(u32, displacement));
    // }

    pub fn format(self: Signed, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
        try std.fmt.format(writer, ".correction = {}, ", .{self.correction});
    }
};

pub const GotLoad = struct {
    base: Relocation,

    pub const base_type: Relocation.Type = .got_load;

    // pub fn resolve(got_load: GotLoad, args: Relocation.ResolveArgs) !void {
    //     const displacement = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4);
    //     log.debug("    | displacement 0x{x}", .{displacement});
    //     mem.writeIntLittle(u32, got_load.base.code[0..4], @bitCast(u32, displacement));
    // }

    pub fn format(self: GotLoad, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const Got = struct {
    base: Relocation,
    addend: i32,

    pub const base_type: Relocation.Type = .got;

    // pub fn resolve(got: Got, args: Relocation.ResolveArgs) !void {
    //     const displacement = try math.cast(
    //         i32,
    //         @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4 + got.addend,
    //     );
    //     log.debug("    | displacement 0x{x}", .{displacement});
    //     mem.writeIntLittle(u32, got.base.code[0..4], @bitCast(u32, displacement));
    // }

    pub fn format(self: Got, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
    }
};

pub const Tlv = struct {
    base: Relocation,

    pub const base_type: Relocation.Type = .tlv;

    // pub fn resolve(tlv: Tlv, args: Relocation.ResolveArgs) !void {
    //     // We need to rewrite the opcode from movq to leaq.
    //     tlv.op.* = 0x8d;
    //     log.debug("    | rewriting op to leaq", .{});

    //     const displacement = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4);
    //     log.debug("    | displacement 0x{x}", .{displacement});

    //     mem.writeIntLittle(u32, tlv.base.code[0..4], @bitCast(u32, displacement));
    // }
    pub fn format(self: Tlv, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const Parser = struct {
    object: *Object,
    zld: *Zld,
    it: *reloc.RelocIterator,
    block: *TextBlock,
    base_addr: u64,
    subtractor: ?*Symbol = null,

    pub fn parse(self: *Parser) !void {
        while (self.it.next()) |rel| {
            const out_rel = switch (@intToEnum(macho.reloc_type_x86_64, rel.r_type)) {
                .X86_64_RELOC_BRANCH => try self.parseBranch(rel),
                .X86_64_RELOC_SUBTRACTOR => {
                    // Subtractor is not a relocation with effect on the TextBlock, so
                    // parse it and carry on.
                    try self.parseSubtractor(rel);
                    continue;
                },
                .X86_64_RELOC_UNSIGNED => try self.parseUnsigned(rel),
                .X86_64_RELOC_SIGNED,
                .X86_64_RELOC_SIGNED_1,
                .X86_64_RELOC_SIGNED_2,
                .X86_64_RELOC_SIGNED_4,
                => try self.parseSigned(rel),
                .X86_64_RELOC_GOT_LOAD => try self.parseGotLoad(rel),
                .X86_64_RELOC_GOT => try self.parseGot(rel),
                .X86_64_RELOC_TLV => try self.parseTlv(rel),
            };
            try self.block.relocs.append(out_rel);

            if (out_rel.target.payload == .regular) {
                try self.block.references.put(out_rel.target.payload.regular.local_sym_index, {});
            }

            switch (out_rel.@"type") {
                .got_load, .got => {
                    const sym = out_rel.target;

                    if (sym.got_index != null) continue;

                    const index = @intCast(u32, self.zld.got_entries.items.len);
                    sym.got_index = index;
                    try self.zld.got_entries.append(self.zld.allocator, sym);

                    log.debug("adding GOT entry for symbol {s} at index {}", .{ sym.name, index });
                },
                .branch_x86_64 => {
                    const sym = out_rel.target;

                    if (sym.stubs_index != null) continue;
                    if (sym.payload != .proxy) continue;

                    const index = @intCast(u32, self.zld.stubs.items.len);
                    sym.stubs_index = index;
                    try self.zld.stubs.append(self.zld.allocator, sym);

                    log.debug("adding stub entry for symbol {s} at index {}", .{ sym.name, index });
                },
                else => {},
            }
        }
    }

    fn parseBranch(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_BRANCH);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const target = try self.object.symbolFromReloc(rel);

        var branch = try self.object.allocator.create(Branch);
        errdefer self.object.allocator.destroy(branch);

        branch.* = .{
            .base = .{
                .@"type" = .branch_x86_64,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
        };

        return &branch.base;
    }

    fn parseSigned(self: *Parser, rel: macho.relocation_info) !*Relocation {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        const target = try self.object.symbolFromReloc(rel);
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const correction: i4 = switch (rel_type) {
            .X86_64_RELOC_SIGNED => 0,
            .X86_64_RELOC_SIGNED_1 => 1,
            .X86_64_RELOC_SIGNED_2 => 2,
            .X86_64_RELOC_SIGNED_4 => 4,
            else => unreachable,
        };
        const addend = mem.readIntLittle(i32, self.block.code[offset..][0..4]) + correction;

        var signed = try self.object.allocator.create(Signed);
        errdefer self.object.allocator.destroy(signed);

        signed.* = .{
            .base = .{
                .@"type" = .signed,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
            .addend = addend,
            .correction = correction,
        };

        return &signed.base;
    }

    fn parseGotLoad(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_GOT_LOAD);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const target = try self.object.symbolFromReloc(rel);

        var got_load = try self.object.allocator.create(GotLoad);
        errdefer self.object.allocator.destroy(got_load);

        got_load.* = .{
            .base = .{
                .@"type" = .got_load,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
        };

        return &got_load.base;
    }

    fn parseGot(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_GOT);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const target = try self.object.symbolFromReloc(rel);
        const addend = mem.readIntLittle(i32, self.block.code[offset..][0..4]);

        var got = try self.object.allocator.create(Got);
        errdefer self.object.allocator.destroy(got);

        got.* = .{
            .base = .{
                .@"type" = .got,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
            .addend = addend,
        };

        return &got.base;
    }

    fn parseTlv(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_TLV);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const target = try self.object.symbolFromReloc(rel);

        var tlv = try self.object.allocator.create(Tlv);
        errdefer self.object.allocator.destroy(tlv);

        tlv.* = .{
            .base = .{
                .@"type" = .tlv,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
        };

        return &tlv.base;
    }

    fn parseSubtractor(self: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_SUBTRACTOR);
        assert(rel.r_pcrel == 0);
        assert(self.subtractor == null);

        self.subtractor = try self.object.symbolFromReloc(rel);

        // Verify SUBTRACTOR is followed by UNSIGNED.
        const next = @intToEnum(macho.reloc_type_x86_64, self.it.peek().r_type);
        if (next != .X86_64_RELOC_UNSIGNED) {
            log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
            return error.UnexpectedRelocationType;
        }
    }

    fn parseUnsigned(self: *Parser, rel: macho.relocation_info) !*Relocation {
        defer {
            // Reset parser's subtractor state
            self.subtractor = null;
        }

        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_UNSIGNED);
        assert(rel.r_pcrel == 0);

        const target = try self.object.symbolFromReloc(rel);
        const is_64bit: bool = switch (rel.r_length) {
            3 => true,
            2 => false,
            else => unreachable,
        };
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const addend: i64 = if (is_64bit)
            mem.readIntLittle(i64, self.block.code[offset..][0..8])
        else
            mem.readIntLittle(i32, self.block.code[offset..][0..4]);

        var unsigned = try self.object.allocator.create(reloc.Unsigned);
        errdefer self.object.allocator.destroy(unsigned);

        unsigned.* = .{
            .base = .{
                .@"type" = .unsigned,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
            .subtractor = self.subtractor,
            .is_64bit = is_64bit,
            .addend = addend,
        };

        return &unsigned.base;
    }
};
