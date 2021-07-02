const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.reloc);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const reloc = @import("../reloc.zig");

const Allocator = mem.Allocator;
const Relocation = reloc.Relocation;

pub const Branch = struct {
    base: Relocation,

    pub const base_type: Relocation.Type = .branch_x86_64;

    pub fn resolve(branch: Branch, args: Relocation.ResolveArgs) !void {
        const displacement = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4);
        log.debug("    | displacement 0x{x}", .{displacement});
        mem.writeIntLittle(u32, branch.base.code[0..4], @bitCast(u32, displacement));
    }
};

pub const Signed = struct {
    base: Relocation,
    addend: i32,
    correction: i4,

    pub const base_type: Relocation.Type = .signed;

    pub fn resolve(signed: Signed, args: Relocation.ResolveArgs) !void {
        const target_addr = target_addr: {
            if (signed.base.target == .section) {
                const source_target = @intCast(i64, args.source_source_sect_addr.?) + @intCast(i64, signed.base.offset) + signed.addend + 4;
                const source_disp = source_target - @intCast(i64, args.source_target_sect_addr.?);
                break :target_addr @intCast(i64, args.target_addr) + source_disp;
            }
            break :target_addr @intCast(i64, args.target_addr) + signed.addend;
        };
        const displacement = try math.cast(
            i32,
            target_addr - @intCast(i64, args.source_addr) - signed.correction - 4,
        );

        log.debug("    | addend 0x{x}", .{signed.addend});
        log.debug("    | correction 0x{x}", .{signed.correction});
        log.debug("    | displacement 0x{x}", .{displacement});

        mem.writeIntLittle(u32, signed.base.code[0..4], @bitCast(u32, displacement));
    }
};

pub const GotLoad = struct {
    base: Relocation,

    pub const base_type: Relocation.Type = .got_load;

    pub fn resolve(got_load: GotLoad, args: Relocation.ResolveArgs) !void {
        const displacement = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4);
        log.debug("    | displacement 0x{x}", .{displacement});
        mem.writeIntLittle(u32, got_load.base.code[0..4], @bitCast(u32, displacement));
    }
};

pub const Got = struct {
    base: Relocation,
    addend: i32,

    pub const base_type: Relocation.Type = .got;

    pub fn resolve(got: Got, args: Relocation.ResolveArgs) !void {
        const displacement = try math.cast(
            i32,
            @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4 + got.addend,
        );
        log.debug("    | displacement 0x{x}", .{displacement});
        mem.writeIntLittle(u32, got.base.code[0..4], @bitCast(u32, displacement));
    }
};

pub const Tlv = struct {
    base: Relocation,
    op: *u8,

    pub const base_type: Relocation.Type = .tlv;

    pub fn resolve(tlv: Tlv, args: Relocation.ResolveArgs) !void {
        // We need to rewrite the opcode from movq to leaq.
        tlv.op.* = 0x8d;
        log.debug("    | rewriting op to leaq", .{});

        const displacement = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4);
        log.debug("    | displacement 0x{x}", .{displacement});

        mem.writeIntLittle(u32, tlv.base.code[0..4], @bitCast(u32, displacement));
    }
};

pub const Parser = struct {
    allocator: *Allocator,
    it: *reloc.RelocIterator,
    code: []u8,
    parsed: std.ArrayList(*Relocation),
    subtractor: ?Relocation.Target = null,

    pub fn deinit(parser: *Parser) void {
        parser.parsed.deinit();
    }

    pub fn parse(parser: *Parser) !void {
        while (parser.it.next()) |rel| {
            switch (@intToEnum(macho.reloc_type_x86_64, rel.r_type)) {
                .X86_64_RELOC_BRANCH => {
                    try parser.parseBranch(rel);
                },
                .X86_64_RELOC_SUBTRACTOR => {
                    try parser.parseSubtractor(rel);
                },
                .X86_64_RELOC_UNSIGNED => {
                    try parser.parseUnsigned(rel);
                },
                .X86_64_RELOC_SIGNED,
                .X86_64_RELOC_SIGNED_1,
                .X86_64_RELOC_SIGNED_2,
                .X86_64_RELOC_SIGNED_4,
                => {
                    try parser.parseSigned(rel);
                },
                .X86_64_RELOC_GOT_LOAD => {
                    try parser.parseGotLoad(rel);
                },
                .X86_64_RELOC_GOT => {
                    try parser.parseGot(rel);
                },
                .X86_64_RELOC_TLV => {
                    try parser.parseTlv(rel);
                },
            }
        }
    }

    fn parseBranch(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_BRANCH);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];

        var branch = try parser.allocator.create(Branch);
        errdefer parser.allocator.destroy(branch);

        const target = Relocation.Target.fromReloc(rel);

        branch.* = .{
            .base = .{
                .@"type" = .branch_x86_64,
                .code = inst,
                .offset = offset,
                .target = target,
            },
        };

        log.debug("    | emitting {}", .{branch});
        try parser.parsed.append(&branch.base);
    }

    fn parseSigned(parser: *Parser, rel: macho.relocation_info) !void {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        const target = Relocation.Target.fromReloc(rel);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        const correction: i4 = switch (rel_type) {
            .X86_64_RELOC_SIGNED => 0,
            .X86_64_RELOC_SIGNED_1 => 1,
            .X86_64_RELOC_SIGNED_2 => 2,
            .X86_64_RELOC_SIGNED_4 => 4,
            else => unreachable,
        };
        const addend = mem.readIntLittle(i32, inst) + correction;

        var signed = try parser.allocator.create(Signed);
        errdefer parser.allocator.destroy(signed);

        signed.* = .{
            .base = .{
                .@"type" = .signed,
                .code = inst,
                .offset = offset,
                .target = target,
            },
            .addend = addend,
            .correction = correction,
        };

        log.debug("    | emitting {}", .{signed});
        try parser.parsed.append(&signed.base);
    }

    fn parseGotLoad(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_GOT_LOAD);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        const target = Relocation.Target.fromReloc(rel);

        var got_load = try parser.allocator.create(GotLoad);
        errdefer parser.allocator.destroy(got_load);

        got_load.* = .{
            .base = .{
                .@"type" = .got_load,
                .code = inst,
                .offset = offset,
                .target = target,
            },
        };

        log.debug("    | emitting {}", .{got_load});
        try parser.parsed.append(&got_load.base);
    }

    fn parseGot(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_GOT);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        const target = Relocation.Target.fromReloc(rel);
        const addend = mem.readIntLittle(i32, inst);

        var got = try parser.allocator.create(Got);
        errdefer parser.allocator.destroy(got);

        got.* = .{
            .base = .{
                .@"type" = .got,
                .code = inst,
                .offset = offset,
                .target = target,
            },
            .addend = addend,
        };

        log.debug("    | emitting {}", .{got});
        try parser.parsed.append(&got.base);
    }

    fn parseTlv(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_TLV);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        const target = Relocation.Target.fromReloc(rel);

        var tlv = try parser.allocator.create(Tlv);
        errdefer parser.allocator.destroy(tlv);

        tlv.* = .{
            .base = .{
                .@"type" = .tlv,
                .code = inst,
                .offset = offset,
                .target = target,
            },
            .op = &parser.code[offset - 2],
        };

        log.debug("    | emitting {}", .{tlv});
        try parser.parsed.append(&tlv.base);
    }

    fn parseSubtractor(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_SUBTRACTOR);
        assert(rel.r_pcrel == 0);
        assert(parser.subtractor == null);

        parser.subtractor = Relocation.Target.fromReloc(rel);

        // Verify SUBTRACTOR is followed by UNSIGNED.
        const next = @intToEnum(macho.reloc_type_x86_64, parser.it.peek().r_type);
        if (next != .X86_64_RELOC_UNSIGNED) {
            log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
            return error.UnexpectedRelocationType;
        }
    }

    fn parseUnsigned(parser: *Parser, rel: macho.relocation_info) !void {
        defer {
            // Reset parser's subtractor state
            parser.subtractor = null;
        }

        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        assert(rel_type == .X86_64_RELOC_UNSIGNED);
        assert(rel.r_pcrel == 0);

        var unsigned = try parser.allocator.create(reloc.Unsigned);
        errdefer parser.allocator.destroy(unsigned);

        const target = Relocation.Target.fromReloc(rel);
        const is_64bit: bool = switch (rel.r_length) {
            3 => true,
            2 => false,
            else => unreachable,
        };
        const offset = @intCast(u32, rel.r_address);
        const addend: i64 = if (is_64bit)
            mem.readIntLittle(i64, parser.code[offset..][0..8])
        else
            mem.readIntLittle(i32, parser.code[offset..][0..4]);

        unsigned.* = .{
            .base = .{
                .@"type" = .unsigned,
                .code = if (is_64bit) parser.code[offset..][0..8] else parser.code[offset..][0..4],
                .offset = offset,
                .target = target,
            },
            .subtractor = parser.subtractor,
            .is_64bit = is_64bit,
            .addend = addend,
        };

        log.debug("    | emitting {}", .{unsigned});
        try parser.parsed.append(&unsigned.base);
    }
};
