const std = @import("std");
const aarch64 = @import("../../../codegen/aarch64.zig");
const assert = std.debug.assert;
const log = std.log.scoped(.reloc);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const reloc = @import("../reloc.zig");

const Allocator = mem.Allocator;
const Relocation = reloc.Relocation;
const Symbol = @import("../Symbol.zig");

pub const Branch = struct {
    base: Relocation,
    /// Always .UnconditionalBranchImmediate
    inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .branch_aarch64;

    pub fn resolve(branch: Branch, args: Relocation.ResolveArgs) !void {
        const displacement = try math.cast(i28, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr));

        log.debug("    | displacement 0x{x}", .{displacement});

        var inst = branch.inst;
        inst.unconditional_branch_immediate.imm26 = @truncate(u26, @bitCast(u28, displacement >> 2));
        mem.writeIntLittle(u32, branch.base.code[0..4], inst.toU32());
    }
};

pub const Page = struct {
    base: Relocation,
    addend: ?u32 = null,
    /// Always .PCRelativeAddress
    inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .page;

    pub fn resolve(page: Page, args: Relocation.ResolveArgs) !void {
        const target_addr = if (page.addend) |addend| args.target_addr + addend else args.target_addr;
        const source_page = @intCast(i32, args.source_addr >> 12);
        const target_page = @intCast(i32, target_addr >> 12);
        const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

        log.debug("    | calculated addend 0x{x}", .{page.addend});
        log.debug("    | moving by {} pages", .{pages});

        var inst = page.inst;
        inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
        inst.pc_relative_address.immlo = @truncate(u2, pages);

        mem.writeIntLittle(u32, page.base.code[0..4], inst.toU32());
    }
};

pub const PageOff = struct {
    base: Relocation,
    addend: ?u32 = null,
    op_kind: OpKind,
    inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .page_off;

    pub const OpKind = enum {
        arithmetic,
        load_store,
    };

    pub fn resolve(page_off: PageOff, args: Relocation.ResolveArgs) !void {
        const target_addr = if (page_off.addend) |addend| args.target_addr + addend else args.target_addr;
        const narrowed = @truncate(u12, target_addr);

        log.debug("    | narrowed address within the page 0x{x}", .{narrowed});
        log.debug("    | {s} opcode", .{page_off.op_kind});

        var inst = page_off.inst;
        if (page_off.op_kind == .arithmetic) {
            inst.add_subtract_immediate.imm12 = narrowed;
        } else {
            const offset: u12 = blk: {
                if (inst.load_store_register.size == 0) {
                    if (inst.load_store_register.v == 1) {
                        // 128-bit SIMD is scaled by 16.
                        break :blk try math.divExact(u12, narrowed, 16);
                    }
                    // Otherwise, 8-bit SIMD or ldrb.
                    break :blk narrowed;
                } else {
                    const denom: u4 = try math.powi(u4, 2, inst.load_store_register.size);
                    break :blk try math.divExact(u12, narrowed, denom);
                }
            };
            inst.load_store_register.offset = offset;
        }

        mem.writeIntLittle(u32, page_off.base.code[0..4], inst.toU32());
    }
};

pub const GotPage = struct {
    base: Relocation,
    /// Always .PCRelativeAddress
    inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .got_page;

    pub fn resolve(page: GotPage, args: Relocation.ResolveArgs) !void {
        const source_page = @intCast(i32, args.source_addr >> 12);
        const target_page = @intCast(i32, args.target_addr >> 12);
        const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

        log.debug("    | moving by {} pages", .{pages});

        var inst = page.inst;
        inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
        inst.pc_relative_address.immlo = @truncate(u2, pages);

        mem.writeIntLittle(u32, page.base.code[0..4], inst.toU32());
    }
};

pub const GotPageOff = struct {
    base: Relocation,
    /// Always .LoadStoreRegister with size = 3 for GOT indirection
    inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .got_page_off;

    pub fn resolve(page_off: GotPageOff, args: Relocation.ResolveArgs) !void {
        const narrowed = @truncate(u12, args.target_addr);

        log.debug("    | narrowed address within the page 0x{x}", .{narrowed});

        var inst = page_off.inst;
        const offset = try math.divExact(u12, narrowed, 8);
        inst.load_store_register.offset = offset;

        mem.writeIntLittle(u32, page_off.base.code[0..4], inst.toU32());
    }
};

pub const PointerToGot = struct {
    base: Relocation,

    pub const base_type: Relocation.Type = .pointer_to_got;

    pub fn resolve(ptr_to_got: PointerToGot, args: Relocation.ResolveArgs) !void {
        const result = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr));

        log.debug("    | calculated value 0x{x}", .{result});

        mem.writeIntLittle(u32, ptr_to_got.base.code[0..4], @bitCast(u32, result));
    }
};

pub const TlvpPage = struct {
    base: Relocation,
    /// Always .PCRelativeAddress
    inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .tlvp_page;

    pub fn resolve(page: TlvpPage, args: Relocation.ResolveArgs) !void {
        const source_page = @intCast(i32, args.source_addr >> 12);
        const target_page = @intCast(i32, args.target_addr >> 12);
        const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

        log.debug("    | moving by {} pages", .{pages});

        var inst = page.inst;
        inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
        inst.pc_relative_address.immlo = @truncate(u2, pages);

        mem.writeIntLittle(u32, page.base.code[0..4], inst.toU32());
    }
};

pub const TlvpPageOff = struct {
    base: Relocation,
    /// Always .AddSubtractImmediate regardless of the source instruction.
    /// This means, we always rewrite the instruction to add even if the
    /// source instruction was an ldr.
    inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .tlvp_page_off;

    pub fn resolve(page_off: TlvpPageOff, args: Relocation.ResolveArgs) !void {
        const narrowed = @truncate(u12, args.target_addr);

        log.debug("    | narrowed address within the page 0x{x}", .{narrowed});

        var inst = page_off.inst;
        inst.add_subtract_immediate.imm12 = narrowed;

        mem.writeIntLittle(u32, page_off.base.code[0..4], inst.toU32());
    }
};

pub const Parser = struct {
    allocator: *Allocator,
    it: *reloc.RelocIterator,
    code: []u8,
    parsed: std.ArrayList(*Relocation),
    addend: ?u32 = null,
    subtractor: ?Relocation.Target = null,

    pub fn deinit(parser: *Parser) void {
        parser.parsed.deinit();
    }

    pub fn parse(parser: *Parser) !void {
        while (parser.it.next()) |rel| {
            switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                .ARM64_RELOC_BRANCH26 => {
                    try parser.parseBranch(rel);
                },
                .ARM64_RELOC_SUBTRACTOR => {
                    try parser.parseSubtractor(rel);
                },
                .ARM64_RELOC_UNSIGNED => {
                    try parser.parseUnsigned(rel);
                },
                .ARM64_RELOC_ADDEND => {
                    try parser.parseAddend(rel);
                },
                .ARM64_RELOC_PAGE21,
                .ARM64_RELOC_GOT_LOAD_PAGE21,
                .ARM64_RELOC_TLVP_LOAD_PAGE21,
                => {
                    try parser.parsePage(rel);
                },
                .ARM64_RELOC_PAGEOFF12 => {
                    try parser.parsePageOff(rel);
                },
                .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                    try parser.parseGotLoadPageOff(rel);
                },
                .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                    try parser.parseTlvpLoadPageOff(rel);
                },
                .ARM64_RELOC_POINTER_TO_GOT => {
                    try parser.parsePointerToGot(rel);
                },
            }
        }
    }

    fn parseAddend(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_ADDEND);
        assert(rel.r_pcrel == 0);
        assert(rel.r_extern == 0);
        assert(parser.addend == null);

        parser.addend = rel.r_symbolnum;

        // Verify ADDEND is followed by a load.
        const next = @intToEnum(macho.reloc_type_arm64, parser.it.peek().r_type);
        switch (next) {
            .ARM64_RELOC_PAGE21, .ARM64_RELOC_PAGEOFF12 => {},
            else => {
                log.err("unexpected relocation type: expected PAGE21 or PAGEOFF12, found {s}", .{next});
                return error.UnexpectedRelocationType;
            },
        }
    }

    fn parseBranch(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_BRANCH26);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        const parsed_inst = aarch64.Instruction{ .unconditional_branch_immediate = mem.bytesToValue(
            meta.TagPayload(
                aarch64.Instruction,
                aarch64.Instruction.unconditional_branch_immediate,
            ),
            inst,
        ) };

        var branch = try parser.allocator.create(Branch);
        errdefer parser.allocator.destroy(branch);

        const target = Relocation.Target.fromReloc(rel);

        branch.* = .{
            .base = .{
                .@"type" = .branch_aarch64,
                .code = inst,
                .offset = offset,
                .target = target,
            },
            .inst = parsed_inst,
        };

        log.debug("    | emitting {}", .{branch});
        try parser.parsed.append(&branch.base);
    }

    fn parsePage(parser: *Parser, rel: macho.relocation_info) !void {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        const target = Relocation.Target.fromReloc(rel);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        const parsed_inst = aarch64.Instruction{ .pc_relative_address = mem.bytesToValue(meta.TagPayload(
            aarch64.Instruction,
            aarch64.Instruction.pc_relative_address,
        ), inst) };

        const ptr: *Relocation = ptr: {
            switch (rel_type) {
                .ARM64_RELOC_PAGE21 => {
                    defer {
                        // Reset parser's addend state
                        parser.addend = null;
                    }
                    var page = try parser.allocator.create(Page);
                    errdefer parser.allocator.destroy(page);

                    page.* = .{
                        .base = .{
                            .@"type" = .page,
                            .code = inst,
                            .offset = offset,
                            .target = target,
                        },
                        .addend = parser.addend,
                        .inst = parsed_inst,
                    };

                    log.debug("    | emitting {}", .{page});

                    break :ptr &page.base;
                },
                .ARM64_RELOC_GOT_LOAD_PAGE21 => {
                    var page = try parser.allocator.create(GotPage);
                    errdefer parser.allocator.destroy(page);

                    page.* = .{
                        .base = .{
                            .@"type" = .got_page,
                            .code = inst,
                            .offset = offset,
                            .target = target,
                        },
                        .inst = parsed_inst,
                    };

                    log.debug("    | emitting {}", .{page});

                    break :ptr &page.base;
                },
                .ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                    var page = try parser.allocator.create(TlvpPage);
                    errdefer parser.allocator.destroy(page);

                    page.* = .{
                        .base = .{
                            .@"type" = .tlvp_page,
                            .code = inst,
                            .offset = offset,
                            .target = target,
                        },
                        .inst = parsed_inst,
                    };

                    log.debug("    | emitting {}", .{page});

                    break :ptr &page.base;
                },
                else => unreachable,
            }
        };

        try parser.parsed.append(ptr);
    }

    fn parsePageOff(parser: *Parser, rel: macho.relocation_info) !void {
        defer {
            // Reset parser's addend state
            parser.addend = null;
        }

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_PAGEOFF12);
        assert(rel.r_pcrel == 0);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];

        var op_kind: PageOff.OpKind = undefined;
        var parsed_inst: aarch64.Instruction = undefined;
        if (isArithmeticOp(inst)) {
            op_kind = .arithmetic;
            parsed_inst = .{ .add_subtract_immediate = mem.bytesToValue(meta.TagPayload(
                aarch64.Instruction,
                aarch64.Instruction.add_subtract_immediate,
            ), inst) };
        } else {
            op_kind = .load_store;
            parsed_inst = .{ .load_store_register = mem.bytesToValue(meta.TagPayload(
                aarch64.Instruction,
                aarch64.Instruction.load_store_register,
            ), inst) };
        }
        const target = Relocation.Target.fromReloc(rel);

        var page_off = try parser.allocator.create(PageOff);
        errdefer parser.allocator.destroy(page_off);

        page_off.* = .{
            .base = .{
                .@"type" = .page_off,
                .code = inst,
                .offset = offset,
                .target = target,
            },
            .op_kind = op_kind,
            .inst = parsed_inst,
            .addend = parser.addend,
        };

        log.debug("    | emitting {}", .{page_off});
        try parser.parsed.append(&page_off.base);
    }

    fn parseGotLoadPageOff(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_GOT_LOAD_PAGEOFF12);
        assert(rel.r_pcrel == 0);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        assert(!isArithmeticOp(inst));

        const parsed_inst = mem.bytesToValue(meta.TagPayload(
            aarch64.Instruction,
            aarch64.Instruction.load_store_register,
        ), inst);
        assert(parsed_inst.size == 3);

        const target = Relocation.Target.fromReloc(rel);

        var page_off = try parser.allocator.create(GotPageOff);
        errdefer parser.allocator.destroy(page_off);

        page_off.* = .{
            .base = .{
                .@"type" = .got_page_off,
                .code = inst,
                .offset = offset,
                .target = target,
            },
            .inst = .{
                .load_store_register = parsed_inst,
            },
        };

        log.debug("    | emitting {}", .{page_off});
        try parser.parsed.append(&page_off.base);
    }

    fn parseTlvpLoadPageOff(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_TLVP_LOAD_PAGEOFF12);
        assert(rel.r_pcrel == 0);
        assert(rel.r_length == 2);

        const RegInfo = struct {
            rd: u5,
            rn: u5,
            size: u1,
        };

        const offset = @intCast(u32, rel.r_address);
        const inst = parser.code[offset..][0..4];
        const parsed: RegInfo = parsed: {
            if (isArithmeticOp(inst)) {
                const parsed_inst = mem.bytesAsValue(meta.TagPayload(
                    aarch64.Instruction,
                    aarch64.Instruction.add_subtract_immediate,
                ), inst);
                break :parsed .{
                    .rd = parsed_inst.rd,
                    .rn = parsed_inst.rn,
                    .size = parsed_inst.sf,
                };
            } else {
                const parsed_inst = mem.bytesAsValue(meta.TagPayload(
                    aarch64.Instruction,
                    aarch64.Instruction.load_store_register,
                ), inst);
                break :parsed .{
                    .rd = parsed_inst.rt,
                    .rn = parsed_inst.rn,
                    .size = @truncate(u1, parsed_inst.size),
                };
            }
        };

        const target = Relocation.Target.fromReloc(rel);

        var page_off = try parser.allocator.create(TlvpPageOff);
        errdefer parser.allocator.destroy(page_off);

        page_off.* = .{
            .base = .{
                .@"type" = .tlvp_page_off,
                .code = inst,
                .offset = offset,
                .target = target,
            },
            .inst = .{
                .add_subtract_immediate = .{
                    .rd = parsed.rd,
                    .rn = parsed.rn,
                    .imm12 = 0, // This will be filled when target addresses are known.
                    .sh = 0,
                    .s = 0,
                    .op = 0,
                    .sf = parsed.size,
                },
            },
        };

        log.debug("    | emitting {}", .{page_off});
        try parser.parsed.append(&page_off.base);
    }

    fn parseSubtractor(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_SUBTRACTOR);
        assert(rel.r_pcrel == 0);
        assert(parser.subtractor == null);

        parser.subtractor = Relocation.Target.fromReloc(rel);

        // Verify SUBTRACTOR is followed by UNSIGNED.
        const next = @intToEnum(macho.reloc_type_arm64, parser.it.peek().r_type);
        if (next != .ARM64_RELOC_UNSIGNED) {
            log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
            return error.UnexpectedRelocationType;
        }
    }

    fn parseUnsigned(parser: *Parser, rel: macho.relocation_info) !void {
        defer {
            // Reset parser's subtractor state
            parser.subtractor = null;
        }

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_UNSIGNED);
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

    fn parsePointerToGot(parser: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_POINTER_TO_GOT);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        var ptr_to_got = try parser.allocator.create(PointerToGot);
        errdefer parser.allocator.destroy(ptr_to_got);

        const target = Relocation.Target.fromReloc(rel);
        const offset = @intCast(u32, rel.r_address);

        ptr_to_got.* = .{
            .base = .{
                .@"type" = .pointer_to_got,
                .code = parser.code[offset..][0..4],
                .offset = offset,
                .target = target,
            },
        };

        log.debug("    | emitting {}", .{ptr_to_got});
        try parser.parsed.append(&ptr_to_got.base);
    }
};

inline fn isArithmeticOp(inst: *const [4]u8) bool {
    const group_decode = @truncate(u5, inst[3]);
    return ((group_decode >> 2) == 4);
}
