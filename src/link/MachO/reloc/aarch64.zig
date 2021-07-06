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
const Object = @import("../Object.zig");
const Relocation = reloc.Relocation;
const Symbol = @import("../Symbol.zig");
const TextBlock = Zld.TextBlock;
const Zld = @import("../Zld.zig");

pub const Branch = struct {
    base: Relocation,
    /// Always .UnconditionalBranchImmediate
    // inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .branch_aarch64;

    // pub fn resolve(branch: Branch, args: Relocation.ResolveArgs) !void {
    //     const displacement = try math.cast(i28, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr));

    //     log.debug("    | displacement 0x{x}", .{displacement});

    //     var inst = branch.inst;
    //     inst.unconditional_branch_immediate.imm26 = @truncate(u26, @bitCast(u28, displacement >> 2));
    //     mem.writeIntLittle(u32, branch.base.code[0..4], inst.toU32());
    // }

    pub fn format(self: Branch, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const Page = struct {
    base: Relocation,
    addend: ?u32 = null,
    /// Always .PCRelativeAddress
    // inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .page;

    // pub fn resolve(page: Page, args: Relocation.ResolveArgs) !void {
    //     const target_addr = if (page.addend) |addend| args.target_addr + addend else args.target_addr;
    //     const source_page = @intCast(i32, args.source_addr >> 12);
    //     const target_page = @intCast(i32, target_addr >> 12);
    //     const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

    //     log.debug("    | calculated addend 0x{x}", .{page.addend});
    //     log.debug("    | moving by {} pages", .{pages});

    //     var inst = page.inst;
    //     inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
    //     inst.pc_relative_address.immlo = @truncate(u2, pages);

    //     mem.writeIntLittle(u32, page.base.code[0..4], inst.toU32());
    // }

    pub fn format(self: Page, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (self.addend) |addend| {
            try std.fmt.format(writer, ".addend = {}, ", .{addend});
        }
    }
};

pub const PageOff = struct {
    base: Relocation,
    addend: ?u32 = null,
    op_kind: OpKind,
    // inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .page_off;

    pub const OpKind = enum {
        arithmetic,
        load_store,
    };

    // pub fn resolve(page_off: PageOff, args: Relocation.ResolveArgs) !void {
    //     const target_addr = if (page_off.addend) |addend| args.target_addr + addend else args.target_addr;
    //     const narrowed = @truncate(u12, target_addr);

    //     log.debug("    | narrowed address within the page 0x{x}", .{narrowed});
    //     log.debug("    | {s} opcode", .{page_off.op_kind});

    //     var inst = page_off.inst;
    //     if (page_off.op_kind == .arithmetic) {
    //         inst.add_subtract_immediate.imm12 = narrowed;
    //     } else {
    //         const offset: u12 = blk: {
    //             if (inst.load_store_register.size == 0) {
    //                 if (inst.load_store_register.v == 1) {
    //                     // 128-bit SIMD is scaled by 16.
    //                     break :blk try math.divExact(u12, narrowed, 16);
    //                 }
    //                 // Otherwise, 8-bit SIMD or ldrb.
    //                 break :blk narrowed;
    //             } else {
    //                 const denom: u4 = try math.powi(u4, 2, inst.load_store_register.size);
    //                 break :blk try math.divExact(u12, narrowed, denom);
    //             }
    //         };
    //         inst.load_store_register.offset = offset;
    //     }

    //     mem.writeIntLittle(u32, page_off.base.code[0..4], inst.toU32());
    // }

    pub fn format(self: PageOff, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (self.addend) |addend| {
            try std.fmt.format(writer, ".addend = {}, ", .{addend});
        }
        try std.fmt.format(writer, ".op_kind = {s}, ", .{self.op_kind});
    }
};

pub const GotPage = struct {
    base: Relocation,
    /// Always .PCRelativeAddress
    // inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .got_page;

    // pub fn resolve(page: GotPage, args: Relocation.ResolveArgs) !void {
    //     const source_page = @intCast(i32, args.source_addr >> 12);
    //     const target_page = @intCast(i32, args.target_addr >> 12);
    //     const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

    //     log.debug("    | moving by {} pages", .{pages});

    //     var inst = page.inst;
    //     inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
    //     inst.pc_relative_address.immlo = @truncate(u2, pages);

    //     mem.writeIntLittle(u32, page.base.code[0..4], inst.toU32());
    // }

    pub fn format(self: GotPage, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const GotPageOff = struct {
    base: Relocation,
    /// Always .LoadStoreRegister with size = 3 for GOT indirection
    // inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .got_page_off;

    // pub fn resolve(page_off: GotPageOff, args: Relocation.ResolveArgs) !void {
    //     const narrowed = @truncate(u12, args.target_addr);

    //     log.debug("    | narrowed address within the page 0x{x}", .{narrowed});

    //     var inst = page_off.inst;
    //     const offset = try math.divExact(u12, narrowed, 8);
    //     inst.load_store_register.offset = offset;

    //     mem.writeIntLittle(u32, page_off.base.code[0..4], inst.toU32());
    // }

    pub fn format(self: GotPageOff, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const PointerToGot = struct {
    base: Relocation,

    pub const base_type: Relocation.Type = .pointer_to_got;

    // pub fn resolve(ptr_to_got: PointerToGot, args: Relocation.ResolveArgs) !void {
    //     const result = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr));

    //     log.debug("    | calculated value 0x{x}", .{result});

    //     mem.writeIntLittle(u32, ptr_to_got.base.code[0..4], @bitCast(u32, result));
    // }

    pub fn format(self: PointerToGot, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const TlvpPage = struct {
    base: Relocation,
    /// Always .PCRelativeAddress
    // inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .tlvp_page;

    // pub fn resolve(page: TlvpPage, args: Relocation.ResolveArgs) !void {
    //     const source_page = @intCast(i32, args.source_addr >> 12);
    //     const target_page = @intCast(i32, args.target_addr >> 12);
    //     const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

    //     log.debug("    | moving by {} pages", .{pages});

    //     var inst = page.inst;
    //     inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
    //     inst.pc_relative_address.immlo = @truncate(u2, pages);

    //     mem.writeIntLittle(u32, page.base.code[0..4], inst.toU32());
    // }

    pub fn format(self: TlvpPage, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = self;
        _ = fmt;
        _ = options;
        _ = writer;
    }
};

pub const TlvpPageOff = struct {
    base: Relocation,
    /// Always .AddSubtractImmediate regardless of the source instruction.
    /// This means, we always rewrite the instruction to add even if the
    /// source instruction was an ldr.
    // inst: aarch64.Instruction,

    pub const base_type: Relocation.Type = .tlvp_page_off;

    // pub fn resolve(page_off: TlvpPageOff, args: Relocation.ResolveArgs) !void {
    //     const narrowed = @truncate(u12, args.target_addr);

    //     log.debug("    | narrowed address within the page 0x{x}", .{narrowed});

    //     var inst = page_off.inst;
    //     inst.add_subtract_immediate.imm12 = narrowed;

    //     mem.writeIntLittle(u32, page_off.base.code[0..4], inst.toU32());
    // }

    pub fn format(self: TlvpPageOff, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
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
    addend: ?u32 = null,
    subtractor: ?*Symbol = null,

    pub fn parse(self: *Parser) !void {
        while (self.it.next()) |rel| {
            const out_rel = switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                .ARM64_RELOC_BRANCH26 => try self.parseBranch(rel),
                .ARM64_RELOC_SUBTRACTOR => {
                    // Subtractor is not a relocation with effect on the TextBlock, so
                    // parse it and carry on.
                    try self.parseSubtractor(rel);
                    continue;
                },
                .ARM64_RELOC_UNSIGNED => try self.parseUnsigned(rel),
                .ARM64_RELOC_ADDEND => {
                    // Addend is not a relocation with effect on the TextBlock, so
                    // parse it and carry on.
                    try self.parseAddend(rel);
                    continue;
                },
                .ARM64_RELOC_PAGE21,
                .ARM64_RELOC_GOT_LOAD_PAGE21,
                .ARM64_RELOC_TLVP_LOAD_PAGE21,
                => try self.parsePage(rel),
                .ARM64_RELOC_PAGEOFF12 => try self.parsePageOff(rel),
                .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => try self.parseGotLoadPageOff(rel),
                .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => try self.parseTlvpLoadPageOff(rel),
                .ARM64_RELOC_POINTER_TO_GOT => try self.parsePointerToGot(rel),
            };
            try self.block.relocs.append(out_rel);

            if (out_rel.target.payload == .regular) {
                try self.block.references.put(out_rel.target.payload.regular.local_sym_index, {});
            }

            switch (out_rel.@"type") {
                .got_page, .got_page_off, .pointer_to_got => {
                    const sym = out_rel.target;

                    if (sym.got_index != null) continue;

                    const index = @intCast(u32, self.zld.got_entries.items.len);
                    sym.got_index = index;
                    try self.zld.got_entries.append(self.zld.allocator, sym);

                    log.debug("adding GOT entry for symbol {s} at index {}", .{ sym.name, index });
                },
                .branch_aarch64 => {
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

    fn parseAddend(self: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_ADDEND);
        assert(rel.r_pcrel == 0);
        assert(rel.r_extern == 0);
        assert(self.addend == null);

        self.addend = rel.r_symbolnum;

        // Verify ADDEND is followed by a load.
        const next = @intToEnum(macho.reloc_type_arm64, self.it.peek().r_type);
        switch (next) {
            .ARM64_RELOC_PAGE21, .ARM64_RELOC_PAGEOFF12 => {},
            else => {
                log.err("unexpected relocation type: expected PAGE21 or PAGEOFF12, found {s}", .{next});
                return error.UnexpectedRelocationType;
            },
        }
    }

    fn parseBranch(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_BRANCH26);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const target = try self.object.symbolFromReloc(rel);

        var branch = try self.object.allocator.create(Branch);
        errdefer self.object.allocator.destroy(branch);

        branch.* = .{
            .base = .{
                .@"type" = .branch_aarch64,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
        };

        return &branch.base;
    }

    fn parsePage(self: *Parser, rel: macho.relocation_info) !*Relocation {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        const target = try self.object.symbolFromReloc(rel);
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);

        const ptr: *Relocation = ptr: {
            switch (rel_type) {
                .ARM64_RELOC_PAGE21 => {
                    defer {
                        // Reset parser's addend state
                        self.addend = null;
                    }
                    var page = try self.object.allocator.create(Page);
                    errdefer self.object.allocator.destroy(page);

                    page.* = .{
                        .base = .{
                            .@"type" = .page,
                            .offset = offset,
                            .target = target,
                            .block = self.block,
                        },
                        .addend = self.addend,
                    };

                    break :ptr &page.base;
                },
                .ARM64_RELOC_GOT_LOAD_PAGE21 => {
                    var page = try self.object.allocator.create(GotPage);
                    errdefer self.object.allocator.destroy(page);

                    page.* = .{
                        .base = .{
                            .@"type" = .got_page,
                            .offset = offset,
                            .target = target,
                            .block = self.block,
                        },
                    };

                    break :ptr &page.base;
                },
                .ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                    var page = try self.object.allocator.create(TlvpPage);
                    errdefer self.object.allocator.destroy(page);

                    page.* = .{
                        .base = .{
                            .@"type" = .tlvp_page,
                            .offset = offset,
                            .target = target,
                            .block = self.block,
                        },
                    };

                    break :ptr &page.base;
                },
                else => unreachable,
            }
        };

        return ptr;
    }

    fn parsePageOff(self: *Parser, rel: macho.relocation_info) !*Relocation {
        defer {
            // Reset parser's addend state
            self.addend = null;
        }

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_PAGEOFF12);
        assert(rel.r_pcrel == 0);
        assert(rel.r_length == 2);

        const target = try self.object.symbolFromReloc(rel);
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const op_kind: PageOff.OpKind = if (isArithmeticOp(self.block.code[offset..][0..4]))
            .arithmetic
        else
            .load_store;

        var page_off = try self.object.allocator.create(PageOff);
        errdefer self.object.allocator.destroy(page_off);

        page_off.* = .{
            .base = .{
                .@"type" = .page_off,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
            .op_kind = op_kind,
            .addend = self.addend,
        };

        return &page_off.base;
    }

    fn parseGotLoadPageOff(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_GOT_LOAD_PAGEOFF12);
        assert(rel.r_pcrel == 0);
        assert(rel.r_length == 2);

        const target = try self.object.symbolFromReloc(rel);
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        assert(!isArithmeticOp(self.block.code[offset..][0..4]));

        var page_off = try self.object.allocator.create(GotPageOff);
        errdefer self.object.allocator.destroy(page_off);

        page_off.* = .{
            .base = .{
                .@"type" = .got_page_off,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
        };

        return &page_off.base;
    }

    fn parseTlvpLoadPageOff(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_TLVP_LOAD_PAGEOFF12);
        assert(rel.r_pcrel == 0);
        assert(rel.r_length == 2);

        const RegInfo = struct {
            rd: u5,
            rn: u5,
            size: u1,
        };

        const target = try self.object.symbolFromReloc(rel);
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);

        var page_off = try self.object.allocator.create(TlvpPageOff);
        errdefer self.object.allocator.destroy(page_off);

        page_off.* = .{
            .base = .{
                .@"type" = .tlvp_page_off,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
        };

        return &page_off.base;
    }

    fn parseSubtractor(self: *Parser, rel: macho.relocation_info) !void {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_SUBTRACTOR);
        assert(rel.r_pcrel == 0);
        assert(self.subtractor == null);

        self.subtractor = try self.object.symbolFromReloc(rel);

        // Verify SUBTRACTOR is followed by UNSIGNED.
        const next = @intToEnum(macho.reloc_type_arm64, self.it.peek().r_type);
        if (next != .ARM64_RELOC_UNSIGNED) {
            log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
            return error.UnexpectedRelocationType;
        }
    }

    fn parseUnsigned(self: *Parser, rel: macho.relocation_info) !*Relocation {
        defer {
            // Reset parser's subtractor state
            self.subtractor = null;
        }

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_UNSIGNED);
        assert(rel.r_pcrel == 0);

        const target = try self.object.symbolFromReloc(rel);
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const is_64bit: bool = switch (rel.r_length) {
            3 => true,
            2 => false,
            else => unreachable,
        };
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

    fn parsePointerToGot(self: *Parser, rel: macho.relocation_info) !*Relocation {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        assert(rel_type == .ARM64_RELOC_POINTER_TO_GOT);
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        var ptr_to_got = try self.object.allocator.create(PointerToGot);
        errdefer self.object.allocator.destroy(ptr_to_got);

        const target = try self.object.symbolFromReloc(rel);
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);

        ptr_to_got.* = .{
            .base = .{
                .@"type" = .pointer_to_got,
                .offset = offset,
                .target = target,
                .block = self.block,
            },
        };

        return &ptr_to_got.base;
    }
};

inline fn isArithmeticOp(inst: *const [4]u8) bool {
    const group_decode = @truncate(u5, inst[3]);
    return ((group_decode >> 2) == 4);
}
