const TextBlock = @This();

const std = @import("std");
const aarch64 = @import("../../codegen/aarch64.zig");
const assert = std.debug.assert;
const commands = @import("commands.zig");
const log = std.log.scoped(.text_block);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const Allocator = mem.Allocator;
const Arch = std.Target.Cpu.Arch;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");

/// Each decl always gets a local symbol with the fully qualified name.
/// The vaddr and size are found here directly.
/// The file offset is found by computing the vaddr offset from the section vaddr
/// the symbol references, and adding that to the file offset of the section.
/// If this field is 0, it means the codegen size = 0 and there is no symbol or
/// offset table entry.
local_sym_index: u32,

/// List of symbol aliases pointing to the same block via different nlists
aliases: std.ArrayListUnmanaged(u32) = .{},

/// List of symbols contained within this block
contained: std.ArrayListUnmanaged(SymbolAtOffset) = .{},

/// Code (may be non-relocated) this block represents
code: []u8,

/// Size and alignment of this text block
/// Unlike in Elf, we need to store the size of this symbol as part of
/// the TextBlock since macho.nlist_64 lacks this information.
size: u64,
alignment: u32,

relocs: std.ArrayListUnmanaged(Relocation) = .{},

/// List of offsets contained within this block that need rebasing by the dynamic
/// loader in presence of ASLR
rebases: std.ArrayListUnmanaged(u64) = .{},

/// List of offsets contained within this block that will be dynamically bound
/// by the dynamic loader and contain pointers to resolved (at load time) extern
/// symbols (aka proxies aka imports)
bindings: std.ArrayListUnmanaged(SymbolAtOffset) = .{},

/// List of data-in-code entries. This is currently specific to x86_64 only.
dices: std.ArrayListUnmanaged(macho.data_in_code_entry) = .{},

/// Stab entry for this block. This is currently specific to a binary created
/// by linking object files in a traditional sense - in incremental sense, we
/// bypass stabs altogether to produce dSYM bundle directly with fully relocated
/// DWARF sections.
stab: ?Stab = null,

/// Points to the previous and next neighbours
next: ?*TextBlock,
prev: ?*TextBlock,

/// Previous/next linked list pointers.
/// This is the linked list node for this Decl's corresponding .debug_info tag.
dbg_info_prev: ?*TextBlock,
dbg_info_next: ?*TextBlock,
/// Offset into .debug_info pointing to the tag for this Decl.
dbg_info_off: u32,
/// Size of the .debug_info tag for this Decl, not including padding.
dbg_info_len: u32,

pub const SymbolAtOffset = struct {
    local_sym_index: u32,
    offset: u64,
    stab: ?Stab = null,
};

pub const Stab = union(enum) {
    function: u64,
    static,
    global,

    pub fn asNlists(stab: Stab, local_sym_index: u32, macho_file: anytype) ![]macho.nlist_64 {
        var nlists = std.ArrayList(macho.nlist_64).init(macho_file.base.allocator);
        defer nlists.deinit();

        const sym = macho_file.locals.items[local_sym_index];
        switch (stab) {
            .function => |size| {
                try nlists.ensureUnusedCapacity(4);
                nlists.appendAssumeCapacity(.{
                    .n_strx = 0,
                    .n_type = macho.N_BNSYM,
                    .n_sect = sym.n_sect,
                    .n_desc = 0,
                    .n_value = sym.n_value,
                });
                nlists.appendAssumeCapacity(.{
                    .n_strx = sym.n_strx,
                    .n_type = macho.N_FUN,
                    .n_sect = sym.n_sect,
                    .n_desc = 0,
                    .n_value = sym.n_value,
                });
                nlists.appendAssumeCapacity(.{
                    .n_strx = 0,
                    .n_type = macho.N_FUN,
                    .n_sect = 0,
                    .n_desc = 0,
                    .n_value = size,
                });
                nlists.appendAssumeCapacity(.{
                    .n_strx = 0,
                    .n_type = macho.N_ENSYM,
                    .n_sect = sym.n_sect,
                    .n_desc = 0,
                    .n_value = size,
                });
            },
            .global => {
                try nlists.append(.{
                    .n_strx = sym.n_strx,
                    .n_type = macho.N_GSYM,
                    .n_sect = 0,
                    .n_desc = 0,
                    .n_value = 0,
                });
            },
            .static => {
                try nlists.append(.{
                    .n_strx = sym.n_strx,
                    .n_type = macho.N_STSYM,
                    .n_sect = sym.n_sect,
                    .n_desc = 0,
                    .n_value = sym.n_value,
                });
            },
        }

        return nlists.toOwnedSlice();
    }
};

pub const Relocation = struct {
    /// Offset within the `block`s code buffer.
    /// Note relocation size can be inferred by relocation's kind.
    offset: u32,

    where: enum {
        local,
        import,
    },

    where_index: u32,

    payload: union(enum) {
        unsigned: Unsigned,
        branch: Branch,
        page: Page,
        page_off: PageOff,
        pointer_to_got: PointerToGot,
        signed: Signed,
        load: Load,
    },

    const ResolveArgs = struct {
        block: *TextBlock,
        offset: u32,
        source_addr: u64,
        target_addr: u64,
        macho_file: *MachO,
    };

    pub const Unsigned = struct {
        subtractor: ?u32,

        /// Addend embedded directly in the relocation slot
        addend: i64,

        /// Extracted from r_length:
        /// => 3 implies true
        /// => 2 implies false
        /// => * is unreachable
        is_64bit: bool,

        pub fn resolve(self: Unsigned, args: ResolveArgs) !void {
            const result = blk: {
                if (self.subtractor) |subtractor| {
                    const sym = args.macho_file.locals.items[subtractor];
                    break :blk @intCast(i64, args.target_addr) - @intCast(i64, sym.n_value) + self.addend;
                } else {
                    break :blk @intCast(i64, args.target_addr) + self.addend;
                }
            };

            if (self.is_64bit) {
                mem.writeIntLittle(u64, args.block.code[args.offset..][0..8], @bitCast(u64, result));
            } else {
                mem.writeIntLittle(u32, args.block.code[args.offset..][0..4], @truncate(u32, @bitCast(u64, result)));
            }
        }

        pub fn format(self: Unsigned, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "Unsigned {{ ", .{});
            if (self.subtractor) |sub| {
                try std.fmt.format(writer, ".subtractor = {}, ", .{sub});
            }
            try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
            const length: usize = if (self.is_64bit) 8 else 4;
            try std.fmt.format(writer, ".length = {}, ", .{length});
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub const Branch = struct {
        arch: Arch,

        pub fn resolve(self: Branch, args: ResolveArgs) !void {
            switch (self.arch) {
                .aarch64 => {
                    const displacement = try math.cast(
                        i28,
                        @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr),
                    );
                    const code = args.block.code[args.offset..][0..4];
                    var inst = aarch64.Instruction{
                        .unconditional_branch_immediate = mem.bytesToValue(meta.TagPayload(
                            aarch64.Instruction,
                            aarch64.Instruction.unconditional_branch_immediate,
                        ), code),
                    };
                    inst.unconditional_branch_immediate.imm26 = @truncate(u26, @bitCast(u28, displacement >> 2));
                    mem.writeIntLittle(u32, code, inst.toU32());
                },
                .x86_64 => {
                    const displacement = try math.cast(
                        i32,
                        @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4,
                    );
                    mem.writeIntLittle(u32, args.block.code[args.offset..][0..4], @bitCast(u32, displacement));
                },
                else => return error.UnsupportedCpuArchitecture,
            }
        }

        pub fn format(self: Branch, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = self;
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "Branch {{}}", .{});
        }
    };

    pub const Page = struct {
        kind: enum {
            page,
            got,
            tlvp,
        },
        addend: u32 = 0,

        pub fn resolve(self: Page, args: ResolveArgs) !void {
            const target_addr = args.target_addr + self.addend;
            const source_page = @intCast(i32, args.source_addr >> 12);
            const target_page = @intCast(i32, target_addr >> 12);
            const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

            const code = args.block.code[args.offset..][0..4];
            var inst = aarch64.Instruction{
                .pc_relative_address = mem.bytesToValue(meta.TagPayload(
                    aarch64.Instruction,
                    aarch64.Instruction.pc_relative_address,
                ), code),
            };
            inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
            inst.pc_relative_address.immlo = @truncate(u2, pages);

            mem.writeIntLittle(u32, code, inst.toU32());
        }

        pub fn format(self: Page, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "Page {{ ", .{});
            switch (self.kind) {
                .page => {},
                .got => {
                    try std.fmt.format(writer, ".got, ", .{});
                },
                .tlvp => {
                    try std.fmt.format(writer, ".tlvp", .{});
                },
            }
            try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub const PageOff = struct {
        kind: enum {
            page,
            got,
            tlvp,
        },
        addend: u32 = 0,
        op_kind: ?OpKind = null,

        pub const OpKind = enum {
            arithmetic,
            load,
        };

        pub fn resolve(self: PageOff, args: ResolveArgs) !void {
            const code = args.block.code[args.offset..][0..4];

            switch (self.kind) {
                .page => {
                    const target_addr = args.target_addr + self.addend;
                    const narrowed = @truncate(u12, target_addr);

                    const op_kind = self.op_kind orelse unreachable;
                    var inst: aarch64.Instruction = blk: {
                        switch (op_kind) {
                            .arithmetic => {
                                break :blk .{
                                    .add_subtract_immediate = mem.bytesToValue(meta.TagPayload(
                                        aarch64.Instruction,
                                        aarch64.Instruction.add_subtract_immediate,
                                    ), code),
                                };
                            },
                            .load => {
                                break :blk .{
                                    .load_store_register = mem.bytesToValue(meta.TagPayload(
                                        aarch64.Instruction,
                                        aarch64.Instruction.load_store_register,
                                    ), code),
                                };
                            },
                        }
                    };

                    if (op_kind == .arithmetic) {
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

                    mem.writeIntLittle(u32, code, inst.toU32());
                },
                .got => {
                    const narrowed = @truncate(u12, args.target_addr);
                    var inst: aarch64.Instruction = .{
                        .load_store_register = mem.bytesToValue(meta.TagPayload(
                            aarch64.Instruction,
                            aarch64.Instruction.load_store_register,
                        ), code),
                    };
                    const offset = try math.divExact(u12, narrowed, 8);
                    inst.load_store_register.offset = offset;
                    mem.writeIntLittle(u32, code, inst.toU32());
                },
                .tlvp => {
                    const RegInfo = struct {
                        rd: u5,
                        rn: u5,
                        size: u1,
                    };
                    const reg_info: RegInfo = blk: {
                        if (isArithmeticOp(code)) {
                            const inst = mem.bytesToValue(meta.TagPayload(
                                aarch64.Instruction,
                                aarch64.Instruction.add_subtract_immediate,
                            ), code);
                            break :blk .{
                                .rd = inst.rd,
                                .rn = inst.rn,
                                .size = inst.sf,
                            };
                        } else {
                            const inst = mem.bytesToValue(meta.TagPayload(
                                aarch64.Instruction,
                                aarch64.Instruction.load_store_register,
                            ), code);
                            break :blk .{
                                .rd = inst.rt,
                                .rn = inst.rn,
                                .size = @truncate(u1, inst.size),
                            };
                        }
                    };
                    const narrowed = @truncate(u12, args.target_addr);
                    var inst = aarch64.Instruction{
                        .add_subtract_immediate = .{
                            .rd = reg_info.rd,
                            .rn = reg_info.rn,
                            .imm12 = narrowed,
                            .sh = 0,
                            .s = 0,
                            .op = 0,
                            .sf = reg_info.size,
                        },
                    };
                    mem.writeIntLittle(u32, code, inst.toU32());
                },
            }
        }

        pub fn format(self: PageOff, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "PageOff {{ ", .{});
            switch (self.kind) {
                .page => {},
                .got => {
                    try std.fmt.format(writer, ".got, ", .{});
                },
                .tlvp => {
                    try std.fmt.format(writer, ".tlvp, ", .{});
                },
            }
            try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
            try std.fmt.format(writer, ".op_kind = {s}, ", .{self.op_kind});
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub const PointerToGot = struct {
        pub fn resolve(_: PointerToGot, args: ResolveArgs) !void {
            const result = try math.cast(i32, @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr));
            mem.writeIntLittle(u32, args.block.code[args.offset..][0..4], @bitCast(u32, result));
        }

        pub fn format(self: PointerToGot, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = self;
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "PointerToGot {{}}", .{});
        }
    };

    pub const Signed = struct {
        addend: i64,
        correction: i4,

        pub fn resolve(self: Signed, args: ResolveArgs) !void {
            const target_addr = @intCast(i64, args.target_addr) + self.addend;
            const displacement = try math.cast(
                i32,
                target_addr - @intCast(i64, args.source_addr) - self.correction - 4,
            );
            mem.writeIntLittle(u32, args.block.code[args.offset..][0..4], @bitCast(u32, displacement));
        }

        pub fn format(self: Signed, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "Signed {{ ", .{});
            try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
            try std.fmt.format(writer, ".correction = {}, ", .{self.correction});
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub const Load = struct {
        kind: enum {
            got,
            tlvp,
        },
        addend: i32 = 0,

        pub fn resolve(self: Load, args: ResolveArgs) !void {
            if (self.kind == .tlvp) {
                // We need to rewrite the opcode from movq to leaq.
                args.block.code[args.offset - 2] = 0x8d;
            }
            const displacement = try math.cast(
                i32,
                @intCast(i64, args.target_addr) - @intCast(i64, args.source_addr) - 4 + self.addend,
            );
            mem.writeIntLittle(u32, args.block.code[args.offset..][0..4], @bitCast(u32, displacement));
        }

        pub fn format(self: Load, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "Load {{ ", .{});
            try std.fmt.format(writer, "{s}, ", .{self.kind});
            try std.fmt.format(writer, ".addend = {}, ", .{self.addend});
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub fn resolve(self: Relocation, args: ResolveArgs) !void {
        switch (self.payload) {
            .unsigned => |unsigned| try unsigned.resolve(args),
            .branch => |branch| try branch.resolve(args),
            .page => |page| try page.resolve(args),
            .page_off => |page_off| try page_off.resolve(args),
            .pointer_to_got => |pointer_to_got| try pointer_to_got.resolve(args),
            .signed => |signed| try signed.resolve(args),
            .load => |load| try load.resolve(args),
        }
    }

    pub fn format(self: Relocation, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try std.fmt.format(writer, "Relocation {{ ", .{});
        try std.fmt.format(writer, ".offset = {}, ", .{self.offset});
        try std.fmt.format(writer, ".where = {}, ", .{self.where});
        try std.fmt.format(writer, ".where_index = {d}, ", .{self.where_index});

        switch (self.payload) {
            .unsigned => |unsigned| try unsigned.format(fmt, options, writer),
            .branch => |branch| try branch.format(fmt, options, writer),
            .page => |page| try page.format(fmt, options, writer),
            .page_off => |page_off| try page_off.format(fmt, options, writer),
            .pointer_to_got => |pointer_to_got| try pointer_to_got.format(fmt, options, writer),
            .signed => |signed| try signed.format(fmt, options, writer),
            .load => |load| try load.format(fmt, options, writer),
        }

        try std.fmt.format(writer, "}}", .{});
    }
};

pub const empty = TextBlock{
    .local_sym_index = 0,
    .code = undefined,
    .size = 0,
    .alignment = 0,
    .prev = null,
    .next = null,
    .dbg_info_prev = null,
    .dbg_info_next = null,
    .dbg_info_off = undefined,
    .dbg_info_len = undefined,
};

pub fn deinit(self: *TextBlock, allocator: *Allocator) void {
    self.dices.deinit(allocator);
    self.bindings.deinit(allocator);
    self.rebases.deinit(allocator);
    self.relocs.deinit(allocator);
    self.contained.deinit(allocator);
    self.aliases.deinit(allocator);
    allocator.free(self.code);
}

/// Returns how much room there is to grow in virtual address space.
/// File offset relocation happens transparently, so it is not included in
/// this calculation.
pub fn capacity(self: TextBlock, macho_file: MachO) u64 {
    const self_sym = macho_file.locals.items[self.local_sym_index];
    if (self.next) |next| {
        const next_sym = macho_file.locals.items[next.local_sym_index];
        return next_sym.n_value - self_sym.n_value;
    } else {
        // We are the last block.
        // The capacity is limited only by virtual address space.
        return std.math.maxInt(u64) - self_sym.n_value;
    }
}

pub fn freeListEligible(self: TextBlock, macho_file: MachO) bool {
    // No need to keep a free list node for the last block.
    const next = self.next orelse return false;
    const self_sym = macho_file.locals.items[self.local_sym_index];
    const next_sym = macho_file.locals.items[next.local_sym_index];
    const cap = next_sym.n_value - self_sym.n_value;
    const ideal_cap = MachO.padToIdeal(self.size);
    if (cap <= ideal_cap) return false;
    const surplus = cap - ideal_cap;
    return surplus >= MachO.min_text_capacity;
}

const RelocContext = struct {
    base_addr: u64 = 0,
    macho_file: *MachO,
};

fn initRelocFromObject(rel: macho.relocation_info, object: *Object, ctx: RelocContext) !Relocation {
    var parsed_rel = Relocation{
        .offset = @intCast(u32, @intCast(u64, rel.r_address) - ctx.base_addr),
        .where = undefined,
        .where_index = undefined,
        .payload = undefined,
    };

    if (rel.r_extern == 0) {
        const sect_id = @intCast(u16, rel.r_symbolnum - 1);

        const local_sym_index = object.sections_as_symbols.get(sect_id) orelse blk: {
            const seg = object.load_commands.items[object.segment_cmd_index.?].Segment;
            const sect = seg.sections.items[sect_id];
            const match = (try ctx.macho_file.getMatchingSection(sect)) orelse unreachable;
            const local_sym_index = @intCast(u32, ctx.macho_file.locals.items.len);
            const sym_name = try std.fmt.allocPrint(ctx.macho_file.base.allocator, "l_{s}_{s}_{s}", .{
                object.name.?,
                commands.segmentName(sect),
                commands.sectionName(sect),
            });
            defer ctx.macho_file.base.allocator.free(sym_name);

            try ctx.macho_file.locals.append(ctx.macho_file.base.allocator, .{
                .n_strx = try ctx.macho_file.makeString(sym_name),
                .n_type = macho.N_SECT,
                .n_sect = ctx.macho_file.sectionId(match),
                .n_desc = 0,
                .n_value = sect.addr,
            });
            try object.sections_as_symbols.putNoClobber(object.allocator, sect_id, local_sym_index);
            break :blk local_sym_index;
        };

        parsed_rel.where = .local;
        parsed_rel.where_index = local_sym_index;
    } else {
        const sym = object.symtab.items[rel.r_symbolnum];
        const sym_name = object.getString(sym.n_strx);

        if (MachO.symbolIsSect(sym) and !MachO.symbolIsExt(sym)) {
            const where_index = object.symbol_mapping.get(rel.r_symbolnum) orelse unreachable;
            parsed_rel.where = .local;
            parsed_rel.where_index = where_index;
        } else {
            const resolv = ctx.macho_file.symbol_resolver.get(sym_name) orelse unreachable;
            switch (resolv.where) {
                .global => {
                    parsed_rel.where = .local;
                    parsed_rel.where_index = resolv.local_sym_index;
                },
                .import => {
                    parsed_rel.where = .import;
                    parsed_rel.where_index = resolv.where_index;
                },
                else => unreachable,
            }
        }
    }

    return parsed_rel;
}

pub fn parseRelocsFromObject(
    self: *TextBlock,
    allocator: *Allocator,
    relocs: []macho.relocation_info,
    object: *Object,
    ctx: RelocContext,
) !void {
    const filtered_relocs = filterRelocs(relocs, ctx.base_addr, ctx.base_addr + self.size);
    var it = RelocIterator{
        .buffer = filtered_relocs,
    };

    var addend: u32 = 0;
    var subtractor: ?u32 = null;

    while (it.next()) |rel| {
        if (isAddend(rel, object.arch.?)) {
            // Addend is not a relocation with effect on the TextBlock, so
            // parse it and carry on.
            assert(addend == 0); // Oh no, addend was not reset!
            addend = rel.r_symbolnum;

            // Verify ADDEND is followed by a load.
            const next = @intToEnum(macho.reloc_type_arm64, it.peek().r_type);
            switch (next) {
                .ARM64_RELOC_PAGE21, .ARM64_RELOC_PAGEOFF12 => {},
                else => {
                    log.err("unexpected relocation type: expected PAGE21 or PAGEOFF12, found {s}", .{next});
                    return error.UnexpectedRelocationType;
                },
            }
            continue;
        }

        if (isSubtractor(rel, object.arch.?)) {
            // Subtractor is not a relocation with effect on the TextBlock, so
            // parse it and carry on.
            assert(subtractor == null); // Oh no, subtractor was not reset!
            assert(rel.r_extern == 1);
            const sym = object.symtab.items[rel.r_symbolnum];
            const sym_name = object.getString(sym.n_strx);

            if (MachO.symbolIsSect(sym) and !MachO.symbolIsExt(sym)) {
                const where_index = object.symbol_mapping.get(rel.r_symbolnum) orelse unreachable;
                subtractor = where_index;
            } else {
                const resolv = ctx.macho_file.symbol_resolver.get(sym_name) orelse unreachable;
                assert(resolv.where == .global);
                subtractor = resolv.local_sym_index;
            }

            // Verify SUBTRACTOR is followed by UNSIGNED.
            switch (object.arch.?) {
                .aarch64 => {
                    const next = @intToEnum(macho.reloc_type_arm64, it.peek().r_type);
                    if (next != .ARM64_RELOC_UNSIGNED) {
                        log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
                        return error.UnexpectedRelocationType;
                    }
                },
                .x86_64 => {
                    const next = @intToEnum(macho.reloc_type_x86_64, it.peek().r_type);
                    if (next != .X86_64_RELOC_UNSIGNED) {
                        log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
                        return error.UnexpectedRelocationType;
                    }
                },
                else => unreachable,
            }
            continue;
        }

        var parsed_rel = try initRelocFromObject(rel, object, ctx);

        switch (object.arch.?) {
            .aarch64 => {
                const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
                switch (rel_type) {
                    .ARM64_RELOC_ADDEND => unreachable,
                    .ARM64_RELOC_SUBTRACTOR => unreachable,
                    .ARM64_RELOC_BRANCH26 => {
                        self.parseBranch(rel, &parsed_rel, ctx);
                    },
                    .ARM64_RELOC_UNSIGNED => {
                        self.parseUnsigned(rel, &parsed_rel, subtractor, ctx);
                        subtractor = null;
                    },
                    .ARM64_RELOC_PAGE21,
                    .ARM64_RELOC_GOT_LOAD_PAGE21,
                    .ARM64_RELOC_TLVP_LOAD_PAGE21,
                    => {
                        self.parsePage(rel, &parsed_rel, addend);
                        if (rel_type == .ARM64_RELOC_PAGE21)
                            addend = 0;
                    },
                    .ARM64_RELOC_PAGEOFF12,
                    .ARM64_RELOC_GOT_LOAD_PAGEOFF12,
                    .ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
                    => {
                        self.parsePageOff(rel, &parsed_rel, addend);
                        if (rel_type == .ARM64_RELOC_PAGEOFF12)
                            addend = 0;
                    },
                    .ARM64_RELOC_POINTER_TO_GOT => {
                        self.parsePointerToGot(rel, &parsed_rel);
                    },
                }
            },
            .x86_64 => {
                switch (@intToEnum(macho.reloc_type_x86_64, rel.r_type)) {
                    .X86_64_RELOC_SUBTRACTOR => unreachable,
                    .X86_64_RELOC_BRANCH => {
                        self.parseBranch(rel, &parsed_rel, ctx);
                    },
                    .X86_64_RELOC_UNSIGNED => {
                        self.parseUnsigned(rel, &parsed_rel, subtractor, ctx);
                        subtractor = null;
                    },
                    .X86_64_RELOC_SIGNED,
                    .X86_64_RELOC_SIGNED_1,
                    .X86_64_RELOC_SIGNED_2,
                    .X86_64_RELOC_SIGNED_4,
                    => {
                        self.parseSigned(rel, &parsed_rel, ctx);
                    },
                    .X86_64_RELOC_GOT_LOAD,
                    .X86_64_RELOC_GOT,
                    .X86_64_RELOC_TLV,
                    => {
                        self.parseLoad(rel, &parsed_rel);
                    },
                }
            },
            else => unreachable,
        }

        try self.relocs.append(allocator, parsed_rel);

        const is_via_got = switch (parsed_rel.payload) {
            .pointer_to_got => true,
            .load => |load| load.kind == .got,
            .page => |page| page.kind == .got,
            .page_off => |page_off| page_off.kind == .got,
            else => false,
        };

        if (is_via_got) blk: {
            const key = MachO.GotIndirectionKey{
                .where = switch (parsed_rel.where) {
                    .local => .local,
                    .import => .import,
                },
                .where_index = parsed_rel.where_index,
            };
            if (ctx.macho_file.got_entries_map.contains(key)) break :blk;

            const got_index = @intCast(u32, ctx.macho_file.got_entries.items.len);
            try ctx.macho_file.got_entries.append(ctx.macho_file.base.allocator, key);
            try ctx.macho_file.got_entries_map.putNoClobber(ctx.macho_file.base.allocator, key, got_index);
        } else if (parsed_rel.payload == .unsigned) {
            switch (parsed_rel.where) {
                .import => {
                    try self.bindings.append(allocator, .{
                        .local_sym_index = parsed_rel.where_index,
                        .offset = parsed_rel.offset,
                    });
                },
                .local => {
                    const source_sym = ctx.macho_file.locals.items[self.local_sym_index];
                    const match = ctx.macho_file.unpackSectionId(source_sym.n_sect);
                    const seg = ctx.macho_file.load_commands.items[match.seg].Segment;
                    const sect = seg.sections.items[match.sect];
                    const sect_type = commands.sectionType(sect);

                    const should_rebase = rebase: {
                        if (!parsed_rel.payload.unsigned.is_64bit) break :rebase false;

                        // TODO actually, a check similar to what dyld is doing, that is, verifying
                        // that the segment is writable should be enough here.
                        const is_right_segment = blk: {
                            if (ctx.macho_file.data_segment_cmd_index) |idx| {
                                if (match.seg == idx) {
                                    break :blk true;
                                }
                            }
                            if (ctx.macho_file.data_const_segment_cmd_index) |idx| {
                                if (match.seg == idx) {
                                    break :blk true;
                                }
                            }
                            break :blk false;
                        };

                        if (!is_right_segment) break :rebase false;
                        if (sect_type != macho.S_LITERAL_POINTERS and
                            sect_type != macho.S_REGULAR and
                            sect_type != macho.S_MOD_INIT_FUNC_POINTERS and
                            sect_type != macho.S_MOD_TERM_FUNC_POINTERS)
                        {
                            break :rebase false;
                        }

                        break :rebase true;
                    };

                    if (should_rebase) {
                        try self.rebases.append(allocator, parsed_rel.offset);
                    }
                },
            }
        } else if (parsed_rel.payload == .branch) blk: {
            if (parsed_rel.where != .import) break :blk;
            if (ctx.macho_file.stubs_map.contains(parsed_rel.where_index)) break :blk;

            const stubs_index = @intCast(u32, ctx.macho_file.stubs.items.len);
            try ctx.macho_file.stubs.append(ctx.macho_file.base.allocator, parsed_rel.where_index);
            try ctx.macho_file.stubs_map.putNoClobber(ctx.macho_file.base.allocator, parsed_rel.where_index, stubs_index);
        }
    }
}

fn isAddend(rel: macho.relocation_info, arch: Arch) bool {
    if (arch != .aarch64) return false;
    return @intToEnum(macho.reloc_type_arm64, rel.r_type) == .ARM64_RELOC_ADDEND;
}

fn isSubtractor(rel: macho.relocation_info, arch: Arch) bool {
    return switch (arch) {
        .aarch64 => @intToEnum(macho.reloc_type_arm64, rel.r_type) == .ARM64_RELOC_SUBTRACTOR,
        .x86_64 => @intToEnum(macho.reloc_type_x86_64, rel.r_type) == .X86_64_RELOC_SUBTRACTOR,
        else => unreachable,
    };
}

fn parseUnsigned(
    self: TextBlock,
    rel: macho.relocation_info,
    out: *Relocation,
    subtractor: ?u32,
    ctx: RelocContext,
) void {
    assert(rel.r_pcrel == 0);

    const is_64bit: bool = switch (rel.r_length) {
        3 => true,
        2 => false,
        else => unreachable,
    };

    var addend: i64 = if (is_64bit)
        mem.readIntLittle(i64, self.code[out.offset..][0..8])
    else
        mem.readIntLittle(i32, self.code[out.offset..][0..4]);

    if (rel.r_extern == 0) {
        assert(out.where == .local);
        const target_sym = ctx.macho_file.locals.items[out.where_index];
        addend -= @intCast(i64, target_sym.n_value);
    }

    out.payload = .{
        .unsigned = .{
            .subtractor = subtractor,
            .is_64bit = is_64bit,
            .addend = addend,
        },
    };
}

fn parseBranch(self: TextBlock, rel: macho.relocation_info, out: *Relocation, ctx: RelocContext) void {
    _ = self;
    assert(rel.r_pcrel == 1);
    assert(rel.r_length == 2);

    out.payload = .{
        .branch = .{
            .arch = ctx.macho_file.base.options.target.cpu.arch,
        },
    };
}

fn parsePage(self: TextBlock, rel: macho.relocation_info, out: *Relocation, addend: u32) void {
    _ = self;
    assert(rel.r_pcrel == 1);
    assert(rel.r_length == 2);

    out.payload = .{
        .page = .{
            .kind = switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                .ARM64_RELOC_PAGE21 => .page,
                .ARM64_RELOC_GOT_LOAD_PAGE21 => .got,
                .ARM64_RELOC_TLVP_LOAD_PAGE21 => .tlvp,
                else => unreachable,
            },
            .addend = addend,
        },
    };
}

fn parsePageOff(self: TextBlock, rel: macho.relocation_info, out: *Relocation, addend: u32) void {
    assert(rel.r_pcrel == 0);
    assert(rel.r_length == 2);

    const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
    const op_kind: ?Relocation.PageOff.OpKind = blk: {
        if (rel_type != .ARM64_RELOC_PAGEOFF12) break :blk null;
        const op_kind: Relocation.PageOff.OpKind = if (isArithmeticOp(self.code[out.offset..][0..4]))
            .arithmetic
        else
            .load;
        break :blk op_kind;
    };

    out.payload = .{
        .page_off = .{
            .kind = switch (rel_type) {
                .ARM64_RELOC_PAGEOFF12 => .page,
                .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => .got,
                .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => .tlvp,
                else => unreachable,
            },
            .addend = addend,
            .op_kind = op_kind,
        },
    };
}

fn parsePointerToGot(self: TextBlock, rel: macho.relocation_info, out: *Relocation) void {
    _ = self;
    assert(rel.r_pcrel == 1);
    assert(rel.r_length == 2);

    out.payload = .{
        .pointer_to_got = .{},
    };
}

fn parseSigned(self: TextBlock, rel: macho.relocation_info, out: *Relocation, ctx: RelocContext) void {
    assert(rel.r_pcrel == 1);
    assert(rel.r_length == 2);

    const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
    const correction: i4 = switch (rel_type) {
        .X86_64_RELOC_SIGNED => 0,
        .X86_64_RELOC_SIGNED_1 => 1,
        .X86_64_RELOC_SIGNED_2 => 2,
        .X86_64_RELOC_SIGNED_4 => 4,
        else => unreachable,
    };
    var addend: i64 = mem.readIntLittle(i32, self.code[out.offset..][0..4]) + correction;

    if (rel.r_extern == 0) {
        const source_sym = ctx.macho_file.locals.items[self.local_sym_index];
        const target_sym = switch (out.where) {
            .local => ctx.macho_file.locals.items[out.where_index],
            .import => ctx.macho_file.imports.items[out.where_index],
        };
        addend = @intCast(i64, source_sym.n_value + out.offset + 4) + addend - @intCast(i64, target_sym.n_value);
    }

    out.payload = .{
        .signed = .{
            .correction = correction,
            .addend = addend,
        },
    };
}

fn parseLoad(self: TextBlock, rel: macho.relocation_info, out: *Relocation) void {
    assert(rel.r_pcrel == 1);
    assert(rel.r_length == 2);

    const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
    const addend: i32 = if (rel_type == .X86_64_RELOC_GOT)
        mem.readIntLittle(i32, self.code[out.offset..][0..4])
    else
        0;

    out.payload = .{
        .load = .{
            .kind = switch (rel_type) {
                .X86_64_RELOC_GOT_LOAD, .X86_64_RELOC_GOT => .got,
                .X86_64_RELOC_TLV => .tlvp,
                else => unreachable,
            },
            .addend = addend,
        },
    };
}

pub fn resolveRelocs(self: *TextBlock, macho_file: *MachO) !void {
    for (self.relocs.items) |rel| {
        log.debug("relocating {}", .{rel});

        const source_addr = blk: {
            const sym = macho_file.locals.items[self.local_sym_index];
            break :blk sym.n_value + rel.offset;
        };
        const target_addr = blk: {
            const is_via_got = switch (rel.payload) {
                .pointer_to_got => true,
                .page => |page| page.kind == .got,
                .page_off => |page_off| page_off.kind == .got,
                .load => |load| load.kind == .got,
                else => false,
            };

            if (is_via_got) {
                const dc_seg = macho_file.load_commands.items[macho_file.data_const_segment_cmd_index.?].Segment;
                const got = dc_seg.sections.items[macho_file.got_section_index.?];
                const got_index = macho_file.got_entries_map.get(.{
                    .where = switch (rel.where) {
                        .local => .local,
                        .import => .import,
                    },
                    .where_index = rel.where_index,
                }) orelse {
                    const sym = switch (rel.where) {
                        .local => macho_file.locals.items[rel.where_index],
                        .import => macho_file.imports.items[rel.where_index],
                    };
                    log.err("expected GOT entry for symbol '{s}'", .{macho_file.getString(sym.n_strx)});
                    log.err("  this is an internal linker error", .{});
                    return error.FailedToResolveRelocationTarget;
                };
                break :blk got.addr + got_index * @sizeOf(u64);
            }

            switch (rel.where) {
                .local => {
                    const sym = macho_file.locals.items[rel.where_index];
                    const is_tlv = is_tlv: {
                        const source_sym = macho_file.locals.items[self.local_sym_index];
                        const match = macho_file.unpackSectionId(source_sym.n_sect);
                        const seg = macho_file.load_commands.items[match.seg].Segment;
                        const sect = seg.sections.items[match.sect];
                        break :is_tlv commands.sectionType(sect) == macho.S_THREAD_LOCAL_VARIABLES;
                    };
                    if (is_tlv) {
                        // For TLV relocations, the value specified as a relocation is the displacement from the
                        // TLV initializer (either value in __thread_data or zero-init in __thread_bss) to the first
                        // defined TLV template init section in the following order:
                        // * wrt to __thread_data if defined, then
                        // * wrt to __thread_bss
                        const seg = macho_file.load_commands.items[macho_file.data_segment_cmd_index.?].Segment;
                        const base_address = inner: {
                            if (macho_file.tlv_data_section_index) |i| {
                                break :inner seg.sections.items[i].addr;
                            } else if (macho_file.tlv_bss_section_index) |i| {
                                break :inner seg.sections.items[i].addr;
                            } else {
                                log.err("threadlocal variables present but no initializer sections found", .{});
                                log.err("  __thread_data not found", .{});
                                log.err("  __thread_bss not found", .{});
                                return error.FailedToResolveRelocationTarget;
                            }
                        };
                        break :blk sym.n_value - base_address;
                    }

                    break :blk sym.n_value;
                },
                .import => {
                    const stubs_index = macho_file.stubs_map.get(rel.where_index) orelse {
                        // TODO verify in TextBlock that the symbol is indeed dynamically bound.
                        break :blk 0; // Dynamically bound by dyld.
                    };
                    const segment = macho_file.load_commands.items[macho_file.text_segment_cmd_index.?].Segment;
                    const stubs = segment.sections.items[macho_file.stubs_section_index.?];
                    break :blk stubs.addr + stubs_index * stubs.reserved2;
                },
            }
        };

        log.debug("  | source_addr = 0x{x}", .{source_addr});
        log.debug("  | target_addr = 0x{x}", .{target_addr});

        try rel.resolve(.{
            .block = self,
            .offset = rel.offset,
            .source_addr = source_addr,
            .target_addr = target_addr,
            .macho_file = macho_file,
        });
    }
}

pub fn print_this(self: *const TextBlock, macho_file: MachO) void {
    log.warn("TextBlock", .{});
    log.warn("  {}: {}", .{ self.local_sym_index, macho_file.locals.items[self.local_sym_index] });
    if (self.stab) |stab| {
        log.warn("  stab: {}", .{stab});
    }
    if (self.aliases.items.len > 0) {
        log.warn("  aliases: {any}", .{self.aliases.items});
    }
    if (self.references.count() > 0) {
        log.warn("  references: {any}", .{self.references.keys()});
    }
    if (self.contained) |contained| {
        log.warn("  contained symbols:", .{});
        for (contained) |sym_at_off| {
            if (sym_at_off.stab) |stab| {
                log.warn("    {}: {}, stab: {}", .{ sym_at_off.offset, sym_at_off.local_sym_index, stab });
            } else {
                log.warn("    {}: {}", .{ sym_at_off.offset, sym_at_off.local_sym_index });
            }
        }
    }
    log.warn("  code.len = {}", .{self.code.len});
    if (self.relocs.items.len > 0) {
        log.warn("  relocations:", .{});
        for (self.relocs.items) |rel| {
            log.warn("    {}", .{rel});
        }
    }
    if (self.rebases.items.len > 0) {
        log.warn("  rebases: {any}", .{self.rebases.items});
    }
    if (self.bindings.items.len > 0) {
        log.warn("  bindings: {any}", .{self.bindings.items});
    }
    if (self.dices.items.len > 0) {
        log.warn("  dices: {any}", .{self.dices.items});
    }
    log.warn("  size = {}", .{self.size});
    log.warn("  align = {}", .{self.alignment});
}

pub fn print(self: *const TextBlock, macho_file: MachO) void {
    if (self.prev) |prev| {
        prev.print(macho_file);
    }
    self.print_this(macho_file);
}

const RelocIterator = struct {
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

fn filterRelocs(relocs: []macho.relocation_info, start_addr: u64, end_addr: u64) []macho.relocation_info {
    const Predicate = struct {
        addr: u64,

        pub fn predicate(self: @This(), rel: macho.relocation_info) bool {
            return rel.r_address < self.addr;
        }
    };

    const start = MachO.findFirst(macho.relocation_info, relocs, 0, Predicate{ .addr = end_addr });
    const end = MachO.findFirst(macho.relocation_info, relocs, start, Predicate{ .addr = start_addr });

    return relocs[start..end];
}

inline fn isArithmeticOp(inst: *const [4]u8) bool {
    const group_decode = @truncate(u5, inst[3]);
    return ((group_decode >> 2) == 4);
}
