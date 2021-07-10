const std = @import("std");
const aarch64 = @import("../../codegen/aarch64.zig");
const assert = std.debug.assert;
const commands = @import("commands.zig");
const log = std.log.scoped(.reloc);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const Allocator = mem.Allocator;
const Arch = std.Target.Cpu.Arch;
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
const TextBlock = Zld.TextBlock;
const Zld = @import("Zld.zig");

pub const Relocation = struct {
    /// Offset within the `block`s code buffer.
    /// Note relocation size can be inferred by relocation's kind.
    offset: u32,

    /// Parent block containing this relocation.
    block: *TextBlock,

    /// Target symbol: either a regular or a proxy.
    target: *Symbol,

    payload: union(enum) {
        unsigned: Unsigned,
        branch: Branch,
        page: Page,
        page_off: PageOff,
        pointer_to_got: PointerToGot,
        signed: Signed,
        load: Load,
    },

    pub const Unsigned = struct {
        subtractor: ?*Symbol = null,

        /// Addend embedded directly in the relocation slot
        addend: i64,

        /// Extracted from r_length:
        /// => 3 implies true
        /// => 2 implies false
        /// => * is unreachable
        is_64bit: bool,

        source_sect_addr: ?u64 = null,

        pub fn resolve(self: Unsigned, base: Relocation, _: u64, target_addr: u64) !void {
            const addend = if (self.source_sect_addr) |addr|
                self.addend - @intCast(i64, addr)
            else
                self.addend;

            const result = if (self.subtractor) |subtractor|
                @intCast(i64, target_addr) - @intCast(i64, subtractor.payload.regular.address) + addend
            else
                @intCast(i64, target_addr) + addend;

            if (self.is_64bit) {
                mem.writeIntLittle(u64, base.block.code[base.offset..][0..8], @bitCast(u64, result));
            } else {
                mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], @truncate(u32, @bitCast(u64, result)));
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

        pub fn resolve(self: Branch, base: Relocation, source_addr: u64, target_addr: u64) !void {
            switch (self.arch) {
                .aarch64 => {
                    const displacement = try math.cast(i28, @intCast(i64, target_addr) - @intCast(i64, source_addr));
                    var inst = aarch64.Instruction{
                        .unconditional_branch_immediate = mem.bytesToValue(
                            meta.TagPayload(
                                aarch64.Instruction,
                                aarch64.Instruction.unconditional_branch_immediate,
                            ),
                            base.block.code[base.offset..][0..4],
                        ),
                    };
                    inst.unconditional_branch_immediate.imm26 = @truncate(u26, @bitCast(u28, displacement >> 2));
                    mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], inst.toU32());
                },
                .x86_64 => {
                    const displacement = try math.cast(i32, @intCast(i64, target_addr) - @intCast(i64, source_addr) - 4);
                    mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], @bitCast(u32, displacement));
                },
                else => return error.UnsupportedCpuArchitecture,
            }
        }

        pub fn format(self: Branch, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
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
        addend: ?u32 = null,

        pub fn resolve(self: Page, base: Relocation, source_addr: u64, target_addr: u64) !void {
            const actual_target_addr = if (self.addend) |addend| target_addr + addend else target_addr;
            const source_page = @intCast(i32, source_addr >> 12);
            const target_page = @intCast(i32, actual_target_addr >> 12);
            const pages = @bitCast(u21, @intCast(i21, target_page - source_page));

            var inst = aarch64.Instruction{
                .pc_relative_address = mem.bytesToValue(
                    meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.pc_relative_address,
                    ),
                    base.block.code[base.offset..][0..4],
                ),
            };
            inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
            inst.pc_relative_address.immlo = @truncate(u2, pages);

            mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], inst.toU32());
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
            if (self.addend) |add| {
                try std.fmt.format(writer, ".addend = {}, ", .{add});
            }
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub const PageOff = struct {
        kind: enum {
            page,
            got,
            tlvp,
        },
        addend: ?u32 = null,
        op_kind: ?OpKind = null,

        pub const OpKind = enum {
            arithmetic,
            load,
        };

        pub fn resolve(self: PageOff, base: Relocation, source_addr: u64, target_addr: u64) !void {
            switch (self.kind) {
                .page => {
                    const actual_target_addr = if (self.addend) |addend| target_addr + addend else target_addr;
                    const narrowed = @truncate(u12, actual_target_addr);

                    const op_kind = self.op_kind orelse unreachable;
                    var inst: aarch64.Instruction = blk: {
                        switch (op_kind) {
                            .arithmetic => {
                                break :blk .{
                                    .add_subtract_immediate = mem.bytesToValue(
                                        meta.TagPayload(
                                            aarch64.Instruction,
                                            aarch64.Instruction.add_subtract_immediate,
                                        ),
                                        base.block.code[base.offset..][0..4],
                                    ),
                                };
                            },
                            .load => {
                                break :blk .{
                                    .load_store_register = mem.bytesToValue(
                                        meta.TagPayload(
                                            aarch64.Instruction,
                                            aarch64.Instruction.load_store_register,
                                        ),
                                        base.block.code[base.offset..][0..4],
                                    ),
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

                    mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], inst.toU32());
                },
                .got => {
                    const narrowed = @truncate(u12, target_addr);
                    var inst: aarch64.Instruction = .{
                        .load_store_register = mem.bytesToValue(
                            meta.TagPayload(
                                aarch64.Instruction,
                                aarch64.Instruction.load_store_register,
                            ),
                            base.block.code[base.offset..][0..4],
                        ),
                    };
                    const offset = try math.divExact(u12, narrowed, 8);
                    inst.load_store_register.offset = offset;
                    mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], inst.toU32());
                },
                .tlvp => {
                    const RegInfo = struct {
                        rd: u5,
                        rn: u5,
                        size: u1,
                    };
                    const reg_info: RegInfo = blk: {
                        if (isArithmeticOp(base.block.code[base.offset..][0..4])) {
                            const inst = mem.bytesToValue(
                                meta.TagPayload(
                                    aarch64.Instruction,
                                    aarch64.Instruction.add_subtract_immediate,
                                ),
                                base.block.code[base.offset..][0..4],
                            );
                            break :blk .{
                                .rd = inst.rd,
                                .rn = inst.rn,
                                .size = inst.sf,
                            };
                        } else {
                            const inst = mem.bytesToValue(
                                meta.TagPayload(
                                    aarch64.Instruction,
                                    aarch64.Instruction.load_store_register,
                                ),
                                base.block.code[base.offset..][0..4],
                            );
                            break :blk .{
                                .rd = inst.rt,
                                .rn = inst.rn,
                                .size = @truncate(u1, inst.size),
                            };
                        }
                    };
                    const narrowed = @truncate(u12, target_addr);
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
                    mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], inst.toU32());
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
            if (self.addend) |add| {
                try std.fmt.format(writer, ".addend = {}, ", .{add});
            }
            if (self.op_kind) |op| {
                try std.fmt.format(writer, ".op_kind = {s}, ", .{op});
            }
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub const PointerToGot = struct {
        pub fn resolve(self: PointerToGot, base: Relocation, source_addr: u64, target_addr: u64) !void {
            const result = try math.cast(i32, @intCast(i64, target_addr) - @intCast(i64, source_addr));
            mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], @bitCast(u32, result));
        }

        pub fn format(self: PointerToGot, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "PointerToGot {{}}", .{});
        }
    };

    pub const Signed = struct {
        addend: i32,
        correction: i4,

        pub fn resolve(self: Signed, base: Relocation, source_addr: u64, target_addr: u64) !void {
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
        addend: ?i32 = null,

        pub fn resolve(self: Load, base: Relocation, source_addr: u64, target_addr: u64) !void {
            if (self.kind == .tlvp) {
                // We need to rewrite the opcode from movq to leaq.
                base.block.code[base.offset - 2] = 0x8d;
            }
            const addend = if (self.addend) |addend| addend else 0;
            const displacement = try math.cast(
                i32,
                @intCast(i64, target_addr) - @intCast(i64, source_addr) - 4 + addend,
            );
            mem.writeIntLittle(u32, base.block.code[base.offset..][0..4], @bitCast(u32, displacement));
        }

        pub fn format(self: Load, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, "Load {{ ", .{});
            try std.fmt.format(writer, "{s}, ", .{self.kind});
            if (self.addend) |addend| {
                try std.fmt.format(writer, ".addend = {}, ", .{addend});
            }
            try std.fmt.format(writer, "}}", .{});
        }
    };

    pub fn resolve(self: Relocation, zld: *Zld) !void {
        const source_addr = blk: {
            const sym = zld.locals.items[self.block.local_sym_index];
            break :blk sym.payload.regular.address + self.offset;
        };
        const target_addr = blk: {
            const is_via_got = switch (self.payload) {
                .pointer_to_got => true,
                .page => |page| page.kind == .got,
                .page_off => |page_off| page_off.kind == .got,
                .load => |load| load.kind == .got,
                else => false,
            };

            if (is_via_got) {
                const dc_seg = zld.load_commands.items[zld.data_const_segment_cmd_index.?].Segment;
                const got = dc_seg.sections.items[zld.got_section_index.?];
                const got_index = self.target.got_index orelse {
                    log.err("expected GOT entry for symbol '{s}'", .{self.target.name});
                    log.err("  this is an internal linker error", .{});
                    return error.FailedToResolveRelocationTarget;
                };
                break :blk got.addr + got_index * @sizeOf(u64);
            }

            switch (self.target.payload) {
                .regular => |reg| {
                    const is_tlv = is_tlv: {
                        const sym = zld.locals.items[self.block.local_sym_index];
                        const seg = zld.load_commands.items[sym.payload.regular.segment_id].Segment;
                        const sect = seg.sections.items[sym.payload.regular.section_id];
                        break :is_tlv commands.sectionType(sect) == macho.S_THREAD_LOCAL_VARIABLES;
                    };
                    if (is_tlv) {
                        // For TLV relocations, the value specified as a relocation is the displacement from the
                        // TLV initializer (either value in __thread_data or zero-init in __thread_bss) to the first
                        // defined TLV template init section in the following order:
                        // * wrt to __thread_data if defined, then
                        // * wrt to __thread_bss
                        const seg = zld.load_commands.items[zld.data_segment_cmd_index.?].Segment;
                        const base_address = inner: {
                            if (zld.tlv_data_section_index) |i| {
                                break :inner seg.sections.items[i].addr;
                            } else if (zld.tlv_bss_section_index) |i| {
                                break :inner seg.sections.items[i].addr;
                            } else {
                                log.err("threadlocal variables present but no initializer sections found", .{});
                                log.err("  __thread_data not found", .{});
                                log.err("  __thread_bss not found", .{});
                                return error.FailedToResolveRelocationTarget;
                            }
                        };
                        break :blk reg.address - base_address;
                    }

                    break :blk reg.address;
                },
                .proxy => |proxy| {
                    if (mem.eql(u8, self.target.name, "__tlv_bootstrap")) {
                        break :blk 0; // Dynamically bound by dyld.
                        // const segment = zld.load_commands.items[zld.data_segment_cmd_index.?].Segment;
                        // const tlv = segment.sections.items[zld.tlv_section_index.?];
                        // break :blk tlv.addr;
                    }

                    const segment = zld.load_commands.items[zld.text_segment_cmd_index.?].Segment;
                    const stubs = segment.sections.items[zld.stubs_section_index.?];
                    const stubs_index = self.target.stubs_index orelse {
                        if (proxy.bind_info.items.len > 0) {
                            break :blk 0; // Dynamically bound by dyld.
                        }
                        log.err("expected stubs index or dynamic bind address for symbol '{s}'", .{
                            self.target.name,
                        });
                        log.err("  this is an internal linker error", .{});
                        return error.FailedToResolveRelocationTarget;
                    };
                    break :blk stubs.addr + stubs_index * stubs.reserved2;
                },
                else => {
                    log.err("failed to resolve symbol '{s}' as a relocation target", .{self.target.name});
                    log.err("  this is an internal linker error", .{});
                    return error.FailedToResolveRelocationTarget;
                },
            }
        };

        log.debug("relocating {}", .{self});
        log.debug("  | source_addr = 0x{x}", .{source_addr});
        log.debug("  | target_addr = 0x{x}", .{target_addr});

        switch (self.payload) {
            .unsigned => |unsigned| try unsigned.resolve(self, source_addr, target_addr),
            .branch => |branch| try branch.resolve(self, source_addr, target_addr),
            .page => |page| try page.resolve(self, source_addr, target_addr),
            .page_off => |page_off| try page_off.resolve(self, source_addr, target_addr),
            .pointer_to_got => |pointer_to_got| try pointer_to_got.resolve(self, source_addr, target_addr),
            .signed => |signed| try signed.resolve(self, source_addr, target_addr),
            .load => |load| try load.resolve(self, source_addr, target_addr),
        }
    }

    pub fn format(self: Relocation, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try std.fmt.format(writer, "Relocation {{ ", .{});
        try std.fmt.format(writer, ".offset = {}, ", .{self.offset});
        try std.fmt.format(writer, ".block = {}", .{self.block.local_sym_index});
        try std.fmt.format(writer, ".target = {}, ", .{self.target});

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

pub const Parser = struct {
    object: *Object,
    zld: *Zld,
    it: *RelocIterator,
    block: *TextBlock,

    /// Base address of the parsed text block in the source section.
    base_addr: u64,

    /// Used only when targeting aarch64
    addend: ?u32 = null,

    /// Parsed subtractor symbol from _RELOC_SUBTRACTOR reloc type.
    subtractor: ?*Symbol = null,

    pub fn parse(self: *Parser) !void {
        while (self.it.next()) |rel| {
            const out_rel = blk: {
                switch (self.object.arch.?) {
                    .aarch64 => {
                        const out_rel = switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                            .ARM64_RELOC_BRANCH26 => try self.parseBranch(rel),
                            .ARM64_RELOC_SUBTRACTOR => {
                                // Subtractor is not a relocation with effect on the TextBlock, so
                                // parse it and carry on.
                                try self.parseSubtractor(rel);

                                // Verify SUBTRACTOR is followed by UNSIGNED.
                                const next = @intToEnum(macho.reloc_type_arm64, self.it.peek().r_type);
                                if (next != .ARM64_RELOC_UNSIGNED) {
                                    log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
                                    return error.UnexpectedRelocationType;
                                }
                                continue;
                            },
                            .ARM64_RELOC_UNSIGNED => try self.parseUnsigned(rel),
                            .ARM64_RELOC_ADDEND => {
                                // Addend is not a relocation with effect on the TextBlock, so
                                // parse it and carry on.
                                try self.parseAddend(rel);

                                // Verify ADDEND is followed by a load.
                                const next = @intToEnum(macho.reloc_type_arm64, self.it.peek().r_type);
                                switch (next) {
                                    .ARM64_RELOC_PAGE21, .ARM64_RELOC_PAGEOFF12 => {},
                                    else => {
                                        log.err("unexpected relocation type: expected PAGE21 or PAGEOFF12, found {s}", .{next});
                                        return error.UnexpectedRelocationType;
                                    },
                                }
                                continue;
                            },
                            .ARM64_RELOC_PAGE21,
                            .ARM64_RELOC_GOT_LOAD_PAGE21,
                            .ARM64_RELOC_TLVP_LOAD_PAGE21,
                            => try self.parsePage(rel),
                            .ARM64_RELOC_PAGEOFF12,
                            .ARM64_RELOC_GOT_LOAD_PAGEOFF12,
                            .ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
                            => try self.parsePageOff(rel),
                            .ARM64_RELOC_POINTER_TO_GOT => try self.parsePointerToGot(rel),
                        };
                        break :blk out_rel;
                    },
                    .x86_64 => {
                        const out_rel = switch (@intToEnum(macho.reloc_type_x86_64, rel.r_type)) {
                            .X86_64_RELOC_BRANCH => try self.parseBranch(rel),
                            .X86_64_RELOC_SUBTRACTOR => {
                                // Subtractor is not a relocation with effect on the TextBlock, so
                                // parse it and carry on.
                                try self.parseSubtractor(rel);

                                // Verify SUBTRACTOR is followed by UNSIGNED.
                                const next = @intToEnum(macho.reloc_type_x86_64, self.it.peek().r_type);
                                if (next != .X86_64_RELOC_UNSIGNED) {
                                    log.err("unexpected relocation type: expected UNSIGNED, found {s}", .{next});
                                    return error.UnexpectedRelocationType;
                                }
                                continue;
                            },
                            .X86_64_RELOC_UNSIGNED => try self.parseUnsigned(rel),
                            .X86_64_RELOC_SIGNED,
                            .X86_64_RELOC_SIGNED_1,
                            .X86_64_RELOC_SIGNED_2,
                            .X86_64_RELOC_SIGNED_4,
                            => try self.parseSigned(rel),
                            .X86_64_RELOC_GOT_LOAD,
                            .X86_64_RELOC_GOT,
                            .X86_64_RELOC_TLV,
                            => try self.parseLoad(rel),
                        };
                        break :blk out_rel;
                    },
                    else => unreachable,
                }
            };
            try self.block.relocs.append(out_rel);

            if (out_rel.target.payload == .regular) {
                try self.block.references.put(out_rel.target.payload.regular.local_sym_index, {});
            }

            const is_via_got = switch (out_rel.payload) {
                .pointer_to_got => true,
                .load => |load| load.kind == .got,
                .page => |page| page.kind == .got,
                .page_off => |page_off| page_off.kind == .got,
                else => false,
            };

            if (is_via_got and out_rel.target.got_index == null) {
                const index = @intCast(u32, self.zld.got_entries.items.len);
                out_rel.target.got_index = index;
                try self.zld.got_entries.append(self.zld.allocator, out_rel.target);

                log.debug("adding GOT entry for symbol {s} at index {}", .{ out_rel.target.name, index });
            } else if (out_rel.payload == .unsigned) {
                const sym = out_rel.target;
                switch (sym.payload) {
                    .proxy => {
                        try sym.payload.proxy.bind_info.append(self.zld.allocator, .{
                            .local_sym_index = self.block.local_sym_index,
                            .offset = out_rel.offset,
                        });
                    },
                    else => {
                        const source_sym = self.zld.locals.items[self.block.local_sym_index];
                        const source_reg = &source_sym.payload.regular;
                        const seg = self.zld.load_commands.items[source_reg.segment_id].Segment;
                        const sect = seg.sections.items[source_reg.section_id];
                        const sect_type = commands.sectionType(sect);

                        const should_rebase = rebase: {
                            if (!out_rel.payload.unsigned.is_64bit) break :rebase false;

                            // TODO actually, a check similar to what dyld is doing, that is, verifying
                            // that the segment is writable should be enough here.
                            const is_right_segment = blk: {
                                if (self.zld.data_segment_cmd_index) |idx| {
                                    if (source_reg.segment_id == idx) {
                                        break :blk true;
                                    }
                                }
                                if (self.zld.data_const_segment_cmd_index) |idx| {
                                    if (source_reg.segment_id == idx) {
                                        break :blk true;
                                    }
                                }
                                break :blk false;
                            };

                            if (!is_right_segment) break :rebase false;
                            if (sect_type != macho.S_LITERAL_POINTERS and
                                sect_type != macho.S_REGULAR)
                            {
                                break :rebase false;
                            }

                            break :rebase true;
                        };

                        if (should_rebase) {
                            try self.block.rebases.append(out_rel.offset);
                        }
                    },
                }
            } else if (out_rel.payload == .branch) blk: {
                const sym = out_rel.target;

                if (sym.stubs_index != null) break :blk;
                if (sym.payload != .proxy) break :blk;

                const index = @intCast(u32, self.zld.stubs.items.len);
                sym.stubs_index = index;
                try self.zld.stubs.append(self.zld.allocator, sym);

                log.debug("adding stub entry for symbol {s} at index {}", .{ sym.name, index });
            }
        }
    }

    fn parseBaseRelInfo(self: *Parser, rel: macho.relocation_info) !Relocation {
        const offset = @intCast(u32, @intCast(u64, rel.r_address) - self.base_addr);
        const target = try self.object.symbolFromReloc(rel);
        return Relocation{
            .offset = offset,
            .target = target,
            .block = self.block,
            .payload = undefined,
        };
    }

    fn parseUnsigned(self: *Parser, rel: macho.relocation_info) !Relocation {
        defer {
            // Reset parser's subtractor state
            self.subtractor = null;
        }

        assert(rel.r_pcrel == 0);

        var parsed = try self.parseBaseRelInfo(rel);
        const is_64bit: bool = switch (rel.r_length) {
            3 => true,
            2 => false,
            else => unreachable,
        };
        const addend: i64 = if (is_64bit)
            mem.readIntLittle(i64, self.block.code[parsed.offset..][0..8])
        else
            mem.readIntLittle(i32, self.block.code[parsed.offset..][0..4]);
        const source_sect_addr = if (rel.r_extern == 0) blk: {
            if (parsed.target.payload == .regular) break :blk parsed.target.payload.regular.address;
            break :blk null;
        } else null;

        parsed.payload = .{
            .unsigned = .{
                .subtractor = self.subtractor,
                .is_64bit = is_64bit,
                .addend = addend,
                .source_sect_addr = source_sect_addr,
            },
        };

        return parsed;
    }

    fn parseBranch(self: *Parser, rel: macho.relocation_info) !Relocation {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        var parsed = try self.parseBaseRelInfo(rel);
        parsed.payload = .{
            .branch = .{
                .arch = self.object.arch.?,
            },
        };
        return parsed;
    }

    fn parsePage(self: *Parser, rel: macho.relocation_info) !Relocation {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);

        defer if (rel_type == .ARM64_RELOC_PAGE21) {
            // Reset parser's addend state
            self.addend = null;
        };

        const addend = if (rel_type == .ARM64_RELOC_PAGE21)
            self.addend
        else
            null;

        var parsed = try self.parseBaseRelInfo(rel);
        parsed.payload = .{
            .page = .{
                .kind = switch (rel_type) {
                    .ARM64_RELOC_PAGE21 => .page,
                    .ARM64_RELOC_GOT_LOAD_PAGE21 => .got,
                    .ARM64_RELOC_TLVP_LOAD_PAGE21 => .tlvp,
                    else => unreachable,
                },
                .addend = addend,
            },
        };
        return parsed;
    }

    fn parsePageOff(self: *Parser, rel: macho.relocation_info) !Relocation {
        assert(rel.r_pcrel == 0);
        assert(rel.r_length == 2);

        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);

        defer if (rel_type == .ARM64_RELOC_PAGEOFF12) {
            // Reset parser's addend state
            self.addend = null;
        };

        const addend = if (rel_type == .ARM64_RELOC_PAGEOFF12)
            self.addend
        else
            null;

        var parsed = try self.parseBaseRelInfo(rel);
        const op_kind: ?Relocation.PageOff.OpKind = blk: {
            if (rel_type != .ARM64_RELOC_PAGEOFF12) break :blk null;
            const op_kind: Relocation.PageOff.OpKind = if (isArithmeticOp(self.block.code[parsed.offset..][0..4]))
                .arithmetic
            else
                .load;
            break :blk op_kind;
        };

        parsed.payload = .{
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
        return parsed;
    }

    fn parsePointerToGot(self: *Parser, rel: macho.relocation_info) !Relocation {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        var parsed = try self.parseBaseRelInfo(rel);
        parsed.payload = .{
            .pointer_to_got = .{},
        };
        return parsed;
    }

    fn parseAddend(self: *Parser, rel: macho.relocation_info) !void {
        assert(rel.r_pcrel == 0);
        assert(rel.r_extern == 0);
        assert(self.addend == null);

        self.addend = rel.r_symbolnum;
    }

    fn parseSigned(self: *Parser, rel: macho.relocation_info) !Relocation {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        var parsed = try self.parseBaseRelInfo(rel);
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        const correction: i4 = switch (rel_type) {
            .X86_64_RELOC_SIGNED => 0,
            .X86_64_RELOC_SIGNED_1 => 1,
            .X86_64_RELOC_SIGNED_2 => 2,
            .X86_64_RELOC_SIGNED_4 => 4,
            else => unreachable,
        };
        const addend = mem.readIntLittle(i32, self.block.code[parsed.offset..][0..4]) + correction;

        parsed.payload = .{
            .signed = .{
                .correction = correction,
                .addend = addend,
            },
        };

        return parsed;
    }

    fn parseSubtractor(self: *Parser, rel: macho.relocation_info) !void {
        assert(rel.r_pcrel == 0);
        assert(self.subtractor == null);

        self.subtractor = try self.object.symbolFromReloc(rel);
    }

    fn parseLoad(self: *Parser, rel: macho.relocation_info) !Relocation {
        assert(rel.r_pcrel == 1);
        assert(rel.r_length == 2);

        var parsed = try self.parseBaseRelInfo(rel);
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
        const addend = if (rel_type == .X86_64_RELOC_GOT)
            mem.readIntLittle(i32, self.block.code[parsed.offset..][0..4])
        else
            null;

        parsed.payload = .{
            .load = .{
                .kind = switch (rel_type) {
                    .X86_64_RELOC_GOT_LOAD, .X86_64_RELOC_GOT => .got,
                    .X86_64_RELOC_TLV => .tlvp,
                    else => unreachable,
                },
                .addend = addend,
            },
        };
        return parsed;
    }
};

inline fn isArithmeticOp(inst: *const [4]u8) bool {
    const group_decode = @truncate(u5, inst[3]);
    return ((group_decode >> 2) == 4);
}
