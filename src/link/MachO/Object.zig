const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const fs = std.fs;
const io = std.io;
const log = std.log.scoped(.object);
const macho = std.macho;
const mem = std.mem;
const reloc = @import("reloc.zig");

const Allocator = mem.Allocator;
const Arch = std.Target.Cpu.Arch;
const Relocation = reloc.Relocation;
const Symbol = @import("Symbol.zig");
const TextBlock = Zld.TextBlock;
const Zld = @import("Zld.zig");

usingnamespace @import("commands.zig");

allocator: *Allocator,
arch: ?Arch = null,
header: ?macho.mach_header_64 = null,
file: ?fs.File = null,
file_offset: ?u32 = null,
name: ?[]const u8 = null,
mtime: ?u64 = null,

load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},
sections: std.ArrayListUnmanaged(Section) = .{},

segment_cmd_index: ?u16 = null,
symtab_cmd_index: ?u16 = null,
dysymtab_cmd_index: ?u16 = null,
build_version_cmd_index: ?u16 = null,
data_in_code_cmd_index: ?u16 = null,

text_section_index: ?u16 = null,
mod_init_func_section_index: ?u16 = null,

// __DWARF segment sections
dwarf_debug_info_index: ?u16 = null,
dwarf_debug_abbrev_index: ?u16 = null,
dwarf_debug_str_index: ?u16 = null,
dwarf_debug_line_index: ?u16 = null,
dwarf_debug_ranges_index: ?u16 = null,

symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

symbols: std.ArrayListUnmanaged(*Symbol) = .{},
stabs: std.ArrayListUnmanaged(*Symbol) = .{},
initializers: std.ArrayListUnmanaged(u32) = .{},
data_in_code_entries: std.ArrayListUnmanaged(macho.data_in_code_entry) = .{},

pub const Section = struct {
    inner: macho.section_64,
    code: []u8,
    relocs: ?[]*Relocation,
    target_map: ?struct {
        segment_id: u16,
        section_id: u16,
        offset: u32,
    } = null,

    pub fn deinit(self: *Section, allocator: *Allocator) void {
        allocator.free(self.code);

        if (self.relocs) |relocs| {
            for (relocs) |rel| {
                allocator.destroy(rel);
            }
            allocator.free(relocs);
        }
    }
};

const DebugInfo = struct {
    inner: dwarf.DwarfInfo,
    debug_info: []u8,
    debug_abbrev: []u8,
    debug_str: []u8,
    debug_line: []u8,
    debug_ranges: []u8,

    pub fn parseFromObject(allocator: *Allocator, object: *const Object) !?DebugInfo {
        var debug_info = blk: {
            const index = object.dwarf_debug_info_index orelse return null;
            break :blk try object.readSection(allocator, index);
        };
        var debug_abbrev = blk: {
            const index = object.dwarf_debug_abbrev_index orelse return null;
            break :blk try object.readSection(allocator, index);
        };
        var debug_str = blk: {
            const index = object.dwarf_debug_str_index orelse return null;
            break :blk try object.readSection(allocator, index);
        };
        var debug_line = blk: {
            const index = object.dwarf_debug_line_index orelse return null;
            break :blk try object.readSection(allocator, index);
        };
        var debug_ranges = blk: {
            if (object.dwarf_debug_ranges_index) |ind| {
                break :blk try object.readSection(allocator, ind);
            }
            break :blk try allocator.alloc(u8, 0);
        };

        var inner: dwarf.DwarfInfo = .{
            .endian = .Little,
            .debug_info = debug_info,
            .debug_abbrev = debug_abbrev,
            .debug_str = debug_str,
            .debug_line = debug_line,
            .debug_ranges = debug_ranges,
        };
        try dwarf.openDwarfDebugInfo(&inner, allocator);

        return DebugInfo{
            .inner = inner,
            .debug_info = debug_info,
            .debug_abbrev = debug_abbrev,
            .debug_str = debug_str,
            .debug_line = debug_line,
            .debug_ranges = debug_ranges,
        };
    }

    pub fn deinit(self: *DebugInfo, allocator: *Allocator) void {
        allocator.free(self.debug_info);
        allocator.free(self.debug_abbrev);
        allocator.free(self.debug_str);
        allocator.free(self.debug_line);
        allocator.free(self.debug_ranges);
        self.inner.abbrev_table_list.deinit();
        self.inner.compile_unit_list.deinit();
        self.inner.func_list.deinit();
    }
};

pub fn createAndParseFromPath(allocator: *Allocator, arch: Arch, path: []const u8) !?*Object {
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    errdefer file.close();

    const object = try allocator.create(Object);
    errdefer allocator.destroy(object);

    const name = try allocator.dupe(u8, path);
    errdefer allocator.free(name);

    object.* = .{
        .allocator = allocator,
        .arch = arch,
        .name = name,
        .file = file,
    };

    object.parse() catch |err| switch (err) {
        error.EndOfStream, error.NotObject => {
            object.deinit();
            allocator.destroy(object);
            return null;
        },
        else => |e| return e,
    };

    return object;
}

pub fn deinit(self: *Object) void {
    for (self.load_commands.items) |*lc| {
        lc.deinit(self.allocator);
    }
    self.load_commands.deinit(self.allocator);

    for (self.sections.items) |*sect| {
        sect.deinit(self.allocator);
    }
    self.sections.deinit(self.allocator);

    self.symbols.deinit(self.allocator);
    self.stabs.deinit(self.allocator);

    self.data_in_code_entries.deinit(self.allocator);
    self.initializers.deinit(self.allocator);
    self.symtab.deinit(self.allocator);
    self.strtab.deinit(self.allocator);

    if (self.name) |n| {
        self.allocator.free(n);
    }
}

pub fn closeFile(self: Object) void {
    if (self.file) |f| {
        f.close();
    }
}

pub fn parse(self: *Object) !void {
    var reader = self.file.?.reader();
    if (self.file_offset) |offset| {
        try reader.context.seekTo(offset);
    }

    const header = try reader.readStruct(macho.mach_header_64);

    if (header.filetype != macho.MH_OBJECT) {
        log.debug("invalid filetype: expected 0x{x}, found 0x{x}", .{ macho.MH_OBJECT, header.filetype });
        return error.NotObject;
    }

    const this_arch: Arch = switch (header.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => |value| {
            log.err("unsupported cpu architecture 0x{x}", .{value});
            return error.UnsupportedCpuArchitecture;
        },
    };
    if (this_arch != self.arch.?) {
        log.err("mismatched cpu architecture: expected {s}, found {s}", .{ self.arch.?, this_arch });
        return error.MismatchedCpuArchitecture;
    }

    self.header = header;

    try self.readLoadCommands(reader);
    try self.parseSections();
    try self.parseSymtab();
    try self.parseDataInCode();
    try self.parseInitializers();
}

pub fn readLoadCommands(self: *Object, reader: anytype) !void {
    const offset = self.file_offset orelse 0;
    try self.load_commands.ensureCapacity(self.allocator, self.header.?.ncmds);

    var i: u16 = 0;
    while (i < self.header.?.ncmds) : (i += 1) {
        var cmd = try LoadCommand.read(self.allocator, reader);
        switch (cmd.cmd()) {
            macho.LC_SEGMENT_64 => {
                self.segment_cmd_index = i;
                var seg = cmd.Segment;
                for (seg.sections.items) |*sect, j| {
                    const index = @intCast(u16, j);
                    const segname = segmentName(sect.*);
                    const sectname = sectionName(sect.*);
                    if (mem.eql(u8, segname, "__DWARF")) {
                        if (mem.eql(u8, sectname, "__debug_info")) {
                            self.dwarf_debug_info_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_abbrev")) {
                            self.dwarf_debug_abbrev_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_str")) {
                            self.dwarf_debug_str_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_line")) {
                            self.dwarf_debug_line_index = index;
                        } else if (mem.eql(u8, sectname, "__debug_ranges")) {
                            self.dwarf_debug_ranges_index = index;
                        }
                    } else if (mem.eql(u8, segname, "__TEXT")) {
                        if (mem.eql(u8, sectname, "__text")) {
                            self.text_section_index = index;
                        }
                    } else if (mem.eql(u8, segname, "__DATA")) {
                        if (mem.eql(u8, sectname, "__mod_init_func")) {
                            self.mod_init_func_section_index = index;
                        }
                    }

                    sect.offset += offset;
                    if (sect.reloff > 0) {
                        sect.reloff += offset;
                    }
                }

                seg.inner.fileoff += offset;
            },
            macho.LC_SYMTAB => {
                self.symtab_cmd_index = i;
                cmd.Symtab.symoff += offset;
                cmd.Symtab.stroff += offset;
            },
            macho.LC_DYSYMTAB => {
                self.dysymtab_cmd_index = i;
            },
            macho.LC_BUILD_VERSION => {
                self.build_version_cmd_index = i;
            },
            macho.LC_DATA_IN_CODE => {
                self.data_in_code_cmd_index = i;
                cmd.LinkeditData.dataoff += offset;
            },
            else => {
                log.debug("Unknown load command detected: 0x{x}.", .{cmd.cmd()});
            },
        }
        self.load_commands.appendAssumeCapacity(cmd);
    }
}

pub fn parseSections(self: *Object) !void {
    const seg = self.load_commands.items[self.segment_cmd_index.?].Segment;

    log.debug("parsing sections in {s}", .{self.name.?});

    try self.sections.ensureCapacity(self.allocator, seg.sections.items.len);

    for (seg.sections.items) |sect| {
        log.debug("parsing section '{s},{s}'", .{ segmentName(sect), sectionName(sect) });
        // Read sections' code
        var code = try self.allocator.alloc(u8, @intCast(usize, sect.size));
        _ = try self.file.?.preadAll(code, sect.offset);

        var section = Section{
            .inner = sect,
            .code = code,
            .relocs = null,
        };

        // Parse relocations
        if (sect.nreloc > 0) {
            var raw_relocs = try self.allocator.alloc(u8, @sizeOf(macho.relocation_info) * sect.nreloc);
            defer self.allocator.free(raw_relocs);

            _ = try self.file.?.preadAll(raw_relocs, sect.reloff);

            section.relocs = try reloc.parse(
                self.allocator,
                self.arch.?,
                section.code,
                mem.bytesAsSlice(macho.relocation_info, raw_relocs),
            );
        }

        self.sections.appendAssumeCapacity(section);
    }
}

pub fn parseTextBlocks(self: *Object, zld: *Zld) !*TextBlock {
    const seg = self.load_commands.items[self.segment_cmd_index.?].Segment;

    log.warn("analysing {s}", .{self.name.?});

    const dysymtab = self.load_commands.items[self.dysymtab_cmd_index.?].Dysymtab;

    const SymWithIndex = struct {
        nlist: macho.nlist_64,
        index: u32,

        pub fn cmp(_: void, lhs: @This(), rhs: @This()) bool {
            return lhs.nlist.n_value < rhs.nlist.n_value;
        }

        fn filterSymsInSection(symbols: []@This(), sect_id: u8) []@This() {
            var start: usize = 0;
            var end: usize = symbols.len;

            while (true) {
                var change = false;
                if (symbols[start].nlist.n_sect != sect_id) {
                    start += 1;
                    change = true;
                }
                if (symbols[end - 1].nlist.n_sect != sect_id) {
                    end -= 1;
                    change = true;
                }

                if (start == end) break;
                if (!change) break;
            }

            return symbols[start..end];
        }

        fn filterRelocs(relocs: []macho.relocation_info, start: u64, end: u64) []macho.relocation_info {
            if (relocs.len == 0) return relocs;

            var start_id: usize = 0;
            var end_id: usize = relocs.len;

            while (true) {
                var change = false;
                if (relocs[start_id].r_address > end) {
                    start_id += 1;
                    change = true;
                }
                if (relocs[end_id - 1].r_address < start) {
                    end_id -= 1;
                    change = true;
                }

                if (start_id == end_id) break;
                if (!change) break;
            }

            return relocs[start_id..end_id];
        }
    };

    const nlists = self.symtab.items[dysymtab.ilocalsym..dysymtab.iundefsym];

    var sorted_syms = std.ArrayList(SymWithIndex).init(self.allocator);
    defer sorted_syms.deinit();
    try sorted_syms.ensureTotalCapacity(nlists.len);

    for (nlists) |nlist, index| {
        sorted_syms.appendAssumeCapacity(.{
            .nlist = nlist,
            .index = @intCast(u32, index + dysymtab.ilocalsym),
        });
    }

    std.sort.sort(SymWithIndex, sorted_syms.items, {}, SymWithIndex.cmp);

    for (seg.sections.items) |sect, sect_id| {
        log.warn("section {s},{s}", .{ segmentName(sect), sectionName(sect) });

        const match = (try zld.getMatchingSection(sect)) orelse {
            log.warn("unhandled section", .{});
            continue;
        };

        // Read code
        var code = try self.allocator.alloc(u8, @intCast(usize, sect.size));
        defer self.allocator.free(code);
        _ = try self.file.?.preadAll(code, sect.offset);

        // Read and parse relocs
        const raw_relocs = try self.allocator.alloc(u8, @sizeOf(macho.relocation_info) * sect.nreloc);
        defer self.allocator.free(raw_relocs);
        _ = try self.file.?.preadAll(raw_relocs, sect.reloff);
        const relocs = mem.bytesAsSlice(macho.relocation_info, raw_relocs);

        const alignment = sect.@"align";

        if (self.header.?.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0) {
            const syms = SymWithIndex.filterSymsInSection(sorted_syms.items, @intCast(u8, sect_id + 1));

            if (syms.len == 0) {
                // One large text block referenced by section offsets only
                log.warn("TextBlock", .{});
                log.warn("  | referenced by section offsets", .{});
                log.warn("  | start_addr = {}", .{sect.addr});
                log.warn("  | end_addr = {}", .{sect.size});
                log.warn("  | size = {}", .{sect.size});
                log.warn("  | alignment = 0x{x}", .{alignment});
                log.warn("  | segment_id = {}", .{match.seg});
                log.warn("  | section_id = {}", .{match.sect});
                log.warn("  | relocs: {any}", .{relocs});
            }

            var indices = std.ArrayList(u32).init(self.allocator);
            defer indices.deinit();

            var i: u32 = 0;
            while (i < syms.len) : (i += 1) {
                const curr = syms[i];
                try indices.append(i);

                const next: ?SymWithIndex = if (i + 1 < syms.len)
                    syms[i + 1]
                else
                    null;

                if (next) |n| {
                    if (curr.nlist.n_value == n.nlist.n_value) {
                        continue;
                    }
                }

                const start_addr = curr.nlist.n_value - sect.addr;
                const end_addr = if (next) |n| n.nlist.n_value - sect.addr else sect.size;

                const tb_code = code[start_addr..end_addr];
                const size = tb_code.len;

                log.warn("TextBlock", .{});
                for (indices.items) |id| {
                    const sym = self.symbols.items[syms[id].index];
                    log.warn("  | symbol = {s}", .{sym.name});
                }
                log.warn("  | start_addr = {}", .{start_addr});
                log.warn("  | end_addr = {}", .{end_addr});
                log.warn("  | size = {}", .{size});
                log.warn("  | alignment = 0x{x}", .{alignment});
                log.warn("  | segment_id = {}", .{match.seg});
                log.warn("  | section_id = {}", .{match.sect});
                log.warn("  | relocs: {any}", .{SymWithIndex.filterRelocs(relocs, start_addr, end_addr)});

                indices.clearRetainingCapacity();
            }
        } else {
            return error.TODOOneLargeTextBlock;
        }
    }
}

const SectionAsTextBlocksArgs = struct {
    sect: macho.section_64,
    code: []u8,
    subsections_via_symbols: bool = false,
    relocs: ?[]macho.relocation_info = null,
    segment_id: u16 = 0,
    section_id: u16 = 0,
};

fn sectionAsTextBlocks(self: *Object, args: SectionAsTextBlocksArgs) !*TextBlock {
    const sect = args.sect;

    log.warn("putting section '{s},{s}' as a TextBlock", .{ segmentName(sect), sectionName(sect) });

    // Section alignment will be the assumed alignment per symbol.
    const alignment = sect.@"align";

    const first_block: *TextBlock = blk: {
        if (args.subsections_via_symbols) {
            return error.TODO;
        } else {
            const block = try self.allocator.create(TextBlock);
            errdefer self.allocator.destroy(block);

            block.* = .{
                .ref = .{
                    .section = undefined, // Will be populated when we allocated final sections.
                },
                .code = args.code,
                .relocs = null,
                .size = sect.size,
                .alignment = alignment,
                .segment_id = args.segment_id,
                .section_id = args.section_id,
            };

            // TODO parse relocs
            if (args.relocs) |relocs| {
                block.relocs = try reloc.parse(self.allocator, self.arch.?, args.code, relocs, symbols);
            }

            break :blk block;
        }
    };

    return first_block;
}

pub fn parseInitializers(self: *Object) !void {
    const index = self.mod_init_func_section_index orelse return;
    const section = self.sections.items[index];

    log.debug("parsing initializers in {s}", .{self.name.?});

    // Parse C++ initializers
    const relocs = section.relocs orelse unreachable;
    try self.initializers.ensureCapacity(self.allocator, relocs.len);
    for (relocs) |rel| {
        self.initializers.appendAssumeCapacity(rel.target.symbol);
    }

    mem.reverse(u32, self.initializers.items);
}

fn parseSymtab(self: *Object) !void {
    const index = self.symtab_cmd_index orelse return;
    const symtab_cmd = self.load_commands.items[index].Symtab;

    var symtab = try self.allocator.alloc(u8, @sizeOf(macho.nlist_64) * symtab_cmd.nsyms);
    defer self.allocator.free(symtab);
    _ = try self.file.?.preadAll(symtab, symtab_cmd.symoff);
    const slice = @alignCast(@alignOf(macho.nlist_64), mem.bytesAsSlice(macho.nlist_64, symtab));
    try self.symtab.appendSlice(self.allocator, slice);

    var strtab = try self.allocator.alloc(u8, symtab_cmd.strsize);
    defer self.allocator.free(strtab);
    _ = try self.file.?.preadAll(strtab, symtab_cmd.stroff);
    try self.strtab.appendSlice(self.allocator, strtab);
}

pub fn parseDebugInfo(self: *Object) !void {
    var debug_info = blk: {
        var di = try DebugInfo.parseFromObject(self.allocator, self);
        break :blk di orelse return;
    };
    defer debug_info.deinit(self.allocator);

    log.debug("parsing debug info in '{s}'", .{self.name.?});

    // We assume there is only one CU.
    const compile_unit = debug_info.inner.findCompileUnit(0x0) catch |err| switch (err) {
        error.MissingDebugInfo => {
            // TODO audit cases with missing debug info and audit our dwarf.zig module.
            log.debug("invalid or missing debug info in {s}; skipping", .{self.name.?});
            return;
        },
        else => |e| return e,
    };
    const name = try compile_unit.die.getAttrString(&debug_info.inner, dwarf.AT_name);
    const comp_dir = try compile_unit.die.getAttrString(&debug_info.inner, dwarf.AT_comp_dir);

    if (self.mtime == null) {
        self.mtime = mtime: {
            const file = self.file orelse break :mtime 0;
            const stat = file.stat() catch break :mtime 0;
            break :mtime @intCast(u64, @divFloor(stat.mtime, 1_000_000_000));
        };
    }

    try self.stabs.ensureUnusedCapacity(self.allocator, self.symbols.items.len + 4);

    // Current dir
    self.stabs.appendAssumeCapacity(try Symbol.Stab.new(self.allocator, comp_dir, .{
        .kind = .so,
        .file = self,
    }));

    // Artifact name
    self.stabs.appendAssumeCapacity(try Symbol.Stab.new(self.allocator, name, .{
        .kind = .so,
        .file = self,
    }));

    // Path to object file with debug info
    self.stabs.appendAssumeCapacity(try Symbol.Stab.new(self.allocator, self.name.?, .{
        .kind = .oso,
        .file = self,
    }));

    for (self.symbols.items) |sym| {
        if (sym.cast(Symbol.Regular)) |reg| {
            const size: u64 = blk: for (debug_info.inner.func_list.items) |func| {
                if (func.pc_range) |range| {
                    if (reg.address >= range.start and reg.address < range.end) {
                        break :blk range.end - range.start;
                    }
                }
            } else 0;

            const stab = try Symbol.Stab.new(self.allocator, sym.name, .{
                .kind = kind: {
                    if (size > 0) break :kind .function;
                    switch (reg.linkage) {
                        .translation_unit => break :kind .static,
                        else => break :kind .global,
                    }
                },
                .size = size,
                .symbol = sym,
                .file = self,
            });
            self.stabs.appendAssumeCapacity(stab);
        } else if (sym.cast(Symbol.Tentative)) |_| {
            const stab = try Symbol.Stab.new(self.allocator, sym.name, .{
                .kind = .global,
                .size = 0,
                .symbol = sym,
                .file = self,
            });
            self.stabs.appendAssumeCapacity(stab);
        }
    }

    // Closing delimiter.
    const delim_stab = try Symbol.Stab.new(self.allocator, "", .{
        .kind = .so,
        .file = self,
    });
    self.stabs.appendAssumeCapacity(delim_stab);
}

pub fn parseDataInCode(self: *Object) !void {
    const index = self.data_in_code_cmd_index orelse return;
    const data_in_code = self.load_commands.items[index].LinkeditData;

    var buffer = try self.allocator.alloc(u8, data_in_code.datasize);
    defer self.allocator.free(buffer);

    _ = try self.file.?.preadAll(buffer, data_in_code.dataoff);

    var stream = io.fixedBufferStream(buffer);
    var reader = stream.reader();
    while (true) {
        const dice = reader.readStruct(macho.data_in_code_entry) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        try self.data_in_code_entries.append(self.allocator, dice);
    }
}

fn readSection(self: Object, allocator: *Allocator, index: u16) ![]u8 {
    const seg = self.load_commands.items[self.segment_cmd_index.?].Segment;
    const sect = seg.sections.items[index];
    var buffer = try allocator.alloc(u8, @intCast(usize, sect.size));
    _ = try self.file.?.preadAll(buffer, sect.offset);
    return buffer;
}

pub fn getString(self: Object, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.strtab.items.ptr + off));
}
