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
const parseName = @import("Zld.zig").parseName;

const Allocator = mem.Allocator;
const Arch = std.Target.Cpu.Arch;
const Relocation = reloc.Relocation;
const Symbol = @import("Symbol.zig");

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

symbols: std.ArrayListUnmanaged(*Symbol) = .{},
stabs: std.ArrayListUnmanaged(*Symbol) = .{},
initializers: std.ArrayListUnmanaged(*Symbol) = .{},
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

    pub fn segname(self: Section) []const u8 {
        return parseName(&self.inner.segname);
    }

    pub fn sectname(self: Section) []const u8 {
        return parseName(&self.inner.sectname);
    }

    pub fn flags(self: Section) u32 {
        return self.inner.flags;
    }

    pub fn sectionType(self: Section) u8 {
        return @truncate(u8, self.flags() & 0xff);
    }

    pub fn sectionAttrs(self: Section) u32 {
        return self.flags() & 0xffffff00;
    }

    pub fn isCode(self: Section) bool {
        const attr = self.sectionAttrs();
        return attr & macho.S_ATTR_PURE_INSTRUCTIONS != 0 or attr & macho.S_ATTR_SOME_INSTRUCTIONS != 0;
    }

    pub fn isDebug(self: Section) bool {
        return self.sectionAttrs() & macho.S_ATTR_DEBUG != 0;
    }

    pub fn dontDeadStrip(self: Section) bool {
        return self.sectionAttrs() & macho.S_ATTR_NO_DEAD_STRIP != 0;
    }

    pub fn dontDeadStripIfReferencesLive(self: Section) bool {
        return self.sectionAttrs() & macho.S_ATTR_LIVE_SUPPORT != 0;
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

    for (self.symbols.items) |sym| {
        sym.deinit(self.allocator);
        self.allocator.destroy(sym);
    }
    self.symbols.deinit(self.allocator);

    for (self.stabs.items) |stab| {
        stab.deinit(self.allocator);
        self.allocator.destroy(stab);
    }
    self.stabs.deinit(self.allocator);

    self.data_in_code_entries.deinit(self.allocator);
    self.initializers.deinit(self.allocator);

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
    try self.parseSymbols();
    try self.parseSections();
    try self.parseDataInCode();
    try self.parseInitializers();
    try self.parseDebugInfo();
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
                    const segname = parseName(&sect.segname);
                    const sectname = parseName(&sect.sectname);
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
        log.debug("parsing section '{s},{s}'", .{ parseName(&sect.segname), parseName(&sect.sectname) });
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

pub fn parseInitializers(self: *Object) !void {
    const index = self.mod_init_func_section_index orelse return;
    const section = self.sections.items[index];

    log.debug("parsing initializers in {s}", .{self.name.?});

    // Parse C++ initializers
    const relocs = section.relocs orelse unreachable;
    try self.initializers.ensureCapacity(self.allocator, relocs.len);
    for (relocs) |rel| {
        const sym = self.symbols.items[rel.target.symbol];
        self.initializers.appendAssumeCapacity(sym);
    }

    mem.reverse(*Symbol, self.initializers.items);
}

pub fn parseSymbols(self: *Object) !void {
    const index = self.symtab_cmd_index orelse return;
    const symtab_cmd = self.load_commands.items[index].Symtab;

    var symtab = try self.allocator.alloc(u8, @sizeOf(macho.nlist_64) * symtab_cmd.nsyms);
    defer self.allocator.free(symtab);
    _ = try self.file.?.preadAll(symtab, symtab_cmd.symoff);
    const slice = @alignCast(@alignOf(macho.nlist_64), mem.bytesAsSlice(macho.nlist_64, symtab));

    var strtab = try self.allocator.alloc(u8, symtab_cmd.strsize);
    defer self.allocator.free(strtab);
    _ = try self.file.?.preadAll(strtab, symtab_cmd.stroff);

    for (slice) |sym| {
        const sym_name = mem.spanZ(@ptrCast([*:0]const u8, strtab.ptr + sym.n_strx));

        if (Symbol.isStab(sym)) {
            log.err("unhandled symbol type: stab {s} in {s}", .{ sym_name, self.name.? });
            return error.UnhandledSymbolType;
        }
        if (Symbol.isIndr(sym)) {
            log.err("unhandled symbol type: indirect {s} in {s}", .{ sym_name, self.name.? });
            return error.UnhandledSymbolType;
        }
        if (Symbol.isAbs(sym)) {
            log.err("unhandled symbol type: absolute {s} in {s}", .{ sym_name, self.name.? });
            return error.UnhandledSymbolType;
        }

        const name = try self.allocator.dupe(u8, sym_name);
        const symbol: *Symbol = symbol: {
            if (Symbol.isSect(sym)) {
                const linkage: Symbol.Regular.Linkage = linkage: {
                    if (!Symbol.isExt(sym)) break :linkage .translation_unit;
                    if (Symbol.isWeakDef(sym) or Symbol.isPext(sym)) break :linkage .linkage_unit;
                    break :linkage .global;
                };
                break :symbol try Symbol.Regular.new(self.allocator, name, .{
                    .linkage = linkage,
                    .address = sym.n_value,
                    .section = sym.n_sect - 1,
                    .weak_ref = Symbol.isWeakRef(sym),
                    .file = self,
                });
            }

            if (sym.n_value != 0) {
                break :symbol try Symbol.Tentative.new(self.allocator, name, .{
                    .size = sym.n_value,
                    .alignment = (sym.n_desc >> 8) & 0x0f,
                    .file = self,
                });
            }

            break :symbol try Symbol.Unresolved.new(self.allocator, name, .{
                .file = self,
            });
        };

        try self.symbols.append(self.allocator, symbol);
    }
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

fn readSection(self: Object, allocator: *Allocator, index: u16) ![]u8 {
    const seg = self.load_commands.items[self.segment_cmd_index.?].Segment;
    const sect = seg.sections.items[index];
    var buffer = try allocator.alloc(u8, @intCast(usize, sect.size));
    _ = try self.file.?.preadAll(buffer, sect.offset);
    return buffer;
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
