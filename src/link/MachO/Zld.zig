const Zld = @This();

const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const mem = std.mem;
const meta = std.meta;
const fs = std.fs;
const macho = std.macho;
const math = std.math;
const log = std.log.scoped(.zld);
const aarch64 = @import("../../codegen/aarch64.zig");
const reloc = @import("reloc.zig");

const Allocator = mem.Allocator;
const Archive = @import("Archive.zig");
const CodeSignature = @import("CodeSignature.zig");
const Dylib = @import("Dylib.zig");
const Object = @import("Object.zig");
const Relocation = reloc.Relocation;
const StringTable = @import("StringTable.zig");
const Symbol = @import("Symbol.zig");
const Trie = @import("Trie.zig");

usingnamespace @import("commands.zig");
usingnamespace @import("bind.zig");

allocator: *Allocator,
strtab: StringTable,

target: ?std.Target = null,
page_size: ?u16 = null,
file: ?fs.File = null,
output: ?Output = null,

// TODO these args will become obselete once Zld is coalesced with incremental
// linker.
stack_size: u64 = 0,

objects: std.ArrayListUnmanaged(*Object) = .{},
archives: std.ArrayListUnmanaged(*Archive) = .{},
dylibs: std.ArrayListUnmanaged(*Dylib) = .{},

next_dylib_ordinal: u16 = 1,

load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},

pagezero_segment_cmd_index: ?u16 = null,
text_segment_cmd_index: ?u16 = null,
data_const_segment_cmd_index: ?u16 = null,
data_segment_cmd_index: ?u16 = null,
linkedit_segment_cmd_index: ?u16 = null,
dyld_info_cmd_index: ?u16 = null,
symtab_cmd_index: ?u16 = null,
dysymtab_cmd_index: ?u16 = null,
dylinker_cmd_index: ?u16 = null,
data_in_code_cmd_index: ?u16 = null,
function_starts_cmd_index: ?u16 = null,
main_cmd_index: ?u16 = null,
dylib_id_cmd_index: ?u16 = null,
version_min_cmd_index: ?u16 = null,
source_version_cmd_index: ?u16 = null,
uuid_cmd_index: ?u16 = null,
code_signature_cmd_index: ?u16 = null,

// __TEXT segment sections
text_section_index: ?u16 = null,
stubs_section_index: ?u16 = null,
stub_helper_section_index: ?u16 = null,
text_const_section_index: ?u16 = null,
cstring_section_index: ?u16 = null,
ustring_section_index: ?u16 = null,
gcc_except_tab_section_index: ?u16 = null,
unwind_info_section_index: ?u16 = null,
eh_frame_section_index: ?u16 = null,

objc_methlist_section_index: ?u16 = null,
objc_methname_section_index: ?u16 = null,
objc_methtype_section_index: ?u16 = null,
objc_classname_section_index: ?u16 = null,

// __DATA_CONST segment sections
got_section_index: ?u16 = null,
mod_init_func_section_index: ?u16 = null,
mod_term_func_section_index: ?u16 = null,
data_const_section_index: ?u16 = null,

objc_cfstring_section_index: ?u16 = null,
objc_classlist_section_index: ?u16 = null,
objc_imageinfo_section_index: ?u16 = null,

// __DATA segment sections
tlv_section_index: ?u16 = null,
tlv_data_section_index: ?u16 = null,
tlv_bss_section_index: ?u16 = null,
la_symbol_ptr_section_index: ?u16 = null,
data_section_index: ?u16 = null,
bss_section_index: ?u16 = null,
common_section_index: ?u16 = null,

objc_const_section_index: ?u16 = null,
objc_selrefs_section_index: ?u16 = null,
objc_classrefs_section_index: ?u16 = null,
objc_data_section_index: ?u16 = null,

locals: std.ArrayListUnmanaged(*Symbol) = .{},
imports: std.ArrayListUnmanaged(*Symbol) = .{},
globals: std.StringArrayHashMapUnmanaged(*Symbol) = .{},

threadlocal_offsets: std.ArrayListUnmanaged(TlvOffset) = .{}, // TODO merge with Symbol abstraction
local_rebases: std.ArrayListUnmanaged(Pointer) = .{},
stubs: std.ArrayListUnmanaged(*Symbol) = .{},
got_entries: std.ArrayListUnmanaged(*Symbol) = .{},

stub_helper_stubs_start_off: ?u64 = null,

last_text_block: ?*TextBlock = null,

pub const Output = struct {
    tag: enum { exe, dylib },
    path: []const u8,
    install_name: ?[]const u8 = null,
};

const TlvOffset = struct {
    source_addr: u64,
    offset: u64,

    fn cmp(context: void, a: TlvOffset, b: TlvOffset) bool {
        _ = context;
        return a.source_addr < b.source_addr;
    }
};

pub const TextBlock = struct {
    local_sym_index: u32,
    aliases: ?[]u32 = null,
    references: std.AutoArrayHashMap(u32, void),
    code: []u8,
    relocs: std.ArrayList(*Relocation),
    size: u64,
    alignment: u32,
    next: ?*TextBlock = null,
    prev: ?*TextBlock = null,

    pub fn deinit(block: *TextBlock, allocator: *Allocator) void {
        if (block.aliases) |aliases| {
            allocator.free(aliases);
        }
        block.relocs.deinit();
        block.references.deinit();
        allocator.free(code);
    }

    pub fn print_this(self: *const TextBlock, zld: *Zld) void {
        log.warn("TextBlock", .{});
        log.warn("  | {}: {}", .{ self.local_sym_index, zld.locals.items[self.local_sym_index] });
        if (self.aliases) |aliases| {
            log.warn("  | Aliases:", .{});
            for (aliases) |index| {
                log.warn("    | {}: {}", .{ index, zld.locals.items[index] });
            }
        }
        if (self.references.count() > 0) {
            log.warn("  | References:", .{});
            for (self.references.keys()) |index| {
                log.warn("    | {}: {}", .{ index, zld.locals.items[index] });
            }
        }
        log.warn("  | code.len = {}", .{self.code.len});
        if (self.relocs.items.len > 0) {
            log.warn("Relocations:", .{});
            for (self.relocs.items) |rel| {
                log.warn("  | {}", .{rel});
            }
        }
        log.warn("  | size = {}", .{self.size});
        log.warn("  | align = {}", .{self.alignment});
    }

    pub fn print(self: *const TextBlock, zld: *Zld) void {
        if (self.prev) |prev| {
            prev.print(zld);
        }
        self.print_this(zld);
    }
};

/// Default path to dyld
const DEFAULT_DYLD_PATH: [*:0]const u8 = "/usr/lib/dyld";

pub fn init(allocator: *Allocator) !Zld {
    return Zld{
        .allocator = allocator,
        .strtab = try StringTable.init(allocator),
    };
}

pub fn deinit(self: *Zld) void {
    self.threadlocal_offsets.deinit(self.allocator);
    self.local_rebases.deinit(self.allocator);
    self.stubs.deinit(self.allocator);
    self.got_entries.deinit(self.allocator);

    for (self.load_commands.items) |*lc| {
        lc.deinit(self.allocator);
    }
    self.load_commands.deinit(self.allocator);

    for (self.objects.items) |object| {
        object.deinit();
        self.allocator.destroy(object);
    }
    self.objects.deinit(self.allocator);

    for (self.archives.items) |archive| {
        archive.deinit();
        self.allocator.destroy(archive);
    }
    self.archives.deinit(self.allocator);

    for (self.dylibs.items) |dylib| {
        dylib.deinit();
        self.allocator.destroy(dylib);
    }
    self.dylibs.deinit(self.allocator);

    self.globals.deinit(self.allocator);

    for (self.imports.items) |sym| {
        sym.deinit(self.allocator);
        self.allocator.destroy(sym);
    }
    self.imports.deinit(self.allocator);

    for (self.locals.items) |sym| {
        sym.deinit(self.allocator);
        self.allocator.destroy(sym);
    }
    self.locals.deinit(self.allocator);

    self.strtab.deinit();
}

pub fn closeFiles(self: Zld) void {
    for (self.objects.items) |object| {
        object.closeFile();
    }
    for (self.archives.items) |archive| {
        archive.closeFile();
    }
    if (self.file) |f| f.close();
}

const LinkArgs = struct {
    syslibroot: ?[]const u8,
    libs: []const []const u8,
    rpaths: []const []const u8,
};

pub fn link(self: *Zld, files: []const []const u8, output: Output, args: LinkArgs) !void {
    if (files.len == 0) return error.NoInputFiles;
    if (output.path.len == 0) return error.EmptyOutputPath;

    self.page_size = switch (self.target.?.cpu.arch) {
        .aarch64 => 0x4000,
        .x86_64 => 0x1000,
        else => unreachable,
    };
    self.output = output;
    self.file = try fs.cwd().createFile(self.output.?.path, .{
        .truncate = true,
        .read = true,
        .mode = if (std.Target.current.os.tag == .windows) 0 else 0o777,
    });

    try self.populateMetadata();
    try self.parseInputFiles(files, args.syslibroot);
    try self.parseLibs(args.libs, args.syslibroot);
    try self.resolveSymbols();
    try self.parseTextBlocks();
    return error.TODO;
    // try self.updateMetadata();
    // try self.sortSections();
    // try self.addRpaths(args.rpaths);
    // try self.addDataInCodeLC();
    // try self.addCodeSignatureLC();
    // try self.allocateTextSegment();
    // try self.allocateDataConstSegment();
    // try self.allocateDataSegment();
    // self.allocateLinkeditSegment();
    // try self.allocateSymbols();
    // try self.allocateProxyBindAddresses();
    // try self.flush();
}

fn parseInputFiles(self: *Zld, files: []const []const u8, syslibroot: ?[]const u8) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpath(file_name, &buffer);
            break :full_path try self.allocator.dupe(u8, path);
        };

        if (try Object.createAndParseFromPath(self.allocator, self.target.?.cpu.arch, full_path)) |object| {
            try self.objects.append(self.allocator, object);
            continue;
        }

        if (try Archive.createAndParseFromPath(self.allocator, self.target.?.cpu.arch, full_path)) |archive| {
            try self.archives.append(self.allocator, archive);
            continue;
        }

        if (try Dylib.createAndParseFromPath(
            self.allocator,
            self.target.?.cpu.arch,
            full_path,
            .{ .syslibroot = syslibroot },
        )) |dylibs| {
            defer self.allocator.free(dylibs);
            try self.dylibs.appendSlice(self.allocator, dylibs);
            continue;
        }

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseLibs(self: *Zld, libs: []const []const u8, syslibroot: ?[]const u8) !void {
    for (libs) |lib| {
        if (try Dylib.createAndParseFromPath(
            self.allocator,
            self.target.?.cpu.arch,
            lib,
            .{ .syslibroot = syslibroot },
        )) |dylibs| {
            defer self.allocator.free(dylibs);
            try self.dylibs.appendSlice(self.allocator, dylibs);
            continue;
        }

        if (try Archive.createAndParseFromPath(self.allocator, self.target.?.cpu.arch, lib)) |archive| {
            try self.archives.append(self.allocator, archive);
            continue;
        }

        log.warn("unknown filetype for a library: '{s}'", .{lib});
    }
}

fn mapAndUpdateSections(
    self: *Zld,
    object: *Object,
    source_sect_id: u16,
    target_seg_id: u16,
    target_sect_id: u16,
) !void {
    const source_sect = &object.sections.items[source_sect_id];
    const target_seg = &self.load_commands.items[target_seg_id].Segment;
    const target_sect = &target_seg.sections.items[target_sect_id];

    const alignment = try math.powi(u32, 2, target_sect.@"align");
    const offset = mem.alignForwardGeneric(u64, target_sect.size, alignment);
    const size = mem.alignForwardGeneric(u64, source_sect.inner.size, alignment);

    log.debug("{s}: '{s},{s}' mapped to '{s},{s}' from 0x{x} to 0x{x}", .{
        object.name.?,
        segmentName(source_sect.inner),
        sectionName(source_sect.inner),
        segmentName(target_sect.*),
        sectionName(target_sect.*),
        offset,
        offset + size,
    });
    log.debug("  | flags 0x{x}", .{source_sect.inner.flags});

    source_sect.target_map = .{
        .segment_id = target_seg_id,
        .section_id = target_sect_id,
        .offset = @intCast(u32, offset),
    };
    target_sect.size = offset + size;
}

fn updateMetadata(self: *Zld) !void {
    for (self.objects.items) |object| {
        // Find ideal section alignment and update section mappings
        for (object.sections.items) |sect, sect_id| {
            const match = (try self.getMatchingSection(sect.inner)) orelse {
                log.debug("{s}: unhandled section type 0x{x} for '{s},{s}'", .{
                    object.name.?,
                    sect.inner.flags,
                    segmentName(sect.inner),
                    sectionName(sect.inner),
                });
                continue;
            };
            const target_seg = &self.load_commands.items[match.seg].Segment;
            const target_sect = &target_seg.sections.items[match.sect];
            target_sect.@"align" = math.max(target_sect.@"align", sect.inner.@"align");

            try self.mapAndUpdateSections(object, @intCast(u16, sect_id), match.seg, match.sect);
        }
    }

    tlv_align: {
        const has_tlv =
            self.tlv_section_index != null or
            self.tlv_data_section_index != null or
            self.tlv_bss_section_index != null;

        if (!has_tlv) break :tlv_align;

        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;

        if (self.tlv_section_index) |index| {
            const sect = &seg.sections.items[index];
            sect.@"align" = 3; // __thread_vars is always 8byte aligned
        }

        // Apparently __tlv_data and __tlv_bss need to have matching alignment, so fix it up.
        // <rdar://problem/24221680> All __thread_data and __thread_bss sections must have same alignment
        // https://github.com/apple-opensource/ld64/blob/e28c028b20af187a16a7161d89e91868a450cadc/src/ld/ld.cpp#L1172
        const data_align: u32 = data: {
            if (self.tlv_data_section_index) |index| {
                const sect = &seg.sections.items[index];
                break :data sect.@"align";
            }
            break :tlv_align;
        };
        const bss_align: u32 = bss: {
            if (self.tlv_bss_section_index) |index| {
                const sect = &seg.sections.items[index];
                break :bss sect.@"align";
            }
            break :tlv_align;
        };
        const max_align = math.max(data_align, bss_align);

        if (self.tlv_data_section_index) |index| {
            const sect = &seg.sections.items[index];
            sect.@"align" = max_align;
        }
        if (self.tlv_bss_section_index) |index| {
            const sect = &seg.sections.items[index];
            sect.@"align" = max_align;
        }
    }
}

const MatchingSection = struct {
    seg: u16,
    sect: u16,
};

pub fn getMatchingSection(self: *Zld, sect: macho.section_64) !?MatchingSection {
    const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const segname = segmentName(sect);
    const sectname = sectionName(sect);

    const res: ?MatchingSection = blk: {
        switch (sectionType(sect)) {
            macho.S_4BYTE_LITERALS, macho.S_8BYTE_LITERALS, macho.S_16BYTE_LITERALS => {
                if (self.text_const_section_index == null) {
                    self.text_const_section_index = @intCast(u16, text_seg.sections.items.len);
                    try text_seg.addSection(self.allocator, "__const", .{});
                }

                break :blk .{
                    .seg = self.text_segment_cmd_index.?,
                    .sect = self.text_const_section_index.?,
                };
            },
            macho.S_CSTRING_LITERALS => {
                if (mem.eql(u8, sectname, "__objc_methname")) {
                    // TODO it seems the common values within the sections in objects are deduplicated/merged
                    // on merging the sections' contents.
                    if (self.objc_methname_section_index == null) {
                        self.objc_methname_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.allocator, "__objc_methname", .{
                            .flags = macho.S_CSTRING_LITERALS,
                        });
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_methname_section_index.?,
                    };
                } else if (mem.eql(u8, sectname, "__objc_methtype")) {
                    if (self.objc_methtype_section_index == null) {
                        self.objc_methtype_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.allocator, "__objc_methtype", .{
                            .flags = macho.S_CSTRING_LITERALS,
                        });
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_methtype_section_index.?,
                    };
                } else if (mem.eql(u8, sectname, "__objc_classname")) {
                    if (self.objc_classname_section_index == null) {
                        self.objc_classname_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.allocator, "__objc_classname", .{});
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_classname_section_index.?,
                    };
                }

                if (self.cstring_section_index == null) {
                    self.cstring_section_index = @intCast(u16, text_seg.sections.items.len);
                    try text_seg.addSection(self.allocator, "__cstring", .{
                        .flags = macho.S_CSTRING_LITERALS,
                    });
                }

                break :blk .{
                    .seg = self.text_segment_cmd_index.?,
                    .sect = self.cstring_section_index.?,
                };
            },
            macho.S_LITERAL_POINTERS => {
                if (mem.eql(u8, segname, "__DATA") and mem.eql(u8, sectname, "__objc_selrefs")) {
                    if (self.objc_selrefs_section_index == null) {
                        self.objc_selrefs_section_index = @intCast(u16, data_seg.sections.items.len);
                        try data_seg.addSection(self.allocator, "__objc_selrefs", .{
                            .flags = macho.S_LITERAL_POINTERS,
                        });
                    }

                    break :blk .{
                        .seg = self.data_segment_cmd_index.?,
                        .sect = self.objc_selrefs_section_index.?,
                    };
                }

                // TODO investigate
                break :blk null;
            },
            macho.S_MOD_INIT_FUNC_POINTERS => {
                if (self.mod_init_func_section_index == null) {
                    self.mod_init_func_section_index = @intCast(u16, data_const_seg.sections.items.len);
                    try data_const_seg.addSection(self.allocator, "__mod_init_func", .{
                        .flags = macho.S_MOD_INIT_FUNC_POINTERS,
                    });
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.mod_init_func_section_index.?,
                };
            },
            macho.S_MOD_TERM_FUNC_POINTERS => {
                if (self.mod_term_func_section_index == null) {
                    self.mod_term_func_section_index = @intCast(u16, data_const_seg.sections.items.len);
                    try data_const_seg.addSection(self.allocator, "__mod_term_func", .{
                        .flags = macho.S_MOD_TERM_FUNC_POINTERS,
                    });
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.mod_term_func_section_index.?,
                };
            },
            macho.S_ZEROFILL => {
                if (mem.eql(u8, sectname, "__common")) {
                    if (self.common_section_index == null) {
                        self.common_section_index = @intCast(u16, data_seg.sections.items.len);
                        try data_seg.addSection(self.allocator, "__common", .{
                            .flags = macho.S_ZEROFILL,
                        });
                    }

                    break :blk .{
                        .seg = self.data_segment_cmd_index.?,
                        .sect = self.common_section_index.?,
                    };
                } else {
                    if (self.bss_section_index == null) {
                        self.bss_section_index = @intCast(u16, data_seg.sections.items.len);
                        try data_seg.addSection(self.allocator, "__bss", .{
                            .flags = macho.S_ZEROFILL,
                        });
                    }

                    break :blk .{
                        .seg = self.data_segment_cmd_index.?,
                        .sect = self.bss_section_index.?,
                    };
                }
            },
            macho.S_THREAD_LOCAL_VARIABLES => {
                if (self.tlv_section_index == null) {
                    self.tlv_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.allocator, "__thread_vars", .{
                        .flags = macho.S_THREAD_LOCAL_VARIABLES,
                    });
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_REGULAR => {
                if (self.tlv_data_section_index == null) {
                    self.tlv_data_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.allocator, "__thread_data", .{
                        .flags = macho.S_THREAD_LOCAL_REGULAR,
                    });
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_data_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_ZEROFILL => {
                if (self.tlv_bss_section_index == null) {
                    self.tlv_bss_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.allocator, "__thread_bss", .{
                        .flags = macho.S_THREAD_LOCAL_ZEROFILL,
                    });
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_bss_section_index.?,
                };
            },
            macho.S_COALESCED => {
                if (mem.eql(u8, "__TEXT", segname) and mem.eql(u8, "__eh_frame", sectname)) {
                    // TODO I believe __eh_frame is currently part of __unwind_info section
                    // in the latest ld64 output.
                    if (self.eh_frame_section_index == null) {
                        self.eh_frame_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.allocator, "__eh_frame", .{});
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.eh_frame_section_index.?,
                    };
                }

                // TODO audit this: is this the right mapping?
                if (self.data_const_section_index == null) {
                    self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                    try data_const_seg.addSection(self.allocator, "__const", .{});
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.data_const_section_index.?,
                };
            },
            macho.S_REGULAR => {
                if (sectionIsCode(sect)) {
                    if (self.text_section_index == null) {
                        self.text_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.allocator, "__text", .{
                            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
                        });
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.text_section_index.?,
                    };
                }
                if (sectionIsDebug(sect)) {
                    // TODO debug attributes
                    if (mem.eql(u8, "__LD", segname) and mem.eql(u8, "__compact_unwind", sectname)) {
                        log.debug("TODO compact unwind section: type 0x{x}, name '{s},{s}'", .{
                            sect.flags, segname, sectname,
                        });
                    }
                    break :blk null;
                }

                if (mem.eql(u8, segname, "__TEXT")) {
                    if (mem.eql(u8, sectname, "__ustring")) {
                        if (self.ustring_section_index == null) {
                            self.ustring_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.allocator, "__ustring", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.ustring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__gcc_except_tab")) {
                        if (self.gcc_except_tab_section_index == null) {
                            self.gcc_except_tab_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.allocator, "__gcc_except_tab", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.gcc_except_tab_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_methlist")) {
                        if (self.objc_methlist_section_index == null) {
                            self.objc_methlist_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.allocator, "__objc_methlist", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.objc_methlist_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__rodata") or
                        mem.eql(u8, sectname, "__typelink") or
                        mem.eql(u8, sectname, "__itablink") or
                        mem.eql(u8, sectname, "__gosymtab") or
                        mem.eql(u8, sectname, "__gopclntab"))
                    {
                        if (self.data_const_section_index == null) {
                            self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else {
                        if (self.text_const_section_index == null) {
                            self.text_const_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.text_const_section_index.?,
                        };
                    }
                }

                if (mem.eql(u8, segname, "__DATA_CONST")) {
                    if (self.data_const_section_index == null) {
                        self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                        try data_const_seg.addSection(self.allocator, "__const", .{});
                    }

                    break :blk .{
                        .seg = self.data_const_segment_cmd_index.?,
                        .sect = self.data_const_section_index.?,
                    };
                }

                if (mem.eql(u8, segname, "__DATA")) {
                    if (mem.eql(u8, sectname, "__const")) {
                        if (self.data_const_section_index == null) {
                            self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__cfstring")) {
                        if (self.objc_cfstring_section_index == null) {
                            self.objc_cfstring_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.allocator, "__cfstring", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_cfstring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classlist")) {
                        if (self.objc_classlist_section_index == null) {
                            self.objc_classlist_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.allocator, "__objc_classlist", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_classlist_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_imageinfo")) {
                        if (self.objc_imageinfo_section_index == null) {
                            self.objc_imageinfo_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.allocator, "__objc_imageinfo", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_imageinfo_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_const")) {
                        if (self.objc_const_section_index == null) {
                            self.objc_const_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.allocator, "__objc_const", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classrefs")) {
                        if (self.objc_classrefs_section_index == null) {
                            self.objc_classrefs_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.allocator, "__objc_classrefs", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_classrefs_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_data")) {
                        if (self.objc_data_section_index == null) {
                            self.objc_data_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.allocator, "__objc_data", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_data_section_index.?,
                        };
                    } else {
                        if (self.data_section_index == null) {
                            self.data_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.allocator, "__data", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.data_section_index.?,
                        };
                    }
                }

                if (mem.eql(u8, "__LLVM", segname) and mem.eql(u8, "__asm", sectname)) {
                    log.debug("TODO LLVM asm section: type 0x{x}, name '{s},{s}'", .{
                        sect.flags, segname, sectname,
                    });
                }

                break :blk null;
            },
            else => break :blk null,
        }
    };

    return res;
}

fn sortSections(self: *Zld) !void {
    var text_index_mapping = std.AutoHashMap(u16, u16).init(self.allocator);
    defer text_index_mapping.deinit();
    var data_const_index_mapping = std.AutoHashMap(u16, u16).init(self.allocator);
    defer data_const_index_mapping.deinit();
    var data_index_mapping = std.AutoHashMap(u16, u16).init(self.allocator);
    defer data_index_mapping.deinit();

    {
        // __TEXT segment
        const seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        var sections = seg.sections.toOwnedSlice(self.allocator);
        defer self.allocator.free(sections);
        try seg.sections.ensureCapacity(self.allocator, sections.len);

        const indices = &[_]*?u16{
            &self.text_section_index,
            &self.stubs_section_index,
            &self.stub_helper_section_index,
            &self.gcc_except_tab_section_index,
            &self.cstring_section_index,
            &self.ustring_section_index,
            &self.text_const_section_index,
            &self.objc_methname_section_index,
            &self.objc_methtype_section_index,
            &self.objc_classname_section_index,
            &self.eh_frame_section_index,
        };
        for (indices) |maybe_index| {
            const new_index: u16 = if (maybe_index.*) |index| blk: {
                const idx = @intCast(u16, seg.sections.items.len);
                seg.sections.appendAssumeCapacity(sections[index]);
                try text_index_mapping.putNoClobber(index, idx);
                break :blk idx;
            } else continue;
            maybe_index.* = new_index;
        }
    }

    {
        // __DATA_CONST segment
        const seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        var sections = seg.sections.toOwnedSlice(self.allocator);
        defer self.allocator.free(sections);
        try seg.sections.ensureCapacity(self.allocator, sections.len);

        const indices = &[_]*?u16{
            &self.got_section_index,
            &self.mod_init_func_section_index,
            &self.mod_term_func_section_index,
            &self.data_const_section_index,
            &self.objc_cfstring_section_index,
            &self.objc_classlist_section_index,
            &self.objc_imageinfo_section_index,
        };
        for (indices) |maybe_index| {
            const new_index: u16 = if (maybe_index.*) |index| blk: {
                const idx = @intCast(u16, seg.sections.items.len);
                seg.sections.appendAssumeCapacity(sections[index]);
                try data_const_index_mapping.putNoClobber(index, idx);
                break :blk idx;
            } else continue;
            maybe_index.* = new_index;
        }
    }

    {
        // __DATA segment
        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        var sections = seg.sections.toOwnedSlice(self.allocator);
        defer self.allocator.free(sections);
        try seg.sections.ensureCapacity(self.allocator, sections.len);

        // __DATA segment
        const indices = &[_]*?u16{
            &self.la_symbol_ptr_section_index,
            &self.objc_const_section_index,
            &self.objc_selrefs_section_index,
            &self.objc_classrefs_section_index,
            &self.objc_data_section_index,
            &self.data_section_index,
            &self.tlv_section_index,
            &self.tlv_data_section_index,
            &self.tlv_bss_section_index,
            &self.bss_section_index,
            &self.common_section_index,
        };
        for (indices) |maybe_index| {
            const new_index: u16 = if (maybe_index.*) |index| blk: {
                const idx = @intCast(u16, seg.sections.items.len);
                seg.sections.appendAssumeCapacity(sections[index]);
                try data_index_mapping.putNoClobber(index, idx);
                break :blk idx;
            } else continue;
            maybe_index.* = new_index;
        }
    }

    for (self.objects.items) |object| {
        for (object.sections.items) |*sect| {
            const target_map = sect.target_map orelse continue;

            const new_index = blk: {
                if (self.text_segment_cmd_index.? == target_map.segment_id) {
                    break :blk text_index_mapping.get(target_map.section_id) orelse unreachable;
                } else if (self.data_const_segment_cmd_index.? == target_map.segment_id) {
                    break :blk data_const_index_mapping.get(target_map.section_id) orelse unreachable;
                } else if (self.data_segment_cmd_index.? == target_map.segment_id) {
                    break :blk data_index_mapping.get(target_map.section_id) orelse unreachable;
                } else unreachable;
            };

            log.debug("remapping in {s}: '{s},{s}': {} => {}", .{
                object.name.?,
                segmentName(sect.inner),
                sectionName(sect.inner),
                target_map.section_id,
                new_index,
            });

            sect.target_map = .{
                .segment_id = target_map.segment_id,
                .section_id = new_index,
                .offset = target_map.offset,
            };
        }
    }
}

fn allocateTextSegment(self: *Zld) !void {
    const seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const nstubs = @intCast(u32, self.stubs.items.len);

    const base_vmaddr = self.load_commands.items[self.pagezero_segment_cmd_index.?].Segment.inner.vmsize;
    seg.inner.fileoff = 0;
    seg.inner.vmaddr = base_vmaddr;

    // Set stubs and stub_helper sizes
    const stubs = &seg.sections.items[self.stubs_section_index.?];
    const stub_helper = &seg.sections.items[self.stub_helper_section_index.?];
    stubs.size += nstubs * stubs.reserved2;

    const stub_size: u4 = switch (self.target.?.cpu.arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    stub_helper.size += nstubs * stub_size;

    var sizeofcmds: u64 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    try self.allocateSegment(self.text_segment_cmd_index.?, @sizeOf(macho.mach_header_64) + sizeofcmds);

    // Shift all sections to the back to minimize jump size between __TEXT and __DATA segments.
    var min_alignment: u32 = 0;
    for (seg.sections.items) |sect| {
        const alignment = try math.powi(u32, 2, sect.@"align");
        min_alignment = math.max(min_alignment, alignment);
    }

    assert(min_alignment > 0);
    const last_sect_idx = seg.sections.items.len - 1;
    const last_sect = seg.sections.items[last_sect_idx];
    const shift: u32 = blk: {
        const diff = seg.inner.filesize - last_sect.offset - last_sect.size;
        const factor = @divTrunc(diff, min_alignment);
        break :blk @intCast(u32, factor * min_alignment);
    };

    if (shift > 0) {
        for (seg.sections.items) |*sect| {
            sect.offset += shift;
            sect.addr += shift;
        }
    }
}

fn allocateDataConstSegment(self: *Zld) !void {
    const seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const nentries = @intCast(u32, self.got_entries.items.len);

    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    seg.inner.fileoff = text_seg.inner.fileoff + text_seg.inner.filesize;
    seg.inner.vmaddr = text_seg.inner.vmaddr + text_seg.inner.vmsize;

    // Set got size
    const got = &seg.sections.items[self.got_section_index.?];
    got.size += nentries * @sizeOf(u64);

    try self.allocateSegment(self.data_const_segment_cmd_index.?, 0);
}

fn allocateDataSegment(self: *Zld) !void {
    const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const nstubs = @intCast(u32, self.stubs.items.len);

    const data_const_seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    seg.inner.fileoff = data_const_seg.inner.fileoff + data_const_seg.inner.filesize;
    seg.inner.vmaddr = data_const_seg.inner.vmaddr + data_const_seg.inner.vmsize;

    // Set la_symbol_ptr and data size
    const la_symbol_ptr = &seg.sections.items[self.la_symbol_ptr_section_index.?];
    const data = &seg.sections.items[self.data_section_index.?];
    la_symbol_ptr.size += nstubs * @sizeOf(u64);
    data.size += @sizeOf(u64); // We need at least 8bytes for address of dyld_stub_binder

    try self.allocateSegment(self.data_segment_cmd_index.?, 0);
}

fn allocateLinkeditSegment(self: *Zld) void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const data_seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    seg.inner.fileoff = data_seg.inner.fileoff + data_seg.inner.filesize;
    seg.inner.vmaddr = data_seg.inner.vmaddr + data_seg.inner.vmsize;
}

fn allocateSegment(self: *Zld, index: u16, offset: u64) !void {
    const seg = &self.load_commands.items[index].Segment;

    // Allocate the sections according to their alignment at the beginning of the segment.
    var start: u64 = offset;
    for (seg.sections.items) |*sect| {
        const alignment = try math.powi(u32, 2, sect.@"align");
        const start_aligned = mem.alignForwardGeneric(u64, start, alignment);
        const end_aligned = mem.alignForwardGeneric(u64, start_aligned + sect.size, alignment);
        sect.offset = @intCast(u32, seg.inner.fileoff + start_aligned);
        sect.addr = seg.inner.vmaddr + start_aligned;
        start = end_aligned;
    }

    const seg_size_aligned = mem.alignForwardGeneric(u64, start, self.page_size.?);
    seg.inner.filesize = seg_size_aligned;
    seg.inner.vmsize = seg_size_aligned;
}

fn allocateSymbol(self: *Zld, symbol: *Symbol) !void {
    const reg = &symbol.payload.regular;
    const object = reg.file orelse return;
    const source_sect = &object.sections.items[reg.section];
    const target_map = source_sect.target_map orelse {
        log.debug("section '{s},{s}' not mapped for symbol '{s}'", .{
            segmentName(source_sect.inner),
            sectionName(source_sect.inner),
            symbol.name,
        });
        return;
    };

    const target_seg = self.load_commands.items[target_map.segment_id].Segment;
    const target_sect = target_seg.sections.items[target_map.section_id];
    const target_addr = target_sect.addr + target_map.offset;
    const address = reg.address - source_sect.inner.addr + target_addr;

    log.debug("resolving symbol '{s}' at 0x{x}", .{ symbol.name, address });

    // TODO there might be a more generic way of doing this.
    var section: u8 = 0;
    for (self.load_commands.items) |cmd, cmd_id| {
        if (cmd != .Segment) break;
        if (cmd_id == target_map.segment_id) {
            section += @intCast(u8, target_map.section_id) + 1;
            break;
        }
        section += @intCast(u8, cmd.Segment.sections.items.len);
    }

    reg.address = address;
    reg.section = section;
}

fn allocateSymbols(self: *Zld) !void {
    for (self.locals.items) |symbol| {
        if (symbol.payload != .regular) continue;
        try self.allocateSymbol(symbol);
    }

    for (self.globals.values()) |symbol| {
        if (symbol.payload != .regular) continue;
        try self.allocateSymbol(symbol);
    }
}

fn allocateProxyBindAddresses(self: *Zld) !void {
    for (self.objects.items) |object| {
        for (object.sections.items) |sect| {
            const relocs = sect.relocs orelse continue;

            for (relocs) |rel| {
                if (rel.@"type" != .unsigned) continue; // GOT is currently special-cased
                if (rel.target != .symbol) continue;

                const sym = object.symbols.items[rel.target.symbol];
                if (sym.payload != .proxy) continue;

                const target_map = sect.target_map orelse continue;
                const target_seg = self.load_commands.items[target_map.segment_id].Segment;
                const target_sect = target_seg.sections.items[target_map.section_id];

                try sym.payload.proxy.bind_info.append(self.allocator, .{
                    .segment_id = target_map.segment_id,
                    .address = target_sect.addr + target_map.offset + rel.offset,
                });
            }
        }
    }
}

fn writeStubHelperCommon(self: *Zld) !void {
    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = &text_segment.sections.items[self.stub_helper_section_index.?];
    const data_const_segment = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_segment.sections.items[self.got_section_index.?];
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const data = &data_segment.sections.items[self.data_section_index.?];

    self.stub_helper_stubs_start_off = blk: {
        switch (self.target.?.cpu.arch) {
            .x86_64 => {
                const code_size = 15;
                var code: [code_size]u8 = undefined;
                // lea %r11, [rip + disp]
                code[0] = 0x4c;
                code[1] = 0x8d;
                code[2] = 0x1d;
                {
                    const target_addr = data.addr + data.size - @sizeOf(u64);
                    const displacement = try math.cast(u32, target_addr - stub_helper.addr - 7);
                    mem.writeIntLittle(u32, code[3..7], displacement);
                }
                // push %r11
                code[7] = 0x41;
                code[8] = 0x53;
                // jmp [rip + disp]
                code[9] = 0xff;
                code[10] = 0x25;
                {
                    const dyld_stub_binder = self.globals.get("dyld_stub_binder").?;
                    const addr = (got.addr + dyld_stub_binder.got_index.? * @sizeOf(u64));
                    const displacement = try math.cast(u32, addr - stub_helper.addr - code_size);
                    mem.writeIntLittle(u32, code[11..], displacement);
                }
                try self.file.?.pwriteAll(&code, stub_helper.offset);
                break :blk stub_helper.offset + code_size;
            },
            .aarch64 => {
                var code: [6 * @sizeOf(u32)]u8 = undefined;
                data_blk_outer: {
                    const this_addr = stub_helper.addr;
                    const target_addr = data.addr + data.size - @sizeOf(u64);
                    data_blk: {
                        const displacement = math.cast(i21, target_addr - this_addr) catch break :data_blk;
                        // adr x17, disp
                        mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.adr(.x17, displacement).toU32());
                        // nop
                        mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.nop().toU32());
                        break :data_blk_outer;
                    }
                    data_blk: {
                        const new_this_addr = this_addr + @sizeOf(u32);
                        const displacement = math.cast(i21, target_addr - new_this_addr) catch break :data_blk;
                        // nop
                        mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.nop().toU32());
                        // adr x17, disp
                        mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.adr(.x17, displacement).toU32());
                        break :data_blk_outer;
                    }
                    // Jump is too big, replace adr with adrp and add.
                    const this_page = @intCast(i32, this_addr >> 12);
                    const target_page = @intCast(i32, target_addr >> 12);
                    const pages = @intCast(i21, target_page - this_page);
                    mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.adrp(.x17, pages).toU32());
                    const narrowed = @truncate(u12, target_addr);
                    mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.add(.x17, .x17, narrowed, false).toU32());
                }
                // stp x16, x17, [sp, #-16]!
                code[8] = 0xf0;
                code[9] = 0x47;
                code[10] = 0xbf;
                code[11] = 0xa9;
                binder_blk_outer: {
                    const dyld_stub_binder = self.globals.get("dyld_stub_binder").?;
                    const this_addr = stub_helper.addr + 3 * @sizeOf(u32);
                    const target_addr = (got.addr + dyld_stub_binder.got_index.? * @sizeOf(u64));
                    binder_blk: {
                        const displacement = math.divExact(u64, target_addr - this_addr, 4) catch break :binder_blk;
                        const literal = math.cast(u18, displacement) catch break :binder_blk;
                        // ldr x16, label
                        mem.writeIntLittle(u32, code[12..16], aarch64.Instruction.ldr(.x16, .{
                            .literal = literal,
                        }).toU32());
                        // nop
                        mem.writeIntLittle(u32, code[16..20], aarch64.Instruction.nop().toU32());
                        break :binder_blk_outer;
                    }
                    binder_blk: {
                        const new_this_addr = this_addr + @sizeOf(u32);
                        const displacement = math.divExact(u64, target_addr - new_this_addr, 4) catch break :binder_blk;
                        const literal = math.cast(u18, displacement) catch break :binder_blk;
                        // Pad with nop to please division.
                        // nop
                        mem.writeIntLittle(u32, code[12..16], aarch64.Instruction.nop().toU32());
                        // ldr x16, label
                        mem.writeIntLittle(u32, code[16..20], aarch64.Instruction.ldr(.x16, .{
                            .literal = literal,
                        }).toU32());
                        break :binder_blk_outer;
                    }
                    // Use adrp followed by ldr(immediate).
                    const this_page = @intCast(i32, this_addr >> 12);
                    const target_page = @intCast(i32, target_addr >> 12);
                    const pages = @intCast(i21, target_page - this_page);
                    mem.writeIntLittle(u32, code[12..16], aarch64.Instruction.adrp(.x16, pages).toU32());
                    const narrowed = @truncate(u12, target_addr);
                    const offset = try math.divExact(u12, narrowed, 8);
                    mem.writeIntLittle(u32, code[16..20], aarch64.Instruction.ldr(.x16, .{
                        .register = .{
                            .rn = .x16,
                            .offset = aarch64.Instruction.LoadStoreOffset.imm(offset),
                        },
                    }).toU32());
                }
                // br x16
                code[20] = 0x00;
                code[21] = 0x02;
                code[22] = 0x1f;
                code[23] = 0xd6;
                try self.file.?.pwriteAll(&code, stub_helper.offset);
                break :blk stub_helper.offset + 6 * @sizeOf(u32);
            },
            else => unreachable,
        }
    };

    for (self.stubs.items) |sym| {
        // TODO weak bound pointers
        const index = sym.stubs_index orelse unreachable;
        try self.writeLazySymbolPointer(index);
        try self.writeStub(index);
        try self.writeStubInStubHelper(index);
    }
}

fn writeLazySymbolPointer(self: *Zld, index: u32) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = text_segment.sections.items[self.stub_helper_section_index.?];
    const data_segment = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = data_segment.sections.items[self.la_symbol_ptr_section_index.?];

    const stub_size: u4 = switch (self.target.?.cpu.arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const stub_off = self.stub_helper_stubs_start_off.? + index * stub_size;
    const end = stub_helper.addr + stub_off - stub_helper.offset;
    var buf: [@sizeOf(u64)]u8 = undefined;
    mem.writeIntLittle(u64, &buf, end);
    const off = la_symbol_ptr.offset + index * @sizeOf(u64);
    log.debug("writing lazy symbol pointer entry 0x{x} at 0x{x}", .{ end, off });
    try self.file.?.pwriteAll(&buf, off);
}

fn writeStub(self: *Zld, index: u32) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stubs = text_segment.sections.items[self.stubs_section_index.?];
    const data_segment = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = data_segment.sections.items[self.la_symbol_ptr_section_index.?];

    const stub_off = stubs.offset + index * stubs.reserved2;
    const stub_addr = stubs.addr + index * stubs.reserved2;
    const la_ptr_addr = la_symbol_ptr.addr + index * @sizeOf(u64);
    log.debug("writing stub at 0x{x}", .{stub_off});
    var code = try self.allocator.alloc(u8, stubs.reserved2);
    defer self.allocator.free(code);
    switch (self.target.?.cpu.arch) {
        .x86_64 => {
            assert(la_ptr_addr >= stub_addr + stubs.reserved2);
            const displacement = try math.cast(u32, la_ptr_addr - stub_addr - stubs.reserved2);
            // jmp
            code[0] = 0xff;
            code[1] = 0x25;
            mem.writeIntLittle(u32, code[2..][0..4], displacement);
        },
        .aarch64 => {
            assert(la_ptr_addr >= stub_addr);
            outer: {
                const this_addr = stub_addr;
                const target_addr = la_ptr_addr;
                inner: {
                    const displacement = math.divExact(u64, target_addr - this_addr, 4) catch break :inner;
                    const literal = math.cast(u18, displacement) catch break :inner;
                    // ldr x16, literal
                    mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.ldr(.x16, .{
                        .literal = literal,
                    }).toU32());
                    // nop
                    mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.nop().toU32());
                    break :outer;
                }
                inner: {
                    const new_this_addr = this_addr + @sizeOf(u32);
                    const displacement = math.divExact(u64, target_addr - new_this_addr, 4) catch break :inner;
                    const literal = math.cast(u18, displacement) catch break :inner;
                    // nop
                    mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.nop().toU32());
                    // ldr x16, literal
                    mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.ldr(.x16, .{
                        .literal = literal,
                    }).toU32());
                    break :outer;
                }
                // Use adrp followed by ldr(immediate).
                const this_page = @intCast(i32, this_addr >> 12);
                const target_page = @intCast(i32, target_addr >> 12);
                const pages = @intCast(i21, target_page - this_page);
                mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.adrp(.x16, pages).toU32());
                const narrowed = @truncate(u12, target_addr);
                const offset = try math.divExact(u12, narrowed, 8);
                mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.ldr(.x16, .{
                    .register = .{
                        .rn = .x16,
                        .offset = aarch64.Instruction.LoadStoreOffset.imm(offset),
                    },
                }).toU32());
            }
            // br x16
            mem.writeIntLittle(u32, code[8..12], aarch64.Instruction.br(.x16).toU32());
        },
        else => unreachable,
    }
    try self.file.?.pwriteAll(code, stub_off);
}

fn writeStubInStubHelper(self: *Zld, index: u32) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = text_segment.sections.items[self.stub_helper_section_index.?];

    const stub_size: u4 = switch (self.target.?.cpu.arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const stub_off = self.stub_helper_stubs_start_off.? + index * stub_size;
    var code = try self.allocator.alloc(u8, stub_size);
    defer self.allocator.free(code);
    switch (self.target.?.cpu.arch) {
        .x86_64 => {
            const displacement = try math.cast(
                i32,
                @intCast(i64, stub_helper.offset) - @intCast(i64, stub_off) - stub_size,
            );
            // pushq
            code[0] = 0x68;
            mem.writeIntLittle(u32, code[1..][0..4], 0x0); // Just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
            // jmpq
            code[5] = 0xe9;
            mem.writeIntLittle(u32, code[6..][0..4], @bitCast(u32, displacement));
        },
        .aarch64 => {
            const displacement = try math.cast(i28, @intCast(i64, stub_helper.offset) - @intCast(i64, stub_off) - 4);
            const literal = @divExact(stub_size - @sizeOf(u32), 4);
            // ldr w16, literal
            mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.ldr(.w16, .{
                .literal = literal,
            }).toU32());
            // b disp
            mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.b(displacement).toU32());
            mem.writeIntLittle(u32, code[8..12], 0x0); // Just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
        },
        else => unreachable,
    }
    try self.file.?.pwriteAll(code, stub_off);
}

fn resolveSymbolsInObject(self: *Zld, object: *Object) !void {
    log.debug("resolving symbols in '{s}'", .{object.name});

    for (object.symtab.items) |sym, sym_id| {
        const sym_name = object.getString(sym.n_strx);

        if (Symbol.isStab(sym)) {
            log.err("unhandled symbol type: stab {s}", .{sym_name});
            log.err("  | first definition in {s}", .{object.name.?});
            return error.UnhandledSymbolType;
        }

        if (Symbol.isIndr(sym)) {
            log.err("unhandled symbol type: indirect {s}", .{sym_name});
            log.err("  | first definition in {s}", .{object.name.?});
            return error.UnhandledSymbolType;
        }

        if (Symbol.isAbs(sym)) {
            log.err("unhandled symbol type: absolute {s}", .{sym_name});
            log.err("  | first definition in {s}", .{object.name.?});
            return error.UnhandledSymbolType;
        }

        if (Symbol.isSect(sym) and !Symbol.isExt(sym)) {
            // Regular symbol local to translation unit
            const symbol = try Symbol.new(self.allocator, sym_name);
            symbol.payload = .{
                .regular = .{
                    .linkage = .translation_unit,
                    .weak_ref = Symbol.isWeakRef(sym),
                    .file = object,
                    .local_sym_index = @intCast(u32, self.locals.items.len),
                },
            };
            try self.locals.append(self.allocator, symbol);
            try object.symbols.append(self.allocator, symbol);
            continue;
        }

        const symbol = self.globals.get(sym_name) orelse symbol: {
            // Insert new global symbol.
            const symbol = try Symbol.new(self.allocator, sym_name);
            symbol.payload.undef.file = object;
            try self.globals.putNoClobber(self.allocator, symbol.name, symbol);
            break :symbol symbol;
        };

        if (Symbol.isSect(sym)) {
            // Global symbol
            const linkage: Symbol.Regular.Linkage = if (Symbol.isWeakDef(sym) or Symbol.isPext(sym))
                .linkage_unit
            else
                .global;

            const should_update = if (symbol.payload == .regular) blk: {
                if (symbol.payload.regular.linkage == .global and linkage == .global) {
                    log.err("symbol '{s}' defined multiple times", .{sym_name});
                    log.err("  | first definition in {s}", .{symbol.payload.regular.file.?.name.?});
                    log.err("  | next definition in {s}", .{object.name.?});
                    return error.MultipleSymbolDefinitions;
                }
                break :blk symbol.payload.regular.linkage != .global;
            } else true;

            if (should_update) {
                symbol.payload = .{
                    .regular = .{
                        .linkage = linkage,
                        .weak_ref = Symbol.isWeakRef(sym),
                        .file = object,
                    },
                };
            }
        } else if (sym.n_value != 0) {
            // Tentative definition
            const should_update = switch (symbol.payload) {
                .tentative => |tent| tent.size < sym.n_value,
                .undef => true,
                else => false,
            };

            if (should_update) {
                symbol.payload = .{
                    .tentative = .{
                        .size = sym.n_value,
                        .alignment = (sym.n_desc >> 8) & 0x0f,
                        .file = object,
                    },
                };
            }
        }

        try object.symbols.append(self.allocator, symbol);
    }
}

fn resolveSymbols(self: *Zld) !void {
    // TODO mimicking insertion of null symbol from incremental linker.
    // This will need to moved.
    const null_sym = try Symbol.new(self.allocator, "");
    try self.locals.append(self.allocator, null_sym);

    // First pass, resolve symbols in provided objects.
    for (self.objects.items) |object| {
        try self.resolveSymbolsInObject(object);
    }

    // Second pass, resolve symbols in static libraries.
    var sym_it = self.globals.iterator();
    while (sym_it.next()) |entry| {
        const symbol = entry.value_ptr.*;
        if (symbol.payload != .undef) continue;

        for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(symbol.name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object = try archive.parseObject(offsets.items[0]);
            try self.objects.append(self.allocator, object);
            try self.resolveSymbolsInObject(object);

            sym_it = self.globals.iterator();
            break;
        }
    }

    // Put any globally defined regular symbol as local.
    // Convert any tentative definition into a regular symbol and allocate
    // text blocks for each tentative defintion.
    for (self.globals.values()) |symbol| {
        switch (symbol.payload) {
            .regular => |*reg| {
                reg.local_sym_index = @intCast(u32, self.locals.items.len);
                try self.locals.append(self.allocator, symbol);
            },
            .tentative => |tent| {
                if (self.common_section_index == null) {
                    const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
                    self.common_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.allocator, "__common", .{
                        .flags = macho.S_ZEROFILL,
                    });
                }

                const size = tent.size;
                const code = try self.allocator.alloc(u8, size);
                mem.set(u8, code, 0);
                const alignment = tent.alignment;
                const local_sym_index = @intCast(u32, self.locals.items.len);

                symbol.payload = .{
                    .regular = .{
                        .linkage = .global,
                        .segment_id = self.data_segment_cmd_index.?,
                        .section_id = self.common_section_index.?,
                        .local_sym_index = local_sym_index,
                    },
                };
                try self.locals.append(self.allocator, symbol);

                const block = try self.allocator.create(TextBlock);
                errdefer self.allocator.destroy(block);

                block.* = .{
                    .local_sym_index = local_sym_index,
                    .references = std.AutoArrayHashMap(u32, void).init(self.allocator),
                    .code = code,
                    .relocs = std.ArrayList(*Relocation).init(self.allocator),
                    .size = size,
                    .alignment = alignment,
                };

                // TODO I'm not 100% sure about this yet, but I believe we should keep a separate list of
                // TextBlocks per segment.
                if (self.last_text_block) |last| {
                    last.next = block;
                    block.prev = last;
                }
                self.last_text_block = block;
            },
            else => {},
        }
    }

    // Third pass, resolve symbols in dynamic libraries.
    {
        // Put dyld_stub_binder as an undefined special symbol.
        const symbol = try Symbol.new(self.allocator, "dyld_stub_binder");
        const index = @intCast(u32, self.got_entries.items.len);
        symbol.got_index = index;
        try self.got_entries.append(self.allocator, symbol);
        try self.globals.putNoClobber(self.allocator, symbol.name, symbol);
    }

    var referenced = std.AutoHashMap(*Dylib, void).init(self.allocator);
    defer referenced.deinit();

    loop: for (self.globals.values()) |symbol| {
        if (symbol.payload != .undef) continue;

        for (self.dylibs.items) |dylib| {
            if (!dylib.symbols.contains(symbol.name)) continue;

            try referenced.put(dylib, {});
            symbol.payload = .{
                .proxy = .{
                    .file = dylib,
                },
            };
            try self.imports.append(self.allocator, symbol);
            continue :loop;
        }
    }

    // Add LC_LOAD_DYLIB load command for each referenced dylib/stub.
    var it = referenced.iterator();
    while (it.next()) |entry| {
        const dylib = entry.key_ptr.*;
        dylib.ordinal = self.next_dylib_ordinal;
        const dylib_id = dylib.id orelse unreachable;
        var dylib_cmd = try createLoadDylibCommand(
            self.allocator,
            dylib_id.name,
            dylib_id.timestamp,
            dylib_id.current_version,
            dylib_id.compatibility_version,
        );
        errdefer dylib_cmd.deinit(self.allocator);
        try self.load_commands.append(self.allocator, .{ .Dylib = dylib_cmd });
        self.next_dylib_ordinal += 1;
    }

    // Fourth pass, handle synthetic symbols and flag any undefined references.
    if (self.globals.get("___dso_handle")) |symbol| {
        if (symbol.payload == .undef) {
            symbol.payload = .{
                .proxy = .{},
            };
            try self.imports.append(self.allocator, symbol);
        }
    }

    var has_undefined = false;
    for (self.globals.values()) |symbol| {
        if (symbol.payload != .undef) continue;

        log.err("undefined reference to symbol '{s}'", .{symbol.name});
        if (symbol.payload.undef.file) |file| {
            log.err("  | referenced in {s}", .{file.name.?});
        }
        has_undefined = true;
    }

    if (has_undefined) return error.UndefinedSymbolReference;
}

fn parseTextBlocks(self: *Zld) !void {
    for (self.objects.items) |object| {
        try object.parseTextBlocks(self);
    }

    if (self.last_text_block) |block| {
        block.print(self);
    }
}

fn resolveRelocsAndWriteSections(self: *Zld) !void {
    for (self.objects.items) |object| {
        log.debug("relocating object {s}", .{object.name});

        for (object.sections.items) |sect| {
            if (sectionType(sect.inner) == macho.S_MOD_INIT_FUNC_POINTERS or
                sectionType(sect.inner) == macho.S_MOD_TERM_FUNC_POINTERS) continue;

            const segname = segmentName(sect.inner);
            const sectname = sectionName(sect.inner);

            log.debug("relocating section '{s},{s}'", .{ segname, sectname });

            // Get target mapping
            const target_map = sect.target_map orelse {
                log.debug("no mapping for '{s},{s}'; skipping", .{ segname, sectname });
                continue;
            };
            const target_seg = self.load_commands.items[target_map.segment_id].Segment;
            const target_sect = target_seg.sections.items[target_map.section_id];
            const target_sect_addr = target_sect.addr + target_map.offset;
            const target_sect_off = target_sect.offset + target_map.offset;

            if (sect.relocs) |relocs| {
                for (relocs) |rel| {
                    const source_addr = target_sect_addr + rel.offset;

                    var args: reloc.Relocation.ResolveArgs = .{
                        .source_addr = source_addr,
                        .target_addr = undefined,
                    };

                    switch (rel.@"type") {
                        .unsigned => {
                            args.target_addr = try self.relocTargetAddr(object, rel.target);

                            const unsigned = rel.cast(reloc.Unsigned) orelse unreachable;
                            if (unsigned.subtractor) |subtractor| {
                                args.subtractor = try self.relocTargetAddr(object, subtractor);
                            }
                            if (rel.target == .section) {
                                const source_sect = object.sections.items[rel.target.section];
                                args.source_source_sect_addr = sect.inner.addr;
                                args.source_target_sect_addr = source_sect.inner.addr;
                            }

                            const sect_type = sectionType(target_sect);
                            const should_rebase = rebase: {
                                if (!unsigned.is_64bit) break :rebase false;

                                // TODO actually, a check similar to what dyld is doing, that is, verifying
                                // that the segment is writable should be enough here.
                                const is_right_segment = blk: {
                                    if (self.data_segment_cmd_index) |idx| {
                                        if (target_map.segment_id == idx) {
                                            break :blk true;
                                        }
                                    }
                                    if (self.data_const_segment_cmd_index) |idx| {
                                        if (target_map.segment_id == idx) {
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
                                if (rel.target == .symbol) {
                                    const sym = object.symbols.items[rel.target.symbol];
                                    if (sym.payload == .proxy) {
                                        break :rebase false;
                                    }
                                }

                                break :rebase true;
                            };

                            if (should_rebase) {
                                try self.local_rebases.append(self.allocator, .{
                                    .offset = source_addr - target_seg.inner.vmaddr,
                                    .segment_id = target_map.segment_id,
                                });
                            }

                            // TLV is handled via a separate offset mechanism.
                            // Calculate the offset to the initializer.
                            if (sect_type == macho.S_THREAD_LOCAL_VARIABLES) tlv: {
                                // TODO we don't want to save offset to tlv_bootstrap
                                if (mem.eql(u8, object.symbols.items[rel.target.symbol].name, "__tlv_bootstrap")) break :tlv;

                                const base_addr = blk: {
                                    if (self.tlv_data_section_index) |index| {
                                        const tlv_data = target_seg.sections.items[index];
                                        break :blk tlv_data.addr;
                                    } else {
                                        const tlv_bss = target_seg.sections.items[self.tlv_bss_section_index.?];
                                        break :blk tlv_bss.addr;
                                    }
                                };
                                // Since we require TLV data to always preceed TLV bss section, we calculate
                                // offsets wrt to the former if it is defined; otherwise, wrt to the latter.
                                try self.threadlocal_offsets.append(self.allocator, .{
                                    .source_addr = args.source_addr,
                                    .offset = args.target_addr - base_addr,
                                });
                            }
                        },
                        .got_page, .got_page_off, .got_load, .got, .pointer_to_got => {
                            const dc_seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
                            const got = dc_seg.sections.items[self.got_section_index.?];
                            const sym = object.symbols.items[rel.target.symbol];
                            const got_index = sym.got_index orelse {
                                log.err("expected GOT index relocating symbol '{s}'", .{sym.name});
                                log.err("this is an internal linker error", .{});
                                return error.FailedToResolveRelocationTarget;
                            };
                            args.target_addr = got.addr + got_index * @sizeOf(u64);
                        },
                        else => |tt| {
                            if (tt == .signed and rel.target == .section) {
                                const source_sect = object.sections.items[rel.target.section];
                                args.source_source_sect_addr = sect.inner.addr;
                                args.source_target_sect_addr = source_sect.inner.addr;
                            }
                            args.target_addr = try self.relocTargetAddr(object, rel.target);
                        },
                    }

                    try rel.resolve(args);
                }
            }

            log.debug("writing contents of '{s},{s}' section from '{s}' from 0x{x} to 0x{x}", .{
                segname,
                sectname,
                object.name,
                target_sect_off,
                target_sect_off + sect.code.len,
            });

            if (sectionType(target_sect) == macho.S_ZEROFILL or
                sectionType(target_sect) == macho.S_THREAD_LOCAL_ZEROFILL or
                sectionType(target_sect) == macho.S_THREAD_LOCAL_VARIABLES)
            {
                log.debug("zeroing out '{s},{s}' from 0x{x} to 0x{x}", .{
                    segmentName(target_sect),
                    sectionName(target_sect),
                    target_sect_off,
                    target_sect_off + sect.code.len,
                });

                // Zero-out the space
                var zeroes = try self.allocator.alloc(u8, sect.code.len);
                defer self.allocator.free(zeroes);
                mem.set(u8, zeroes, 0);
                try self.file.?.pwriteAll(zeroes, target_sect_off);
            } else {
                try self.file.?.pwriteAll(sect.code, target_sect_off);
            }
        }
    }
}

fn relocTargetAddr(self: *Zld, object: *const Object, target: reloc.Relocation.Target) !u64 {
    const target_addr = blk: {
        switch (target) {
            .symbol => |sym_id| {
                const sym = object.symbols.items[sym_id];
                switch (sym.payload) {
                    .regular => |reg| {
                        log.debug("    | regular '{s}'", .{sym.name});
                        break :blk reg.address;
                    },
                    .proxy => |proxy| {
                        if (mem.eql(u8, sym.name, "__tlv_bootstrap")) {
                            log.debug("    | symbol '__tlv_bootstrap'", .{});
                            const segment = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
                            const tlv = segment.sections.items[self.tlv_section_index.?];
                            break :blk tlv.addr;
                        }

                        log.debug("    | symbol stub '{s}'", .{sym.name});
                        const segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
                        const stubs = segment.sections.items[self.stubs_section_index.?];
                        const stubs_index = sym.stubs_index orelse {
                            if (proxy.bind_info.items.len > 0) {
                                break :blk 0; // Dynamically bound by dyld.
                            }
                            log.err(
                                "expected stubs index or dynamic bind address when relocating symbol '{s}'",
                                .{sym.name},
                            );
                            log.err("this is an internal linker error", .{});
                            return error.FailedToResolveRelocationTarget;
                        };
                        break :blk stubs.addr + stubs_index * stubs.reserved2;
                    },
                    else => {
                        log.err("failed to resolve symbol '{s}' as a relocation target", .{sym.name});
                        log.err("this is an internal linker error", .{});
                        return error.FailedToResolveRelocationTarget;
                    },
                }
            },
            .section => |sect_id| {
                log.debug("    | section offset", .{});
                const source_sect = object.sections.items[sect_id];
                log.debug("    | section '{s},{s}'", .{
                    segmentName(source_sect.inner),
                    sectionName(source_sect.inner),
                });
                const target_map = source_sect.target_map orelse unreachable;
                const target_seg = self.load_commands.items[target_map.segment_id].Segment;
                const target_sect = target_seg.sections.items[target_map.section_id];
                break :blk target_sect.addr + target_map.offset;
            },
        }
    };
    return target_addr;
}

fn populateMetadata(self: *Zld) !void {
    if (self.pagezero_segment_cmd_index == null) {
        self.pagezero_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty("__PAGEZERO", .{
                .vmsize = 0x100000000, // size always set to 4GB
            }),
        });
    }

    if (self.text_segment_cmd_index == null) {
        self.text_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty("__TEXT", .{
                .vmaddr = 0x100000000, // always starts at 4GB
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_EXECUTE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_EXECUTE,
            }),
        });
    }

    if (self.text_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.text_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.target.?.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        try text_seg.addSection(self.allocator, "__text", .{
            .@"align" = alignment,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
    }

    if (self.stubs_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stubs_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.target.?.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_size: u4 = switch (self.target.?.cpu.arch) {
            .x86_64 => 6,
            .aarch64 => 3 * @sizeOf(u32),
            else => unreachable, // unhandled architecture type
        };
        try text_seg.addSection(self.allocator, "__stubs", .{
            .@"align" = alignment,
            .flags = macho.S_SYMBOL_STUBS | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved2 = stub_size,
        });
    }

    if (self.stub_helper_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stub_helper_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.target.?.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_helper_size: u6 = switch (self.target.?.cpu.arch) {
            .x86_64 => 15,
            .aarch64 => 6 * @sizeOf(u32),
            else => unreachable,
        };
        try text_seg.addSection(self.allocator, "__stub_helper", .{
            .size = stub_helper_size,
            .@"align" = alignment,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
    }

    if (self.data_const_segment_cmd_index == null) {
        self.data_const_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty("__DATA_CONST", .{
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
            }),
        });
    }

    if (self.got_section_index == null) {
        const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        self.got_section_index = @intCast(u16, data_const_seg.sections.items.len);
        try data_const_seg.addSection(self.allocator, "__got", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
        });
    }

    if (self.data_segment_cmd_index == null) {
        self.data_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty("__DATA", .{
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
            }),
        });
    }

    if (self.la_symbol_ptr_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.la_symbol_ptr_section_index = @intCast(u16, data_seg.sections.items.len);
        try data_seg.addSection(self.allocator, "__la_symbol_ptr", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = macho.S_LAZY_SYMBOL_POINTERS,
        });
    }

    if (self.data_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.data_section_index = @intCast(u16, data_seg.sections.items.len);
        try data_seg.addSection(self.allocator, "__data", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
        });
    }

    if (self.linkedit_segment_cmd_index == null) {
        self.linkedit_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty("__LINKEDIT", .{
                .maxprot = macho.VM_PROT_READ,
                .initprot = macho.VM_PROT_READ,
            }),
        });
    }

    if (self.dyld_info_cmd_index == null) {
        self.dyld_info_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .DyldInfoOnly = .{
                .cmd = macho.LC_DYLD_INFO_ONLY,
                .cmdsize = @sizeOf(macho.dyld_info_command),
                .rebase_off = 0,
                .rebase_size = 0,
                .bind_off = 0,
                .bind_size = 0,
                .weak_bind_off = 0,
                .weak_bind_size = 0,
                .lazy_bind_off = 0,
                .lazy_bind_size = 0,
                .export_off = 0,
                .export_size = 0,
            },
        });
    }

    if (self.symtab_cmd_index == null) {
        self.symtab_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Symtab = .{
                .cmd = macho.LC_SYMTAB,
                .cmdsize = @sizeOf(macho.symtab_command),
                .symoff = 0,
                .nsyms = 0,
                .stroff = 0,
                .strsize = 0,
            },
        });
    }

    if (self.dysymtab_cmd_index == null) {
        self.dysymtab_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Dysymtab = .{
                .cmd = macho.LC_DYSYMTAB,
                .cmdsize = @sizeOf(macho.dysymtab_command),
                .ilocalsym = 0,
                .nlocalsym = 0,
                .iextdefsym = 0,
                .nextdefsym = 0,
                .iundefsym = 0,
                .nundefsym = 0,
                .tocoff = 0,
                .ntoc = 0,
                .modtaboff = 0,
                .nmodtab = 0,
                .extrefsymoff = 0,
                .nextrefsyms = 0,
                .indirectsymoff = 0,
                .nindirectsyms = 0,
                .extreloff = 0,
                .nextrel = 0,
                .locreloff = 0,
                .nlocrel = 0,
            },
        });
    }

    if (self.dylinker_cmd_index == null) {
        self.dylinker_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.dylinker_command) + mem.lenZ(DEFAULT_DYLD_PATH),
            @sizeOf(u64),
        ));
        var dylinker_cmd = emptyGenericCommandWithData(macho.dylinker_command{
            .cmd = macho.LC_LOAD_DYLINKER,
            .cmdsize = cmdsize,
            .name = @sizeOf(macho.dylinker_command),
        });
        dylinker_cmd.data = try self.allocator.alloc(u8, cmdsize - dylinker_cmd.inner.name);
        mem.set(u8, dylinker_cmd.data, 0);
        mem.copy(u8, dylinker_cmd.data, mem.spanZ(DEFAULT_DYLD_PATH));
        try self.load_commands.append(self.allocator, .{ .Dylinker = dylinker_cmd });
    }

    if (self.main_cmd_index == null and self.output.?.tag == .exe) {
        self.main_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Main = .{
                .cmd = macho.LC_MAIN,
                .cmdsize = @sizeOf(macho.entry_point_command),
                .entryoff = 0x0,
                .stacksize = 0,
            },
        });
    }

    if (self.dylib_id_cmd_index == null and self.output.?.tag == .dylib) {
        self.dylib_id_cmd_index = @intCast(u16, self.load_commands.items.len);
        var dylib_cmd = try createLoadDylibCommand(
            self.allocator,
            self.output.?.install_name.?,
            2,
            0x10000, // TODO forward user-provided versions
            0x10000,
        );
        errdefer dylib_cmd.deinit(self.allocator);
        dylib_cmd.inner.cmd = macho.LC_ID_DYLIB;
        try self.load_commands.append(self.allocator, .{ .Dylib = dylib_cmd });
    }

    if (self.version_min_cmd_index == null) {
        self.version_min_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmd: u32 = switch (self.target.?.os.tag) {
            .macos => macho.LC_VERSION_MIN_MACOSX,
            .ios => macho.LC_VERSION_MIN_IPHONEOS,
            .tvos => macho.LC_VERSION_MIN_TVOS,
            .watchos => macho.LC_VERSION_MIN_WATCHOS,
            else => unreachable, // wrong OS
        };
        const ver = self.target.?.os.version_range.semver.min;
        const version = ver.major << 16 | ver.minor << 8 | ver.patch;
        try self.load_commands.append(self.allocator, .{
            .VersionMin = .{
                .cmd = cmd,
                .cmdsize = @sizeOf(macho.version_min_command),
                .version = version,
                .sdk = version,
            },
        });
    }

    if (self.source_version_cmd_index == null) {
        self.source_version_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .SourceVersion = .{
                .cmd = macho.LC_SOURCE_VERSION,
                .cmdsize = @sizeOf(macho.source_version_command),
                .version = 0x0,
            },
        });
    }

    if (self.uuid_cmd_index == null) {
        self.uuid_cmd_index = @intCast(u16, self.load_commands.items.len);
        var uuid_cmd: macho.uuid_command = .{
            .cmd = macho.LC_UUID,
            .cmdsize = @sizeOf(macho.uuid_command),
            .uuid = undefined,
        };
        std.crypto.random.bytes(&uuid_cmd.uuid);
        try self.load_commands.append(self.allocator, .{ .Uuid = uuid_cmd });
    }
}

fn addDataInCodeLC(self: *Zld) !void {
    if (self.data_in_code_cmd_index == null) {
        self.data_in_code_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .LinkeditData = .{
                .cmd = macho.LC_DATA_IN_CODE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }
}

fn addCodeSignatureLC(self: *Zld) !void {
    if (self.code_signature_cmd_index == null and self.target.?.cpu.arch == .aarch64) {
        self.code_signature_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .LinkeditData = .{
                .cmd = macho.LC_CODE_SIGNATURE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }
}

fn addRpaths(self: *Zld, rpaths: []const []const u8) !void {
    for (rpaths) |rpath| {
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.rpath_command) + rpath.len + 1,
            @sizeOf(u64),
        ));
        var rpath_cmd = emptyGenericCommandWithData(macho.rpath_command{
            .cmd = macho.LC_RPATH,
            .cmdsize = cmdsize,
            .path = @sizeOf(macho.rpath_command),
        });
        rpath_cmd.data = try self.allocator.alloc(u8, cmdsize - rpath_cmd.inner.path);
        mem.set(u8, rpath_cmd.data, 0);
        mem.copy(u8, rpath_cmd.data, rpath);
        try self.load_commands.append(self.allocator, .{ .Rpath = rpath_cmd });
    }
}

fn flush(self: *Zld) !void {
    try self.writeStubHelperCommon();
    try self.resolveRelocsAndWriteSections();

    if (self.common_section_index) |index| {
        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = &seg.sections.items[index];
        sect.offset = 0;
    }

    if (self.bss_section_index) |index| {
        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = &seg.sections.items[index];
        sect.offset = 0;
    }

    if (self.tlv_bss_section_index) |index| {
        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = &seg.sections.items[index];
        sect.offset = 0;
    }

    if (self.tlv_section_index) |index| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = &seg.sections.items[index];

        var buffer = try self.allocator.alloc(u8, @intCast(usize, sect.size));
        defer self.allocator.free(buffer);
        _ = try self.file.?.preadAll(buffer, sect.offset);

        var stream = std.io.fixedBufferStream(buffer);
        var writer = stream.writer();

        std.sort.sort(TlvOffset, self.threadlocal_offsets.items, {}, TlvOffset.cmp);

        const seek_amt = 2 * @sizeOf(u64);
        for (self.threadlocal_offsets.items) |tlv| {
            try writer.context.seekBy(seek_amt);
            try writer.writeIntLittle(u64, tlv.offset);
        }

        try self.file.?.pwriteAll(buffer, sect.offset);
    }

    if (self.mod_init_func_section_index) |index| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = &seg.sections.items[index];

        var initializers = std.ArrayList(u64).init(self.allocator);
        defer initializers.deinit();

        for (self.objects.items) |object| {
            for (object.initializers.items) |sym_id| {
                const address = object.symbols.items[sym_id].payload.regular.address;
                try initializers.append(address);
            }
        }

        _ = try self.file.?.pwriteAll(mem.sliceAsBytes(initializers.items), sect.offset);
        sect.size = @intCast(u32, initializers.items.len * @sizeOf(u64));
    }

    try self.writeGotEntries();
    try self.setEntryPoint();
    try self.writeRebaseInfoTable();
    try self.writeBindInfoTable();
    try self.writeLazyBindInfoTable();
    try self.writeExportInfo();
    try self.writeDataInCode();

    {
        const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
        const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
        symtab.symoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    }

    try self.writeSymbolTable();
    try self.writeStringTable();

    {
        // Seal __LINKEDIT size
        const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
        seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size.?);
    }

    if (self.target.?.cpu.arch == .aarch64) {
        try self.writeCodeSignaturePadding();
    }

    try self.writeLoadCommands();
    try self.writeHeader();

    if (self.target.?.cpu.arch == .aarch64) {
        try self.writeCodeSignature();
    }

    if (comptime std.Target.current.isDarwin() and std.Target.current.cpu.arch == .aarch64) {
        const out_path = self.output.?.path;
        try fs.cwd().copyFile(out_path, fs.cwd(), out_path, .{});
    }
}

fn writeGotEntries(self: *Zld) !void {
    const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const sect = seg.sections.items[self.got_section_index.?];

    var buffer = try self.allocator.alloc(u8, self.got_entries.items.len * @sizeOf(u64));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    var writer = stream.writer();

    for (self.got_entries.items) |sym| {
        const address: u64 = switch (sym.payload) {
            .regular => |reg| reg.address,
            else => 0,
        };
        try writer.writeIntLittle(u64, address);
    }

    log.debug("writing GOT pointers at 0x{x} to 0x{x}", .{ sect.offset, sect.offset + buffer.len });

    try self.file.?.pwriteAll(buffer, sect.offset);
}

fn setEntryPoint(self: *Zld) !void {
    if (self.output.?.tag != .exe) return;

    // TODO we should respect the -entry flag passed in by the user to set a custom
    // entrypoint. For now, assume default of `_main`.
    const seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const sym = self.globals.get("_main") orelse return error.MissingMainEntrypoint;
    const ec = &self.load_commands.items[self.main_cmd_index.?].Main;
    ec.entryoff = @intCast(u32, sym.payload.regular.address - seg.inner.vmaddr);
    ec.stacksize = self.stack_size;
}

fn writeRebaseInfoTable(self: *Zld) !void {
    var pointers = std.ArrayList(Pointer).init(self.allocator);
    defer pointers.deinit();

    try pointers.ensureCapacity(self.local_rebases.items.len);
    pointers.appendSliceAssumeCapacity(self.local_rebases.items);

    if (self.got_section_index) |idx| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_const_segment_cmd_index.?);

        for (self.got_entries.items) |sym| {
            if (sym.payload == .proxy) continue;

            try pointers.append(.{
                .offset = base_offset + sym.got_index.? * @sizeOf(u64),
                .segment_id = segment_id,
            });
        }
    }

    if (self.mod_init_func_section_index) |idx| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_const_segment_cmd_index.?);

        var index: u64 = 0;
        for (self.objects.items) |object| {
            for (object.initializers.items) |_| {
                try pointers.append(.{
                    .offset = base_offset + index * @sizeOf(u64),
                    .segment_id = segment_id,
                });
                index += 1;
            }
        }
    }

    if (self.la_symbol_ptr_section_index) |idx| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_segment_cmd_index.?);

        try pointers.ensureCapacity(pointers.items.len + self.stubs.items.len);
        for (self.stubs.items) |sym| {
            pointers.appendAssumeCapacity(.{
                .offset = base_offset + sym.stubs_index.? * @sizeOf(u64),
                .segment_id = segment_id,
            });
        }
    }

    std.sort.sort(Pointer, pointers.items, {}, pointerCmp);

    const size = try rebaseInfoSize(pointers.items);
    var buffer = try self.allocator.alloc(u8, @intCast(usize, size));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try writeRebaseInfo(pointers.items, stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.rebase_off = @intCast(u32, seg.inner.fileoff);
    dyld_info.rebase_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @sizeOf(u64)));
    seg.inner.filesize += dyld_info.rebase_size;

    log.debug("writing rebase info from 0x{x} to 0x{x}", .{ dyld_info.rebase_off, dyld_info.rebase_off + dyld_info.rebase_size });

    try self.file.?.pwriteAll(buffer, dyld_info.rebase_off);
}

fn writeBindInfoTable(self: *Zld) !void {
    var pointers = std.ArrayList(Pointer).init(self.allocator);
    defer pointers.deinit();

    if (self.got_section_index) |idx| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_const_segment_cmd_index.?);

        for (self.got_entries.items) |sym| {
            if (sym.payload != .proxy) continue;

            const proxy = sym.payload.proxy;
            try pointers.append(.{
                .offset = base_offset + sym.got_index.? * @sizeOf(u64),
                .segment_id = segment_id,
                .dylib_ordinal = proxy.dylibOrdinal(),
                .name = sym.name,
            });
        }
    }

    for (self.globals.values()) |sym| {
        if (sym.payload != .proxy) continue;

        const proxy = sym.payload.proxy;
        for (proxy.bind_info.items) |info| {
            const seg = self.load_commands.items[info.segment_id].Segment;
            try pointers.append(.{
                .offset = info.address - seg.inner.vmaddr,
                .segment_id = info.segment_id,
                .dylib_ordinal = proxy.dylibOrdinal(),
                .name = sym.name,
            });
        }
    }

    if (self.tlv_section_index) |idx| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_segment_cmd_index.?);

        const sym = self.globals.get("__tlv_bootstrap") orelse unreachable;
        const proxy = sym.payload.proxy;
        try pointers.append(.{
            .offset = base_offset,
            .segment_id = segment_id,
            .dylib_ordinal = proxy.dylibOrdinal(),
            .name = sym.name,
        });
    }

    const size = try bindInfoSize(pointers.items);
    var buffer = try self.allocator.alloc(u8, @intCast(usize, size));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try writeBindInfo(pointers.items, stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.bind_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.bind_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.bind_size;

    log.debug("writing binding info from 0x{x} to 0x{x}", .{ dyld_info.bind_off, dyld_info.bind_off + dyld_info.bind_size });

    try self.file.?.pwriteAll(buffer, dyld_info.bind_off);
}

fn writeLazyBindInfoTable(self: *Zld) !void {
    var pointers = std.ArrayList(Pointer).init(self.allocator);
    defer pointers.deinit();

    if (self.la_symbol_ptr_section_index) |idx| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_segment_cmd_index.?);

        try pointers.ensureCapacity(self.stubs.items.len);

        for (self.stubs.items) |sym| {
            const proxy = sym.payload.proxy;
            pointers.appendAssumeCapacity(.{
                .offset = base_offset + sym.stubs_index.? * @sizeOf(u64),
                .segment_id = segment_id,
                .dylib_ordinal = proxy.dylibOrdinal(),
                .name = sym.name,
            });
        }
    }

    const size = try lazyBindInfoSize(pointers.items);
    var buffer = try self.allocator.alloc(u8, @intCast(usize, size));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try writeLazyBindInfo(pointers.items, stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.lazy_bind_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.lazy_bind_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.lazy_bind_size;

    log.debug("writing lazy binding info from 0x{x} to 0x{x}", .{ dyld_info.lazy_bind_off, dyld_info.lazy_bind_off + dyld_info.lazy_bind_size });

    try self.file.?.pwriteAll(buffer, dyld_info.lazy_bind_off);
    try self.populateLazyBindOffsetsInStubHelper(buffer);
}

fn populateLazyBindOffsetsInStubHelper(self: *Zld, buffer: []const u8) !void {
    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    var offsets = std.ArrayList(u32).init(self.allocator);
    try offsets.append(0);
    defer offsets.deinit();
    var valid_block = false;

    while (true) {
        const inst = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const opcode: u8 = inst & macho.BIND_OPCODE_MASK;

        switch (opcode) {
            macho.BIND_OPCODE_DO_BIND => {
                valid_block = true;
            },
            macho.BIND_OPCODE_DONE => {
                if (valid_block) {
                    const offset = try stream.getPos();
                    try offsets.append(@intCast(u32, offset));
                }
                valid_block = false;
            },
            macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                var next = try reader.readByte();
                while (next != @as(u8, 0)) {
                    next = try reader.readByte();
                }
            },
            macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                _ = try leb.readULEB128(u64, reader);
            },
            macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                _ = try leb.readULEB128(u64, reader);
            },
            macho.BIND_OPCODE_SET_ADDEND_SLEB => {
                _ = try leb.readILEB128(i64, reader);
            },
            else => {},
        }
    }
    assert(self.stubs.items.len <= offsets.items.len);

    const stub_size: u4 = switch (self.target.?.cpu.arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const off: u4 = switch (self.target.?.cpu.arch) {
        .x86_64 => 1,
        .aarch64 => 2 * @sizeOf(u32),
        else => unreachable,
    };
    var buf: [@sizeOf(u32)]u8 = undefined;
    for (self.stubs.items) |sym| {
        const index = sym.stubs_index orelse unreachable;
        const placeholder_off = self.stub_helper_stubs_start_off.? + index * stub_size + off;
        mem.writeIntLittle(u32, &buf, offsets.items[index]);
        try self.file.?.pwriteAll(&buf, placeholder_off);
    }
}

fn writeExportInfo(self: *Zld) !void {
    var trie = Trie.init(self.allocator);
    defer trie.deinit();

    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const base_address = text_segment.inner.vmaddr;

    // TODO handle macho.EXPORT_SYMBOL_FLAGS_REEXPORT and macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER.
    log.debug("writing export trie", .{});

    const Sorter = struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    };

    var sorted_globals = std.ArrayList([]const u8).init(self.allocator);
    defer sorted_globals.deinit();

    for (self.globals.values()) |sym| {
        if (sym.payload != .regular) continue;
        const reg = sym.payload.regular;
        if (reg.linkage != .global) continue;
        try sorted_globals.append(sym.name);
    }

    std.sort.sort([]const u8, sorted_globals.items, {}, Sorter.lessThan);

    for (sorted_globals.items) |sym_name| {
        const sym = self.globals.get(sym_name) orelse unreachable;
        const reg = sym.payload.regular;

        log.debug("  | putting '{s}' defined at 0x{x}", .{ sym.name, reg.address });

        try trie.put(.{
            .name = sym.name,
            .vmaddr_offset = reg.address - base_address,
            .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }

    try trie.finalize();

    var buffer = try self.allocator.alloc(u8, @intCast(usize, trie.size));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    const nwritten = try trie.write(stream.writer());
    assert(nwritten == trie.size);

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.export_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.export_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.export_size;

    log.debug("writing export info from 0x{x} to 0x{x}", .{ dyld_info.export_off, dyld_info.export_off + dyld_info.export_size });

    try self.file.?.pwriteAll(buffer, dyld_info.export_off);
}

fn writeSymbolTable(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;

    var locals = std.ArrayList(macho.nlist_64).init(self.allocator);
    defer locals.deinit();
    try locals.ensureTotalCapacity(self.locals.items.len);

    for (self.locals.items) |symbol| {
        if (symbol.isTemp()) continue; // TODO when merging codepaths, this should go into freelist
        const nlist = try symbol.asNlist(&self.strtab);
        locals.appendAssumeCapacity(nlist);
    }

    var exports = std.ArrayList(macho.nlist_64).init(self.allocator);
    defer exports.deinit();

    var undefs = std.ArrayList(macho.nlist_64).init(self.allocator);
    defer undefs.deinit();
    var undef_dir = std.StringHashMap(u32).init(self.allocator);
    defer undef_dir.deinit();

    for (self.globals.values()) |sym| {
        const nlist = try sym.asNlist(&self.strtab);
        switch (sym.payload) {
            .regular => try exports.append(nlist),
            .proxy => {
                const id = @intCast(u32, undefs.items.len);
                try undefs.append(nlist);
                try undef_dir.putNoClobber(sym.name, id);
            },
            else => unreachable,
        }
    }

    const nlocals = locals.items.len;
    const nexports = exports.items.len;
    const nundefs = undefs.items.len;

    const locals_off = symtab.symoff + symtab.nsyms * @sizeOf(macho.nlist_64);
    const locals_size = nlocals * @sizeOf(macho.nlist_64);
    log.debug("writing local symbols from 0x{x} to 0x{x}", .{ locals_off, locals_size + locals_off });
    try self.file.?.pwriteAll(mem.sliceAsBytes(locals.items), locals_off);

    const exports_off = locals_off + locals_size;
    const exports_size = nexports * @sizeOf(macho.nlist_64);
    log.debug("writing exported symbols from 0x{x} to 0x{x}", .{ exports_off, exports_size + exports_off });
    try self.file.?.pwriteAll(mem.sliceAsBytes(exports.items), exports_off);

    const undefs_off = exports_off + exports_size;
    const undefs_size = nundefs * @sizeOf(macho.nlist_64);
    log.debug("writing undefined symbols from 0x{x} to 0x{x}", .{ undefs_off, undefs_size + undefs_off });
    try self.file.?.pwriteAll(mem.sliceAsBytes(undefs.items), undefs_off);

    symtab.nsyms += @intCast(u32, nlocals + nexports + nundefs);
    seg.inner.filesize += locals_size + exports_size + undefs_size;

    // Update dynamic symbol table.
    const dysymtab = &self.load_commands.items[self.dysymtab_cmd_index.?].Dysymtab;
    dysymtab.nlocalsym += @intCast(u32, nlocals);
    dysymtab.iextdefsym = dysymtab.nlocalsym;
    dysymtab.nextdefsym = @intCast(u32, nexports);
    dysymtab.iundefsym = dysymtab.nlocalsym + dysymtab.nextdefsym;
    dysymtab.nundefsym = @intCast(u32, nundefs);

    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stubs = &text_segment.sections.items[self.stubs_section_index.?];
    const data_const_segment = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_segment.sections.items[self.got_section_index.?];
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = &data_segment.sections.items[self.la_symbol_ptr_section_index.?];

    const nstubs = @intCast(u32, self.stubs.items.len);
    const ngot_entries = @intCast(u32, self.got_entries.items.len);

    dysymtab.indirectsymoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dysymtab.nindirectsyms = nstubs * 2 + ngot_entries;

    const needed_size = dysymtab.nindirectsyms * @sizeOf(u32);
    seg.inner.filesize += needed_size;

    log.debug("writing indirect symbol table from 0x{x} to 0x{x}", .{
        dysymtab.indirectsymoff,
        dysymtab.indirectsymoff + needed_size,
    });

    var buf = try self.allocator.alloc(u8, needed_size);
    defer self.allocator.free(buf);

    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();

    stubs.reserved1 = 0;
    for (self.stubs.items) |sym| {
        const id = undef_dir.get(sym.name) orelse unreachable;
        try writer.writeIntLittle(u32, dysymtab.iundefsym + id);
    }

    got.reserved1 = nstubs;
    for (self.got_entries.items) |sym| {
        switch (sym.payload) {
            .proxy => {
                const id = undef_dir.get(sym.name) orelse unreachable;
                try writer.writeIntLittle(u32, dysymtab.iundefsym + id);
            },
            else => {
                try writer.writeIntLittle(u32, macho.INDIRECT_SYMBOL_LOCAL);
            },
        }
    }

    la_symbol_ptr.reserved1 = got.reserved1 + ngot_entries;
    for (self.stubs.items) |sym| {
        const id = undef_dir.get(sym.name) orelse unreachable;
        try writer.writeIntLittle(u32, dysymtab.iundefsym + id);
    }

    try self.file.?.pwriteAll(buf, dysymtab.indirectsymoff);
}

fn writeStringTable(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    symtab.stroff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    symtab.strsize = @intCast(u32, mem.alignForwardGeneric(u64, self.strtab.size(), @alignOf(u64)));
    seg.inner.filesize += symtab.strsize;

    log.debug("writing string table from 0x{x} to 0x{x}", .{ symtab.stroff, symtab.stroff + symtab.strsize });

    try self.file.?.pwriteAll(self.strtab.asSlice(), symtab.stroff);

    if (symtab.strsize > self.strtab.size() and self.target.?.cpu.arch == .x86_64) {
        // This is the last section, so we need to pad it out.
        try self.file.?.pwriteAll(&[_]u8{0}, seg.inner.fileoff + seg.inner.filesize - 1);
    }
}

fn writeDataInCode(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dice_cmd = &self.load_commands.items[self.data_in_code_cmd_index.?].LinkeditData;
    const fileoff = seg.inner.fileoff + seg.inner.filesize;

    var buf = std.ArrayList(u8).init(self.allocator);
    defer buf.deinit();

    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const text_sect = text_seg.sections.items[self.text_section_index.?];
    for (self.objects.items) |object| {
        const source_sect = object.sections.items[object.text_section_index.?];
        const target_map = source_sect.target_map orelse continue;

        try buf.ensureCapacity(
            buf.items.len + object.data_in_code_entries.items.len * @sizeOf(macho.data_in_code_entry),
        );
        for (object.data_in_code_entries.items) |dice| {
            const new_dice: macho.data_in_code_entry = .{
                .offset = text_sect.offset + target_map.offset + dice.offset,
                .length = dice.length,
                .kind = dice.kind,
            };
            buf.appendSliceAssumeCapacity(mem.asBytes(&new_dice));
        }
    }
    const datasize = @intCast(u32, buf.items.len);

    dice_cmd.dataoff = @intCast(u32, fileoff);
    dice_cmd.datasize = datasize;
    seg.inner.filesize += datasize;

    log.debug("writing data-in-code from 0x{x} to 0x{x}", .{ fileoff, fileoff + datasize });

    try self.file.?.pwriteAll(buf.items, fileoff);
}

fn writeCodeSignaturePadding(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const code_sig_cmd = &self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;
    const fileoff = seg.inner.fileoff + seg.inner.filesize;
    const needed_size = CodeSignature.calcCodeSignaturePaddingSize(
        self.output.?.path,
        fileoff,
        self.page_size.?,
    );
    code_sig_cmd.dataoff = @intCast(u32, fileoff);
    code_sig_cmd.datasize = needed_size;

    // Advance size of __LINKEDIT segment
    seg.inner.filesize += needed_size;
    seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size.?);

    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ fileoff, fileoff + needed_size });

    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.file.?.pwriteAll(&[_]u8{0}, fileoff + needed_size - 1);
}

fn writeCodeSignature(self: *Zld) !void {
    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const code_sig_cmd = self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;

    var code_sig = CodeSignature.init(self.allocator, self.page_size.?);
    defer code_sig.deinit();
    try code_sig.calcAdhocSignature(
        self.file.?,
        self.output.?.path,
        text_seg.inner,
        code_sig_cmd,
        .Exe,
    );

    var buffer = try self.allocator.alloc(u8, code_sig.size());
    defer self.allocator.free(buffer);
    var stream = std.io.fixedBufferStream(buffer);
    try code_sig.write(stream.writer());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{ code_sig_cmd.dataoff, code_sig_cmd.dataoff + buffer.len });
    try self.file.?.pwriteAll(buffer, code_sig_cmd.dataoff);
}

fn writeLoadCommands(self: *Zld) !void {
    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    var buffer = try self.allocator.alloc(u8, sizeofcmds);
    defer self.allocator.free(buffer);
    var writer = std.io.fixedBufferStream(buffer).writer();
    for (self.load_commands.items) |lc| {
        try lc.write(writer);
    }

    const off = @sizeOf(macho.mach_header_64);
    log.debug("writing {} load commands from 0x{x} to 0x{x}", .{ self.load_commands.items.len, off, off + sizeofcmds });
    try self.file.?.pwriteAll(buffer, off);
}

fn writeHeader(self: *Zld) !void {
    var header = emptyHeader(.{
        .flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK | macho.MH_PIE | macho.MH_TWOLEVEL,
    });

    switch (self.target.?.cpu.arch) {
        .aarch64 => {
            header.cputype = macho.CPU_TYPE_ARM64;
            header.cpusubtype = macho.CPU_SUBTYPE_ARM_ALL;
        },
        .x86_64 => {
            header.cputype = macho.CPU_TYPE_X86_64;
            header.cpusubtype = macho.CPU_SUBTYPE_X86_64_ALL;
        },
        else => return error.UnsupportedCpuArchitecture,
    }

    switch (self.output.?.tag) {
        .exe => {
            header.filetype = macho.MH_EXECUTE;
        },
        .dylib => {
            header.filetype = macho.MH_DYLIB;
            header.flags |= macho.MH_NO_REEXPORTED_DYLIBS;
        },
    }

    if (self.tlv_section_index) |_|
        header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;

    header.ncmds = @intCast(u32, self.load_commands.items.len);
    header.sizeofcmds = 0;

    for (self.load_commands.items) |cmd| {
        header.sizeofcmds += cmd.cmdsize();
    }

    log.debug("writing Mach-O header {}", .{header});

    try self.file.?.pwriteAll(mem.asBytes(&header), 0);
}
