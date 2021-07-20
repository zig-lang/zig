const DebugSymbols = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;
const DW = std.dwarf;
const leb = std.leb;
const Allocator = mem.Allocator;

const build_options = @import("build_options");
const trace = @import("../../tracy.zig").trace;
const Module = @import("../../Module.zig");
const Type = @import("../../type.zig").Type;
const link = @import("../../link.zig");
const MachO = @import("../MachO.zig");
const SrcFn = MachO.SrcFn;
const Atom = MachO.Atom;
const padToIdeal = MachO.padToIdeal;

usingnamespace @import("commands.zig");

const page_size: u16 = 0x1000;

base: *MachO,
file: fs.File,

/// Mach header
header: ?macho.mach_header_64 = null,

/// Table of all load commands
load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},
/// __PAGEZERO segment
pagezero_segment_cmd_index: ?u16 = null,
/// __TEXT segment
text_segment_cmd_index: ?u16 = null,
/// __DATA_CONST segment
data_const_segment_cmd_index: ?u16 = null,
/// __DATA segment
data_segment_cmd_index: ?u16 = null,
/// __LINKEDIT segment
linkedit_segment_cmd_index: ?u16 = null,
/// __DWARF segment
dwarf_segment_cmd_index: ?u16 = null,
/// Symbol table
symtab_cmd_index: ?u16 = null,
/// UUID load command
uuid_cmd_index: ?u16 = null,

/// Index into __TEXT,__text section.
text_section_index: ?u16 = null,

linkedit_off: u16 = page_size,
linkedit_size: u16 = page_size,

debug_info_section_index: ?u16 = null,
debug_abbrev_section_index: ?u16 = null,
debug_str_section_index: ?u16 = null,
debug_aranges_section_index: ?u16 = null,
debug_line_section_index: ?u16 = null,

debug_abbrev_table_offset: ?u64 = null,

/// A list of `SrcFn` whose Line Number Programs have surplus capacity.
/// This is the same concept as `atom_free_list`; see those doc comments.
dbg_line_fn_free_list: std.AutoHashMapUnmanaged(*SrcFn, void) = .{},
dbg_line_fn_first: ?*SrcFn = null,
dbg_line_fn_last: ?*SrcFn = null,

/// A list of `Atom` whose corresponding .debug_info tags have surplus capacity.
/// This is the same concept as `atom_free_list`; see those doc comments.
dbg_info_decl_free_list: std.AutoHashMapUnmanaged(*Atom, void) = .{},
dbg_info_decl_first: ?*Atom = null,
dbg_info_decl_last: ?*Atom = null,

/// Table of debug symbol names aka the debug string table.
debug_string_table: std.ArrayListUnmanaged(u8) = .{},

header_dirty: bool = false,
load_commands_dirty: bool = false,
string_table_dirty: bool = false,
debug_string_table_dirty: bool = false,
debug_abbrev_section_dirty: bool = false,
debug_aranges_section_dirty: bool = false,
debug_info_header_dirty: bool = false,
debug_line_header_dirty: bool = false,

const abbrev_compile_unit = 1;
const abbrev_subprogram = 2;
const abbrev_subprogram_retvoid = 3;
const abbrev_base_type = 4;
const abbrev_pad1 = 5;
const abbrev_parameter = 6;

/// The reloc offset for the virtual address of a function in its Line Number Program.
/// Size is a virtual address integer.
const dbg_line_vaddr_reloc_index = 3;
/// The reloc offset for the virtual address of a function in its .debug_info TAG_subprogram.
/// Size is a virtual address integer.
const dbg_info_low_pc_reloc_index = 1;

const min_nop_size = 2;

/// You must call this function *after* `MachO.populateMissingMetadata()`
/// has been called to get a viable debug symbols output.
pub fn populateMissingMetadata(self: *DebugSymbols, allocator: *Allocator) !void {
    if (self.header == null) {
        const base_header = self.base.header.?;
        var header: macho.mach_header_64 = undefined;
        header.magic = macho.MH_MAGIC_64;
        header.cputype = base_header.cputype;
        header.cpusubtype = base_header.cpusubtype;
        header.filetype = macho.MH_DSYM;
        // These will get populated at the end of flushing the results to file.
        header.ncmds = 0;
        header.sizeofcmds = 0;
        header.flags = 0;
        header.reserved = 0;
        self.header = header;
        self.header_dirty = true;
    }
    if (self.uuid_cmd_index == null) {
        const base_cmd = self.base.load_commands.items[self.base.uuid_cmd_index.?];
        self.uuid_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(allocator, base_cmd);
        self.header_dirty = true;
        self.load_commands_dirty = true;
    }
    if (self.symtab_cmd_index == null) {
        self.symtab_cmd_index = @intCast(u16, self.load_commands.items.len);
        const base_cmd = self.base.load_commands.items[self.base.symtab_cmd_index.?].Symtab;
        const symtab_size = base_cmd.nsyms * @sizeOf(macho.nlist_64);
        const symtab_off = self.findFreeSpaceLinkedit(symtab_size, @sizeOf(macho.nlist_64));

        log.debug("found dSym symbol table free space 0x{x} to 0x{x}", .{ symtab_off, symtab_off + symtab_size });

        const strtab_off = self.findFreeSpaceLinkedit(base_cmd.strsize, 1);

        log.debug("found dSym string table free space 0x{x} to 0x{x}", .{ strtab_off, strtab_off + base_cmd.strsize });

        try self.load_commands.append(allocator, .{
            .Symtab = .{
                .cmd = macho.LC_SYMTAB,
                .cmdsize = @sizeOf(macho.symtab_command),
                .symoff = @intCast(u32, symtab_off),
                .nsyms = base_cmd.nsyms,
                .stroff = @intCast(u32, strtab_off),
                .strsize = base_cmd.strsize,
            },
        });
        self.header_dirty = true;
        self.load_commands_dirty = true;
        self.string_table_dirty = true;
    }
    if (self.pagezero_segment_cmd_index == null) {
        self.pagezero_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const base_cmd = self.base.load_commands.items[self.base.pagezero_segment_cmd_index.?].Segment;
        const cmd = try self.copySegmentCommand(allocator, base_cmd);
        try self.load_commands.append(allocator, .{ .Segment = cmd });
        self.header_dirty = true;
        self.load_commands_dirty = true;
    }
    if (self.text_segment_cmd_index == null) {
        self.text_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const base_cmd = self.base.load_commands.items[self.base.text_segment_cmd_index.?].Segment;
        const cmd = try self.copySegmentCommand(allocator, base_cmd);
        try self.load_commands.append(allocator, .{ .Segment = cmd });
        self.header_dirty = true;
        self.load_commands_dirty = true;
    }
    if (self.data_const_segment_cmd_index == null) outer: {
        if (self.base.data_const_segment_cmd_index == null) break :outer; // __DATA_CONST is optional
        self.data_const_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const base_cmd = self.base.load_commands.items[self.base.data_const_segment_cmd_index.?].Segment;
        const cmd = try self.copySegmentCommand(allocator, base_cmd);
        try self.load_commands.append(allocator, .{ .Segment = cmd });
        self.header_dirty = true;
        self.load_commands_dirty = true;
    }
    if (self.data_segment_cmd_index == null) outer: {
        if (self.base.data_segment_cmd_index == null) break :outer; // __DATA is optional
        self.data_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const base_cmd = self.base.load_commands.items[self.base.data_segment_cmd_index.?].Segment;
        const cmd = try self.copySegmentCommand(allocator, base_cmd);
        try self.load_commands.append(allocator, .{ .Segment = cmd });
        self.header_dirty = true;
        self.load_commands_dirty = true;
    }
    if (self.linkedit_segment_cmd_index == null) {
        self.linkedit_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const base_cmd = self.base.load_commands.items[self.base.linkedit_segment_cmd_index.?].Segment;
        var cmd = try self.copySegmentCommand(allocator, base_cmd);
        cmd.inner.vmsize = self.linkedit_size;
        cmd.inner.fileoff = self.linkedit_off;
        cmd.inner.filesize = self.linkedit_size;
        try self.load_commands.append(allocator, .{ .Segment = cmd });
        self.header_dirty = true;
        self.load_commands_dirty = true;
    }
    if (self.dwarf_segment_cmd_index == null) {
        self.dwarf_segment_cmd_index = @intCast(u16, self.load_commands.items.len);

        const linkedit = self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
        const ideal_size: u16 = 200 + 128 + 160 + 250;
        const needed_size = mem.alignForwardGeneric(u64, padToIdeal(ideal_size), page_size);
        const off = linkedit.inner.fileoff + linkedit.inner.filesize;
        const vmaddr = linkedit.inner.vmaddr + linkedit.inner.vmsize;

        log.debug("found dSym __DWARF segment free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try self.load_commands.append(allocator, .{
            .Segment = SegmentCommand.empty("__DWARF", .{
                .vmaddr = vmaddr,
                .vmsize = needed_size,
                .fileoff = off,
                .filesize = needed_size,
            }),
        });
        self.header_dirty = true;
        self.load_commands_dirty = true;
    }
    if (self.debug_str_section_index == null) {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        self.debug_str_section_index = @intCast(u16, dwarf_segment.sections.items.len);
        assert(self.debug_string_table.items.len == 0);

        try dwarf_segment.addSection(allocator, "__debug_str", .{
            .addr = dwarf_segment.inner.vmaddr,
            .size = @intCast(u32, self.debug_string_table.items.len),
            .offset = @intCast(u32, dwarf_segment.inner.fileoff),
            .@"align" = 1,
        });
        self.header_dirty = true;
        self.load_commands_dirty = true;
        self.debug_string_table_dirty = true;
    }
    if (self.debug_info_section_index == null) {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        self.debug_info_section_index = @intCast(u16, dwarf_segment.sections.items.len);

        const file_size_hint = 200;
        const p_align = 1;
        const off = dwarf_segment.findFreeSpace(file_size_hint, p_align, null);

        log.debug("found dSym __debug_info free space 0x{x} to 0x{x}", .{ off, off + file_size_hint });

        try dwarf_segment.addSection(allocator, "__debug_info", .{
            .addr = dwarf_segment.inner.vmaddr + off - dwarf_segment.inner.fileoff,
            .size = file_size_hint,
            .offset = @intCast(u32, off),
            .@"align" = p_align,
        });
        self.header_dirty = true;
        self.load_commands_dirty = true;
        self.debug_info_header_dirty = true;
    }
    if (self.debug_abbrev_section_index == null) {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        self.debug_abbrev_section_index = @intCast(u16, dwarf_segment.sections.items.len);

        const file_size_hint = 128;
        const p_align = 1;
        const off = dwarf_segment.findFreeSpace(file_size_hint, p_align, null);

        log.debug("found dSym __debug_abbrev free space 0x{x} to 0x{x}", .{ off, off + file_size_hint });

        try dwarf_segment.addSection(allocator, "__debug_abbrev", .{
            .addr = dwarf_segment.inner.vmaddr + off - dwarf_segment.inner.fileoff,
            .size = file_size_hint,
            .offset = @intCast(u32, off),
            .@"align" = p_align,
        });
        self.header_dirty = true;
        self.load_commands_dirty = true;
        self.debug_abbrev_section_dirty = true;
    }
    if (self.debug_aranges_section_index == null) {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        self.debug_aranges_section_index = @intCast(u16, dwarf_segment.sections.items.len);

        const file_size_hint = 160;
        const p_align = 16;
        const off = dwarf_segment.findFreeSpace(file_size_hint, p_align, null);

        log.debug("found dSym __debug_aranges free space 0x{x} to 0x{x}", .{ off, off + file_size_hint });

        try dwarf_segment.addSection(allocator, "__debug_aranges", .{
            .addr = dwarf_segment.inner.vmaddr + off - dwarf_segment.inner.fileoff,
            .size = file_size_hint,
            .offset = @intCast(u32, off),
            .@"align" = p_align,
        });
        self.header_dirty = true;
        self.load_commands_dirty = true;
        self.debug_aranges_section_dirty = true;
    }
    if (self.debug_line_section_index == null) {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        self.debug_line_section_index = @intCast(u16, dwarf_segment.sections.items.len);

        const file_size_hint = 250;
        const p_align = 1;
        const off = dwarf_segment.findFreeSpace(file_size_hint, p_align, null);

        log.debug("found dSym __debug_line free space 0x{x} to 0x{x}", .{ off, off + file_size_hint });

        try dwarf_segment.addSection(allocator, "__debug_line", .{
            .addr = dwarf_segment.inner.vmaddr + off - dwarf_segment.inner.fileoff,
            .size = file_size_hint,
            .offset = @intCast(u32, off),
            .@"align" = p_align,
        });
        self.header_dirty = true;
        self.load_commands_dirty = true;
        self.debug_line_header_dirty = true;
    }
}

pub fn flushModule(self: *DebugSymbols, allocator: *Allocator, options: link.Options) !void {
    // TODO This linker code currently assumes there is only 1 compilation unit and it corresponds to the
    // Zig source code.
    const module = options.module orelse return error.LinkingWithoutZigSourceUnimplemented;
    const init_len_size: usize = 4;

    if (self.debug_abbrev_section_dirty) {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        const debug_abbrev_sect = &dwarf_segment.sections.items[self.debug_abbrev_section_index.?];

        // These are LEB encoded but since the values are all less than 127
        // we can simply append these bytes.
        const abbrev_buf = [_]u8{
            abbrev_compile_unit, DW.TAG_compile_unit, DW.CHILDREN_yes, // header
            DW.AT_stmt_list, DW.FORM_sec_offset, // offset
            DW.AT_low_pc,    DW.FORM_addr,
            DW.AT_high_pc,   DW.FORM_addr,
            DW.AT_name,      DW.FORM_strp,
            DW.AT_comp_dir,  DW.FORM_strp,
            DW.AT_producer,  DW.FORM_strp,
            DW.AT_language,  DW.FORM_data2,
            0, 0, // table sentinel
            abbrev_subprogram, DW.TAG_subprogram, DW.CHILDREN_yes, // header
            DW.AT_low_pc,    DW.FORM_addr, // start VM address
            DW.AT_high_pc,   DW.FORM_data4,
            DW.AT_type,      DW.FORM_ref4,
            DW.AT_name,      DW.FORM_string,
            DW.AT_decl_line, DW.FORM_data4,
            DW.AT_decl_file, DW.FORM_data1,
            0,                         0, // table sentinel
            abbrev_subprogram_retvoid,
            DW.TAG_subprogram, DW.CHILDREN_yes, // header
            DW.AT_low_pc,      DW.FORM_addr,
            DW.AT_high_pc,     DW.FORM_data4,
            DW.AT_name,        DW.FORM_string,
            DW.AT_decl_line,   DW.FORM_data4,
            DW.AT_decl_file,   DW.FORM_data1,
            0, 0, // table sentinel
            abbrev_base_type, DW.TAG_base_type, DW.CHILDREN_no, // header
            DW.AT_encoding,   DW.FORM_data1,    DW.AT_byte_size,
            DW.FORM_data1,    DW.AT_name,       DW.FORM_string,
            0, 0, // table sentinel
            abbrev_pad1, DW.TAG_unspecified_type, DW.CHILDREN_no, // header
            0, 0, // table sentinel
            abbrev_parameter, DW.TAG_formal_parameter, DW.CHILDREN_no, // header
            DW.AT_location,   DW.FORM_exprloc,         DW.AT_type,
            DW.FORM_ref4,     DW.AT_name,              DW.FORM_string,
            0, 0, // table sentinel
            0, 0, 0, // section sentinel
        };

        const needed_size = abbrev_buf.len;
        const allocated_size = dwarf_segment.allocatedSize(debug_abbrev_sect.offset);
        if (needed_size > allocated_size) {
            debug_abbrev_sect.size = 0; // free the space
            const offset = dwarf_segment.findFreeSpace(needed_size, 1, null);
            debug_abbrev_sect.offset = @intCast(u32, offset);
            debug_abbrev_sect.addr = dwarf_segment.inner.vmaddr + offset - dwarf_segment.inner.fileoff;
        }
        debug_abbrev_sect.size = needed_size;
        log.debug("__debug_abbrev start=0x{x} end=0x{x}", .{
            debug_abbrev_sect.offset,
            debug_abbrev_sect.offset + needed_size,
        });

        const abbrev_offset = 0;
        self.debug_abbrev_table_offset = abbrev_offset;
        try self.file.pwriteAll(&abbrev_buf, debug_abbrev_sect.offset + abbrev_offset);
        self.load_commands_dirty = true;
        self.debug_abbrev_section_dirty = false;
    }

    if (self.debug_info_header_dirty) debug_info: {
        // If this value is null it means there is an error in the module;
        // leave debug_info_header_dirty=true.
        const first_dbg_info_decl = self.dbg_info_decl_first orelse break :debug_info;
        const last_dbg_info_decl = self.dbg_info_decl_last.?;
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        const debug_info_sect = &dwarf_segment.sections.items[self.debug_info_section_index.?];

        var di_buf = std.ArrayList(u8).init(allocator);
        defer di_buf.deinit();

        // We have a function to compute the upper bound size, because it's needed
        // for determining where to put the offset of the first `LinkBlock`.
        try di_buf.ensureCapacity(self.dbgInfoNeededHeaderBytes());

        // initial length - length of the .debug_info contribution for this compilation unit,
        // not including the initial length itself.
        // We have to come back and write it later after we know the size.
        const after_init_len = di_buf.items.len + init_len_size;
        // +1 for the final 0 that ends the compilation unit children.
        const dbg_info_end = last_dbg_info_decl.dbg_info_off + last_dbg_info_decl.dbg_info_len + 1;
        const init_len = dbg_info_end - after_init_len;
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), @intCast(u32, init_len));
        mem.writeIntLittle(u16, di_buf.addManyAsArrayAssumeCapacity(2), 4); // DWARF version
        const abbrev_offset = self.debug_abbrev_table_offset.?;
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), @intCast(u32, abbrev_offset));
        di_buf.appendAssumeCapacity(8); // address size
        // Write the form for the compile unit, which must match the abbrev table above.
        const name_strp = try self.makeDebugString(allocator, module.root_pkg.root_src_path);
        const comp_dir_strp = try self.makeDebugString(allocator, module.root_pkg.root_src_directory.path orelse ".");
        const producer_strp = try self.makeDebugString(allocator, link.producer_string);
        // Currently only one compilation unit is supported, so the address range is simply
        // identical to the main program header virtual address and memory size.
        const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        const text_section = text_segment.sections.items[self.text_section_index.?];
        const low_pc = text_section.addr;
        const high_pc = text_section.addr + text_section.size;

        di_buf.appendAssumeCapacity(abbrev_compile_unit);
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), 0); // DW.AT_stmt_list, DW.FORM_sec_offset
        mem.writeIntLittle(u64, di_buf.addManyAsArrayAssumeCapacity(8), low_pc);
        mem.writeIntLittle(u64, di_buf.addManyAsArrayAssumeCapacity(8), high_pc);
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), @intCast(u32, name_strp));
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), @intCast(u32, comp_dir_strp));
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), @intCast(u32, producer_strp));
        // We are still waiting on dwarf-std.org to assign DW_LANG_Zig a number:
        // http://dwarfstd.org/ShowIssue.php?issue=171115.1
        // Until then we say it is C99.
        mem.writeIntLittle(u16, di_buf.addManyAsArrayAssumeCapacity(2), DW.LANG_C99);

        if (di_buf.items.len > first_dbg_info_decl.dbg_info_off) {
            // Move the first N decls to the end to make more padding for the header.
            @panic("TODO: handle __debug_info header exceeding its padding");
        }
        const jmp_amt = first_dbg_info_decl.dbg_info_off - di_buf.items.len;
        try self.pwriteDbgInfoNops(0, di_buf.items, jmp_amt, false, debug_info_sect.offset);
        self.debug_info_header_dirty = false;
    }

    if (self.debug_aranges_section_dirty) {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        const debug_aranges_sect = &dwarf_segment.sections.items[self.debug_aranges_section_index.?];

        var di_buf = std.ArrayList(u8).init(allocator);
        defer di_buf.deinit();

        // Enough for all the data without resizing. When support for more compilation units
        // is added, the size of this section will become more variable.
        try di_buf.ensureCapacity(100);

        // initial length - length of the .debug_aranges contribution for this compilation unit,
        // not including the initial length itself.
        // We have to come back and write it later after we know the size.
        const init_len_index = di_buf.items.len;
        di_buf.items.len += init_len_size;
        const after_init_len = di_buf.items.len;
        mem.writeIntLittle(u16, di_buf.addManyAsArrayAssumeCapacity(2), 2); // version
        // When more than one compilation unit is supported, this will be the offset to it.
        // For now it is always at offset 0 in .debug_info.
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), 0); // __debug_info offset
        di_buf.appendAssumeCapacity(@sizeOf(u64)); // address_size
        di_buf.appendAssumeCapacity(0); // segment_selector_size

        const end_header_offset = di_buf.items.len;
        const begin_entries_offset = mem.alignForward(end_header_offset, @sizeOf(u64) * 2);
        di_buf.appendNTimesAssumeCapacity(0, begin_entries_offset - end_header_offset);

        // Currently only one compilation unit is supported, so the address range is simply
        // identical to the main program header virtual address and memory size.
        const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        const text_section = text_segment.sections.items[self.text_section_index.?];
        mem.writeIntLittle(u64, di_buf.addManyAsArrayAssumeCapacity(8), text_section.addr);
        mem.writeIntLittle(u64, di_buf.addManyAsArrayAssumeCapacity(8), text_section.size);

        // Sentinel.
        mem.writeIntLittle(u64, di_buf.addManyAsArrayAssumeCapacity(8), 0);
        mem.writeIntLittle(u64, di_buf.addManyAsArrayAssumeCapacity(8), 0);

        // Go back and populate the initial length.
        const init_len = di_buf.items.len - after_init_len;
        // initial length - length of the .debug_aranges contribution for this compilation unit,
        // not including the initial length itself.
        mem.writeIntLittle(u32, di_buf.items[init_len_index..][0..4], @intCast(u32, init_len));

        const needed_size = di_buf.items.len;
        const allocated_size = dwarf_segment.allocatedSize(debug_aranges_sect.offset);
        if (needed_size > allocated_size) {
            debug_aranges_sect.size = 0; // free the space
            const new_offset = dwarf_segment.findFreeSpace(needed_size, 16, null);
            debug_aranges_sect.addr = dwarf_segment.inner.vmaddr + new_offset - dwarf_segment.inner.fileoff;
            debug_aranges_sect.offset = @intCast(u32, new_offset);
        }
        debug_aranges_sect.size = needed_size;
        log.debug("__debug_aranges start=0x{x} end=0x{x}", .{
            debug_aranges_sect.offset,
            debug_aranges_sect.offset + needed_size,
        });

        try self.file.pwriteAll(di_buf.items, debug_aranges_sect.offset);
        self.load_commands_dirty = true;
        self.debug_aranges_section_dirty = false;
    }
    if (self.debug_line_header_dirty) debug_line: {
        if (self.dbg_line_fn_first == null) {
            break :debug_line; // Error in module; leave debug_line_header_dirty=true.
        }
        const dbg_line_prg_off = self.getDebugLineProgramOff();
        const dbg_line_prg_end = self.getDebugLineProgramEnd();
        assert(dbg_line_prg_end != 0);

        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        const debug_line_sect = &dwarf_segment.sections.items[self.debug_line_section_index.?];

        var di_buf = std.ArrayList(u8).init(allocator);
        defer di_buf.deinit();

        // The size of this header is variable, depending on the number of directories,
        // files, and padding. We have a function to compute the upper bound size, however,
        // because it's needed for determining where to put the offset of the first `SrcFn`.
        try di_buf.ensureCapacity(self.dbgLineNeededHeaderBytes(module));

        // initial length - length of the .debug_line contribution for this compilation unit,
        // not including the initial length itself.
        const after_init_len = di_buf.items.len + init_len_size;
        const init_len = dbg_line_prg_end - after_init_len;
        mem.writeIntLittle(u32, di_buf.addManyAsArrayAssumeCapacity(4), @intCast(u32, init_len));
        mem.writeIntLittle(u16, di_buf.addManyAsArrayAssumeCapacity(2), 4); // version

        // Empirically, debug info consumers do not respect this field, or otherwise
        // consider it to be an error when it does not point exactly to the end of the header.
        // Therefore we rely on the NOP jump at the beginning of the Line Number Program for
        // padding rather than this field.
        const before_header_len = di_buf.items.len;
        di_buf.items.len += @sizeOf(u32); // We will come back and write this.
        const after_header_len = di_buf.items.len;

        const opcode_base = DW.LNS_set_isa + 1;
        di_buf.appendSliceAssumeCapacity(&[_]u8{
            1, // minimum_instruction_length
            1, // maximum_operations_per_instruction
            1, // default_is_stmt
            1, // line_base (signed)
            1, // line_range
            opcode_base,

            // Standard opcode lengths. The number of items here is based on `opcode_base`.
            // The value is the number of LEB128 operands the instruction takes.
            0, // `DW.LNS_copy`
            1, // `DW.LNS_advance_pc`
            1, // `DW.LNS_advance_line`
            1, // `DW.LNS_set_file`
            1, // `DW.LNS_set_column`
            0, // `DW.LNS_negate_stmt`
            0, // `DW.LNS_set_basic_block`
            0, // `DW.LNS_const_add_pc`
            1, // `DW.LNS_fixed_advance_pc`
            0, // `DW.LNS_set_prologue_end`
            0, // `DW.LNS_set_epilogue_begin`
            1, // `DW.LNS_set_isa`
            0, // include_directories (none except the compilation unit cwd)
        });
        // file_names[0]
        di_buf.appendSliceAssumeCapacity(module.root_pkg.root_src_path); // relative path name
        di_buf.appendSliceAssumeCapacity(&[_]u8{
            0, // null byte for the relative path name
            0, // directory_index
            0, // mtime (TODO supply this)
            0, // file size bytes (TODO supply this)
            0, // file_names sentinel
        });

        const header_len = di_buf.items.len - after_header_len;
        mem.writeIntLittle(u32, di_buf.items[before_header_len..][0..4], @intCast(u32, header_len));

        // We use NOPs because consumers empirically do not respect the header length field.
        if (di_buf.items.len > dbg_line_prg_off) {
            // Move the first N files to the end to make more padding for the header.
            @panic("TODO: handle __debug_line header exceeding its padding");
        }
        const jmp_amt = dbg_line_prg_off - di_buf.items.len;
        try self.pwriteDbgLineNops(0, di_buf.items, jmp_amt, debug_line_sect.offset);
        self.debug_line_header_dirty = false;
    }
    {
        const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
        const debug_strtab_sect = &dwarf_segment.sections.items[self.debug_str_section_index.?];
        if (self.debug_string_table_dirty or self.debug_string_table.items.len != debug_strtab_sect.size) {
            const allocated_size = dwarf_segment.allocatedSize(debug_strtab_sect.offset);
            const needed_size = self.debug_string_table.items.len;

            if (needed_size > allocated_size) {
                debug_strtab_sect.size = 0; // free the space
                const new_offset = dwarf_segment.findFreeSpace(needed_size, 1, null);
                debug_strtab_sect.addr = dwarf_segment.inner.vmaddr + new_offset - dwarf_segment.inner.fileoff;
                debug_strtab_sect.offset = @intCast(u32, new_offset);
            }
            debug_strtab_sect.size = @intCast(u32, needed_size);

            log.debug("__debug_strtab start=0x{x} end=0x{x}", .{
                debug_strtab_sect.offset,
                debug_strtab_sect.offset + needed_size,
            });

            try self.file.pwriteAll(self.debug_string_table.items, debug_strtab_sect.offset);
            self.load_commands_dirty = true;
            self.debug_string_table_dirty = false;
        }
    }

    try self.writeStringTable();
    self.updateDwarfSegment();
    try self.writeLoadCommands(allocator);
    try self.writeHeader();

    assert(!self.header_dirty);
    assert(!self.load_commands_dirty);
    assert(!self.string_table_dirty);
    assert(!self.debug_abbrev_section_dirty);
    assert(!self.debug_aranges_section_dirty);
    assert(!self.debug_string_table_dirty);
}

pub fn deinit(self: *DebugSymbols, allocator: *Allocator) void {
    self.dbg_info_decl_free_list.deinit(allocator);
    self.dbg_line_fn_free_list.deinit(allocator);
    self.debug_string_table.deinit(allocator);
    for (self.load_commands.items) |*lc| {
        lc.deinit(allocator);
    }
    self.load_commands.deinit(allocator);
    self.file.close();
}

fn copySegmentCommand(self: *DebugSymbols, allocator: *Allocator, base_cmd: SegmentCommand) !SegmentCommand {
    var cmd = SegmentCommand.empty("", .{
        .cmdsize = base_cmd.inner.cmdsize,
        .vmaddr = base_cmd.inner.vmaddr,
        .vmsize = base_cmd.inner.vmsize,
        .maxprot = base_cmd.inner.maxprot,
        .initprot = base_cmd.inner.initprot,
        .nsects = base_cmd.inner.nsects,
        .flags = base_cmd.inner.flags,
    });
    mem.copy(u8, &cmd.inner.segname, &base_cmd.inner.segname);

    try cmd.sections.ensureCapacity(allocator, cmd.inner.nsects);
    for (base_cmd.sections.items) |base_sect, i| {
        var sect = macho.section_64{
            .sectname = undefined,
            .segname = undefined,
            .addr = base_sect.addr,
            .size = base_sect.size,
            .offset = 0,
            .@"align" = base_sect.@"align",
            .reloff = 0,
            .nreloc = 0,
            .flags = base_sect.flags,
            .reserved1 = base_sect.reserved1,
            .reserved2 = base_sect.reserved2,
            .reserved3 = base_sect.reserved3,
        };
        mem.copy(u8, &sect.sectname, &base_sect.sectname);
        mem.copy(u8, &sect.segname, &base_sect.segname);

        if (self.base.text_section_index.? == i) {
            self.text_section_index = @intCast(u16, i);
        }

        cmd.sections.appendAssumeCapacity(sect);
    }

    return cmd;
}

fn updateDwarfSegment(self: *DebugSymbols) void {
    const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
    var file_size: u64 = 0;
    for (dwarf_segment.sections.items) |sect| {
        file_size += sect.size;
    }
    if (file_size != dwarf_segment.inner.filesize) {
        dwarf_segment.inner.filesize = file_size;
        if (dwarf_segment.inner.vmsize < dwarf_segment.inner.filesize) {
            dwarf_segment.inner.vmsize = mem.alignForwardGeneric(u64, dwarf_segment.inner.filesize, page_size);
        }
        self.load_commands_dirty = true;
    }
}

/// Writes all load commands and section headers.
fn writeLoadCommands(self: *DebugSymbols, allocator: *Allocator) !void {
    if (!self.load_commands_dirty) return;

    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    var buffer = try allocator.alloc(u8, sizeofcmds);
    defer allocator.free(buffer);
    var writer = std.io.fixedBufferStream(buffer).writer();
    for (self.load_commands.items) |lc| {
        try lc.write(writer);
    }

    const off = @sizeOf(macho.mach_header_64);
    log.debug("writing {} dSym load commands from 0x{x} to 0x{x}", .{ self.load_commands.items.len, off, off + sizeofcmds });
    try self.file.pwriteAll(buffer, off);
    self.load_commands_dirty = false;
}

fn writeHeader(self: *DebugSymbols) !void {
    if (!self.header_dirty) return;

    self.header.?.ncmds = @intCast(u32, self.load_commands.items.len);
    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |cmd| {
        sizeofcmds += cmd.cmdsize();
    }
    self.header.?.sizeofcmds = sizeofcmds;
    log.debug("writing Mach-O dSym header {}", .{self.header.?});
    try self.file.pwriteAll(mem.asBytes(&self.header.?), 0);
    self.header_dirty = false;
}

fn allocatedSizeLinkedit(self: *DebugSymbols, start: u64) u64 {
    assert(start > 0);
    var min_pos: u64 = std.math.maxInt(u64);

    if (self.symtab_cmd_index) |idx| {
        const symtab = self.load_commands.items[idx].Symtab;
        if (symtab.symoff >= start and symtab.symoff < min_pos) min_pos = symtab.symoff;
        if (symtab.stroff >= start and symtab.stroff < min_pos) min_pos = symtab.stroff;
    }

    return min_pos - start;
}

fn detectAllocCollisionLinkedit(self: *DebugSymbols, start: u64, size: u64) ?u64 {
    const end = start + padToIdeal(size);

    if (self.symtab_cmd_index) |idx| outer: {
        if (self.load_commands.items.len == idx) break :outer;
        const symtab = self.load_commands.items[idx].Symtab;
        {
            // Symbol table
            const symsize = symtab.nsyms * @sizeOf(macho.nlist_64);
            const increased_size = padToIdeal(symsize);
            const test_end = symtab.symoff + increased_size;
            if (end > symtab.symoff and start < test_end) {
                return test_end;
            }
        }
        {
            // String table
            const increased_size = padToIdeal(symtab.strsize);
            const test_end = symtab.stroff + increased_size;
            if (end > symtab.stroff and start < test_end) {
                return test_end;
            }
        }
    }

    return null;
}

fn findFreeSpaceLinkedit(self: *DebugSymbols, object_size: u64, min_alignment: u16) u64 {
    var start: u64 = self.linkedit_off;
    while (self.detectAllocCollisionLinkedit(start, object_size)) |item_end| {
        start = mem.alignForwardGeneric(u64, item_end, min_alignment);
    }
    return start;
}

fn relocateSymbolTable(self: *DebugSymbols) !void {
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    const nlocals = self.base.locals.items.len;
    const nglobals = self.base.globals.items.len;
    const nsyms = nlocals + nglobals;

    if (symtab.nsyms < nsyms) {
        const needed_size = nsyms * @sizeOf(macho.nlist_64);
        if (needed_size > self.allocatedSizeLinkedit(symtab.symoff)) {
            // Move the entire symbol table to a new location
            const new_symoff = self.findFreeSpaceLinkedit(needed_size, @alignOf(macho.nlist_64));
            const existing_size = symtab.nsyms * @sizeOf(macho.nlist_64);

            assert(new_symoff + existing_size <= self.linkedit_off + self.linkedit_size); // TODO expand LINKEDIT segment.
            log.debug("relocating dSym symbol table from 0x{x}-0x{x} to 0x{x}-0x{x}", .{
                symtab.symoff,
                symtab.symoff + existing_size,
                new_symoff,
                new_symoff + existing_size,
            });

            const amt = try self.file.copyRangeAll(symtab.symoff, self.file, new_symoff, existing_size);
            if (amt != existing_size) return error.InputOutput;
            symtab.symoff = @intCast(u32, new_symoff);
        }
        symtab.nsyms = @intCast(u32, nsyms);
        self.load_commands_dirty = true;
    }
}

pub fn writeLocalSymbol(self: *DebugSymbols, index: usize) !void {
    const tracy = trace(@src());
    defer tracy.end();
    try self.relocateSymbolTable();
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    const off = symtab.symoff + @sizeOf(macho.nlist_64) * index;
    log.debug("writing dSym local symbol {} at 0x{x}", .{ index, off });
    try self.file.pwriteAll(mem.asBytes(&self.base.locals.items[index]), off);
}

fn writeStringTable(self: *DebugSymbols) !void {
    if (!self.string_table_dirty) return;

    const tracy = trace(@src());
    defer tracy.end();

    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    const allocated_size = self.allocatedSizeLinkedit(symtab.stroff);
    const needed_size = mem.alignForwardGeneric(u64, self.base.string_table.items.len, @alignOf(u64));

    if (needed_size > allocated_size) {
        symtab.strsize = 0;
        symtab.stroff = @intCast(u32, self.findFreeSpaceLinkedit(needed_size, 1));
    }
    symtab.strsize = @intCast(u32, needed_size);
    log.debug("writing dSym string table from 0x{x} to 0x{x}", .{ symtab.stroff, symtab.stroff + symtab.strsize });

    try self.file.pwriteAll(self.base.string_table.items, symtab.stroff);
    self.load_commands_dirty = true;
    self.string_table_dirty = false;
}

pub fn updateDeclLineNumber(self: *DebugSymbols, module: *Module, decl: *const Module.Decl) !void {
    _ = module;
    const tracy = trace(@src());
    defer tracy.end();

    const func = decl.val.castTag(.function).?.data;
    const line_off = @intCast(u28, decl.src_line + func.lbrace_line);

    const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
    const shdr = &dwarf_segment.sections.items[self.debug_line_section_index.?];
    const file_pos = shdr.offset + decl.fn_link.macho.off + getRelocDbgLineOff();
    var data: [4]u8 = undefined;
    leb.writeUnsignedFixed(4, &data, line_off);
    try self.file.pwriteAll(&data, file_pos);
}

pub const DeclDebugBuffers = struct {
    dbg_line_buffer: std.ArrayList(u8),
    dbg_info_buffer: std.ArrayList(u8),
    dbg_info_type_relocs: link.File.DbgInfoTypeRelocsTable,
};

/// Caller owns the returned memory.
pub fn initDeclDebugBuffers(
    self: *DebugSymbols,
    allocator: *Allocator,
    module: *Module,
    decl: *Module.Decl,
) !DeclDebugBuffers {
    _ = self;
    _ = module;
    const tracy = trace(@src());
    defer tracy.end();

    var dbg_line_buffer = std.ArrayList(u8).init(allocator);
    var dbg_info_buffer = std.ArrayList(u8).init(allocator);
    var dbg_info_type_relocs: link.File.DbgInfoTypeRelocsTable = .{};

    assert(decl.has_tv);
    switch (decl.ty.zigTypeTag()) {
        .Fn => {
            // For functions we need to add a prologue to the debug line program.
            try dbg_line_buffer.ensureCapacity(26);

            const func = decl.val.castTag(.function).?.data;
            const line_off = @intCast(u28, decl.src_line + func.lbrace_line);

            dbg_line_buffer.appendSliceAssumeCapacity(&[_]u8{
                DW.LNS_extended_op,
                @sizeOf(u64) + 1,
                DW.LNE_set_address,
            });
            // This is the "relocatable" vaddr, corresponding to `code_buffer` index `0`.
            assert(dbg_line_vaddr_reloc_index == dbg_line_buffer.items.len);
            dbg_line_buffer.items.len += @sizeOf(u64);

            dbg_line_buffer.appendAssumeCapacity(DW.LNS_advance_line);
            // This is the "relocatable" relative line offset from the previous function's end curly
            // to this function's begin curly.
            assert(getRelocDbgLineOff() == dbg_line_buffer.items.len);
            // Here we use a ULEB128-fixed-4 to make sure this field can be overwritten later.
            leb.writeUnsignedFixed(4, dbg_line_buffer.addManyAsArrayAssumeCapacity(4), line_off);

            dbg_line_buffer.appendAssumeCapacity(DW.LNS_set_file);
            assert(getRelocDbgFileIndex() == dbg_line_buffer.items.len);
            // Once we support more than one source file, this will have the ability to be more
            // than one possible value.
            const file_index = 1;
            leb.writeUnsignedFixed(4, dbg_line_buffer.addManyAsArrayAssumeCapacity(4), file_index);

            // Emit a line for the begin curly with prologue_end=false. The codegen will
            // do the work of setting prologue_end=true and epilogue_begin=true.
            dbg_line_buffer.appendAssumeCapacity(DW.LNS_copy);

            // .debug_info subprogram
            const decl_name_with_null = decl.name[0 .. mem.lenZ(decl.name) + 1];
            try dbg_info_buffer.ensureCapacity(dbg_info_buffer.items.len + 27 + decl_name_with_null.len);

            const fn_ret_type = decl.ty.fnReturnType();
            const fn_ret_has_bits = fn_ret_type.hasCodeGenBits();
            if (fn_ret_has_bits) {
                dbg_info_buffer.appendAssumeCapacity(abbrev_subprogram);
            } else {
                dbg_info_buffer.appendAssumeCapacity(abbrev_subprogram_retvoid);
            }
            // These get overwritten after generating the machine code. These values are
            // "relocations" and have to be in this fixed place so that functions can be
            // moved in virtual address space.
            assert(dbg_info_low_pc_reloc_index == dbg_info_buffer.items.len);
            dbg_info_buffer.items.len += @sizeOf(u64); // DW.AT_low_pc,  DW.FORM_addr
            assert(getRelocDbgInfoSubprogramHighPC() == dbg_info_buffer.items.len);
            dbg_info_buffer.items.len += 4; // DW.AT_high_pc,  DW.FORM_data4
            if (fn_ret_has_bits) {
                const gop = try dbg_info_type_relocs.getOrPut(allocator, fn_ret_type);
                if (!gop.found_existing) {
                    gop.value_ptr.* = .{
                        .off = undefined,
                        .relocs = .{},
                    };
                }
                try gop.value_ptr.relocs.append(allocator, @intCast(u32, dbg_info_buffer.items.len));
                dbg_info_buffer.items.len += 4; // DW.AT_type,  DW.FORM_ref4
            }
            dbg_info_buffer.appendSliceAssumeCapacity(decl_name_with_null); // DW.AT_name, DW.FORM_string
            mem.writeIntLittle(u32, dbg_info_buffer.addManyAsArrayAssumeCapacity(4), line_off + 1); // DW.AT_decl_line, DW.FORM_data4
            dbg_info_buffer.appendAssumeCapacity(file_index); // DW.AT_decl_file, DW.FORM_data1
        },
        else => {
            // TODO implement .debug_info for global variables
        },
    }

    return DeclDebugBuffers{
        .dbg_info_buffer = dbg_info_buffer,
        .dbg_line_buffer = dbg_line_buffer,
        .dbg_info_type_relocs = dbg_info_type_relocs,
    };
}

pub fn commitDeclDebugInfo(
    self: *DebugSymbols,
    allocator: *Allocator,
    module: *Module,
    decl: *Module.Decl,
    debug_buffers: *DeclDebugBuffers,
    target: std.Target,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    var dbg_line_buffer = &debug_buffers.dbg_line_buffer;
    var dbg_info_buffer = &debug_buffers.dbg_info_buffer;
    var dbg_info_type_relocs = &debug_buffers.dbg_info_type_relocs;

    const symbol = self.base.locals.items[decl.link.macho.local_sym_index];
    const atom = &decl.link.macho;
    // If the Decl is a function, we need to update the __debug_line program.
    assert(decl.has_tv);
    switch (decl.ty.zigTypeTag()) {
        .Fn => {
            // Perform the relocations based on vaddr.
            {
                const ptr = dbg_line_buffer.items[dbg_line_vaddr_reloc_index..][0..8];
                mem.writeIntLittle(u64, ptr, symbol.n_value);
            }
            {
                const ptr = dbg_info_buffer.items[dbg_info_low_pc_reloc_index..][0..8];
                mem.writeIntLittle(u64, ptr, symbol.n_value);
            }
            {
                const ptr = dbg_info_buffer.items[getRelocDbgInfoSubprogramHighPC()..][0..4];
                mem.writeIntLittle(u32, ptr, @intCast(u32, atom.size));
            }

            {
                // Advance line and PC.
                // TODO encapsulate logic in a helper function.
                try dbg_line_buffer.append(DW.LNS_advance_pc);
                try leb.writeULEB128(dbg_line_buffer.writer(), atom.size);

                try dbg_line_buffer.append(DW.LNS_advance_line);
                const func = decl.val.castTag(.function).?.data;
                const line_off = @intCast(u28, func.rbrace_line - func.lbrace_line);
                try leb.writeULEB128(dbg_line_buffer.writer(), line_off);
            }

            try dbg_line_buffer.appendSlice(&[_]u8{ DW.LNS_extended_op, 1, DW.LNE_end_sequence });

            // Now we have the full contents and may allocate a region to store it.

            // This logic is nearly identical to the logic below in `updateDeclDebugInfo` for
            // `Atom` and the .debug_info. If you are editing this logic, you
            // probably need to edit that logic too.

            const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
            const debug_line_sect = &dwarf_segment.sections.items[self.debug_line_section_index.?];
            const src_fn = &decl.fn_link.macho;
            src_fn.len = @intCast(u32, dbg_line_buffer.items.len);
            if (self.dbg_line_fn_last) |last| blk: {
                if (src_fn == last) break :blk;
                if (src_fn.next) |next| {
                    // Update existing function - non-last item.
                    if (src_fn.off + src_fn.len + min_nop_size > next.off) {
                        // It grew too big, so we move it to a new location.
                        if (src_fn.prev) |prev| {
                            self.dbg_line_fn_free_list.put(allocator, prev, {}) catch {};
                            prev.next = src_fn.next;
                        }
                        next.prev = src_fn.prev;
                        src_fn.next = null;
                        // Populate where it used to be with NOPs.
                        const file_pos = debug_line_sect.offset + src_fn.off;
                        try self.pwriteDbgLineNops(0, &[0]u8{}, src_fn.len, file_pos);
                        // TODO Look at the free list before appending at the end.
                        src_fn.prev = last;
                        last.next = src_fn;
                        self.dbg_line_fn_last = src_fn;

                        src_fn.off = last.off + padToIdeal(last.len);
                    }
                } else if (src_fn.prev == null) {
                    // Append new function.
                    // TODO Look at the free list before appending at the end.
                    src_fn.prev = last;
                    last.next = src_fn;
                    self.dbg_line_fn_last = src_fn;

                    src_fn.off = last.off + padToIdeal(last.len);
                }
            } else {
                // This is the first function of the Line Number Program.
                self.dbg_line_fn_first = src_fn;
                self.dbg_line_fn_last = src_fn;

                src_fn.off = padToIdeal(self.dbgLineNeededHeaderBytes(module));
            }

            const last_src_fn = self.dbg_line_fn_last.?;
            const needed_size = last_src_fn.off + last_src_fn.len;
            if (needed_size != debug_line_sect.size) {
                if (needed_size > dwarf_segment.allocatedSize(debug_line_sect.offset)) {
                    const new_offset = dwarf_segment.findFreeSpace(needed_size, 1, null);
                    const existing_size = last_src_fn.off;

                    log.debug("moving __debug_line section: {} bytes from 0x{x} to 0x{x}", .{
                        existing_size,
                        debug_line_sect.offset,
                        new_offset,
                    });

                    const amt = try self.file.copyRangeAll(debug_line_sect.offset, self.file, new_offset, existing_size);
                    if (amt != existing_size) return error.InputOutput;
                    debug_line_sect.offset = @intCast(u32, new_offset);
                    debug_line_sect.addr = dwarf_segment.inner.vmaddr + new_offset - dwarf_segment.inner.fileoff;
                }
                debug_line_sect.size = needed_size;
                self.load_commands_dirty = true; // TODO look into making only the one section dirty
                self.debug_line_header_dirty = true;
            }
            const prev_padding_size: u32 = if (src_fn.prev) |prev| src_fn.off - (prev.off + prev.len) else 0;
            const next_padding_size: u32 = if (src_fn.next) |next| next.off - (src_fn.off + src_fn.len) else 0;

            // We only have support for one compilation unit so far, so the offsets are directly
            // from the .debug_line section.
            const file_pos = debug_line_sect.offset + src_fn.off;
            try self.pwriteDbgLineNops(prev_padding_size, dbg_line_buffer.items, next_padding_size, file_pos);

            // .debug_info - End the TAG_subprogram children.
            try dbg_info_buffer.append(0);
        },
        else => {},
    }

    if (dbg_info_buffer.items.len == 0)
        return;

    {
        // Now we emit the .debug_info types of the Decl. These will count towards the size of
        // the buffer, so we have to do it before computing the offset, and we can't perform the actual
        // relocations yet.
        var it = dbg_info_type_relocs.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.off = @intCast(u32, dbg_info_buffer.items.len);
            try self.addDbgInfoType(entry.key_ptr.*, dbg_info_buffer, target);
        }
    }

    try self.updateDeclDebugInfoAllocation(allocator, atom, @intCast(u32, dbg_info_buffer.items.len));

    {
        // Now that we have the offset assigned we can finally perform type relocations.
        var it = dbg_info_type_relocs.valueIterator();
        while (it.next()) |value| {
            for (value.relocs.items) |off| {
                mem.writeIntLittle(
                    u32,
                    dbg_info_buffer.items[off..][0..4],
                    atom.dbg_info_off + value.off,
                );
            }
        }
    }

    try self.writeDeclDebugInfo(atom, dbg_info_buffer.items);
}

/// Asserts the type has codegen bits.
fn addDbgInfoType(
    self: *DebugSymbols,
    ty: Type,
    dbg_info_buffer: *std.ArrayList(u8),
    target: std.Target,
) !void {
    _ = self;
    switch (ty.zigTypeTag()) {
        .Void => unreachable,
        .NoReturn => unreachable,
        .Bool => {
            try dbg_info_buffer.appendSlice(&[_]u8{
                abbrev_base_type,
                DW.ATE_boolean, // DW.AT_encoding ,  DW.FORM_data1
                1, // DW.AT_byte_size,  DW.FORM_data1
                'b',
                'o',
                'o',
                'l',
                0, // DW.AT_name,  DW.FORM_string
            });
        },
        .Int => {
            const info = ty.intInfo(target);
            try dbg_info_buffer.ensureCapacity(dbg_info_buffer.items.len + 12);
            dbg_info_buffer.appendAssumeCapacity(abbrev_base_type);
            // DW.AT_encoding, DW.FORM_data1
            dbg_info_buffer.appendAssumeCapacity(switch (info.signedness) {
                .signed => DW.ATE_signed,
                .unsigned => DW.ATE_unsigned,
            });
            // DW.AT_byte_size,  DW.FORM_data1
            dbg_info_buffer.appendAssumeCapacity(@intCast(u8, ty.abiSize(target)));
            // DW.AT_name,  DW.FORM_string
            try dbg_info_buffer.writer().print("{}\x00", .{ty});
        },
        else => {
            std.log.scoped(.compiler).err("TODO implement .debug_info for type '{}'", .{ty});
            try dbg_info_buffer.append(abbrev_pad1);
        },
    }
}

fn updateDeclDebugInfoAllocation(
    self: *DebugSymbols,
    allocator: *Allocator,
    atom: *Atom,
    len: u32,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // This logic is nearly identical to the logic above in `updateDecl` for
    // `SrcFn` and the line number programs. If you are editing this logic, you
    // probably need to edit that logic too.

    const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
    const debug_info_sect = &dwarf_segment.sections.items[self.debug_info_section_index.?];
    atom.dbg_info_len = len;
    if (self.dbg_info_decl_last) |last| blk: {
        if (atom == last) break :blk;
        if (atom.dbg_info_next) |next| {
            // Update existing Decl - non-last item.
            if (atom.dbg_info_off + atom.dbg_info_len + min_nop_size > next.dbg_info_off) {
                // It grew too big, so we move it to a new location.
                if (atom.dbg_info_prev) |prev| {
                    self.dbg_info_decl_free_list.put(allocator, prev, {}) catch {};
                    prev.dbg_info_next = atom.dbg_info_next;
                }
                next.dbg_info_prev = atom.dbg_info_prev;
                atom.dbg_info_next = null;
                // Populate where it used to be with NOPs.
                const file_pos = debug_info_sect.offset + atom.dbg_info_off;
                try self.pwriteDbgInfoNops(0, &[0]u8{}, atom.dbg_info_len, false, file_pos);
                // TODO Look at the free list before appending at the end.
                atom.dbg_info_prev = last;
                last.dbg_info_next = atom;
                self.dbg_info_decl_last = atom;

                atom.dbg_info_off = last.dbg_info_off + padToIdeal(last.dbg_info_len);
            }
        } else if (atom.dbg_info_prev == null) {
            // Append new Decl.
            // TODO Look at the free list before appending at the end.
            atom.dbg_info_prev = last;
            last.dbg_info_next = atom;
            self.dbg_info_decl_last = atom;

            atom.dbg_info_off = last.dbg_info_off + padToIdeal(last.dbg_info_len);
        }
    } else {
        // This is the first Decl of the .debug_info
        self.dbg_info_decl_first = atom;
        self.dbg_info_decl_last = atom;

        atom.dbg_info_off = padToIdeal(self.dbgInfoNeededHeaderBytes());
    }
}

fn writeDeclDebugInfo(self: *DebugSymbols, atom: *Atom, dbg_info_buf: []const u8) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // This logic is nearly identical to the logic above in `updateDecl` for
    // `SrcFn` and the line number programs. If you are editing this logic, you
    // probably need to edit that logic too.

    const dwarf_segment = &self.load_commands.items[self.dwarf_segment_cmd_index.?].Segment;
    const debug_info_sect = &dwarf_segment.sections.items[self.debug_info_section_index.?];

    const last_decl = self.dbg_info_decl_last.?;
    // +1 for a trailing zero to end the children of the decl tag.
    const needed_size = last_decl.dbg_info_off + last_decl.dbg_info_len + 1;
    if (needed_size != debug_info_sect.size) {
        if (needed_size > dwarf_segment.allocatedSize(debug_info_sect.offset)) {
            const new_offset = dwarf_segment.findFreeSpace(needed_size, 1, null);
            const existing_size = last_decl.dbg_info_off;

            log.debug("moving __debug_info section: {} bytes from 0x{x} to 0x{x}", .{
                existing_size,
                debug_info_sect.offset,
                new_offset,
            });

            const amt = try self.file.copyRangeAll(debug_info_sect.offset, self.file, new_offset, existing_size);
            if (amt != existing_size) return error.InputOutput;
            debug_info_sect.offset = @intCast(u32, new_offset);
            debug_info_sect.addr = dwarf_segment.inner.vmaddr + new_offset - dwarf_segment.inner.fileoff;
        }
        debug_info_sect.size = needed_size;
        self.load_commands_dirty = true; // TODO look into making only the one section dirty
        self.debug_info_header_dirty = true;
    }
    const prev_padding_size: u32 = if (atom.dbg_info_prev) |prev|
        atom.dbg_info_off - (prev.dbg_info_off + prev.dbg_info_len)
    else
        0;
    const next_padding_size: u32 = if (atom.dbg_info_next) |next|
        next.dbg_info_off - (atom.dbg_info_off + atom.dbg_info_len)
    else
        0;

    // To end the children of the decl tag.
    const trailing_zero = atom.dbg_info_next == null;

    // We only have support for one compilation unit so far, so the offsets are directly
    // from the .debug_info section.
    const file_pos = debug_info_sect.offset + atom.dbg_info_off;
    try self.pwriteDbgInfoNops(prev_padding_size, dbg_info_buf, next_padding_size, trailing_zero, file_pos);
}

fn getDebugLineProgramOff(self: DebugSymbols) u32 {
    return self.dbg_line_fn_first.?.off;
}

fn getDebugLineProgramEnd(self: DebugSymbols) u32 {
    return self.dbg_line_fn_last.?.off + self.dbg_line_fn_last.?.len;
}

/// TODO Improve this to use a table.
fn makeDebugString(self: *DebugSymbols, allocator: *Allocator, bytes: []const u8) !u32 {
    try self.debug_string_table.ensureCapacity(allocator, self.debug_string_table.items.len + bytes.len + 1);
    const result = self.debug_string_table.items.len;
    self.debug_string_table.appendSliceAssumeCapacity(bytes);
    self.debug_string_table.appendAssumeCapacity(0);
    return @intCast(u32, result);
}

/// The reloc offset for the line offset of a function from the previous function's line.
/// It's a fixed-size 4-byte ULEB128.
fn getRelocDbgLineOff() usize {
    return dbg_line_vaddr_reloc_index + @sizeOf(u64) + 1;
}

fn getRelocDbgFileIndex() usize {
    return getRelocDbgLineOff() + 5;
}

fn getRelocDbgInfoSubprogramHighPC() u32 {
    return dbg_info_low_pc_reloc_index + @sizeOf(u64);
}

fn dbgLineNeededHeaderBytes(self: DebugSymbols, module: *Module) u32 {
    _ = self;
    const directory_entry_format_count = 1;
    const file_name_entry_format_count = 1;
    const directory_count = 1;
    const file_name_count = 1;
    const root_src_dir_path_len = if (module.root_pkg.root_src_directory.path) |p| p.len else 1; // "."
    return @intCast(u32, 53 + directory_entry_format_count * 2 + file_name_entry_format_count * 2 +
        directory_count * 8 + file_name_count * 8 +
        // These are encoded as DW.FORM_string rather than DW.FORM_strp as we would like
        // because of a workaround for readelf and gdb failing to understand DWARFv5 correctly.
        root_src_dir_path_len +
        module.root_pkg.root_src_path.len);
}

fn dbgInfoNeededHeaderBytes(self: DebugSymbols) u32 {
    _ = self;
    return 120;
}

/// Writes to the file a buffer, prefixed and suffixed by the specified number of
/// bytes of NOPs. Asserts each padding size is at least `min_nop_size` and total padding bytes
/// are less than 126,976 bytes (if this limit is ever reached, this function can be
/// improved to make more than one pwritev call, or the limit can be raised by a fixed
/// amount by increasing the length of `vecs`).
fn pwriteDbgLineNops(
    self: *DebugSymbols,
    prev_padding_size: usize,
    buf: []const u8,
    next_padding_size: usize,
    offset: u64,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const page_of_nops = [1]u8{DW.LNS_negate_stmt} ** 4096;
    const three_byte_nop = [3]u8{ DW.LNS_advance_pc, 0b1000_0000, 0 };
    var vecs: [32]std.os.iovec_const = undefined;
    var vec_index: usize = 0;
    {
        var padding_left = prev_padding_size;
        if (padding_left % 2 != 0) {
            vecs[vec_index] = .{
                .iov_base = &three_byte_nop,
                .iov_len = three_byte_nop.len,
            };
            vec_index += 1;
            padding_left -= three_byte_nop.len;
        }
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = padding_left,
            };
            vec_index += 1;
        }
    }

    vecs[vec_index] = .{
        .iov_base = buf.ptr,
        .iov_len = buf.len,
    };
    vec_index += 1;

    {
        var padding_left = next_padding_size;
        if (padding_left % 2 != 0) {
            vecs[vec_index] = .{
                .iov_base = &three_byte_nop,
                .iov_len = three_byte_nop.len,
            };
            vec_index += 1;
            padding_left -= three_byte_nop.len;
        }
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = padding_left,
            };
            vec_index += 1;
        }
    }
    try self.file.pwritevAll(vecs[0..vec_index], offset - prev_padding_size);
}

/// Writes to the file a buffer, prefixed and suffixed by the specified number of
/// bytes of padding.
fn pwriteDbgInfoNops(
    self: *DebugSymbols,
    prev_padding_size: usize,
    buf: []const u8,
    next_padding_size: usize,
    trailing_zero: bool,
    offset: u64,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const page_of_nops = [1]u8{abbrev_pad1} ** 4096;
    var vecs: [32]std.os.iovec_const = undefined;
    var vec_index: usize = 0;
    {
        var padding_left = prev_padding_size;
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = padding_left,
            };
            vec_index += 1;
        }
    }

    vecs[vec_index] = .{
        .iov_base = buf.ptr,
        .iov_len = buf.len,
    };
    vec_index += 1;

    {
        var padding_left = next_padding_size;
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .iov_base = &page_of_nops,
                .iov_len = padding_left,
            };
            vec_index += 1;
        }
    }

    if (trailing_zero) {
        var zbuf = [1]u8{0};
        vecs[vec_index] = .{
            .iov_base = &zbuf,
            .iov_len = zbuf.len,
        };
        vec_index += 1;
    }

    try self.file.pwritevAll(vecs[0..vec_index], offset - prev_padding_size);
}
