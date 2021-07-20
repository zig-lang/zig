const MachO = @This();

const std = @import("std");
const build_options = @import("build_options");
const assert = std.debug.assert;
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const aarch64 = @import("../codegen/aarch64.zig");
const bind = @import("MachO/bind.zig");
const codegen = @import("../codegen.zig");
const commands = @import("MachO/commands.zig");
const link = @import("../link.zig");
const target_util = @import("../target.zig");
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Archive = @import("MachO/Archive.zig");
const Cache = @import("../Cache.zig");
const CodeSignature = @import("MachO/CodeSignature.zig");
const Compilation = @import("../Compilation.zig");
const DebugSymbols = @import("MachO/DebugSymbols.zig");
const Dylib = @import("MachO/Dylib.zig");
const Object = @import("MachO/Object.zig");
const LoadCommand = commands.LoadCommand;
const Module = @import("../Module.zig");
const File = link.File;
pub const TextBlock = @import("MachO/TextBlock.zig");
const Trie = @import("MachO/Trie.zig");
const SegmentCommand = commands.SegmentCommand;

pub const base_tag: File.Tag = File.Tag.macho;

base: File,

/// Debug symbols bundle (or dSym).
d_sym: ?DebugSymbols = null,

/// Page size is dependent on the target cpu architecture.
/// For x86_64 that's 4KB, whereas for aarch64, that's 16KB.
page_size: u16,

/// We commit 0x1000 = 4096 bytes of space to the header and
/// the table of load commands. This should be plenty for any
/// potential future extensions.
header_pad: u16 = 0x1000,

/// The absolute address of the entry point.
entry_addr: ?u64 = null,

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
/// Path to libSystem
/// TODO this is obsolete, remove it.
libsystem_cmd_index: ?u16 = null,

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

locals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
globals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
imports: std.ArrayListUnmanaged(macho.nlist_64) = .{},
undefs: std.ArrayListUnmanaged(macho.nlist_64) = .{},
tentatives: std.ArrayListUnmanaged(macho.nlist_64) = .{},
symbol_resolver: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},

locals_free_list: std.ArrayListUnmanaged(u32) = .{},
globals_free_list: std.ArrayListUnmanaged(u32) = .{},

stub_helper_stubs_start_off: ?u64 = null,

strtab: std.ArrayListUnmanaged(u8) = .{},

got_entries: std.ArrayListUnmanaged(GotIndirectionKey) = .{},
got_entries_map: std.AutoHashMapUnmanaged(GotIndirectionKey, u32) = .{},

got_entries_free_list: std.ArrayListUnmanaged(u32) = .{},

stubs: std.ArrayListUnmanaged(u32) = .{},
stubs_map: std.AutoHashMapUnmanaged(u32, u32) = .{},

error_flags: File.ErrorFlags = File.ErrorFlags{},

got_entries_count_dirty: bool = false,
load_commands_dirty: bool = false,
rebase_info_dirty: bool = false,
binding_info_dirty: bool = false,
lazy_binding_info_dirty: bool = false,
export_info_dirty: bool = false,

strtab_dirty: bool = false,
strtab_needs_relocation: bool = false,

has_dices: bool = false,
has_stabs: bool = false,

pending_updates: std.ArrayListUnmanaged(struct {
    kind: enum {
        got,
        stub,
    },
    index: u32,
}) = .{},

/// A list of text blocks that have surplus capacity. This list can have false
/// positives, as functions grow and shrink over time, only sometimes being added
/// or removed from the freelist.
///
/// A text block has surplus capacity when its overcapacity value is greater than
/// padToIdeal(minimum_text_block_size). That is, when it has so
/// much extra capacity, that we could fit a small new symbol in it, itself with
/// ideal_capacity or more.
///
/// Ideal capacity is defined by size + (size / ideal_factor).
///
/// Overcapacity is measured by actual_capacity - ideal_capacity. Note that
/// overcapacity can be negative. A simple way to have negative overcapacity is to
/// allocate a fresh text block, which will have ideal capacity, and then grow it
/// by 1 byte. It will then have -1 overcapacity.
text_block_free_list: std.ArrayListUnmanaged(*TextBlock) = .{},

/// Pointer to the last allocated text block
last_text_block: ?*TextBlock = null,

managed_blocks: std.ArrayListUnmanaged(TextBlock) = .{},
blocks: std.AutoHashMapUnmanaged(MatchingSection, *TextBlock) = .{},

/// A list of all PIE fixups required for this run of the linker.
/// Warning, this is currently NOT thread-safe. See the TODO below.
/// TODO Move this list inside `updateDecl` where it should be allocated
/// prior to calling `generateSymbol`, and then immediately deallocated
/// rather than sitting in the global scope.
/// TODO We should also rewrite this using generic relocations common to all
/// backends.
pie_fixups: std.ArrayListUnmanaged(PIEFixup) = .{},

const SymbolWithLoc = struct {
    // Table where the symbol can be found.
    where: enum {
        global,
        import,
        undef,
        tentative,
    },
    where_index: u32,
    local_sym_index: u32 = 0,
    file: u16 = 0,
};

pub const GotIndirectionKey = struct {
    where: enum {
        local,
        import,
    },
    where_index: u32,
};

pub const PIEFixup = struct {
    /// Target VM address of this relocation.
    target_addr: u64,

    /// Offset within the byte stream.
    offset: usize,

    /// Size of the relocation.
    size: usize,
};

/// When allocating, the ideal_capacity is calculated by
/// actual_capacity + (actual_capacity / ideal_factor)
const ideal_factor = 2;

/// Default path to dyld
/// TODO instead of hardcoding it, we should probably look through some env vars and search paths
/// instead but this will do for now.
const DEFAULT_DYLD_PATH: [*:0]const u8 = "/usr/lib/dyld";

/// Default lib search path
/// TODO instead of hardcoding it, we should probably look through some env vars and search paths
/// instead but this will do for now.
const DEFAULT_LIB_SEARCH_PATH: []const u8 = "/usr/lib";

const LIB_SYSTEM_NAME: [*:0]const u8 = "System";
/// TODO we should search for libSystem and fail if it doesn't exist, instead of hardcoding it
const LIB_SYSTEM_PATH: [*:0]const u8 = DEFAULT_LIB_SEARCH_PATH ++ "/libSystem.B.dylib";

/// In order for a slice of bytes to be considered eligible to keep metadata pointing at
/// it as a possible place to put new symbols, it must have enough room for this many bytes
/// (plus extra for reserved capacity).
const minimum_text_block_size = 64;
pub const min_text_capacity = padToIdeal(minimum_text_block_size);

pub const Export = struct {
    sym_index: ?u32 = null,
};

pub const SrcFn = struct {
    /// Offset from the beginning of the Debug Line Program header that contains this function.
    off: u32,
    /// Size of the line number program component belonging to this function, not
    /// including padding.
    len: u32,

    /// Points to the previous and next neighbors, based on the offset from .debug_line.
    /// This can be used to find, for example, the capacity of this `SrcFn`.
    prev: ?*SrcFn,
    next: ?*SrcFn,

    pub const empty: SrcFn = .{
        .off = 0,
        .len = 0,
        .prev = null,
        .next = null,
    };
};

pub fn openPath(allocator: *Allocator, sub_path: []const u8, options: link.Options) !*MachO {
    assert(options.object_format == .macho);

    if (options.use_llvm) return error.LLVM_BackendIsTODO_ForMachO; // TODO

    const file = try options.emit.?.directory.handle.createFile(sub_path, .{
        .truncate = false,
        .read = true,
        .mode = link.determineMode(options),
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer {
        self.base.file = null;
        self.base.destroy();
    }

    self.base.file = file;

    if (options.output_mode == .Lib and options.link_mode == .Static) {
        return self;
    }

    if (!options.strip and options.module != null) {
        // Create dSYM bundle.
        const dir = options.module.?.zig_cache_artifact_directory;
        log.debug("creating {s}.dSYM bundle in {s}", .{ sub_path, dir.path });

        const d_sym_path = try fmt.allocPrint(
            allocator,
            "{s}.dSYM" ++ fs.path.sep_str ++ "Contents" ++ fs.path.sep_str ++ "Resources" ++ fs.path.sep_str ++ "DWARF",
            .{sub_path},
        );
        defer allocator.free(d_sym_path);

        var d_sym_bundle = try dir.handle.makeOpenPath(d_sym_path, .{});
        defer d_sym_bundle.close();

        const d_sym_file = try d_sym_bundle.createFile(sub_path, .{
            .truncate = false,
            .read = true,
        });

        self.d_sym = .{
            .base = self,
            .file = d_sym_file,
        };
    }

    // Index 0 is always a null symbol.
    try self.locals.append(allocator, .{
        .n_strx = 0,
        .n_type = 0,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });

    try self.populateMissingMetadata();
    try self.writeLocalSymbol(0);

    if (self.d_sym) |*ds| {
        try ds.populateMissingMetadata(allocator);
        try ds.writeLocalSymbol(0);
    }

    return self;
}

pub fn createEmpty(gpa: *Allocator, options: link.Options) !*MachO {
    const self = try gpa.create(MachO);

    self.* = .{
        .base = .{
            .tag = .macho,
            .options = options,
            .allocator = gpa,
            .file = null,
        },
        .page_size = if (options.target.cpu.arch == .aarch64) 0x4000 else 0x1000,
    };

    return self;
}

pub fn flush(self: *MachO, comp: *Compilation) !void {
    if (self.base.options.output_mode == .Lib and self.base.options.link_mode == .Static) {
        if (build_options.have_llvm) {
            return self.base.linkAsArchive(comp);
        } else {
            log.err("TODO: non-LLVM archiver for MachO object files", .{});
            return error.TODOImplementWritingStaticLibFiles;
        }
    }

    if (build_options.is_stage1) {
        return self.linkWithZld(comp);
    } else {
        switch (self.base.options.effectiveOutputMode()) {
            .Exe, .Obj => {},
            .Lib => return error.TODOImplementWritingLibFiles,
        }
        return self.flushModule(comp);
    }
}

pub fn flushModule(self: *MachO, comp: *Compilation) !void {
    _ = comp;
    const tracy = trace(@src());
    defer tracy.end();

    const output_mode = self.base.options.output_mode;
    const target = self.base.options.target;

    switch (output_mode) {
        .Exe => {
            if (self.entry_addr) |addr| {
                // Update LC_MAIN with entry offset.
                const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
                const main_cmd = &self.load_commands.items[self.main_cmd_index.?].Main;
                main_cmd.entryoff = addr - text_segment.inner.vmaddr;
                main_cmd.stacksize = self.base.options.stack_size_override orelse 0;
                self.load_commands_dirty = true;
            }
            try self.writeRebaseInfoTable();
            try self.writeBindInfoTable();
            try self.writeLazyBindInfoTable();
            try self.writeExportInfo();
            try self.writeAllGlobalAndUndefSymbols();
            try self.writeIndirectSymbolTable();
            try self.writeStringTable();
            try self.updateLinkeditSegmentSizes();

            if (self.d_sym) |*ds| {
                // Flush debug symbols bundle.
                try ds.flushModule(self.base.allocator, self.base.options);
            }

            if (target.cpu.arch == .aarch64) {
                // Preallocate space for the code signature.
                // We need to do this at this stage so that we have the load commands with proper values
                // written out to the file.
                // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
                // where the code signature goes into.
                try self.writeCodeSignaturePadding();
            }
        },
        .Obj => {},
        .Lib => return error.TODOImplementWritingLibFiles,
    }

    try self.writeLoadCommands();
    try self.writeHeader();

    if (self.entry_addr == null and self.base.options.output_mode == .Exe) {
        log.debug("flushing. no_entry_point_found = true", .{});
        self.error_flags.no_entry_point_found = true;
    } else {
        log.debug("flushing. no_entry_point_found = false", .{});
        self.error_flags.no_entry_point_found = false;
    }

    assert(!self.got_entries_count_dirty);
    assert(!self.load_commands_dirty);
    assert(!self.rebase_info_dirty);
    assert(!self.binding_info_dirty);
    assert(!self.lazy_binding_info_dirty);
    assert(!self.export_info_dirty);
    assert(!self.strtab_dirty);
    assert(!self.strtab_needs_relocation);

    if (target.cpu.arch == .aarch64) {
        switch (output_mode) {
            .Exe, .Lib => try self.writeCodeSignature(), // code signing always comes last
            else => {},
        }
    }
}

fn resolveSearchDir(
    arena: *Allocator,
    dir: []const u8,
    syslibroot: ?[]const u8,
) !?[]const u8 {
    var candidates = std.ArrayList([]const u8).init(arena);

    if (fs.path.isAbsolute(dir)) {
        if (syslibroot) |root| {
            const full_path = try fs.path.join(arena, &[_][]const u8{ root, dir });
            try candidates.append(full_path);
        }
    }

    try candidates.append(dir);

    for (candidates.items) |candidate| {
        // Verify that search path actually exists
        var tmp = fs.cwd().openDir(candidate, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return candidate;
    }

    return null;
}

fn resolveLib(
    arena: *Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "lib{s}{s}", .{ name, ext });

    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, search_name });

        // Check if the file exists.
        const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return full_path;
    }

    return null;
}

fn resolveFramework(
    arena: *Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "{s}{s}", .{ name, ext });
    const prefix_path = try std.fmt.allocPrint(arena, "{s}.framework", .{name});

    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, prefix_path, search_name });

        // Check if the file exists.
        const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return full_path;
    }

    return null;
}

fn linkWithZld(self: *MachO, comp: *Compilation) !void {
    const tracy = trace(@src());
    defer tracy.end();

    var arena_allocator = std.heap.ArenaAllocator.init(self.base.allocator);
    defer arena_allocator.deinit();
    const arena = &arena_allocator.allocator;

    const directory = self.base.options.emit.?.directory; // Just an alias to make it shorter to type.

    // If there is no Zig code to compile, then we should skip flushing the output file because it
    // will not be part of the linker line anyway.
    const module_obj_path: ?[]const u8 = if (self.base.options.module) |module| blk: {
        const use_stage1 = build_options.is_stage1 and self.base.options.use_stage1;
        if (use_stage1) {
            const obj_basename = try std.zig.binNameAlloc(arena, .{
                .root_name = self.base.options.root_name,
                .target = self.base.options.target,
                .output_mode = .Obj,
            });
            const o_directory = module.zig_cache_artifact_directory;
            const full_obj_path = try o_directory.join(arena, &[_][]const u8{obj_basename});
            break :blk full_obj_path;
        }

        try self.flushModule(comp);
        const obj_basename = self.base.intermediary_basename.?;
        const full_obj_path = try directory.join(arena, &[_][]const u8{obj_basename});
        break :blk full_obj_path;
    } else null;

    const is_lib = self.base.options.output_mode == .Lib;
    const is_dyn_lib = self.base.options.link_mode == .Dynamic and is_lib;
    const is_exe_or_dyn_lib = is_dyn_lib or self.base.options.output_mode == .Exe;
    const stack_size = self.base.options.stack_size_override orelse 0;
    const allow_shlib_undefined = self.base.options.allow_shlib_undefined orelse !self.base.options.is_native_os;

    const id_symlink_basename = "zld.id";

    var man: Cache.Manifest = undefined;
    defer if (!self.base.options.disable_lld_caching) man.deinit();

    var digest: [Cache.hex_digest_len]u8 = undefined;

    if (!self.base.options.disable_lld_caching) {
        man = comp.cache_parent.obtain();

        // We are about to obtain this lock, so here we give other processes a chance first.
        self.base.releaseLock();

        try man.addOptionalFile(self.base.options.linker_script);
        try man.addOptionalFile(self.base.options.version_script);
        try man.addListOfFiles(self.base.options.objects);
        for (comp.c_object_table.keys()) |key| {
            _ = try man.addFile(key.status.success.object_path, null);
        }
        try man.addOptionalFile(module_obj_path);
        // We can skip hashing libc and libc++ components that we are in charge of building from Zig
        // installation sources because they are always a product of the compiler version + target information.
        man.hash.add(stack_size);
        man.hash.add(self.base.options.rdynamic);
        man.hash.addListOfBytes(self.base.options.extra_lld_args);
        man.hash.addListOfBytes(self.base.options.lib_dirs);
        man.hash.addListOfBytes(self.base.options.framework_dirs);
        man.hash.addListOfBytes(self.base.options.frameworks);
        man.hash.addListOfBytes(self.base.options.rpath_list);
        man.hash.add(self.base.options.skip_linker_dependencies);
        man.hash.add(self.base.options.z_nodelete);
        man.hash.add(self.base.options.z_defs);
        if (is_dyn_lib) {
            man.hash.addOptional(self.base.options.version);
        }
        man.hash.addStringSet(self.base.options.system_libs);
        man.hash.add(allow_shlib_undefined);
        man.hash.add(self.base.options.bind_global_refs_locally);
        man.hash.addOptionalBytes(self.base.options.sysroot);

        // We don't actually care whether it's a cache hit or miss; we just need the digest and the lock.
        _ = try man.hit();
        digest = man.final();

        var prev_digest_buf: [digest.len]u8 = undefined;
        const prev_digest: []u8 = Cache.readSmallFile(
            directory.handle,
            id_symlink_basename,
            &prev_digest_buf,
        ) catch |err| blk: {
            log.debug("MachO Zld new_digest={s} error: {s}", .{ std.fmt.fmtSliceHexLower(&digest), @errorName(err) });
            // Handle this as a cache miss.
            break :blk prev_digest_buf[0..0];
        };
        if (mem.eql(u8, prev_digest, &digest)) {
            log.debug("MachO Zld digest={s} match - skipping invocation", .{std.fmt.fmtSliceHexLower(&digest)});
            // Hot diggity dog! The output binary is already there.
            self.base.lock = man.toOwnedLock();
            return;
        }
        log.debug("MachO Zld prev_digest={s} new_digest={s}", .{ std.fmt.fmtSliceHexLower(prev_digest), std.fmt.fmtSliceHexLower(&digest) });

        // We are about to change the output file to be different, so we invalidate the build hash now.
        directory.handle.deleteFile(id_symlink_basename) catch |err| switch (err) {
            error.FileNotFound => {},
            else => |e| return e,
        };
    }

    const full_out_path = try directory.join(arena, &[_][]const u8{self.base.options.emit.?.sub_path});

    if (self.base.options.output_mode == .Obj) {
        // LLD's MachO driver does not support the equvialent of `-r` so we do a simple file copy
        // here. TODO: think carefully about how we can avoid this redundant operation when doing
        // build-obj. See also the corresponding TODO in linkAsArchive.
        const the_object_path = blk: {
            if (self.base.options.objects.len != 0)
                break :blk self.base.options.objects[0];

            if (comp.c_object_table.count() != 0)
                break :blk comp.c_object_table.keys()[0].status.success.object_path;

            if (module_obj_path) |p|
                break :blk p;

            // TODO I think this is unreachable. Audit this situation when solving the above TODO
            // regarding eliding redundant object -> object transformations.
            return error.NoObjectsToLink;
        };
        // This can happen when using --enable-cache and using the stage1 backend. In this case
        // we can skip the file copy.
        if (!mem.eql(u8, the_object_path, full_out_path)) {
            try fs.cwd().copyFile(the_object_path, fs.cwd(), full_out_path, .{});
        }
    } else {
        // Positional arguments to the linker such as object files and static archives.
        var positionals = std.ArrayList([]const u8).init(arena);

        try positionals.appendSlice(self.base.options.objects);

        for (comp.c_object_table.keys()) |key| {
            try positionals.append(key.status.success.object_path);
        }

        if (module_obj_path) |p| {
            try positionals.append(p);
        }

        try positionals.append(comp.compiler_rt_static_lib.?.full_object_path);

        // libc++ dep
        if (self.base.options.link_libcpp) {
            try positionals.append(comp.libcxxabi_static_lib.?.full_object_path);
            try positionals.append(comp.libcxx_static_lib.?.full_object_path);
        }

        // Shared and static libraries passed via `-l` flag.
        var search_lib_names = std.ArrayList([]const u8).init(arena);

        const system_libs = self.base.options.system_libs.keys();
        for (system_libs) |link_lib| {
            // By this time, we depend on these libs being dynamically linked libraries and not static libraries
            // (the check for that needs to be earlier), but they could be full paths to .dylib files, in which
            // case we want to avoid prepending "-l".
            if (Compilation.classifyFileExt(link_lib) == .shared_library) {
                try positionals.append(link_lib);
                continue;
            }

            try search_lib_names.append(link_lib);
        }

        var lib_dirs = std.ArrayList([]const u8).init(arena);
        for (self.base.options.lib_dirs) |dir| {
            if (try resolveSearchDir(arena, dir, self.base.options.sysroot)) |search_dir| {
                try lib_dirs.append(search_dir);
            } else {
                log.warn("directory not found for '-L{s}'", .{dir});
            }
        }

        var libs = std.ArrayList([]const u8).init(arena);
        var lib_not_found = false;
        for (search_lib_names.items) |lib_name| {
            // Assume ld64 default: -search_paths_first
            // Look in each directory for a dylib (stub first), and then for archive
            // TODO implement alternative: -search_dylibs_first
            for (&[_][]const u8{ ".tbd", ".dylib", ".a" }) |ext| {
                if (try resolveLib(arena, lib_dirs.items, lib_name, ext)) |full_path| {
                    try libs.append(full_path);
                    break;
                }
            } else {
                log.warn("library not found for '-l{s}'", .{lib_name});
                lib_not_found = true;
            }
        }

        if (lib_not_found) {
            log.warn("Library search paths:", .{});
            for (lib_dirs.items) |dir| {
                log.warn("  {s}", .{dir});
            }
        }

        // If we're compiling native and we can find libSystem.B.{dylib, tbd},
        // we link against that instead of embedded libSystem.B.tbd file.
        var native_libsystem_available = false;
        if (self.base.options.is_native_os) blk: {
            // Try stub file first. If we hit it, then we're done as the stub file
            // re-exports every single symbol definition.
            if (try resolveLib(arena, lib_dirs.items, "System", ".tbd")) |full_path| {
                try libs.append(full_path);
                native_libsystem_available = true;
                break :blk;
            }
            // If we didn't hit the stub file, try .dylib next. However, libSystem.dylib
            // doesn't export libc.dylib which we'll need to resolve subsequently also.
            if (try resolveLib(arena, lib_dirs.items, "System", ".dylib")) |libsystem_path| {
                if (try resolveLib(arena, lib_dirs.items, "c", ".dylib")) |libc_path| {
                    try libs.append(libsystem_path);
                    try libs.append(libc_path);
                    native_libsystem_available = true;
                    break :blk;
                }
            }
        }
        if (!native_libsystem_available) {
            const full_path = try comp.zig_lib_directory.join(arena, &[_][]const u8{
                "libc", "darwin", "libSystem.B.tbd",
            });
            try libs.append(full_path);
        }

        // frameworks
        var framework_dirs = std.ArrayList([]const u8).init(arena);
        for (self.base.options.framework_dirs) |dir| {
            if (try resolveSearchDir(arena, dir, self.base.options.sysroot)) |search_dir| {
                try framework_dirs.append(search_dir);
            } else {
                log.warn("directory not found for '-F{s}'", .{dir});
            }
        }

        var framework_not_found = false;
        for (self.base.options.frameworks) |framework| {
            for (&[_][]const u8{ ".tbd", ".dylib", "" }) |ext| {
                if (try resolveFramework(arena, framework_dirs.items, framework, ext)) |full_path| {
                    try libs.append(full_path);
                    break;
                }
            } else {
                log.warn("framework not found for '-f{s}'", .{framework});
                framework_not_found = true;
            }
        }

        if (framework_not_found) {
            log.warn("Framework search paths:", .{});
            for (framework_dirs.items) |dir| {
                log.warn("  {s}", .{dir});
            }
        }

        // rpaths
        var rpath_table = std.StringArrayHashMap(void).init(arena);
        for (self.base.options.rpath_list) |rpath| {
            if (rpath_table.contains(rpath)) continue;
            try rpath_table.putNoClobber(rpath, {});
        }

        var rpaths = std.ArrayList([]const u8).init(arena);
        try rpaths.ensureCapacity(rpath_table.count());
        for (rpath_table.keys()) |*key| {
            rpaths.appendAssumeCapacity(key.*);
        }

        if (self.base.options.verbose_link) {
            var argv = std.ArrayList([]const u8).init(arena);

            try argv.append("zig");
            try argv.append("ld");

            if (is_exe_or_dyn_lib) {
                try argv.append("-dynamic");
            }

            if (is_dyn_lib) {
                try argv.append("-dylib");

                const install_name = try std.fmt.allocPrint(arena, "@rpath/{s}", .{
                    self.base.options.emit.?.sub_path,
                });
                try argv.append("-install_name");
                try argv.append(install_name);
            }

            if (self.base.options.sysroot) |syslibroot| {
                try argv.append("-syslibroot");
                try argv.append(syslibroot);
            }

            for (rpaths.items) |rpath| {
                try argv.append("-rpath");
                try argv.append(rpath);
            }

            try argv.appendSlice(positionals.items);

            try argv.append("-o");
            try argv.append(full_out_path);

            if (native_libsystem_available) {
                try argv.append("-lSystem");
                try argv.append("-lc");
            }

            for (search_lib_names.items) |l_name| {
                try argv.append(try std.fmt.allocPrint(arena, "-l{s}", .{l_name}));
            }

            for (self.base.options.lib_dirs) |lib_dir| {
                try argv.append(try std.fmt.allocPrint(arena, "-L{s}", .{lib_dir}));
            }

            Compilation.dump_argv(argv.items);
        }

        self.base.file = try fs.cwd().createFile(full_out_path, .{
            .truncate = true,
            .read = true,
            .mode = if (std.Target.current.os.tag == .windows) 0 else 0o777,
        });
        self.page_size = switch (self.base.options.target.cpu.arch) {
            .aarch64 => 0x4000,
            .x86_64 => 0x1000,
            else => unreachable,
        };

        try self.populateMetadata();
        try self.parseInputFiles(positionals.items, self.base.options.sysroot);
        try self.parseLibs(libs.items, self.base.options.sysroot);
        try self.resolveSymbols();
        try self.parseTextBlocks();

        {
            // Add dyld_stub_binder as the final GOT entry.
            const resolv = self.symbol_resolver.get("dyld_stub_binder") orelse unreachable;
            const got_index = @intCast(u32, self.got_entries.items.len);
            const got_entry = GotIndirectionKey{
                .where = .import,
                .where_index = resolv.where_index,
            };
            try self.got_entries.append(self.base.allocator, got_entry);
            try self.got_entries_map.putNoClobber(self.base.allocator, got_entry, got_index);
        }

        try self.sortSections();
        try self.addRpaths(rpaths.items);
        try self.addDataInCodeLC();
        try self.addCodeSignatureLC();
        try self.allocateTextSegment();
        try self.allocateDataConstSegment();
        try self.allocateDataSegment();
        self.allocateLinkeditSegment();
        try self.allocateTextBlocks();

        // log.warn("locals", .{});
        // for (self.locals.items) |sym, id| {
        //     log.warn("  {d}: {s}, {}", .{ id, self.getString(sym.n_strx), sym });
        // }

        // log.warn("globals", .{});
        // for (self.globals.items) |sym, id| {
        //     log.warn("  {d}: {s}, {}", .{ id, self.getString(sym.n_strx), sym });
        // }

        // log.warn("tentatives", .{});
        // for (self.tentatives.items) |sym, id| {
        //     log.warn("  {d}: {s}, {}", .{ id, self.getString(sym.n_strx), sym });
        // }

        // log.warn("undefines", .{});
        // for (self.undefs.items) |sym, id| {
        //     log.warn("  {d}: {s}, {}", .{ id, self.getString(sym.n_strx), sym });
        // }

        // log.warn("imports", .{});
        // for (self.imports.items) |sym, id| {
        //     log.warn("  {d}: {s}, {}", .{ id, self.getString(sym.n_strx), sym });
        // }

        // log.warn("symbol resolver", .{});
        // for (self.symbol_resolver.keys()) |key| {
        //     log.warn("  {s} => {}", .{ key, self.symbol_resolver.get(key).? });
        // }

        // log.warn("mappings", .{});
        // for (self.objects.items) |object, id| {
        //     const object_id = @intCast(u16, id);
        //     log.warn("  in object {s}", .{object.name.?});
        //     for (object.symtab.items) |sym, sym_id| {
        //         if (object.symbol_mapping.get(@intCast(u32, sym_id))) |local_id| {
        //             log.warn("    | {d} => {d}", .{ sym_id, local_id });
        //         } else {
        //             log.warn("    | {d} no local mapping for {s}", .{ sym_id, object.getString(sym.n_strx) });
        //         }
        //     }
        // }

        // var it = self.blocks.iterator();
        // while (it.next()) |entry| {
        //     const seg = self.load_commands.items[entry.key_ptr.seg].Segment;
        //     const sect = seg.sections.items[entry.key_ptr.sect];

        //     log.warn("\n\n{s},{s} contents:", .{ segmentName(sect), sectionName(sect) });
        //     log.warn("  {}", .{sect});
        //     entry.value_ptr.*.print(self);
        // }

        try self.flushZld();
    }

    if (!self.base.options.disable_lld_caching) {
        // Update the file with the digest. If it fails we can continue; it only
        // means that the next invocation will have an unnecessary cache miss.
        Cache.writeSmallFile(directory.handle, id_symlink_basename, &digest) catch |err| {
            log.warn("failed to save linking hash digest file: {s}", .{@errorName(err)});
        };
        // Again failure here only means an unnecessary cache miss.
        man.writeManifest() catch |err| {
            log.warn("failed to write cache manifest when linking: {s}", .{@errorName(err)});
        };
        // We hang on to this lock so that the output file path can be used without
        // other processes clobbering it.
        self.base.lock = man.toOwnedLock();
    }
}

fn parseInputFiles(self: *MachO, files: []const []const u8, syslibroot: ?[]const u8) !void {
    const arch = self.base.options.target.cpu.arch;
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpath(file_name, &buffer);
            break :full_path try self.base.allocator.dupe(u8, path);
        };

        if (try Object.createAndParseFromPath(self.base.allocator, arch, full_path)) |object| {
            try self.objects.append(self.base.allocator, object);
            continue;
        }

        if (try Archive.createAndParseFromPath(self.base.allocator, arch, full_path)) |archive| {
            try self.archives.append(self.base.allocator, archive);
            continue;
        }

        if (try Dylib.createAndParseFromPath(self.base.allocator, arch, full_path, .{
            .syslibroot = syslibroot,
        })) |dylibs| {
            defer self.base.allocator.free(dylibs);
            try self.dylibs.appendSlice(self.base.allocator, dylibs);
            continue;
        }

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseLibs(self: *MachO, libs: []const []const u8, syslibroot: ?[]const u8) !void {
    const arch = self.base.options.target.cpu.arch;
    for (libs) |lib| {
        if (try Dylib.createAndParseFromPath(self.base.allocator, arch, lib, .{
            .syslibroot = syslibroot,
        })) |dylibs| {
            defer self.base.allocator.free(dylibs);
            try self.dylibs.appendSlice(self.base.allocator, dylibs);
            continue;
        }

        if (try Archive.createAndParseFromPath(self.base.allocator, arch, lib)) |archive| {
            try self.archives.append(self.base.allocator, archive);
            continue;
        }

        log.warn("unknown filetype for a library: '{s}'", .{lib});
    }
}

pub const MatchingSection = struct {
    seg: u16,
    sect: u16,
};

pub fn getMatchingSection(self: *MachO, sect: macho.section_64) !?MatchingSection {
    const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const segname = commands.segmentName(sect);
    const sectname = commands.sectionName(sect);

    const res: ?MatchingSection = blk: {
        switch (commands.sectionType(sect)) {
            macho.S_4BYTE_LITERALS, macho.S_8BYTE_LITERALS, macho.S_16BYTE_LITERALS => {
                if (self.text_const_section_index == null) {
                    self.text_const_section_index = @intCast(u16, text_seg.sections.items.len);
                    try text_seg.addSection(self.base.allocator, "__const", .{});
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
                        try text_seg.addSection(self.base.allocator, "__objc_methname", .{
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
                        try text_seg.addSection(self.base.allocator, "__objc_methtype", .{
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
                        try text_seg.addSection(self.base.allocator, "__objc_classname", .{});
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_classname_section_index.?,
                    };
                }

                if (self.cstring_section_index == null) {
                    self.cstring_section_index = @intCast(u16, text_seg.sections.items.len);
                    try text_seg.addSection(self.base.allocator, "__cstring", .{
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
                        try data_seg.addSection(self.base.allocator, "__objc_selrefs", .{
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
                    try data_const_seg.addSection(self.base.allocator, "__mod_init_func", .{
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
                    try data_const_seg.addSection(self.base.allocator, "__mod_term_func", .{
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
                        try data_seg.addSection(self.base.allocator, "__common", .{
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
                        try data_seg.addSection(self.base.allocator, "__bss", .{
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
                    try data_seg.addSection(self.base.allocator, "__thread_vars", .{
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
                    try data_seg.addSection(self.base.allocator, "__thread_data", .{
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
                    try data_seg.addSection(self.base.allocator, "__thread_bss", .{
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
                        try text_seg.addSection(self.base.allocator, "__eh_frame", .{});
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.eh_frame_section_index.?,
                    };
                }

                // TODO audit this: is this the right mapping?
                if (self.data_const_section_index == null) {
                    self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                    try data_const_seg.addSection(self.base.allocator, "__const", .{});
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.data_const_section_index.?,
                };
            },
            macho.S_REGULAR => {
                if (commands.sectionIsCode(sect)) {
                    if (self.text_section_index == null) {
                        self.text_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.base.allocator, "__text", .{
                            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
                        });
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.text_section_index.?,
                    };
                }
                if (commands.sectionIsDebug(sect)) {
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
                            try text_seg.addSection(self.base.allocator, "__ustring", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.ustring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__gcc_except_tab")) {
                        if (self.gcc_except_tab_section_index == null) {
                            self.gcc_except_tab_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.base.allocator, "__gcc_except_tab", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.gcc_except_tab_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_methlist")) {
                        if (self.objc_methlist_section_index == null) {
                            self.objc_methlist_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.base.allocator, "__objc_methlist", .{});
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
                            try data_const_seg.addSection(self.base.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else {
                        if (self.text_const_section_index == null) {
                            self.text_const_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.base.allocator, "__const", .{});
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
                        try data_const_seg.addSection(self.base.allocator, "__const", .{});
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
                            try data_const_seg.addSection(self.base.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__cfstring")) {
                        if (self.objc_cfstring_section_index == null) {
                            self.objc_cfstring_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__cfstring", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_cfstring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classlist")) {
                        if (self.objc_classlist_section_index == null) {
                            self.objc_classlist_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__objc_classlist", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_classlist_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_imageinfo")) {
                        if (self.objc_imageinfo_section_index == null) {
                            self.objc_imageinfo_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__objc_imageinfo", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_imageinfo_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_const")) {
                        if (self.objc_const_section_index == null) {
                            self.objc_const_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__objc_const", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classrefs")) {
                        if (self.objc_classrefs_section_index == null) {
                            self.objc_classrefs_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__objc_classrefs", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_classrefs_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_data")) {
                        if (self.objc_data_section_index == null) {
                            self.objc_data_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__objc_data", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_data_section_index.?,
                        };
                    } else {
                        if (self.data_section_index == null) {
                            self.data_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__data", .{});
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

fn sortSections(self: *MachO) !void {
    var text_index_mapping = std.AutoHashMap(u16, u16).init(self.base.allocator);
    defer text_index_mapping.deinit();
    var data_const_index_mapping = std.AutoHashMap(u16, u16).init(self.base.allocator);
    defer data_const_index_mapping.deinit();
    var data_index_mapping = std.AutoHashMap(u16, u16).init(self.base.allocator);
    defer data_index_mapping.deinit();

    {
        // __TEXT segment
        const seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        var sections = seg.sections.toOwnedSlice(self.base.allocator);
        defer self.base.allocator.free(sections);
        try seg.sections.ensureCapacity(self.base.allocator, sections.len);

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
        var sections = seg.sections.toOwnedSlice(self.base.allocator);
        defer self.base.allocator.free(sections);
        try seg.sections.ensureCapacity(self.base.allocator, sections.len);

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
        var sections = seg.sections.toOwnedSlice(self.base.allocator);
        defer self.base.allocator.free(sections);
        try seg.sections.ensureCapacity(self.base.allocator, sections.len);

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

    {
        var transient: std.AutoHashMapUnmanaged(MatchingSection, *TextBlock) = .{};
        try transient.ensureCapacity(self.base.allocator, self.blocks.count());

        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            const old = entry.key_ptr.*;
            const sect = if (old.seg == self.text_segment_cmd_index.?)
                text_index_mapping.get(old.sect).?
            else if (old.seg == self.data_const_segment_cmd_index.?)
                data_const_index_mapping.get(old.sect).?
            else
                data_index_mapping.get(old.sect).?;
            transient.putAssumeCapacityNoClobber(.{
                .seg = old.seg,
                .sect = sect,
            }, entry.value_ptr.*);
        }

        self.blocks.clearAndFree(self.base.allocator);
        self.blocks.deinit(self.base.allocator);
        self.blocks = transient;
    }
}

fn allocateTextSegment(self: *MachO) !void {
    const seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const nstubs = @intCast(u32, self.stubs.items.len);

    const base_vmaddr = self.load_commands.items[self.pagezero_segment_cmd_index.?].Segment.inner.vmsize;
    seg.inner.fileoff = 0;
    seg.inner.vmaddr = base_vmaddr;

    // Set stubs and stub_helper sizes
    const stubs = &seg.sections.items[self.stubs_section_index.?];
    const stub_helper = &seg.sections.items[self.stub_helper_section_index.?];
    stubs.size += nstubs * stubs.reserved2;

    const stub_size: u4 = switch (self.base.options.target.cpu.arch) {
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

fn allocateDataConstSegment(self: *MachO) !void {
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

fn allocateDataSegment(self: *MachO) !void {
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

fn allocateLinkeditSegment(self: *MachO) void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const data_seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    seg.inner.fileoff = data_seg.inner.fileoff + data_seg.inner.filesize;
    seg.inner.vmaddr = data_seg.inner.vmaddr + data_seg.inner.vmsize;
}

fn allocateSegment(self: *MachO, index: u16, offset: u64) !void {
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

    const seg_size_aligned = mem.alignForwardGeneric(u64, start, self.page_size);
    seg.inner.filesize = seg_size_aligned;
    seg.inner.vmsize = seg_size_aligned;
}

fn allocateTextBlocks(self: *MachO) !void {
    var it = self.blocks.iterator();
    while (it.next()) |entry| {
        const match = entry.key_ptr.*;
        var block: *TextBlock = entry.value_ptr.*;

        // Find the first block
        while (block.prev) |prev| {
            block = prev;
        }

        const seg = self.load_commands.items[match.seg].Segment;
        const sect = seg.sections.items[match.sect];

        var base_addr: u64 = sect.addr;
        const n_sect = self.sectionId(match);

        log.debug("  within section {s},{s}", .{ commands.segmentName(sect), commands.sectionName(sect) });
        log.debug("    {}", .{sect});

        while (true) {
            const block_alignment = try math.powi(u32, 2, block.alignment);
            base_addr = mem.alignForwardGeneric(u64, base_addr, block_alignment);

            const sym = &self.locals.items[block.local_sym_index];
            sym.n_value = base_addr;
            sym.n_sect = n_sect;

            log.debug("    {s}: start=0x{x}, end=0x{x}, size={}, align={}", .{
                self.getString(sym.n_strx),
                base_addr,
                base_addr + block.size,
                block.size,
                block.alignment,
            });

            // Update each alias (if any)
            for (block.aliases.items) |index| {
                const alias_sym = &self.locals.items[index];
                alias_sym.n_value = base_addr;
                alias_sym.n_sect = n_sect;
            }

            // Update each symbol contained within the TextBlock
            for (block.contained.items) |sym_at_off| {
                const contained_sym = &self.locals.items[sym_at_off.local_sym_index];
                contained_sym.n_value = base_addr + sym_at_off.offset;
                contained_sym.n_sect = n_sect;
            }

            base_addr += block.size;

            if (block.next) |next| {
                block = next;
            } else break;
        }
    }

    // Update globals
    for (self.symbol_resolver.values()) |resolv| {
        if (resolv.where != .global) continue;

        assert(resolv.local_sym_index != 0);
        const local_sym = self.locals.items[resolv.local_sym_index];
        const sym = &self.globals.items[resolv.where_index];
        sym.n_value = local_sym.n_value;
        sym.n_sect = local_sym.n_sect;
    }
}

fn writeTextBlocks(self: *MachO) !void {
    var it = self.blocks.iterator();
    while (it.next()) |entry| {
        const match = entry.key_ptr.*;
        var block: *TextBlock = entry.value_ptr.*;

        while (block.prev) |prev| {
            block = prev;
        }

        const seg = self.load_commands.items[match.seg].Segment;
        const sect = seg.sections.items[match.sect];
        const sect_type = commands.sectionType(sect);

        log.debug("  for section {s},{s}", .{ commands.segmentName(sect), commands.sectionName(sect) });
        log.debug("    {}", .{sect});

        var code = try self.base.allocator.alloc(u8, sect.size);
        defer self.base.allocator.free(code);

        if (sect_type == macho.S_ZEROFILL or sect_type == macho.S_THREAD_LOCAL_ZEROFILL) {
            mem.set(u8, code, 0);
        } else {
            var base_off: u64 = 0;

            while (true) {
                const block_alignment = try math.powi(u32, 2, block.alignment);
                const aligned_base_off = mem.alignForwardGeneric(u64, base_off, block_alignment);

                const sym = self.locals.items[block.local_sym_index];
                log.debug("    {s}: start=0x{x}, end=0x{x}, size={}, align={}", .{
                    self.getString(sym.n_strx),
                    aligned_base_off,
                    aligned_base_off + block.size,
                    block.size,
                    block.alignment,
                });

                try block.resolveRelocs(self);
                mem.copy(u8, code[aligned_base_off..][0..block.size], block.code);

                // TODO NOP for machine code instead of just zeroing out
                const padding_len = aligned_base_off - base_off;
                mem.set(u8, code[base_off..][0..padding_len], 0);

                base_off = aligned_base_off + block.size;

                if (block.next) |next| {
                    block = next;
                } else break;
            }

            mem.set(u8, code[base_off..], 0);
        }

        try self.base.file.?.pwriteAll(code, sect.offset);
    }
}

fn writeStubHelperCommon(self: *MachO) !void {
    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = &text_segment.sections.items[self.stub_helper_section_index.?];
    const data_const_segment = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_segment.sections.items[self.got_section_index.?];
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const data = &data_segment.sections.items[self.data_section_index.?];

    self.stub_helper_stubs_start_off = blk: {
        switch (self.base.options.target.cpu.arch) {
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
                    const resolv = self.symbol_resolver.get("dyld_stub_binder") orelse unreachable;
                    const got_index = self.got_entries_map.get(.{
                        .where = .import,
                        .where_index = resolv.where_index,
                    }) orelse unreachable;
                    const addr = got.addr + got_index * @sizeOf(u64);
                    const displacement = try math.cast(u32, addr - stub_helper.addr - code_size);
                    mem.writeIntLittle(u32, code[11..], displacement);
                }
                try self.base.file.?.pwriteAll(&code, stub_helper.offset);
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
                    const resolv = self.symbol_resolver.get("dyld_stub_binder") orelse unreachable;
                    const got_index = self.got_entries_map.get(.{
                        .where = .import,
                        .where_index = resolv.where_index,
                    }) orelse unreachable;
                    const this_addr = stub_helper.addr + 3 * @sizeOf(u32);
                    const target_addr = got.addr + got_index * @sizeOf(u64);
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
                try self.base.file.?.pwriteAll(&code, stub_helper.offset);
                break :blk stub_helper.offset + 6 * @sizeOf(u32);
            },
            else => unreachable,
        }
    };

    for (self.stubs.items) |_, i| {
        const index = @intCast(u32, i);
        // TODO weak bound pointers
        try self.writeLazySymbolPointer(index);
        try self.writeStub(index);
        try self.writeStubInStubHelper(index);
    }
}

fn resolveSymbolsInObject(self: *MachO, object_id: u16) !void {
    const object = self.objects.items[object_id];

    log.debug("resolving symbols in '{s}'", .{object.name});

    for (object.symtab.items) |sym, id| {
        const sym_id = @intCast(u32, id);
        const sym_name = object.getString(sym.n_strx);

        if (symbolIsStab(sym)) {
            log.err("unhandled symbol type: stab", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name.?});
            return error.UnhandledSymbolType;
        }

        if (symbolIsIndr(sym)) {
            log.err("unhandled symbol type: indirect", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name.?});
            return error.UnhandledSymbolType;
        }

        if (symbolIsAbs(sym)) {
            log.err("unhandled symbol type: absolute", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name.?});
            return error.UnhandledSymbolType;
        }

        if (symbolIsSect(sym)) {
            // Defined symbol regardless of scope lands in the locals symbol table.
            const n_strx = blk: {
                if (self.symbol_resolver.get(sym_name)) |resolv| {
                    switch (resolv.where) {
                        .global => break :blk self.globals.items[resolv.where_index].n_strx,
                        .tentative => break :blk self.tentatives.items[resolv.where_index].n_strx,
                        .undef => break :blk self.undefs.items[resolv.where_index].n_strx,
                        .import => unreachable,
                    }
                }
                break :blk try self.makeString(sym_name);
            };
            const local_sym_index = @intCast(u32, self.locals.items.len);
            try self.locals.append(self.base.allocator, .{
                .n_strx = n_strx,
                .n_type = macho.N_SECT,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = sym.n_value,
            });
            try object.symbol_mapping.putNoClobber(self.base.allocator, sym_id, local_sym_index);

            // If the symbol's scope is not local aka translation unit, then we need work out
            // if we should save the symbol as a global, or potentially flag the error.
            if (!symbolIsExt(sym)) continue;

            const local = self.locals.items[local_sym_index];
            const resolv = self.symbol_resolver.getPtr(sym_name) orelse {
                const global_sym_index = @intCast(u32, self.globals.items.len);
                try self.globals.append(self.base.allocator, .{
                    .n_strx = n_strx,
                    .n_type = sym.n_type,
                    .n_sect = 0,
                    .n_desc = sym.n_desc,
                    .n_value = sym.n_value,
                });
                try self.symbol_resolver.putNoClobber(self.base.allocator, try self.base.allocator.dupe(u8, sym_name), .{
                    .where = .global,
                    .where_index = global_sym_index,
                    .local_sym_index = local_sym_index,
                    .file = object_id,
                });
                continue;
            };

            switch (resolv.where) {
                .import => unreachable,
                .global => {
                    const global = &self.globals.items[resolv.where_index];

                    if (!(symbolIsWeakDef(sym) or symbolIsPext(sym)) and
                        !(symbolIsWeakDef(global.*) or symbolIsPext(global.*)))
                    {
                        log.err("symbol '{s}' defined multiple times", .{sym_name});
                        log.err("  first definition in '{s}'", .{self.objects.items[resolv.file].name.?});
                        log.err("  next definition in '{s}'", .{object.name.?});
                        return error.MultipleSymbolDefinitions;
                    }

                    if (symbolIsWeakDef(sym) or symbolIsPext(sym)) continue; // Current symbol is weak, so skip it.

                    // Otherwise, update the resolver and the global symbol.
                    global.n_type = sym.n_type;
                    resolv.local_sym_index = local_sym_index;
                    resolv.file = object_id;

                    continue;
                },
                .undef => {
                    const undef = &self.undefs.items[resolv.where_index];
                    undef.* = .{
                        .n_strx = 0,
                        .n_type = macho.N_UNDF,
                        .n_sect = 0,
                        .n_desc = 0,
                        .n_value = 0,
                    };
                },
                .tentative => {
                    const tentative = &self.tentatives.items[resolv.where_index];
                    tentative.* = .{
                        .n_strx = 0,
                        .n_type = macho.N_UNDF,
                        .n_sect = 0,
                        .n_desc = 0,
                        .n_value = 0,
                    };
                },
            }

            const global_sym_index = @intCast(u32, self.globals.items.len);
            try self.globals.append(self.base.allocator, .{
                .n_strx = local.n_strx,
                .n_type = sym.n_type,
                .n_sect = 0,
                .n_desc = sym.n_desc,
                .n_value = sym.n_value,
            });
            resolv.* = .{
                .where = .global,
                .where_index = global_sym_index,
                .local_sym_index = local_sym_index,
                .file = object_id,
            };
        } else if (symbolIsTentative(sym)) {
            // Symbol is a tentative definition.
            const resolv = self.symbol_resolver.getPtr(sym_name) orelse {
                const tent_sym_index = @intCast(u32, self.tentatives.items.len);
                try self.tentatives.append(self.base.allocator, .{
                    .n_strx = try self.makeString(sym_name),
                    .n_type = sym.n_type,
                    .n_sect = 0,
                    .n_desc = sym.n_desc,
                    .n_value = sym.n_value,
                });
                try self.symbol_resolver.putNoClobber(self.base.allocator, try self.base.allocator.dupe(u8, sym_name), .{
                    .where = .tentative,
                    .where_index = tent_sym_index,
                    .file = object_id,
                });
                continue;
            };

            switch (resolv.where) {
                .import => unreachable,
                .global => {},
                .undef => {
                    const undef = &self.undefs.items[resolv.where_index];
                    const tent_sym_index = @intCast(u32, self.tentatives.items.len);
                    try self.tentatives.append(self.base.allocator, .{
                        .n_strx = undef.n_strx,
                        .n_type = sym.n_type,
                        .n_sect = 0,
                        .n_desc = sym.n_desc,
                        .n_value = sym.n_value,
                    });
                    resolv.* = .{
                        .where = .tentative,
                        .where_index = tent_sym_index,
                        .file = object_id,
                    };
                    undef.* = .{
                        .n_strx = 0,
                        .n_type = macho.N_UNDF,
                        .n_sect = 0,
                        .n_desc = 0,
                        .n_value = 0,
                    };
                },
                .tentative => {
                    const tentative = &self.tentatives.items[resolv.where_index];
                    if (tentative.n_value >= sym.n_value) continue;

                    tentative.n_desc = sym.n_desc;
                    tentative.n_value = sym.n_value;
                    resolv.file = object_id;
                },
            }
        } else {
            // Symbol is undefined.
            if (self.symbol_resolver.contains(sym_name)) continue;

            const undef_sym_index = @intCast(u32, self.undefs.items.len);
            try self.undefs.append(self.base.allocator, .{
                .n_strx = try self.makeString(sym_name),
                .n_type = macho.N_UNDF,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            });
            try self.symbol_resolver.putNoClobber(self.base.allocator, try self.base.allocator.dupe(u8, sym_name), .{
                .where = .undef,
                .where_index = undef_sym_index,
                .file = object_id,
            });
        }
    }
}

fn resolveSymbols(self: *MachO) !void {
    // TODO mimicking insertion of null symbol from incremental linker.
    // This will need to moved.
    try self.locals.append(self.base.allocator, .{
        .n_strx = 0,
        .n_type = macho.N_UNDF,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    try self.strtab.append(self.base.allocator, 0);

    // First pass, resolve symbols in provided objects.
    for (self.objects.items) |_, object_id| {
        try self.resolveSymbolsInObject(@intCast(u16, object_id));
    }

    // Second pass, resolve symbols in static libraries.
    var next_sym: usize = 0;
    loop: while (true) : (next_sym += 1) {
        if (next_sym == self.undefs.items.len) break;

        const sym = self.undefs.items[next_sym];
        if (symbolIsNull(sym)) continue;

        const sym_name = self.getString(sym.n_strx);

        for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(sym_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object = try archive.parseObject(offsets.items[0]);
            const object_id = @intCast(u16, self.objects.items.len);
            try self.objects.append(self.base.allocator, object);
            try self.resolveSymbolsInObject(object_id);

            continue :loop;
        }
    }

    // Convert any tentative definition into a regular symbol and allocate
    // text blocks for each tentative defintion.
    for (self.tentatives.items) |sym| {
        if (symbolIsNull(sym)) continue;

        const sym_name = self.getString(sym.n_strx);
        const match: MatchingSection = blk: {
            if (self.common_section_index == null) {
                const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
                self.common_section_index = @intCast(u16, data_seg.sections.items.len);
                try data_seg.addSection(self.base.allocator, "__common", .{
                    .flags = macho.S_ZEROFILL,
                });
            }
            break :blk .{
                .seg = self.data_segment_cmd_index.?,
                .sect = self.common_section_index.?,
            };
        };

        const size = sym.n_value;
        const code = try self.base.allocator.alloc(u8, size);
        mem.set(u8, code, 0);
        const alignment = (sym.n_desc >> 8) & 0x0f;

        const resolv = self.symbol_resolver.getPtr(sym_name) orelse unreachable;
        const local_sym_index = @intCast(u32, self.locals.items.len);
        var nlist = macho.nlist_64{
            .n_strx = sym.n_strx,
            .n_type = macho.N_SECT,
            .n_sect = self.sectionId(match),
            .n_desc = 0,
            .n_value = 0,
        };
        try self.locals.append(self.base.allocator, nlist);
        const global_sym_index = @intCast(u32, self.globals.items.len);
        nlist.n_type |= macho.N_EXT;
        try self.globals.append(self.base.allocator, nlist);
        resolv.* = .{
            .where = .global,
            .where_index = global_sym_index,
            .local_sym_index = local_sym_index,
        };

        const block = try self.managed_blocks.addOne(self.base.allocator);
        block.* = TextBlock.empty;
        block.local_sym_index = local_sym_index;
        block.code = code;
        block.size = size;
        block.alignment = alignment;

        // Update target section's metadata
        // TODO should we update segment's size here too?
        // How does it tie with incremental space allocs?
        const tseg = &self.load_commands.items[match.seg].Segment;
        const tsect = &tseg.sections.items[match.sect];
        const new_alignment = math.max(tsect.@"align", block.alignment);
        const new_alignment_pow_2 = try math.powi(u32, 2, new_alignment);
        const new_size = mem.alignForwardGeneric(u64, tsect.size, new_alignment_pow_2) + block.size;
        tsect.size = new_size;
        tsect.@"align" = new_alignment;

        if (self.blocks.getPtr(match)) |last| {
            last.*.next = block;
            block.prev = last.*;
            last.* = block;
        } else {
            try self.blocks.putNoClobber(self.base.allocator, match, block);
        }
    }

    // Third pass, resolve symbols in dynamic libraries.
    {
        // Put dyld_stub_binder as an undefined special symbol.
        const undef_sym_index = @intCast(u32, self.undefs.items.len);
        try self.undefs.append(self.base.allocator, .{
            .n_strx = try self.makeString("dyld_stub_binder"),
            .n_type = macho.N_UNDF,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        });
        try self.symbol_resolver.putNoClobber(self.base.allocator, try self.base.allocator.dupe(u8, "dyld_stub_binder"), .{
            .where = .undef,
            .where_index = undef_sym_index,
        });
    }

    var referenced = std.AutoHashMap(*Dylib, void).init(self.base.allocator);
    defer referenced.deinit();

    loop: for (self.undefs.items) |sym| {
        if (symbolIsNull(sym)) continue;

        const sym_name = self.getString(sym.n_strx);
        for (self.dylibs.items) |dylib| {
            if (!dylib.symbols.contains(sym_name)) continue;

            if (!referenced.contains(dylib)) {
                // Add LC_LOAD_DYLIB load command for each referenced dylib/stub.
                dylib.ordinal = self.next_dylib_ordinal;
                const dylib_id = dylib.id orelse unreachable;
                var dylib_cmd = try commands.createLoadDylibCommand(
                    self.base.allocator,
                    dylib_id.name,
                    dylib_id.timestamp,
                    dylib_id.current_version,
                    dylib_id.compatibility_version,
                );
                errdefer dylib_cmd.deinit(self.base.allocator);
                try self.load_commands.append(self.base.allocator, .{ .Dylib = dylib_cmd });
                self.next_dylib_ordinal += 1;
                try referenced.putNoClobber(dylib, {});
            }

            const resolv = self.symbol_resolver.getPtr(sym_name) orelse unreachable;
            const undef = &self.undefs.items[resolv.where_index];
            const import_sym_index = @intCast(u32, self.imports.items.len);
            try self.imports.append(self.base.allocator, .{
                .n_strx = undef.n_strx,
                .n_type = macho.N_UNDF | macho.N_EXT,
                .n_sect = 0,
                .n_desc = packDylibOrdinal(dylib.ordinal.?),
                .n_value = 0,
            });
            resolv.* = .{
                .where = .import,
                .where_index = import_sym_index,
            };
            undef.* = .{
                .n_strx = 0,
                .n_type = macho.N_UNDF,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };

            continue :loop;
        }
    }

    // Fourth pass, handle synthetic symbols and flag any undefined references.
    if (self.symbol_resolver.getPtr("___dso_handle")) |resolv| blk: {
        if (resolv.where != .undef) break :blk;

        const undef = &self.undefs.items[resolv.where_index];
        const match: MatchingSection = .{
            .seg = self.text_segment_cmd_index.?,
            .sect = self.text_section_index.?,
        };
        const local_sym_index = @intCast(u32, self.locals.items.len);
        var nlist = macho.nlist_64{
            .n_strx = undef.n_strx,
            .n_type = macho.N_SECT,
            .n_sect = self.sectionId(match),
            .n_desc = 0,
            .n_value = 0,
        };
        try self.locals.append(self.base.allocator, nlist);
        const global_sym_index = @intCast(u32, self.globals.items.len);
        nlist.n_type |= macho.N_EXT;
        nlist.n_desc = macho.N_WEAK_DEF;
        try self.globals.append(self.base.allocator, nlist);

        undef.* = .{
            .n_strx = 0,
            .n_type = macho.N_UNDF,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };
        resolv.* = .{
            .where = .global,
            .where_index = global_sym_index,
            .local_sym_index = local_sym_index,
        };

        // We create an empty atom for this symbol.
        // TODO perhaps we should special-case special symbols? Create a separate
        // linked list of atoms?
        const block = try self.managed_blocks.addOne(self.base.allocator);
        block.* = TextBlock.empty;
        block.local_sym_index = local_sym_index;
        block.code = try self.base.allocator.alloc(u8, 0);
        block.size = 0;
        block.alignment = 0;

        if (self.blocks.getPtr(match)) |last| {
            last.*.next = block;
            block.prev = last.*;
            last.* = block;
        } else {
            try self.blocks.putNoClobber(self.base.allocator, match, block);
        }
    }

    var has_undefined = false;
    for (self.undefs.items) |sym| {
        if (symbolIsNull(sym)) continue;

        const sym_name = self.getString(sym.n_strx);
        const resolv = self.symbol_resolver.get(sym_name) orelse unreachable;

        log.err("undefined reference to symbol '{s}'", .{sym_name});
        log.err("  first referenced in '{s}'", .{self.objects.items[resolv.file].name.?});
        has_undefined = true;
    }

    if (has_undefined) return error.UndefinedSymbolReference;
}

fn parseTextBlocks(self: *MachO) !void {
    for (self.objects.items) |object| {
        try object.parseTextBlocks(self);
    }
}

fn populateMetadata(self: *MachO) !void {
    if (self.pagezero_segment_cmd_index == null) {
        self.pagezero_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__PAGEZERO", .{
                .vmsize = 0x100000000, // size always set to 4GB
            }),
        });
    }

    if (self.text_segment_cmd_index == null) {
        self.text_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
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
        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        try text_seg.addSection(self.base.allocator, "__text", .{
            .@"align" = alignment,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
    }

    if (self.stubs_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stubs_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_size: u4 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 6,
            .aarch64 => 3 * @sizeOf(u32),
            else => unreachable, // unhandled architecture type
        };
        try text_seg.addSection(self.base.allocator, "__stubs", .{
            .@"align" = alignment,
            .flags = macho.S_SYMBOL_STUBS | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved2 = stub_size,
        });
    }

    if (self.stub_helper_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stub_helper_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_helper_size: u6 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 15,
            .aarch64 => 6 * @sizeOf(u32),
            else => unreachable,
        };
        try text_seg.addSection(self.base.allocator, "__stub_helper", .{
            .size = stub_helper_size,
            .@"align" = alignment,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
    }

    if (self.data_const_segment_cmd_index == null) {
        self.data_const_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__DATA_CONST", .{
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
            }),
        });
    }

    if (self.got_section_index == null) {
        const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        self.got_section_index = @intCast(u16, data_const_seg.sections.items.len);
        try data_const_seg.addSection(self.base.allocator, "__got", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
        });
    }

    if (self.data_segment_cmd_index == null) {
        self.data_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__DATA", .{
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
            }),
        });
    }

    if (self.la_symbol_ptr_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.la_symbol_ptr_section_index = @intCast(u16, data_seg.sections.items.len);
        try data_seg.addSection(self.base.allocator, "__la_symbol_ptr", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = macho.S_LAZY_SYMBOL_POINTERS,
        });
    }

    if (self.data_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.data_section_index = @intCast(u16, data_seg.sections.items.len);
        try data_seg.addSection(self.base.allocator, "__data", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
        });
    }

    if (self.linkedit_segment_cmd_index == null) {
        self.linkedit_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__LINKEDIT", .{
                .maxprot = macho.VM_PROT_READ,
                .initprot = macho.VM_PROT_READ,
            }),
        });
    }

    if (self.dyld_info_cmd_index == null) {
        self.dyld_info_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
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
        try self.load_commands.append(self.base.allocator, .{
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
        try self.load_commands.append(self.base.allocator, .{
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
        var dylinker_cmd = commands.emptyGenericCommandWithData(macho.dylinker_command{
            .cmd = macho.LC_LOAD_DYLINKER,
            .cmdsize = cmdsize,
            .name = @sizeOf(macho.dylinker_command),
        });
        dylinker_cmd.data = try self.base.allocator.alloc(u8, cmdsize - dylinker_cmd.inner.name);
        mem.set(u8, dylinker_cmd.data, 0);
        mem.copy(u8, dylinker_cmd.data, mem.spanZ(DEFAULT_DYLD_PATH));
        try self.load_commands.append(self.base.allocator, .{ .Dylinker = dylinker_cmd });
    }

    if (self.main_cmd_index == null and self.base.options.output_mode == .Exe) {
        self.main_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Main = .{
                .cmd = macho.LC_MAIN,
                .cmdsize = @sizeOf(macho.entry_point_command),
                .entryoff = 0x0,
                .stacksize = 0,
            },
        });
    }

    if (self.dylib_id_cmd_index == null and self.base.options.output_mode == .Lib) {
        self.dylib_id_cmd_index = @intCast(u16, self.load_commands.items.len);
        const install_name = try std.fmt.allocPrint(self.base.allocator, "@rpath/{s}", .{
            self.base.options.emit.?.sub_path,
        });
        defer self.base.allocator.free(install_name);
        var dylib_cmd = try commands.createLoadDylibCommand(
            self.base.allocator,
            install_name,
            2,
            0x10000, // TODO forward user-provided versions
            0x10000,
        );
        errdefer dylib_cmd.deinit(self.base.allocator);
        dylib_cmd.inner.cmd = macho.LC_ID_DYLIB;
        try self.load_commands.append(self.base.allocator, .{ .Dylib = dylib_cmd });
    }

    if (self.version_min_cmd_index == null) {
        self.version_min_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmd: u32 = switch (self.base.options.target.os.tag) {
            .macos => macho.LC_VERSION_MIN_MACOSX,
            .ios => macho.LC_VERSION_MIN_IPHONEOS,
            .tvos => macho.LC_VERSION_MIN_TVOS,
            .watchos => macho.LC_VERSION_MIN_WATCHOS,
            else => unreachable, // wrong OS
        };
        const ver = self.base.options.target.os.version_range.semver.min;
        const version = ver.major << 16 | ver.minor << 8 | ver.patch;
        try self.load_commands.append(self.base.allocator, .{
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
        try self.load_commands.append(self.base.allocator, .{
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
        try self.load_commands.append(self.base.allocator, .{ .Uuid = uuid_cmd });
    }
}

fn addDataInCodeLC(self: *MachO) !void {
    if (self.data_in_code_cmd_index == null) {
        self.data_in_code_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .LinkeditData = .{
                .cmd = macho.LC_DATA_IN_CODE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }
}

fn addCodeSignatureLC(self: *MachO) !void {
    if (self.code_signature_cmd_index == null and self.base.options.target.cpu.arch == .aarch64) {
        self.code_signature_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .LinkeditData = .{
                .cmd = macho.LC_CODE_SIGNATURE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }
}

fn addRpaths(self: *MachO, rpaths: []const []const u8) !void {
    for (rpaths) |rpath| {
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.rpath_command) + rpath.len + 1,
            @sizeOf(u64),
        ));
        var rpath_cmd = commands.emptyGenericCommandWithData(macho.rpath_command{
            .cmd = macho.LC_RPATH,
            .cmdsize = cmdsize,
            .path = @sizeOf(macho.rpath_command),
        });
        rpath_cmd.data = try self.base.allocator.alloc(u8, cmdsize - rpath_cmd.inner.path);
        mem.set(u8, rpath_cmd.data, 0);
        mem.copy(u8, rpath_cmd.data, rpath);
        try self.load_commands.append(self.base.allocator, .{ .Rpath = rpath_cmd });
    }
}

fn flushZld(self: *MachO) !void {
    self.load_commands_dirty = true;
    try self.writeTextBlocks();
    try self.writeStubHelperCommon();

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

    try self.writeGotEntries();
    try self.setEntryPoint();
    try self.writeRebaseInfoTableZld();
    try self.writeBindInfoTableZld();
    try self.writeLazyBindInfoTableZld();
    try self.writeExportInfoZld();
    try self.writeDices();

    {
        const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
        const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
        symtab.symoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    }

    try self.writeSymbolTable();
    try self.writeStringTableZld();

    {
        // Seal __LINKEDIT size
        const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
        seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size);
    }

    if (self.base.options.target.cpu.arch == .aarch64) {
        try self.writeCodeSignaturePadding();
    }

    try self.writeLoadCommands();
    try self.writeHeader();

    if (self.base.options.target.cpu.arch == .aarch64) {
        try self.writeCodeSignature();
    }

    // if (comptime std.Target.current.isDarwin() and std.Target.current.cpu.arch == .aarch64) {
    //     const out_path = self.output.?.path;
    //     try fs.cwd().copyFile(out_path, fs.cwd(), out_path, .{});
    // }
}

fn writeGotEntries(self: *MachO) !void {
    const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const sect = seg.sections.items[self.got_section_index.?];

    var buffer = try self.base.allocator.alloc(u8, self.got_entries.items.len * @sizeOf(u64));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    var writer = stream.writer();

    for (self.got_entries.items) |key| {
        const address: u64 = switch (key.where) {
            .local => self.locals.items[key.where_index].n_value,
            .import => 0,
        };
        try writer.writeIntLittle(u64, address);
    }

    log.debug("writing GOT pointers at 0x{x} to 0x{x}", .{ sect.offset, sect.offset + buffer.len });

    try self.base.file.?.pwriteAll(buffer, sect.offset);
}

fn setEntryPoint(self: *MachO) !void {
    if (self.base.options.output_mode != .Exe) return;

    // TODO we should respect the -entry flag passed in by the user to set a custom
    // entrypoint. For now, assume default of `_main`.
    const seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const resolv = self.symbol_resolver.get("_main") orelse {
        log.err("'_main' export not found", .{});
        return error.MissingMainEntrypoint;
    };
    assert(resolv.where == .global);
    const sym = self.globals.items[resolv.where_index];
    const ec = &self.load_commands.items[self.main_cmd_index.?].Main;
    ec.entryoff = @intCast(u32, sym.n_value - seg.inner.vmaddr);
    ec.stacksize = self.base.options.stack_size_override orelse 0;
}

fn writeRebaseInfoTableZld(self: *MachO) !void {
    var pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer pointers.deinit();

    {
        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            const match = entry.key_ptr.*;
            var block: *TextBlock = entry.value_ptr.*;

            if (match.seg == self.text_segment_cmd_index.?) continue; // __TEXT is non-writable

            const seg = self.load_commands.items[match.seg].Segment;

            while (true) {
                const sym = self.locals.items[block.local_sym_index];
                const base_offset = sym.n_value - seg.inner.vmaddr;

                for (block.rebases.items) |offset| {
                    try pointers.append(.{
                        .offset = base_offset + offset,
                        .segment_id = match.seg,
                    });
                }

                if (block.prev) |prev| {
                    block = prev;
                } else break;
            }
        }
    }

    if (self.got_section_index) |idx| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_const_segment_cmd_index.?);

        for (self.got_entries.items) |entry, i| {
            if (entry.where == .import) continue;

            try pointers.append(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
            });
        }
    }

    if (self.la_symbol_ptr_section_index) |idx| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_segment_cmd_index.?);

        try pointers.ensureUnusedCapacity(self.stubs.items.len);
        for (self.stubs.items) |_, i| {
            pointers.appendAssumeCapacity(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
            });
        }
    }

    std.sort.sort(bind.Pointer, pointers.items, {}, bind.pointerCmp);

    const size = try bind.rebaseInfoSize(pointers.items);
    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, size));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try bind.writeRebaseInfo(pointers.items, stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.rebase_off = @intCast(u32, seg.inner.fileoff);
    dyld_info.rebase_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @sizeOf(u64)));
    seg.inner.filesize += dyld_info.rebase_size;

    log.debug("writing rebase info from 0x{x} to 0x{x}", .{ dyld_info.rebase_off, dyld_info.rebase_off + dyld_info.rebase_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.rebase_off);
}

fn writeBindInfoTableZld(self: *MachO) !void {
    var pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer pointers.deinit();

    if (self.got_section_index) |idx| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_const_segment_cmd_index.?);

        for (self.got_entries.items) |entry, i| {
            if (entry.where == .local) continue;

            const sym = self.imports.items[entry.where_index];
            try pointers.append(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
                .dylib_ordinal = unpackDylibOrdinal(sym.n_desc),
                .name = self.getString(sym.n_strx),
            });
        }
    }

    {
        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            const match = entry.key_ptr.*;
            var block: *TextBlock = entry.value_ptr.*;

            if (match.seg == self.text_segment_cmd_index.?) continue; // __TEXT is non-writable

            const seg = self.load_commands.items[match.seg].Segment;

            while (true) {
                const sym = self.locals.items[block.local_sym_index];
                const base_offset = sym.n_value - seg.inner.vmaddr;

                for (block.bindings.items) |binding| {
                    const bind_sym = self.imports.items[binding.local_sym_index];
                    try pointers.append(.{
                        .offset = binding.offset + base_offset,
                        .segment_id = match.seg,
                        .dylib_ordinal = unpackDylibOrdinal(bind_sym.n_desc),
                        .name = self.getString(bind_sym.n_strx),
                    });
                }

                if (block.prev) |prev| {
                    block = prev;
                } else break;
            }
        }
    }

    const size = try bind.bindInfoSize(pointers.items);
    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, size));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try bind.writeBindInfo(pointers.items, stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.bind_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.bind_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.bind_size;

    log.debug("writing binding info from 0x{x} to 0x{x}", .{ dyld_info.bind_off, dyld_info.bind_off + dyld_info.bind_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.bind_off);
}

fn writeLazyBindInfoTableZld(self: *MachO) !void {
    var pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer pointers.deinit();

    if (self.la_symbol_ptr_section_index) |idx| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_segment_cmd_index.?);

        try pointers.ensureUnusedCapacity(self.stubs.items.len);

        for (self.stubs.items) |import_id, i| {
            const sym = self.imports.items[import_id];
            pointers.appendAssumeCapacity(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
                .dylib_ordinal = unpackDylibOrdinal(sym.n_desc),
                .name = self.getString(sym.n_strx),
            });
        }
    }

    const size = try bind.lazyBindInfoSize(pointers.items);
    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, size));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try bind.writeLazyBindInfo(pointers.items, stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.lazy_bind_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.lazy_bind_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.lazy_bind_size;

    log.debug("writing lazy binding info from 0x{x} to 0x{x}", .{ dyld_info.lazy_bind_off, dyld_info.lazy_bind_off + dyld_info.lazy_bind_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.lazy_bind_off);
    try self.populateLazyBindOffsetsInStubHelper(buffer);
}

fn writeExportInfoZld(self: *MachO) !void {
    var trie = Trie.init(self.base.allocator);
    defer trie.deinit();

    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const base_address = text_segment.inner.vmaddr;

    // TODO handle macho.EXPORT_SYMBOL_FLAGS_REEXPORT and macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER.
    log.debug("writing export trie", .{});

    for (self.globals.items) |sym| {
        const sym_name = self.getString(sym.n_strx);
        log.debug("  | putting '{s}' defined at 0x{x}", .{ sym_name, sym.n_value });

        try trie.put(.{
            .name = sym_name,
            .vmaddr_offset = sym.n_value - base_address,
            .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }

    try trie.finalize();

    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, trie.size));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    const nwritten = try trie.write(stream.writer());
    assert(nwritten == trie.size);

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.export_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.export_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.export_size;

    log.debug("writing export info from 0x{x} to 0x{x}", .{ dyld_info.export_off, dyld_info.export_off + dyld_info.export_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.export_off);
}

fn writeSymbolTable(self: *MachO) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;

    var locals = std.ArrayList(macho.nlist_64).init(self.base.allocator);
    defer locals.deinit();
    try locals.appendSlice(self.locals.items);

    if (self.has_stabs) {
        for (self.objects.items) |object| {
            if (object.debug_info == null) continue;

            // Open scope
            try locals.ensureUnusedCapacity(4);
            locals.appendAssumeCapacity(.{
                .n_strx = try self.makeString(object.tu_comp_dir.?),
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            });
            locals.appendAssumeCapacity(.{
                .n_strx = try self.makeString(object.tu_name.?),
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            });
            locals.appendAssumeCapacity(.{
                .n_strx = try self.makeString(object.name.?),
                .n_type = macho.N_OSO,
                .n_sect = 0,
                .n_desc = 1,
                .n_value = object.mtime orelse 0,
            });

            for (object.text_blocks.items) |block| {
                if (block.stab) |stab| {
                    const nlists = try stab.asNlists(block.local_sym_index, self);
                    defer self.base.allocator.free(nlists);
                    try locals.appendSlice(nlists);
                } else {
                    for (block.contained.items) |sym_at_off| {
                        const stab = sym_at_off.stab orelse continue;
                        const nlists = try stab.asNlists(sym_at_off.local_sym_index, self);
                        defer self.base.allocator.free(nlists);
                        try locals.appendSlice(nlists);
                    }
                }
            }

            // Close scope
            locals.appendAssumeCapacity(.{
                .n_strx = 0,
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            });
        }
    }

    const nlocals = locals.items.len;
    const nexports = self.globals.items.len;
    const nundefs = self.imports.items.len;

    const locals_off = symtab.symoff + symtab.nsyms * @sizeOf(macho.nlist_64);
    const locals_size = nlocals * @sizeOf(macho.nlist_64);
    log.debug("writing local symbols from 0x{x} to 0x{x}", .{ locals_off, locals_size + locals_off });
    try self.base.file.?.pwriteAll(mem.sliceAsBytes(locals.items), locals_off);

    const exports_off = locals_off + locals_size;
    const exports_size = nexports * @sizeOf(macho.nlist_64);
    log.debug("writing exported symbols from 0x{x} to 0x{x}", .{ exports_off, exports_size + exports_off });
    try self.base.file.?.pwriteAll(mem.sliceAsBytes(self.globals.items), exports_off);

    const undefs_off = exports_off + exports_size;
    const undefs_size = nundefs * @sizeOf(macho.nlist_64);
    log.debug("writing undefined symbols from 0x{x} to 0x{x}", .{ undefs_off, undefs_size + undefs_off });
    try self.base.file.?.pwriteAll(mem.sliceAsBytes(self.imports.items), undefs_off);

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

    var buf = try self.base.allocator.alloc(u8, needed_size);
    defer self.base.allocator.free(buf);

    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();

    stubs.reserved1 = 0;
    for (self.stubs.items) |id| {
        try writer.writeIntLittle(u32, dysymtab.iundefsym + id);
    }

    got.reserved1 = nstubs;
    for (self.got_entries.items) |entry| {
        switch (entry.where) {
            .import => {
                try writer.writeIntLittle(u32, dysymtab.iundefsym + entry.where_index);
            },
            .local => {
                try writer.writeIntLittle(u32, macho.INDIRECT_SYMBOL_LOCAL);
            },
        }
    }

    la_symbol_ptr.reserved1 = got.reserved1 + ngot_entries;
    for (self.stubs.items) |id| {
        try writer.writeIntLittle(u32, dysymtab.iundefsym + id);
    }

    try self.base.file.?.pwriteAll(buf, dysymtab.indirectsymoff);
}

pub fn deinit(self: *MachO) void {
    if (self.d_sym) |*ds| {
        ds.deinit(self.base.allocator);
    }

    self.pending_updates.deinit(self.base.allocator);
    self.pie_fixups.deinit(self.base.allocator);
    self.got_entries.deinit(self.base.allocator);
    self.got_entries_map.deinit(self.base.allocator);
    self.got_entries_free_list.deinit(self.base.allocator);
    self.stubs.deinit(self.base.allocator);
    self.stubs_map.deinit(self.base.allocator);
    self.strtab.deinit(self.base.allocator);
    self.undefs.deinit(self.base.allocator);
    self.tentatives.deinit(self.base.allocator);
    self.imports.deinit(self.base.allocator);
    self.globals.deinit(self.base.allocator);
    self.globals_free_list.deinit(self.base.allocator);
    self.locals.deinit(self.base.allocator);
    self.locals_free_list.deinit(self.base.allocator);

    for (self.symbol_resolver.keys()) |key| {
        self.base.allocator.free(key);
    }
    self.symbol_resolver.deinit(self.base.allocator);

    for (self.objects.items) |object| {
        object.deinit();
        self.base.allocator.destroy(object);
    }
    self.objects.deinit(self.base.allocator);

    for (self.archives.items) |archive| {
        archive.deinit();
        self.base.allocator.destroy(archive);
    }
    self.archives.deinit(self.base.allocator);

    for (self.dylibs.items) |dylib| {
        dylib.deinit();
        self.base.allocator.destroy(dylib);
    }
    self.dylibs.deinit(self.base.allocator);

    for (self.load_commands.items) |*lc| {
        lc.deinit(self.base.allocator);
    }
    self.load_commands.deinit(self.base.allocator);

    for (self.managed_blocks.items) |*block| {
        block.deinit(self.base.allocator);
    }
    self.managed_blocks.deinit(self.base.allocator);
    self.blocks.deinit(self.base.allocator);
    self.text_block_free_list.deinit(self.base.allocator);
}

pub fn closeFiles(self: MachO) void {
    for (self.objects.items) |object| {
        object.closeFile();
    }
    for (self.archives.items) |archive| {
        archive.closeFile();
    }
}

fn freeTextBlock(self: *MachO, text_block: *TextBlock) void {
    log.debug("freeTextBlock {*}", .{text_block});
    // text_block.deinit(self.base.allocator);

    var already_have_free_list_node = false;
    {
        var i: usize = 0;
        // TODO turn text_block_free_list into a hash map
        while (i < self.text_block_free_list.items.len) {
            if (self.text_block_free_list.items[i] == text_block) {
                _ = self.text_block_free_list.swapRemove(i);
                continue;
            }
            if (self.text_block_free_list.items[i] == text_block.prev) {
                already_have_free_list_node = true;
            }
            i += 1;
        }
    }
    // TODO process free list for dbg info just like we do above for vaddrs

    if (self.last_text_block == text_block) {
        // TODO shrink the __text section size here
        self.last_text_block = text_block.prev;
    }
    if (self.d_sym) |*ds| {
        if (ds.dbg_info_decl_first == text_block) {
            ds.dbg_info_decl_first = text_block.dbg_info_next;
        }
        if (ds.dbg_info_decl_last == text_block) {
            // TODO shrink the .debug_info section size here
            ds.dbg_info_decl_last = text_block.dbg_info_prev;
        }
    }

    if (text_block.prev) |prev| {
        prev.next = text_block.next;

        if (!already_have_free_list_node and prev.freeListEligible(self.*)) {
            // The free list is heuristics, it doesn't have to be perfect, so we can ignore
            // the OOM here.
            self.text_block_free_list.append(self.base.allocator, prev) catch {};
        }
    } else {
        text_block.prev = null;
    }

    if (text_block.next) |next| {
        next.prev = text_block.prev;
    } else {
        text_block.next = null;
    }

    if (text_block.dbg_info_prev) |prev| {
        prev.dbg_info_next = text_block.dbg_info_next;

        // TODO the free list logic like we do for text blocks above
    } else {
        text_block.dbg_info_prev = null;
    }

    if (text_block.dbg_info_next) |next| {
        next.dbg_info_prev = text_block.dbg_info_prev;
    } else {
        text_block.dbg_info_next = null;
    }
}

fn shrinkTextBlock(self: *MachO, text_block: *TextBlock, new_block_size: u64) void {
    _ = self;
    _ = text_block;
    _ = new_block_size;
    // TODO check the new capacity, and if it crosses the size threshold into a big enough
    // capacity, insert a free list node for it.
}

fn growTextBlock(self: *MachO, text_block: *TextBlock, new_block_size: u64, alignment: u64) !u64 {
    const sym = self.locals.items[text_block.local_sym_index];
    const align_ok = mem.alignBackwardGeneric(u64, sym.n_value, alignment) == sym.n_value;
    const need_realloc = !align_ok or new_block_size > text_block.capacity(self.*);
    if (!need_realloc) return sym.n_value;
    return self.allocateTextBlock(text_block, new_block_size, alignment);
}

pub fn allocateDeclIndexes(self: *MachO, decl: *Module.Decl) !void {
    if (decl.link.macho.local_sym_index != 0) return;

    try self.locals.ensureUnusedCapacity(self.base.allocator, 1);
    try self.got_entries.ensureUnusedCapacity(self.base.allocator, 1);

    if (self.locals_free_list.popOrNull()) |i| {
        log.debug("reusing symbol index {d} for {s}", .{ i, decl.name });
        decl.link.macho.local_sym_index = i;
    } else {
        log.debug("allocating symbol index {d} for {s}", .{ self.locals.items.len, decl.name });
        decl.link.macho.local_sym_index = @intCast(u32, self.locals.items.len);
        _ = self.locals.addOneAssumeCapacity();
    }

    const got_index: u32 = blk: {
        if (self.got_entries_free_list.popOrNull()) |i| {
            log.debug("reusing GOT entry index {d} for {s}", .{ i, decl.name });
            break :blk i;
        } else {
            const got_index = @intCast(u32, self.got_entries.items.len);
            log.debug("allocating GOT entry index {d} for {s}", .{ got_index, decl.name });
            _ = self.got_entries.addOneAssumeCapacity();
            self.got_entries_count_dirty = true;
            self.rebase_info_dirty = true;
            break :blk got_index;
        }
    };

    self.locals.items[decl.link.macho.local_sym_index] = .{
        .n_strx = 0,
        .n_type = 0,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    };
    const got_entry = GotIndirectionKey{
        .where = .local,
        .where_index = decl.link.macho.local_sym_index,
    };
    self.got_entries.items[got_index] = got_entry;
    try self.got_entries_map.putNoClobber(self.base.allocator, got_entry, got_index);
}

pub fn updateDecl(self: *MachO, module: *Module, decl: *Module.Decl) !void {
    const tracy = trace(@src());
    defer tracy.end();

    if (decl.val.tag() == .extern_fn) {
        return; // TODO Should we do more when front-end analyzed extern decl?
    }

    var code_buffer = std.ArrayList(u8).init(self.base.allocator);
    defer code_buffer.deinit();

    var debug_buffers = if (self.d_sym) |*ds| try ds.initDeclDebugBuffers(self.base.allocator, module, decl) else null;
    defer {
        if (debug_buffers) |*dbg| {
            dbg.dbg_line_buffer.deinit();
            dbg.dbg_info_buffer.deinit();
            var it = dbg.dbg_info_type_relocs.valueIterator();
            while (it.next()) |value| {
                value.relocs.deinit(self.base.allocator);
            }
            dbg.dbg_info_type_relocs.deinit(self.base.allocator);
        }
    }

    const res = if (debug_buffers) |*dbg|
        try codegen.generateSymbol(&self.base, decl.srcLoc(), .{
            .ty = decl.ty,
            .val = decl.val,
        }, &code_buffer, .{
            .dwarf = .{
                .dbg_line = &dbg.dbg_line_buffer,
                .dbg_info = &dbg.dbg_info_buffer,
                .dbg_info_type_relocs = &dbg.dbg_info_type_relocs,
            },
        })
    else
        try codegen.generateSymbol(&self.base, decl.srcLoc(), .{
            .ty = decl.ty,
            .val = decl.val,
        }, &code_buffer, .none);

    const code = blk: {
        switch (res) {
            .externally_managed => |x| break :blk x,
            .appended => {
                decl.link.macho.code = code_buffer.toOwnedSlice();
                log.warn("WAT", .{});
                break :blk decl.link.macho.code;
            },
            .fail => |em| {
                // Clear any PIE fixups for this decl.
                self.pie_fixups.shrinkRetainingCapacity(0);
                decl.analysis = .codegen_failure;
                try module.failed_decls.put(module.gpa, decl, em);
                return;
            },
        }
    };

    const required_alignment = decl.ty.abiAlignment(self.base.options.target);
    assert(decl.link.macho.local_sym_index != 0); // Caller forgot to call allocateDeclIndexes()
    const symbol = &self.locals.items[decl.link.macho.local_sym_index];

    if (decl.link.macho.size != 0) {
        const capacity = decl.link.macho.capacity(self.*);
        const need_realloc = code.len > capacity or !mem.isAlignedGeneric(u64, symbol.n_value, required_alignment);
        if (need_realloc) {
            const vaddr = try self.growTextBlock(&decl.link.macho, code.len, required_alignment);

            log.debug("growing {s} and moving from 0x{x} to 0x{x}", .{ decl.name, symbol.n_value, vaddr });

            if (vaddr != symbol.n_value) {
                log.debug(" (writing new GOT entry)", .{});
                const got_index = self.got_entries_map.get(.{
                    .where = .local,
                    .where_index = decl.link.macho.local_sym_index,
                }) orelse unreachable;
                try self.writeGotEntry(got_index);
            }

            symbol.n_value = vaddr;
        } else if (code.len < decl.link.macho.size) {
            self.shrinkTextBlock(&decl.link.macho, code.len);
        }
        decl.link.macho.size = code.len;

        const new_name = try std.fmt.allocPrint(self.base.allocator, "_{s}", .{mem.spanZ(decl.name)});
        defer self.base.allocator.free(new_name);

        symbol.n_strx = try self.makeString(new_name);
        symbol.n_type = macho.N_SECT;
        symbol.n_sect = @intCast(u8, self.text_section_index.?) + 1;
        symbol.n_desc = 0;

        try self.writeLocalSymbol(decl.link.macho.local_sym_index);
        if (self.d_sym) |*ds|
            try ds.writeLocalSymbol(decl.link.macho.local_sym_index);
    } else {
        const decl_name = try std.fmt.allocPrint(self.base.allocator, "_{s}", .{mem.spanZ(decl.name)});
        defer self.base.allocator.free(decl_name);

        const name_str_index = try self.makeString(decl_name);
        const addr = try self.allocateTextBlock(&decl.link.macho, code.len, required_alignment);

        log.debug("allocated text block for {s} at 0x{x}", .{ decl_name, addr });

        errdefer self.freeTextBlock(&decl.link.macho);

        symbol.* = .{
            .n_strx = name_str_index,
            .n_type = macho.N_SECT,
            .n_sect = @intCast(u8, self.text_section_index.?) + 1,
            .n_desc = 0,
            .n_value = addr,
        };

        try self.writeLocalSymbol(decl.link.macho.local_sym_index);

        if (self.d_sym) |*ds|
            try ds.writeLocalSymbol(decl.link.macho.local_sym_index);

        const got_index = self.got_entries_map.get(.{
            .where = .local,
            .where_index = decl.link.macho.local_sym_index,
        }) orelse unreachable;
        try self.writeGotEntry(got_index);
    }

    // Calculate displacements to target addr (if any).
    while (self.pie_fixups.popOrNull()) |fixup| {
        assert(fixup.size == 4);
        const this_addr = symbol.n_value + fixup.offset;
        const target_addr = fixup.target_addr;

        switch (self.base.options.target.cpu.arch) {
            .x86_64 => {
                const displacement = try math.cast(u32, target_addr - this_addr - 4);
                mem.writeIntLittle(u32, decl.link.macho.code[fixup.offset..][0..4], displacement);
            },
            .aarch64 => {
                // TODO optimize instruction based on jump length (use ldr(literal) + nop if possible).
                {
                    const inst = decl.link.macho.code[fixup.offset..][0..4];
                    var parsed = mem.bytesAsValue(meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.pc_relative_address,
                    ), inst);
                    const this_page = @intCast(i32, this_addr >> 12);
                    const target_page = @intCast(i32, target_addr >> 12);
                    const pages = @bitCast(u21, @intCast(i21, target_page - this_page));
                    parsed.immhi = @truncate(u19, pages >> 2);
                    parsed.immlo = @truncate(u2, pages);
                }
                {
                    const inst = decl.link.macho.code[fixup.offset + 4 ..][0..4];
                    var parsed = mem.bytesAsValue(meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.load_store_register,
                    ), inst);
                    const narrowed = @truncate(u12, target_addr);
                    const offset = try math.divExact(u12, narrowed, 8);
                    parsed.offset = offset;
                }
            },
            else => unreachable, // unsupported target architecture
        }
    }

    // Resolve relocations
    try decl.link.macho.resolveRelocs(self);

    // Apply pending updates
    while (self.pending_updates.popOrNull()) |update| {
        switch (update.kind) {
            .got => unreachable,
            .stub => {
                try self.writeStub(update.index);
                try self.writeStubInStubHelper(update.index);
                try self.writeLazySymbolPointer(update.index);
                self.rebase_info_dirty = true;
                self.lazy_binding_info_dirty = true;
            },
        }
    }

    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const text_section = text_segment.sections.items[self.text_section_index.?];
    const section_offset = symbol.n_value - text_section.addr;
    const file_offset = text_section.offset + section_offset;
    try self.base.file.?.pwriteAll(code, file_offset);

    if (debug_buffers) |*db| {
        try self.d_sym.?.commitDeclDebugInfo(
            self.base.allocator,
            module,
            decl,
            db,
            self.base.options.target,
        );
    }

    // Since we updated the vaddr and the size, each corresponding export symbol also needs to be updated.
    const decl_exports = module.decl_exports.get(decl) orelse &[0]*Module.Export{};
    try self.updateDeclExports(module, decl, decl_exports);
}

pub fn updateDeclLineNumber(self: *MachO, module: *Module, decl: *const Module.Decl) !void {
    if (self.d_sym) |*ds| {
        try ds.updateDeclLineNumber(module, decl);
    }
}

pub fn updateDeclExports(
    self: *MachO,
    module: *Module,
    decl: *Module.Decl,
    exports: []const *Module.Export,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    try self.globals.ensureCapacity(self.base.allocator, self.globals.items.len + exports.len);
    if (decl.link.macho.local_sym_index == 0) return;
    const decl_sym = &self.locals.items[decl.link.macho.local_sym_index];

    for (exports) |exp| {
        const exp_name = try std.fmt.allocPrint(self.base.allocator, "_{s}", .{exp.options.name});
        defer self.base.allocator.free(exp_name);

        if (exp.options.section) |section_name| {
            if (!mem.eql(u8, section_name, "__text")) {
                try module.failed_exports.ensureCapacity(module.gpa, module.failed_exports.count() + 1);
                module.failed_exports.putAssumeCapacityNoClobber(
                    exp,
                    try Module.ErrorMsg.create(self.base.allocator, decl.srcLoc(), "Unimplemented: ExportOptions.section", .{}),
                );
                continue;
            }
        }

        var n_type: u8 = macho.N_SECT | macho.N_EXT;
        var n_desc: u16 = 0;

        switch (exp.options.linkage) {
            .Internal => {
                // Symbol should be hidden, or in MachO lingo, private extern.
                // We should also mark the symbol as Weak: n_desc == N_WEAK_DEF.
                // TODO work out when to add N_WEAK_REF.
                n_type |= macho.N_PEXT;
                n_desc |= macho.N_WEAK_DEF;
            },
            .Strong => {
                // Check if the export is _main, and note if os.
                // Otherwise, don't do anything since we already have all the flags
                // set that we need for global (strong) linkage.
                // n_type == N_SECT | N_EXT
                if (mem.eql(u8, exp_name, "_main")) {
                    self.entry_addr = decl_sym.n_value;
                }
            },
            .Weak => {
                // Weak linkage is specified as part of n_desc field.
                // Symbol's n_type is like for a symbol with strong linkage.
                n_desc |= macho.N_WEAK_DEF;
            },
            .LinkOnce => {
                try module.failed_exports.ensureCapacity(module.gpa, module.failed_exports.count() + 1);
                module.failed_exports.putAssumeCapacityNoClobber(
                    exp,
                    try Module.ErrorMsg.create(self.base.allocator, decl.srcLoc(), "Unimplemented: GlobalLinkage.LinkOnce", .{}),
                );
                continue;
            },
        }

        if (exp.link.macho.sym_index) |i| {
            const sym = &self.globals.items[i];
            sym.* = .{
                .n_strx = sym.n_strx,
                .n_type = n_type,
                .n_sect = @intCast(u8, self.text_section_index.?) + 1,
                .n_desc = n_desc,
                .n_value = decl_sym.n_value,
            };
        } else {
            const name_str_index = try self.makeString(exp_name);
            const i = if (self.globals_free_list.popOrNull()) |i| i else blk: {
                _ = self.globals.addOneAssumeCapacity();
                self.export_info_dirty = true;
                break :blk @intCast(u32, self.globals.items.len - 1);
            };
            self.globals.items[i] = .{
                .n_strx = name_str_index,
                .n_type = n_type,
                .n_sect = @intCast(u8, self.text_section_index.?) + 1,
                .n_desc = n_desc,
                .n_value = decl_sym.n_value,
            };
            const resolv_name = try self.base.allocator.dupe(u8, exp_name);
            const resolv = try self.symbol_resolver.getOrPut(self.base.allocator, resolv_name);
            defer if (resolv.found_existing) self.base.allocator.free(resolv_name);
            resolv.value_ptr.* = .{
                .where = .global,
                .where_index = i,
                .local_sym_index = decl.link.macho.local_sym_index,
            };

            exp.link.macho.sym_index = @intCast(u32, i);
        }
    }
}

pub fn deleteExport(self: *MachO, exp: Export) void {
    const sym_index = exp.sym_index orelse return;
    self.globals_free_list.append(self.base.allocator, sym_index) catch {};
    self.globals.items[sym_index].n_type = 0;
}

pub fn freeDecl(self: *MachO, decl: *Module.Decl) void {
    log.debug("freeDecl {*}", .{decl});
    // Appending to free lists is allowed to fail because the free lists are heuristics based anyway.
    self.freeTextBlock(&decl.link.macho);
    if (decl.link.macho.local_sym_index != 0) {
        self.locals_free_list.append(self.base.allocator, decl.link.macho.local_sym_index) catch {};

        const got_key = GotIndirectionKey{
            .where = .local,
            .where_index = decl.link.macho.local_sym_index,
        };
        const got_index = self.got_entries_map.get(got_key) orelse unreachable;
        _ = self.got_entries_map.remove(got_key);
        self.got_entries_free_list.append(self.base.allocator, got_index) catch {};

        self.locals.items[decl.link.macho.local_sym_index].n_type = 0;
        decl.link.macho.local_sym_index = 0;
    }
    if (self.d_sym) |*ds| {
        // TODO make this logic match freeTextBlock. Maybe abstract the logic
        // out since the same thing is desired for both.
        _ = ds.dbg_line_fn_free_list.remove(&decl.fn_link.macho);
        if (decl.fn_link.macho.prev) |prev| {
            ds.dbg_line_fn_free_list.put(self.base.allocator, prev, {}) catch {};
            prev.next = decl.fn_link.macho.next;
            if (decl.fn_link.macho.next) |next| {
                next.prev = prev;
            } else {
                ds.dbg_line_fn_last = prev;
            }
        } else if (decl.fn_link.macho.next) |next| {
            ds.dbg_line_fn_first = next;
            next.prev = null;
        }
        if (ds.dbg_line_fn_first == &decl.fn_link.macho) {
            ds.dbg_line_fn_first = decl.fn_link.macho.next;
        }
        if (ds.dbg_line_fn_last == &decl.fn_link.macho) {
            ds.dbg_line_fn_last = decl.fn_link.macho.prev;
        }
    }
}

pub fn getDeclVAddr(self: *MachO, decl: *const Module.Decl) u64 {
    assert(decl.link.macho.local_sym_index != 0);
    return self.locals.items[decl.link.macho.local_sym_index].n_value;
}

pub fn populateMissingMetadata(self: *MachO) !void {
    switch (self.base.options.output_mode) {
        .Exe => {},
        .Obj => return error.TODOImplementWritingObjFiles,
        .Lib => return error.TODOImplementWritingLibFiles,
    }

    if (self.pagezero_segment_cmd_index == null) {
        self.pagezero_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__PAGEZERO", .{
                .vmsize = 0x100000000, // size always set to 4GB
            }),
        });
        self.load_commands_dirty = true;
    }
    if (self.text_segment_cmd_index == null) {
        self.text_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE;
        const initprot = macho.VM_PROT_READ | macho.VM_PROT_EXECUTE;

        const program_code_size_hint = self.base.options.program_code_size_hint;
        const got_size_hint = @sizeOf(u64) * self.base.options.symbol_count_hint;
        const ideal_size = self.header_pad + program_code_size_hint + 3 * got_size_hint;
        const needed_size = mem.alignForwardGeneric(u64, padToIdeal(ideal_size), self.page_size);

        log.debug("found __TEXT segment free space 0x{x} to 0x{x}", .{ 0, needed_size });

        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__TEXT", .{
                .vmaddr = 0x100000000, // always starts at 4GB
                .vmsize = needed_size,
                .filesize = needed_size,
                .maxprot = maxprot,
                .initprot = initprot,
            }),
        });
        self.load_commands_dirty = true;
    }
    if (self.text_section_index == null) {
        const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.text_section_index = @intCast(u16, text_segment.sections.items.len);

        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS;
        const needed_size = self.base.options.program_code_size_hint;
        const off = text_segment.findFreeSpace(needed_size, @as(u16, 1) << alignment, self.header_pad);

        log.debug("found __text section free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try text_segment.addSection(self.base.allocator, "__text", .{
            .addr = text_segment.inner.vmaddr + off,
            .size = @intCast(u32, needed_size),
            .offset = @intCast(u32, off),
            .@"align" = alignment,
            .flags = flags,
        });
        self.load_commands_dirty = true;
    }
    if (self.stubs_section_index == null) {
        const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stubs_section_index = @intCast(u16, text_segment.sections.items.len);

        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_size: u4 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 6,
            .aarch64 => 3 * @sizeOf(u32),
            else => unreachable, // unhandled architecture type
        };
        const flags = macho.S_SYMBOL_STUBS | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS;
        const needed_size = @sizeOf(u64) * self.base.options.symbol_count_hint;
        const off = text_segment.findFreeSpace(needed_size, @alignOf(u64), self.header_pad);
        assert(off + needed_size <= text_segment.inner.fileoff + text_segment.inner.filesize); // TODO Must expand __TEXT segment.

        log.debug("found __stubs section free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try text_segment.addSection(self.base.allocator, "__stubs", .{
            .addr = text_segment.inner.vmaddr + off,
            .size = needed_size,
            .offset = @intCast(u32, off),
            .@"align" = alignment,
            .flags = flags,
            .reserved2 = stub_size,
        });
        self.load_commands_dirty = true;
    }
    if (self.stub_helper_section_index == null) {
        const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stub_helper_section_index = @intCast(u16, text_segment.sections.items.len);

        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS;
        const needed_size = @sizeOf(u64) * self.base.options.symbol_count_hint;
        const off = text_segment.findFreeSpace(needed_size, @alignOf(u64), self.header_pad);
        assert(off + needed_size <= text_segment.inner.fileoff + text_segment.inner.filesize); // TODO Must expand __TEXT segment.

        log.debug("found __stub_helper section free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try text_segment.addSection(self.base.allocator, "__stub_helper", .{
            .addr = text_segment.inner.vmaddr + off,
            .size = needed_size,
            .offset = @intCast(u32, off),
            .@"align" = alignment,
            .flags = flags,
        });
        self.load_commands_dirty = true;
    }
    if (self.data_const_segment_cmd_index == null) {
        self.data_const_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE;
        const initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE;
        const address_and_offset = self.nextSegmentAddressAndOffset();

        const ideal_size = @sizeOf(u64) * self.base.options.symbol_count_hint;
        const needed_size = mem.alignForwardGeneric(u64, padToIdeal(ideal_size), self.page_size);

        log.debug("found __DATA_CONST segment free space 0x{x} to 0x{x}", .{ address_and_offset.offset, address_and_offset.offset + needed_size });

        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__DATA_CONST", .{
                .vmaddr = address_and_offset.address,
                .vmsize = needed_size,
                .fileoff = address_and_offset.offset,
                .filesize = needed_size,
                .maxprot = maxprot,
                .initprot = initprot,
            }),
        });
        self.load_commands_dirty = true;
    }
    if (self.got_section_index == null) {
        const dc_segment = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        self.got_section_index = @intCast(u16, dc_segment.sections.items.len);

        const flags = macho.S_NON_LAZY_SYMBOL_POINTERS;
        const needed_size = @sizeOf(u64) * self.base.options.symbol_count_hint;
        const off = dc_segment.findFreeSpace(needed_size, @alignOf(u64), null);
        assert(off + needed_size <= dc_segment.inner.fileoff + dc_segment.inner.filesize); // TODO Must expand __DATA_CONST segment.

        log.debug("found __got section free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try dc_segment.addSection(self.base.allocator, "__got", .{
            .addr = dc_segment.inner.vmaddr + off - dc_segment.inner.fileoff,
            .size = needed_size,
            .offset = @intCast(u32, off),
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = flags,
        });
        self.load_commands_dirty = true;
    }
    if (self.data_segment_cmd_index == null) {
        self.data_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        const maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE;
        const initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE;
        const address_and_offset = self.nextSegmentAddressAndOffset();

        const ideal_size = 2 * @sizeOf(u64) * self.base.options.symbol_count_hint;
        const needed_size = mem.alignForwardGeneric(u64, padToIdeal(ideal_size), self.page_size);

        log.debug("found __DATA segment free space 0x{x} to 0x{x}", .{ address_and_offset.offset, address_and_offset.offset + needed_size });

        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__DATA", .{
                .vmaddr = address_and_offset.address,
                .vmsize = needed_size,
                .fileoff = address_and_offset.offset,
                .filesize = needed_size,
                .maxprot = maxprot,
                .initprot = initprot,
            }),
        });
        self.load_commands_dirty = true;
    }
    if (self.la_symbol_ptr_section_index == null) {
        const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.la_symbol_ptr_section_index = @intCast(u16, data_segment.sections.items.len);

        const flags = macho.S_LAZY_SYMBOL_POINTERS;
        const needed_size = @sizeOf(u64) * self.base.options.symbol_count_hint;
        const off = data_segment.findFreeSpace(needed_size, @alignOf(u64), null);
        assert(off + needed_size <= data_segment.inner.fileoff + data_segment.inner.filesize); // TODO Must expand __DATA segment.

        log.debug("found __la_symbol_ptr section free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try data_segment.addSection(self.base.allocator, "__la_symbol_ptr", .{
            .addr = data_segment.inner.vmaddr + off - data_segment.inner.fileoff,
            .size = needed_size,
            .offset = @intCast(u32, off),
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = flags,
        });
        self.load_commands_dirty = true;
    }
    if (self.data_section_index == null) {
        const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.data_section_index = @intCast(u16, data_segment.sections.items.len);

        const needed_size = @sizeOf(u64) * self.base.options.symbol_count_hint;
        const off = data_segment.findFreeSpace(needed_size, @alignOf(u64), null);
        assert(off + needed_size <= data_segment.inner.fileoff + data_segment.inner.filesize); // TODO Must expand __DATA segment.

        log.debug("found __data section free space 0x{x} to 0x{x}", .{ off, off + needed_size });

        try data_segment.addSection(self.base.allocator, "__data", .{
            .addr = data_segment.inner.vmaddr + off - data_segment.inner.fileoff,
            .size = needed_size,
            .offset = @intCast(u32, off),
            .@"align" = 3, // 2^3 = @sizeOf(u64)
        });
        self.load_commands_dirty = true;
    }
    if (self.linkedit_segment_cmd_index == null) {
        self.linkedit_segment_cmd_index = @intCast(u16, self.load_commands.items.len);

        const maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE;
        const initprot = macho.VM_PROT_READ;
        const address_and_offset = self.nextSegmentAddressAndOffset();

        log.debug("found __LINKEDIT segment free space at 0x{x}", .{address_and_offset.offset});

        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__LINKEDIT", .{
                .vmaddr = address_and_offset.address,
                .fileoff = address_and_offset.offset,
                .maxprot = maxprot,
                .initprot = initprot,
            }),
        });
        self.load_commands_dirty = true;
    }
    if (self.dyld_info_cmd_index == null) {
        self.dyld_info_cmd_index = @intCast(u16, self.load_commands.items.len);

        try self.load_commands.append(self.base.allocator, .{
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

        const dyld = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;

        // Preallocate rebase, binding, lazy binding info, and export info.
        const expected_size = 48; // TODO This is totally random.
        const rebase_off = self.findFreeSpaceLinkedit(expected_size, 1, null);
        log.debug("found rebase info free space 0x{x} to 0x{x}", .{ rebase_off, rebase_off + expected_size });
        dyld.rebase_off = @intCast(u32, rebase_off);
        dyld.rebase_size = expected_size;

        const bind_off = self.findFreeSpaceLinkedit(expected_size, 1, null);
        log.debug("found binding info free space 0x{x} to 0x{x}", .{ bind_off, bind_off + expected_size });
        dyld.bind_off = @intCast(u32, bind_off);
        dyld.bind_size = expected_size;

        const lazy_bind_off = self.findFreeSpaceLinkedit(expected_size, 1, null);
        log.debug("found lazy binding info free space 0x{x} to 0x{x}", .{ lazy_bind_off, lazy_bind_off + expected_size });
        dyld.lazy_bind_off = @intCast(u32, lazy_bind_off);
        dyld.lazy_bind_size = expected_size;

        const export_off = self.findFreeSpaceLinkedit(expected_size, 1, null);
        log.debug("found export info free space 0x{x} to 0x{x}", .{ export_off, export_off + expected_size });
        dyld.export_off = @intCast(u32, export_off);
        dyld.export_size = expected_size;

        self.load_commands_dirty = true;
    }
    if (self.symtab_cmd_index == null) {
        self.symtab_cmd_index = @intCast(u16, self.load_commands.items.len);

        try self.load_commands.append(self.base.allocator, .{
            .Symtab = .{
                .cmd = macho.LC_SYMTAB,
                .cmdsize = @sizeOf(macho.symtab_command),
                .symoff = 0,
                .nsyms = 0,
                .stroff = 0,
                .strsize = 0,
            },
        });

        const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;

        const symtab_size = self.base.options.symbol_count_hint * @sizeOf(macho.nlist_64);
        const symtab_off = self.findFreeSpaceLinkedit(symtab_size, @sizeOf(macho.nlist_64), null);
        log.debug("found symbol table free space 0x{x} to 0x{x}", .{ symtab_off, symtab_off + symtab_size });
        symtab.symoff = @intCast(u32, symtab_off);
        symtab.nsyms = @intCast(u32, self.base.options.symbol_count_hint);

        try self.strtab.append(self.base.allocator, 0);
        const strtab_size = self.strtab.items.len;
        const strtab_off = self.findFreeSpaceLinkedit(strtab_size, 1, symtab_off);
        log.debug("found string table free space 0x{x} to 0x{x}", .{ strtab_off, strtab_off + strtab_size });
        symtab.stroff = @intCast(u32, strtab_off);
        symtab.strsize = @intCast(u32, strtab_size);

        self.load_commands_dirty = true;
        self.strtab_dirty = true;
    }
    if (self.dysymtab_cmd_index == null) {
        self.dysymtab_cmd_index = @intCast(u16, self.load_commands.items.len);

        // Preallocate space for indirect symbol table.
        const indsymtab_size = self.base.options.symbol_count_hint * @sizeOf(u64); // Each entry is just a u64.
        const indsymtab_off = self.findFreeSpaceLinkedit(indsymtab_size, @sizeOf(u64), null);

        log.debug("found indirect symbol table free space 0x{x} to 0x{x}", .{ indsymtab_off, indsymtab_off + indsymtab_size });

        try self.load_commands.append(self.base.allocator, .{
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
                .indirectsymoff = @intCast(u32, indsymtab_off),
                .nindirectsyms = @intCast(u32, self.base.options.symbol_count_hint),
                .extreloff = 0,
                .nextrel = 0,
                .locreloff = 0,
                .nlocrel = 0,
            },
        });
        self.load_commands_dirty = true;
    }
    if (self.dylinker_cmd_index == null) {
        self.dylinker_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.dylinker_command) + mem.lenZ(DEFAULT_DYLD_PATH),
            @sizeOf(u64),
        ));
        var dylinker_cmd = commands.emptyGenericCommandWithData(macho.dylinker_command{
            .cmd = macho.LC_LOAD_DYLINKER,
            .cmdsize = cmdsize,
            .name = @sizeOf(macho.dylinker_command),
        });
        dylinker_cmd.data = try self.base.allocator.alloc(u8, cmdsize - dylinker_cmd.inner.name);
        mem.set(u8, dylinker_cmd.data, 0);
        mem.copy(u8, dylinker_cmd.data, mem.spanZ(DEFAULT_DYLD_PATH));
        try self.load_commands.append(self.base.allocator, .{ .Dylinker = dylinker_cmd });
        self.load_commands_dirty = true;
    }
    if (self.libsystem_cmd_index == null) {
        self.libsystem_cmd_index = @intCast(u16, self.load_commands.items.len);

        var dylib_cmd = try commands.createLoadDylibCommand(self.base.allocator, mem.spanZ(LIB_SYSTEM_PATH), 2, 0, 0);
        errdefer dylib_cmd.deinit(self.base.allocator);

        try self.load_commands.append(self.base.allocator, .{ .Dylib = dylib_cmd });

        self.load_commands_dirty = true;
    }
    if (self.main_cmd_index == null) {
        self.main_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Main = .{
                .cmd = macho.LC_MAIN,
                .cmdsize = @sizeOf(macho.entry_point_command),
                .entryoff = 0x0,
                .stacksize = 0,
            },
        });
        self.load_commands_dirty = true;
    }
    if (self.version_min_cmd_index == null) {
        self.version_min_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmd: u32 = switch (self.base.options.target.os.tag) {
            .macos => macho.LC_VERSION_MIN_MACOSX,
            .ios => macho.LC_VERSION_MIN_IPHONEOS,
            .tvos => macho.LC_VERSION_MIN_TVOS,
            .watchos => macho.LC_VERSION_MIN_WATCHOS,
            else => unreachable, // wrong OS
        };
        const ver = self.base.options.target.os.version_range.semver.min;
        const version = ver.major << 16 | ver.minor << 8 | ver.patch;
        try self.load_commands.append(self.base.allocator, .{
            .VersionMin = .{
                .cmd = cmd,
                .cmdsize = @sizeOf(macho.version_min_command),
                .version = version,
                .sdk = version,
            },
        });
        self.load_commands_dirty = true;
    }
    if (self.source_version_cmd_index == null) {
        self.source_version_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .SourceVersion = .{
                .cmd = macho.LC_SOURCE_VERSION,
                .cmdsize = @sizeOf(macho.source_version_command),
                .version = 0x0,
            },
        });
        self.load_commands_dirty = true;
    }
    if (self.uuid_cmd_index == null) {
        self.uuid_cmd_index = @intCast(u16, self.load_commands.items.len);
        var uuid_cmd: macho.uuid_command = .{
            .cmd = macho.LC_UUID,
            .cmdsize = @sizeOf(macho.uuid_command),
            .uuid = undefined,
        };
        std.crypto.random.bytes(&uuid_cmd.uuid);
        try self.load_commands.append(self.base.allocator, .{ .Uuid = uuid_cmd });
        self.load_commands_dirty = true;
    }
    if (self.code_signature_cmd_index == null) {
        self.code_signature_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .LinkeditData = .{
                .cmd = macho.LC_CODE_SIGNATURE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
        self.load_commands_dirty = true;
    }
    if (!self.symbol_resolver.contains("dyld_stub_binder")) {
        const import_sym_index = @intCast(u32, self.imports.items.len);
        try self.imports.append(self.base.allocator, .{
            .n_strx = try self.makeString("dyld_stub_binder"),
            .n_type = macho.N_UNDF | macho.N_EXT,
            .n_sect = 0,
            .n_desc = packDylibOrdinal(1),
            .n_value = 0,
        });
        const name = try self.base.allocator.dupe(u8, "dyld_stub_binder");
        try self.symbol_resolver.putNoClobber(self.base.allocator, name, .{
            .where = .import,
            .where_index = import_sym_index,
        });
        const got_key = GotIndirectionKey{
            .where = .import,
            .where_index = import_sym_index,
        };
        const got_index = @intCast(u32, self.got_entries.items.len);
        try self.got_entries.append(self.base.allocator, got_key);
        try self.got_entries_map.putNoClobber(self.base.allocator, got_key, got_index);
        try self.writeGotEntry(got_index);
        self.binding_info_dirty = true;
    }
    if (self.stub_helper_stubs_start_off == null) {
        try self.writeStubHelperPreamble();
    }
}

fn allocateTextBlock(self: *MachO, text_block: *TextBlock, new_block_size: u64, alignment: u64) !u64 {
    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const text_section = &text_segment.sections.items[self.text_section_index.?];
    const new_block_ideal_capacity = padToIdeal(new_block_size);

    // We use these to indicate our intention to update metadata, placing the new block,
    // and possibly removing a free list node.
    // It would be simpler to do it inside the for loop below, but that would cause a
    // problem if an error was returned later in the function. So this action
    // is actually carried out at the end of the function, when errors are no longer possible.
    var block_placement: ?*TextBlock = null;
    var free_list_removal: ?usize = null;

    // First we look for an appropriately sized free list node.
    // The list is unordered. We'll just take the first thing that works.
    const vaddr = blk: {
        var i: usize = 0;
        while (i < self.text_block_free_list.items.len) {
            const big_block = self.text_block_free_list.items[i];
            // We now have a pointer to a live text block that has too much capacity.
            // Is it enough that we could fit this new text block?
            const sym = self.locals.items[big_block.local_sym_index];
            const capacity = big_block.capacity(self.*);
            const ideal_capacity = padToIdeal(capacity);
            const ideal_capacity_end_vaddr = sym.n_value + ideal_capacity;
            const capacity_end_vaddr = sym.n_value + capacity;
            const new_start_vaddr_unaligned = capacity_end_vaddr - new_block_ideal_capacity;
            const new_start_vaddr = mem.alignBackwardGeneric(u64, new_start_vaddr_unaligned, alignment);
            if (new_start_vaddr < ideal_capacity_end_vaddr) {
                // Additional bookkeeping here to notice if this free list node
                // should be deleted because the block that it points to has grown to take up
                // more of the extra capacity.
                if (!big_block.freeListEligible(self.*)) {
                    const bl = self.text_block_free_list.swapRemove(i);
                    bl.deinit(self.base.allocator);
                } else {
                    i += 1;
                }
                continue;
            }
            // At this point we know that we will place the new block here. But the
            // remaining question is whether there is still yet enough capacity left
            // over for there to still be a free list node.
            const remaining_capacity = new_start_vaddr - ideal_capacity_end_vaddr;
            const keep_free_list_node = remaining_capacity >= min_text_capacity;

            // Set up the metadata to be updated, after errors are no longer possible.
            block_placement = big_block;
            if (!keep_free_list_node) {
                free_list_removal = i;
            }
            break :blk new_start_vaddr;
        } else if (self.last_text_block) |last| {
            const last_symbol = self.locals.items[last.local_sym_index];
            // TODO We should pad out the excess capacity with NOPs. For executables,
            // no padding seems to be OK, but it will probably not be for objects.
            const ideal_capacity = padToIdeal(last.size);
            const ideal_capacity_end_vaddr = last_symbol.n_value + ideal_capacity;
            const new_start_vaddr = mem.alignForwardGeneric(u64, ideal_capacity_end_vaddr, alignment);
            block_placement = last;
            break :blk new_start_vaddr;
        } else {
            break :blk text_section.addr;
        }
    };

    const expand_text_section = block_placement == null or block_placement.?.next == null;
    if (expand_text_section) {
        const needed_size = (vaddr + new_block_size) - text_section.addr;
        assert(needed_size <= text_segment.inner.filesize); // TODO must move the entire text section.

        self.last_text_block = text_block;
        text_section.size = needed_size;
        self.load_commands_dirty = true; // TODO Make more granular.

        if (self.d_sym) |*ds| {
            const debug_text_seg = &ds.load_commands.items[ds.text_segment_cmd_index.?].Segment;
            const debug_text_sect = &debug_text_seg.sections.items[ds.text_section_index.?];
            debug_text_sect.size = needed_size;
            ds.load_commands_dirty = true;
        }
    }
    text_block.size = new_block_size;

    if (text_block.prev) |prev| {
        prev.next = text_block.next;
    }
    if (text_block.next) |next| {
        next.prev = text_block.prev;
    }

    if (block_placement) |big_block| {
        text_block.prev = big_block;
        text_block.next = big_block.next;
        big_block.next = text_block;
    } else {
        text_block.prev = null;
        text_block.next = null;
    }
    if (free_list_removal) |i| {
        _ = self.text_block_free_list.swapRemove(i);
    }

    return vaddr;
}

pub fn addExternFn(self: *MachO, name: []const u8) !u32 {
    const sym_name = try std.fmt.allocPrint(self.base.allocator, "_{s}", .{name});
    const already_defined = self.symbol_resolver.contains(sym_name);

    if (already_defined) {
        const resolv = self.symbol_resolver.get(sym_name) orelse unreachable;
        self.base.allocator.free(sym_name);
        return resolv.where_index;
    }

    log.debug("adding new extern function '{s}' with dylib ordinal 1", .{sym_name});
    const import_sym_index = @intCast(u32, self.imports.items.len);
    try self.imports.append(self.base.allocator, .{
        .n_strx = try self.makeString(sym_name),
        .n_type = macho.N_UNDF | macho.N_EXT,
        .n_sect = 0,
        .n_desc = packDylibOrdinal(1),
        .n_value = 0,
    });
    try self.symbol_resolver.putNoClobber(self.base.allocator, sym_name, .{
        .where = .import,
        .where_index = import_sym_index,
    });

    const stubs_index = @intCast(u32, self.stubs.items.len);
    try self.stubs.append(self.base.allocator, import_sym_index);
    try self.stubs_map.putNoClobber(self.base.allocator, import_sym_index, stubs_index);

    // TODO discuss this. The caller context expects codegen.InnerError{ OutOfMemory, CodegenFail },
    // which obviously doesn't include file writing op errors. So instead of trying to write the stub
    // entry right here and now, queue it up and dispose of when updating decl.
    try self.pending_updates.append(self.base.allocator, .{
        .kind = .stub,
        .index = stubs_index,
    });

    return import_sym_index;
}

const NextSegmentAddressAndOffset = struct {
    address: u64,
    offset: u64,
};

fn nextSegmentAddressAndOffset(self: *MachO) NextSegmentAddressAndOffset {
    var prev_segment_idx: ?usize = null; // We use optional here for safety.
    for (self.load_commands.items) |cmd, i| {
        if (cmd == .Segment) {
            prev_segment_idx = i;
        }
    }
    const prev_segment = self.load_commands.items[prev_segment_idx.?].Segment;
    const address = prev_segment.inner.vmaddr + prev_segment.inner.vmsize;
    const offset = prev_segment.inner.fileoff + prev_segment.inner.filesize;
    return .{
        .address = address,
        .offset = offset,
    };
}

fn allocatedSizeLinkedit(self: *MachO, start: u64) u64 {
    assert(start > 0);
    var min_pos: u64 = std.math.maxInt(u64);

    // __LINKEDIT is a weird segment where sections get their own load commands so we
    // special-case it.
    if (self.dyld_info_cmd_index) |idx| {
        const dyld_info = self.load_commands.items[idx].DyldInfoOnly;
        if (dyld_info.rebase_off > start and dyld_info.rebase_off < min_pos) min_pos = dyld_info.rebase_off;
        if (dyld_info.bind_off > start and dyld_info.bind_off < min_pos) min_pos = dyld_info.bind_off;
        if (dyld_info.weak_bind_off > start and dyld_info.weak_bind_off < min_pos) min_pos = dyld_info.weak_bind_off;
        if (dyld_info.lazy_bind_off > start and dyld_info.lazy_bind_off < min_pos) min_pos = dyld_info.lazy_bind_off;
        if (dyld_info.export_off > start and dyld_info.export_off < min_pos) min_pos = dyld_info.export_off;
    }

    if (self.function_starts_cmd_index) |idx| {
        const fstart = self.load_commands.items[idx].LinkeditData;
        if (fstart.dataoff > start and fstart.dataoff < min_pos) min_pos = fstart.dataoff;
    }

    if (self.data_in_code_cmd_index) |idx| {
        const dic = self.load_commands.items[idx].LinkeditData;
        if (dic.dataoff > start and dic.dataoff < min_pos) min_pos = dic.dataoff;
    }

    if (self.dysymtab_cmd_index) |idx| {
        const dysymtab = self.load_commands.items[idx].Dysymtab;
        if (dysymtab.indirectsymoff > start and dysymtab.indirectsymoff < min_pos) min_pos = dysymtab.indirectsymoff;
        // TODO Handle more dynamic symbol table sections.
    }

    if (self.symtab_cmd_index) |idx| {
        const symtab = self.load_commands.items[idx].Symtab;
        if (symtab.symoff > start and symtab.symoff < min_pos) min_pos = symtab.symoff;
        if (symtab.stroff > start and symtab.stroff < min_pos) min_pos = symtab.stroff;
    }

    return min_pos - start;
}
inline fn checkForCollision(start: u64, end: u64, off: u64, size: u64) ?u64 {
    const increased_size = padToIdeal(size);
    const test_end = off + increased_size;
    if (end > off and start < test_end) {
        return test_end;
    }
    return null;
}

fn detectAllocCollisionLinkedit(self: *MachO, start: u64, size: u64) ?u64 {
    const end = start + padToIdeal(size);

    // __LINKEDIT is a weird segment where sections get their own load commands so we
    // special-case it.
    if (self.dyld_info_cmd_index) |idx| outer: {
        if (self.load_commands.items.len == idx) break :outer;
        const dyld_info = self.load_commands.items[idx].DyldInfoOnly;
        if (checkForCollision(start, end, dyld_info.rebase_off, dyld_info.rebase_size)) |pos| {
            return pos;
        }
        // Binding info
        if (checkForCollision(start, end, dyld_info.bind_off, dyld_info.bind_size)) |pos| {
            return pos;
        }
        // Weak binding info
        if (checkForCollision(start, end, dyld_info.weak_bind_off, dyld_info.weak_bind_size)) |pos| {
            return pos;
        }
        // Lazy binding info
        if (checkForCollision(start, end, dyld_info.lazy_bind_off, dyld_info.lazy_bind_size)) |pos| {
            return pos;
        }
        // Export info
        if (checkForCollision(start, end, dyld_info.export_off, dyld_info.export_size)) |pos| {
            return pos;
        }
    }

    if (self.function_starts_cmd_index) |idx| outer: {
        if (self.load_commands.items.len == idx) break :outer;
        const fstart = self.load_commands.items[idx].LinkeditData;
        if (checkForCollision(start, end, fstart.dataoff, fstart.datasize)) |pos| {
            return pos;
        }
    }

    if (self.data_in_code_cmd_index) |idx| outer: {
        if (self.load_commands.items.len == idx) break :outer;
        const dic = self.load_commands.items[idx].LinkeditData;
        if (checkForCollision(start, end, dic.dataoff, dic.datasize)) |pos| {
            return pos;
        }
    }

    if (self.dysymtab_cmd_index) |idx| outer: {
        if (self.load_commands.items.len == idx) break :outer;
        const dysymtab = self.load_commands.items[idx].Dysymtab;
        // Indirect symbol table
        const nindirectsize = dysymtab.nindirectsyms * @sizeOf(u32);
        if (checkForCollision(start, end, dysymtab.indirectsymoff, nindirectsize)) |pos| {
            return pos;
        }
        // TODO Handle more dynamic symbol table sections.
    }

    if (self.symtab_cmd_index) |idx| outer: {
        if (self.load_commands.items.len == idx) break :outer;
        const symtab = self.load_commands.items[idx].Symtab;
        // Symbol table
        const symsize = symtab.nsyms * @sizeOf(macho.nlist_64);
        if (checkForCollision(start, end, symtab.symoff, symsize)) |pos| {
            return pos;
        }
        // String table
        if (checkForCollision(start, end, symtab.stroff, symtab.strsize)) |pos| {
            return pos;
        }
    }

    return null;
}

fn findFreeSpaceLinkedit(self: *MachO, object_size: u64, min_alignment: u16, start: ?u64) u64 {
    const linkedit = self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    var st: u64 = start orelse linkedit.inner.fileoff;
    while (self.detectAllocCollisionLinkedit(st, object_size)) |item_end| {
        st = mem.alignForwardGeneric(u64, item_end, min_alignment);
    }
    return st;
}

fn writeGotEntry(self: *MachO, index: usize) !void {
    const seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const sect = &seg.sections.items[self.got_section_index.?];
    const off = sect.offset + @sizeOf(u64) * index;

    if (self.got_entries_count_dirty) {
        // TODO relocate.
        self.got_entries_count_dirty = false;
    }

    const got_entry = self.got_entries.items[index];
    const sym = switch (got_entry.where) {
        .local => self.locals.items[got_entry.where_index],
        .import => self.imports.items[got_entry.where_index],
    };
    log.debug("writing offset table entry [ 0x{x} => 0x{x} ({s}) ]", .{
        off,
        sym.n_value,
        self.getString(sym.n_strx),
    });
    try self.base.file.?.pwriteAll(mem.asBytes(&sym.n_value), off);
}

fn writeLazySymbolPointer(self: *MachO, index: u32) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = text_segment.sections.items[self.stub_helper_section_index.?];
    const data_segment = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = data_segment.sections.items[self.la_symbol_ptr_section_index.?];

    const stub_size: u4 = switch (self.base.options.target.cpu.arch) {
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
    try self.base.file.?.pwriteAll(&buf, off);
}

fn writeStubHelperPreamble(self: *MachO) !void {
    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = &text_segment.sections.items[self.stub_helper_section_index.?];
    const data_const_segment = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_segment.sections.items[self.got_section_index.?];
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const data = &data_segment.sections.items[self.data_section_index.?];

    switch (self.base.options.target.cpu.arch) {
        .x86_64 => {
            const code_size = 15;
            var code: [code_size]u8 = undefined;
            // lea %r11, [rip + disp]
            code[0] = 0x4c;
            code[1] = 0x8d;
            code[2] = 0x1d;
            {
                const target_addr = data.addr;
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
                const displacement = try math.cast(u32, got.addr - stub_helper.addr - code_size);
                mem.writeIntLittle(u32, code[11..], displacement);
            }
            try self.base.file.?.pwriteAll(&code, stub_helper.offset);
            self.stub_helper_stubs_start_off = stub_helper.offset + code_size;
        },
        .aarch64 => {
            var code: [6 * @sizeOf(u32)]u8 = undefined;

            data_blk_outer: {
                const this_addr = stub_helper.addr;
                const target_addr = data.addr;
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
                // adrp x17, pages
                mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.adrp(.x17, pages).toU32());
                const narrowed = @truncate(u12, target_addr);
                mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.add(.x17, .x17, narrowed, false).toU32());
            }

            // stp x16, x17, [sp, #-16]!
            mem.writeIntLittle(u32, code[8..12], aarch64.Instruction.stp(
                .x16,
                .x17,
                aarch64.Register.sp,
                aarch64.Instruction.LoadStorePairOffset.pre_index(-16),
            ).toU32());

            binder_blk_outer: {
                const this_addr = stub_helper.addr + 3 * @sizeOf(u32);
                const target_addr = got.addr;
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
                    // nop
                    mem.writeIntLittle(u32, code[12..16], aarch64.Instruction.nop().toU32());
                    // ldr x16, label
                    mem.writeIntLittle(u32, code[16..20], aarch64.Instruction.ldr(.x16, .{
                        .literal = literal,
                    }).toU32());
                    break :binder_blk_outer;
                }
                // Jump is too big, replace ldr with adrp and ldr(register).
                const this_page = @intCast(i32, this_addr >> 12);
                const target_page = @intCast(i32, target_addr >> 12);
                const pages = @intCast(i21, target_page - this_page);
                // adrp x16, pages
                mem.writeIntLittle(u32, code[12..16], aarch64.Instruction.adrp(.x16, pages).toU32());
                const narrowed = @truncate(u12, target_addr);
                const offset = try math.divExact(u12, narrowed, 8);
                // ldr x16, x16, offset
                mem.writeIntLittle(u32, code[16..20], aarch64.Instruction.ldr(.x16, .{
                    .register = .{
                        .rn = .x16,
                        .offset = aarch64.Instruction.LoadStoreOffset.imm(offset),
                    },
                }).toU32());
            }

            // br x16
            mem.writeIntLittle(u32, code[20..24], aarch64.Instruction.br(.x16).toU32());
            try self.base.file.?.pwriteAll(&code, stub_helper.offset);
            self.stub_helper_stubs_start_off = stub_helper.offset + code.len;
        },
        else => unreachable,
    }
}

fn writeStub(self: *MachO, index: u32) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stubs = text_segment.sections.items[self.stubs_section_index.?];
    const data_segment = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = data_segment.sections.items[self.la_symbol_ptr_section_index.?];

    const stub_off = stubs.offset + index * stubs.reserved2;
    const stub_addr = stubs.addr + index * stubs.reserved2;
    const la_ptr_addr = la_symbol_ptr.addr + index * @sizeOf(u64);

    log.debug("writing stub at 0x{x}", .{stub_off});

    var code = try self.base.allocator.alloc(u8, stubs.reserved2);
    defer self.base.allocator.free(code);

    switch (self.base.options.target.cpu.arch) {
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
                // Use adrp followed by ldr(register).
                const this_page = @intCast(i32, this_addr >> 12);
                const target_page = @intCast(i32, target_addr >> 12);
                const pages = @intCast(i21, target_page - this_page);
                // adrp x16, pages
                mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.adrp(.x16, pages).toU32());
                const narrowed = @truncate(u12, target_addr);
                const offset = try math.divExact(u12, narrowed, 8);
                // ldr x16, x16, offset
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
    try self.base.file.?.pwriteAll(code, stub_off);
}

fn writeStubInStubHelper(self: *MachO, index: u32) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = text_segment.sections.items[self.stub_helper_section_index.?];

    const stub_size: u4 = switch (self.base.options.target.cpu.arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const stub_off = self.stub_helper_stubs_start_off.? + index * stub_size;

    var code = try self.base.allocator.alloc(u8, stub_size);
    defer self.base.allocator.free(code);

    switch (self.base.options.target.cpu.arch) {
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
            const literal = blk: {
                const div_res = try math.divExact(u64, stub_size - @sizeOf(u32), 4);
                break :blk try math.cast(u18, div_res);
            };
            // ldr w16, literal
            mem.writeIntLittle(u32, code[0..4], aarch64.Instruction.ldr(.w16, .{
                .literal = literal,
            }).toU32());
            const displacement = try math.cast(i28, @intCast(i64, stub_helper.offset) - @intCast(i64, stub_off) - 4);
            // b disp
            mem.writeIntLittle(u32, code[4..8], aarch64.Instruction.b(displacement).toU32());
            // Just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
            mem.writeIntLittle(u32, code[8..12], 0x0);
        },
        else => unreachable,
    }
    try self.base.file.?.pwriteAll(code, stub_off);
}

fn relocateSymbolTable(self: *MachO) !void {
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    const nlocals = self.locals.items.len;
    const nglobals = self.globals.items.len;
    const nundefs = self.imports.items.len;
    const nsyms = nlocals + nglobals + nundefs;

    if (symtab.nsyms < nsyms) {
        const needed_size = nsyms * @sizeOf(macho.nlist_64);
        if (needed_size > self.allocatedSizeLinkedit(symtab.symoff)) {
            // Move the entire symbol table to a new location
            const new_symoff = self.findFreeSpaceLinkedit(needed_size, @alignOf(macho.nlist_64), null);
            const existing_size = symtab.nsyms * @sizeOf(macho.nlist_64);

            log.debug("relocating symbol table from 0x{x}-0x{x} to 0x{x}-0x{x}", .{
                symtab.symoff,
                symtab.symoff + existing_size,
                new_symoff,
                new_symoff + existing_size,
            });

            const amt = try self.base.file.?.copyRangeAll(symtab.symoff, self.base.file.?, new_symoff, existing_size);
            if (amt != existing_size) return error.InputOutput;
            symtab.symoff = @intCast(u32, new_symoff);
            self.strtab_needs_relocation = true;
        }
        symtab.nsyms = @intCast(u32, nsyms);
        self.load_commands_dirty = true;
    }
}

fn writeLocalSymbol(self: *MachO, index: usize) !void {
    const tracy = trace(@src());
    defer tracy.end();
    try self.relocateSymbolTable();
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    const off = symtab.symoff + @sizeOf(macho.nlist_64) * index;
    log.debug("writing local symbol {} at 0x{x}", .{ index, off });
    try self.base.file.?.pwriteAll(mem.asBytes(&self.locals.items[index]), off);
}

fn writeAllGlobalAndUndefSymbols(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    try self.relocateSymbolTable();
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    const nlocals = self.locals.items.len;
    const nglobals = self.globals.items.len;
    const nundefs = self.imports.items.len;

    const locals_off = symtab.symoff;
    const locals_size = nlocals * @sizeOf(macho.nlist_64);

    const globals_off = locals_off + locals_size;
    const globals_size = nglobals * @sizeOf(macho.nlist_64);
    log.debug("writing global symbols from 0x{x} to 0x{x}", .{ globals_off, globals_size + globals_off });
    try self.base.file.?.pwriteAll(mem.sliceAsBytes(self.globals.items), globals_off);

    const undefs_off = globals_off + globals_size;
    const undefs_size = nundefs * @sizeOf(macho.nlist_64);
    log.debug("writing extern symbols from 0x{x} to 0x{x}", .{ undefs_off, undefs_size + undefs_off });
    try self.base.file.?.pwriteAll(mem.sliceAsBytes(self.imports.items), undefs_off);

    // Update dynamic symbol table.
    const dysymtab = &self.load_commands.items[self.dysymtab_cmd_index.?].Dysymtab;
    dysymtab.nlocalsym = @intCast(u32, nlocals);
    dysymtab.iextdefsym = @intCast(u32, nlocals);
    dysymtab.nextdefsym = @intCast(u32, nglobals);
    dysymtab.iundefsym = @intCast(u32, nlocals + nglobals);
    dysymtab.nundefsym = @intCast(u32, nundefs);
    self.load_commands_dirty = true;
}

fn writeIndirectSymbolTable(self: *MachO) !void {
    // TODO figure out a way not to rewrite the table every time if
    // no new undefs are not added.
    const tracy = trace(@src());
    defer tracy.end();

    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stubs = &text_segment.sections.items[self.stubs_section_index.?];
    const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_seg.sections.items[self.got_section_index.?];
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = &data_segment.sections.items[self.la_symbol_ptr_section_index.?];
    const dysymtab = &self.load_commands.items[self.dysymtab_cmd_index.?].Dysymtab;

    const nstubs = @intCast(u32, self.stubs.items.len);
    const ngot_entries = @intCast(u32, self.got_entries.items.len);
    const allocated_size = self.allocatedSizeLinkedit(dysymtab.indirectsymoff);
    const nindirectsyms = nstubs * 2 + ngot_entries;
    const needed_size = @intCast(u32, nindirectsyms * @sizeOf(u32));

    if (needed_size > allocated_size) {
        dysymtab.nindirectsyms = 0;
        dysymtab.indirectsymoff = @intCast(u32, self.findFreeSpaceLinkedit(needed_size, @sizeOf(u32), null));
    }
    dysymtab.nindirectsyms = nindirectsyms;
    log.debug("writing indirect symbol table from 0x{x} to 0x{x}", .{
        dysymtab.indirectsymoff,
        dysymtab.indirectsymoff + needed_size,
    });

    var buf = try self.base.allocator.alloc(u8, needed_size);
    defer self.base.allocator.free(buf);
    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();

    stubs.reserved1 = 0;
    for (self.stubs.items) |id| {
        try writer.writeIntLittle(u32, dysymtab.iundefsym + id);
    }

    got.reserved1 = nstubs;
    for (self.got_entries.items) |entry| {
        switch (entry.where) {
            .import => {
                try writer.writeIntLittle(u32, dysymtab.iundefsym + entry.where_index);
            },
            .local => {
                try writer.writeIntLittle(u32, macho.INDIRECT_SYMBOL_LOCAL);
            },
        }
    }

    la_symbol_ptr.reserved1 = got.reserved1 + ngot_entries;
    for (self.stubs.items) |id| {
        try writer.writeIntLittle(u32, dysymtab.iundefsym + id);
    }

    try self.base.file.?.pwriteAll(buf, dysymtab.indirectsymoff);
    self.load_commands_dirty = true;
}

fn writeDices(self: *MachO) !void {
    if (!self.has_dices) return;

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dice_cmd = &self.load_commands.items[self.data_in_code_cmd_index.?].LinkeditData;
    const fileoff = seg.inner.fileoff + seg.inner.filesize;

    var buf = std.ArrayList(u8).init(self.base.allocator);
    defer buf.deinit();

    var block: *TextBlock = self.blocks.get(.{
        .seg = self.text_segment_cmd_index orelse return,
        .sect = self.text_section_index orelse return,
    }) orelse return;

    while (block.prev) |prev| {
        block = prev;
    }

    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const text_sect = text_seg.sections.items[self.text_section_index.?];

    while (true) {
        if (block.dices.items.len > 0) {
            const sym = self.locals.items[block.local_sym_index];
            const base_off = try math.cast(u32, sym.n_value - text_sect.addr + text_sect.offset);

            try buf.ensureUnusedCapacity(block.dices.items.len * @sizeOf(macho.data_in_code_entry));
            for (block.dices.items) |dice| {
                const rebased_dice = macho.data_in_code_entry{
                    .offset = base_off + dice.offset,
                    .length = dice.length,
                    .kind = dice.kind,
                };
                buf.appendSliceAssumeCapacity(mem.asBytes(&rebased_dice));
            }
        }

        if (block.next) |next| {
            block = next;
        } else break;
    }

    const datasize = @intCast(u32, buf.items.len);

    dice_cmd.dataoff = @intCast(u32, fileoff);
    dice_cmd.datasize = datasize;
    seg.inner.filesize += datasize;

    log.debug("writing data-in-code from 0x{x} to 0x{x}", .{ fileoff, fileoff + datasize });

    try self.base.file.?.pwriteAll(buf.items, fileoff);
}

fn writeCodeSignaturePadding(self: *MachO) !void {
    // TODO figure out how not to rewrite padding every single time.
    const tracy = trace(@src());
    defer tracy.end();

    const linkedit_segment = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const code_sig_cmd = &self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;
    const fileoff = linkedit_segment.inner.fileoff + linkedit_segment.inner.filesize;
    const needed_size = CodeSignature.calcCodeSignaturePaddingSize(
        self.base.options.emit.?.sub_path,
        fileoff,
        self.page_size,
    );
    code_sig_cmd.dataoff = @intCast(u32, fileoff);
    code_sig_cmd.datasize = needed_size;

    // Advance size of __LINKEDIT segment
    linkedit_segment.inner.filesize += needed_size;
    if (linkedit_segment.inner.vmsize < linkedit_segment.inner.filesize) {
        linkedit_segment.inner.vmsize = mem.alignForwardGeneric(u64, linkedit_segment.inner.filesize, self.page_size);
    }
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ fileoff, fileoff + needed_size });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.base.file.?.pwriteAll(&[_]u8{0}, fileoff + needed_size - 1);
    self.load_commands_dirty = true;
}

fn writeCodeSignature(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const code_sig_cmd = self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;

    var code_sig = CodeSignature.init(self.base.allocator, self.page_size);
    defer code_sig.deinit();
    try code_sig.calcAdhocSignature(
        self.base.file.?,
        self.base.options.emit.?.sub_path,
        text_segment.inner,
        code_sig_cmd,
        self.base.options.output_mode,
    );

    var buffer = try self.base.allocator.alloc(u8, code_sig.size());
    defer self.base.allocator.free(buffer);
    var stream = std.io.fixedBufferStream(buffer);
    try code_sig.write(stream.writer());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{ code_sig_cmd.dataoff, code_sig_cmd.dataoff + buffer.len });

    try self.base.file.?.pwriteAll(buffer, code_sig_cmd.dataoff);
}

fn writeExportInfo(self: *MachO) !void {
    if (!self.export_info_dirty) return;
    if (self.globals.items.len == 0) return;

    const tracy = trace(@src());
    defer tracy.end();

    var trie = Trie.init(self.base.allocator);
    defer trie.deinit();

    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const base_address = text_segment.inner.vmaddr;

    // TODO handle macho.EXPORT_SYMBOL_FLAGS_REEXPORT and macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER.
    log.debug("writing export trie", .{});

    for (self.globals.items) |sym| {
        const sym_name = self.getString(sym.n_strx);
        log.debug("  | putting '{s}' defined at 0x{x}", .{ sym_name, sym.n_value });

        try trie.put(.{
            .name = sym_name,
            .vmaddr_offset = sym.n_value - base_address,
            .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }

    try trie.finalize();
    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, trie.size));
    defer self.base.allocator.free(buffer);
    var stream = std.io.fixedBufferStream(buffer);
    const nwritten = try trie.write(stream.writer());
    assert(nwritten == trie.size);

    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    const allocated_size = self.allocatedSizeLinkedit(dyld_info.export_off);
    const needed_size = mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64));

    if (needed_size > allocated_size) {
        dyld_info.export_off = 0;
        dyld_info.export_off = @intCast(u32, self.findFreeSpaceLinkedit(needed_size, 1, null));
        // TODO this might require relocating all following LC_DYLD_INFO_ONLY sections too.
    }
    dyld_info.export_size = @intCast(u32, needed_size);
    log.debug("writing export info from 0x{x} to 0x{x}", .{ dyld_info.export_off, dyld_info.export_off + dyld_info.export_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.export_off);
    self.load_commands_dirty = true;
    self.export_info_dirty = false;
}

fn writeRebaseInfoTable(self: *MachO) !void {
    if (!self.rebase_info_dirty) return;

    const tracy = trace(@src());
    defer tracy.end();

    var pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer pointers.deinit();

    {
        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            const match = entry.key_ptr.*;
            var block: *TextBlock = entry.value_ptr.*;

            if (match.seg == self.text_segment_cmd_index.?) continue; // __TEXT is non-writable

            const seg = self.load_commands.items[match.seg].Segment;

            while (true) {
                const sym = self.locals.items[block.local_sym_index];
                const base_offset = sym.n_value - seg.inner.vmaddr;

                for (block.rebases.items) |offset| {
                    try pointers.append(.{
                        .offset = base_offset + offset,
                        .segment_id = match.seg,
                    });
                }

                if (block.prev) |prev| {
                    block = prev;
                } else break;
            }
        }
    }

    if (self.got_section_index) |idx| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_const_segment_cmd_index.?);

        for (self.got_entries.items) |entry, i| {
            if (entry.where == .import) continue;

            try pointers.append(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
            });
        }
    }

    if (self.la_symbol_ptr_section_index) |idx| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_segment_cmd_index.?);

        try pointers.ensureUnusedCapacity(self.stubs.items.len);
        for (self.stubs.items) |_, i| {
            pointers.appendAssumeCapacity(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
            });
        }
    }

    std.sort.sort(bind.Pointer, pointers.items, {}, bind.pointerCmp);

    const size = try bind.rebaseInfoSize(pointers.items);
    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, size));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try bind.writeRebaseInfo(pointers.items, stream.writer());

    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    const allocated_size = self.allocatedSizeLinkedit(dyld_info.rebase_off);
    const needed_size = mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64));

    if (needed_size > allocated_size) {
        dyld_info.rebase_off = 0;
        dyld_info.rebase_off = @intCast(u32, self.findFreeSpaceLinkedit(needed_size, 1, null));
        // TODO this might require relocating all following LC_DYLD_INFO_ONLY sections too.
    }

    dyld_info.rebase_size = @intCast(u32, needed_size);
    log.debug("writing rebase info from 0x{x} to 0x{x}", .{ dyld_info.rebase_off, dyld_info.rebase_off + dyld_info.rebase_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.rebase_off);
    self.load_commands_dirty = true;
    self.rebase_info_dirty = false;
}

fn writeBindInfoTable(self: *MachO) !void {
    if (!self.binding_info_dirty) return;

    const tracy = trace(@src());
    defer tracy.end();

    var pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer pointers.deinit();

    if (self.got_section_index) |idx| {
        const seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_const_segment_cmd_index.?);

        for (self.got_entries.items) |entry, i| {
            if (entry.where == .local) continue;

            const sym = self.imports.items[entry.where_index];
            try pointers.append(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
                .dylib_ordinal = unpackDylibOrdinal(sym.n_desc),
                .name = self.getString(sym.n_strx),
            });
        }
    }

    {
        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            const match = entry.key_ptr.*;
            var block: *TextBlock = entry.value_ptr.*;

            if (match.seg == self.text_segment_cmd_index.?) continue; // __TEXT is non-writable

            const seg = self.load_commands.items[match.seg].Segment;

            while (true) {
                const sym = self.locals.items[block.local_sym_index];
                const base_offset = sym.n_value - seg.inner.vmaddr;

                for (block.bindings.items) |binding| {
                    const bind_sym = self.imports.items[binding.local_sym_index];
                    try pointers.append(.{
                        .offset = binding.offset + base_offset,
                        .segment_id = match.seg,
                        .dylib_ordinal = unpackDylibOrdinal(bind_sym.n_desc),
                        .name = self.getString(bind_sym.n_strx),
                    });
                }

                if (block.prev) |prev| {
                    block = prev;
                } else break;
            }
        }
    }

    const size = try bind.bindInfoSize(pointers.items);
    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, size));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try bind.writeBindInfo(pointers.items, stream.writer());

    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    const allocated_size = self.allocatedSizeLinkedit(dyld_info.bind_off);
    const needed_size = mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64));

    if (needed_size > allocated_size) {
        dyld_info.bind_off = 0;
        dyld_info.bind_off = @intCast(u32, self.findFreeSpaceLinkedit(needed_size, 1, null));
        // TODO this might require relocating all following LC_DYLD_INFO_ONLY sections too.
    }

    dyld_info.bind_size = @intCast(u32, needed_size);
    log.debug("writing binding info from 0x{x} to 0x{x}", .{ dyld_info.bind_off, dyld_info.bind_off + dyld_info.bind_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.bind_off);
    self.load_commands_dirty = true;
    self.binding_info_dirty = false;
}

fn writeLazyBindInfoTable(self: *MachO) !void {
    if (!self.lazy_binding_info_dirty) return;

    const tracy = trace(@src());
    defer tracy.end();

    var pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer pointers.deinit();

    if (self.la_symbol_ptr_section_index) |idx| {
        const seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = seg.sections.items[idx];
        const base_offset = sect.addr - seg.inner.vmaddr;
        const segment_id = @intCast(u16, self.data_segment_cmd_index.?);

        try pointers.ensureUnusedCapacity(self.stubs.items.len);

        for (self.stubs.items) |import_id, i| {
            const sym = self.imports.items[import_id];
            pointers.appendAssumeCapacity(.{
                .offset = base_offset + i * @sizeOf(u64),
                .segment_id = segment_id,
                .dylib_ordinal = unpackDylibOrdinal(sym.n_desc),
                .name = self.getString(sym.n_strx),
            });
        }
    }

    const size = try bind.lazyBindInfoSize(pointers.items);
    var buffer = try self.base.allocator.alloc(u8, @intCast(usize, size));
    defer self.base.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try bind.writeLazyBindInfo(pointers.items, stream.writer());

    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    const allocated_size = self.allocatedSizeLinkedit(dyld_info.lazy_bind_off);
    const needed_size = mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64));

    if (needed_size > allocated_size) {
        dyld_info.lazy_bind_off = 0;
        dyld_info.lazy_bind_off = @intCast(u32, self.findFreeSpaceLinkedit(needed_size, 1, null));
        // TODO this might require relocating all following LC_DYLD_INFO_ONLY sections too.
    }

    dyld_info.lazy_bind_size = @intCast(u32, needed_size);
    log.debug("writing lazy binding info from 0x{x} to 0x{x}", .{ dyld_info.lazy_bind_off, dyld_info.lazy_bind_off + dyld_info.lazy_bind_size });

    try self.base.file.?.pwriteAll(buffer, dyld_info.lazy_bind_off);
    try self.populateLazyBindOffsetsInStubHelper(buffer);
    self.load_commands_dirty = true;
    self.lazy_binding_info_dirty = false;
}

fn populateLazyBindOffsetsInStubHelper(self: *MachO, buffer: []const u8) !void {
    if (self.stubs.items.len == 0) return;

    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    var offsets = std.ArrayList(u32).init(self.base.allocator);
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
                _ = try std.leb.readULEB128(u64, reader);
            },
            macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                _ = try std.leb.readULEB128(u64, reader);
            },
            macho.BIND_OPCODE_SET_ADDEND_SLEB => {
                _ = try std.leb.readILEB128(i64, reader);
            },
            else => {},
        }
    }
    assert(self.stubs.items.len <= offsets.items.len);

    const stub_size: u4 = switch (self.base.options.target.cpu.arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const off: u4 = switch (self.base.options.target.cpu.arch) {
        .x86_64 => 1,
        .aarch64 => 2 * @sizeOf(u32),
        else => unreachable,
    };
    var buf: [@sizeOf(u32)]u8 = undefined;
    for (self.stubs.items) |_, index| {
        const placeholder_off = self.stub_helper_stubs_start_off.? + index * stub_size + off;
        mem.writeIntLittle(u32, &buf, offsets.items[index]);
        try self.base.file.?.pwriteAll(&buf, placeholder_off);
    }
}

fn writeStringTable(self: *MachO) !void {
    if (!self.strtab_dirty) return;

    const tracy = trace(@src());
    defer tracy.end();

    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    const allocated_size = self.allocatedSizeLinkedit(symtab.stroff);
    const needed_size = mem.alignForwardGeneric(u64, self.strtab.items.len, @alignOf(u64));

    if (needed_size > allocated_size or self.strtab_needs_relocation) {
        symtab.strsize = 0;
        symtab.stroff = @intCast(u32, self.findFreeSpaceLinkedit(needed_size, 1, symtab.symoff));
        self.strtab_needs_relocation = false;
    }
    symtab.strsize = @intCast(u32, needed_size);
    log.debug("writing string table from 0x{x} to 0x{x}", .{ symtab.stroff, symtab.stroff + symtab.strsize });

    try self.base.file.?.pwriteAll(self.strtab.items, symtab.stroff);
    self.load_commands_dirty = true;
    self.strtab_dirty = false;
}

fn writeStringTableZld(self: *MachO) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    symtab.stroff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    symtab.strsize = @intCast(u32, mem.alignForwardGeneric(u64, self.strtab.items.len, @alignOf(u64)));
    seg.inner.filesize += symtab.strsize;

    log.debug("writing string table from 0x{x} to 0x{x}", .{ symtab.stroff, symtab.stroff + symtab.strsize });

    try self.base.file.?.pwriteAll(self.strtab.items, symtab.stroff);

    if (symtab.strsize > self.strtab.items.len and self.base.options.target.cpu.arch == .x86_64) {
        // This is the last section, so we need to pad it out.
        try self.base.file.?.pwriteAll(&[_]u8{0}, seg.inner.fileoff + seg.inner.filesize - 1);
    }
}

fn updateLinkeditSegmentSizes(self: *MachO) !void {
    if (!self.load_commands_dirty) return;

    const tracy = trace(@src());
    defer tracy.end();

    // Now, we are in position to update __LINKEDIT segment sizes.
    // TODO Add checkpointing so that we don't have to do this every single time.
    const linkedit_segment = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    var final_offset = linkedit_segment.inner.fileoff;

    if (self.dyld_info_cmd_index) |idx| {
        const dyld_info = self.load_commands.items[idx].DyldInfoOnly;
        final_offset = std.math.max(final_offset, dyld_info.rebase_off + dyld_info.rebase_size);
        final_offset = std.math.max(final_offset, dyld_info.bind_off + dyld_info.bind_size);
        final_offset = std.math.max(final_offset, dyld_info.weak_bind_off + dyld_info.weak_bind_size);
        final_offset = std.math.max(final_offset, dyld_info.lazy_bind_off + dyld_info.lazy_bind_size);
        final_offset = std.math.max(final_offset, dyld_info.export_off + dyld_info.export_size);
    }
    if (self.function_starts_cmd_index) |idx| {
        const fstart = self.load_commands.items[idx].LinkeditData;
        final_offset = std.math.max(final_offset, fstart.dataoff + fstart.datasize);
    }
    if (self.data_in_code_cmd_index) |idx| {
        const dic = self.load_commands.items[idx].LinkeditData;
        final_offset = std.math.max(final_offset, dic.dataoff + dic.datasize);
    }
    if (self.dysymtab_cmd_index) |idx| {
        const dysymtab = self.load_commands.items[idx].Dysymtab;
        const nindirectsize = dysymtab.nindirectsyms * @sizeOf(u32);
        final_offset = std.math.max(final_offset, dysymtab.indirectsymoff + nindirectsize);
        // TODO Handle more dynamic symbol table sections.
    }
    if (self.symtab_cmd_index) |idx| {
        const symtab = self.load_commands.items[idx].Symtab;
        const symsize = symtab.nsyms * @sizeOf(macho.nlist_64);
        final_offset = std.math.max(final_offset, symtab.symoff + symsize);
        final_offset = std.math.max(final_offset, symtab.stroff + symtab.strsize);
    }

    const filesize = final_offset - linkedit_segment.inner.fileoff;
    linkedit_segment.inner.filesize = filesize;
    linkedit_segment.inner.vmsize = mem.alignForwardGeneric(u64, filesize, self.page_size);
    try self.base.file.?.pwriteAll(&[_]u8{0}, final_offset);
    self.load_commands_dirty = true;
}

/// Writes all load commands and section headers.
fn writeLoadCommands(self: *MachO) !void {
    if (!self.load_commands_dirty) return;

    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    var buffer = try self.base.allocator.alloc(u8, sizeofcmds);
    defer self.base.allocator.free(buffer);
    var writer = std.io.fixedBufferStream(buffer).writer();
    for (self.load_commands.items) |lc| {
        try lc.write(writer);
    }

    const off = @sizeOf(macho.mach_header_64);

    log.debug("writing {} load commands from 0x{x} to 0x{x}", .{ self.load_commands.items.len, off, off + sizeofcmds });

    try self.base.file.?.pwriteAll(buffer, off);
    self.load_commands_dirty = false;
}

/// Writes Mach-O file header.
fn writeHeader(self: *MachO) !void {
    var header = commands.emptyHeader(.{
        .flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK | macho.MH_PIE | macho.MH_TWOLEVEL,
    });

    switch (self.base.options.target.cpu.arch) {
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

    switch (self.base.options.output_mode) {
        .Exe => {
            header.filetype = macho.MH_EXECUTE;
        },
        .Lib => {
            // By this point, it can only be a dylib.
            header.filetype = macho.MH_DYLIB;
            header.flags |= macho.MH_NO_REEXPORTED_DYLIBS;
        },
        else => unreachable,
    }

    if (self.tlv_section_index) |_| {
        header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;
    }

    header.ncmds = @intCast(u32, self.load_commands.items.len);
    header.sizeofcmds = 0;

    for (self.load_commands.items) |cmd| {
        header.sizeofcmds += cmd.cmdsize();
    }

    log.debug("writing Mach-O header {}", .{header});

    try self.base.file.?.pwriteAll(mem.asBytes(&header), 0);
}

pub fn padToIdeal(actual_size: anytype) @TypeOf(actual_size) {
    // TODO https://github.com/ziglang/zig/issues/1284
    return std.math.add(@TypeOf(actual_size), actual_size, actual_size / ideal_factor) catch
        std.math.maxInt(@TypeOf(actual_size));
}

pub fn makeString(self: *MachO, string: []const u8) !u32 {
    try self.strtab.ensureUnusedCapacity(self.base.allocator, string.len + 1);
    const new_off = @intCast(u32, self.strtab.items.len);

    log.debug("writing new string '{s}' at offset 0x{x}", .{ string, new_off });

    self.strtab.appendSliceAssumeCapacity(string);
    self.strtab.appendAssumeCapacity(0);

    return new_off;
}

pub fn getString(self: *MachO, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.strtab.items.ptr + off));
}

pub fn symbolIsStab(sym: macho.nlist_64) bool {
    return (macho.N_STAB & sym.n_type) != 0;
}

pub fn symbolIsPext(sym: macho.nlist_64) bool {
    return (macho.N_PEXT & sym.n_type) != 0;
}

pub fn symbolIsExt(sym: macho.nlist_64) bool {
    return (macho.N_EXT & sym.n_type) != 0;
}

pub fn symbolIsSect(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_SECT;
}

pub fn symbolIsUndf(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_UNDF;
}

pub fn symbolIsIndr(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_INDR;
}

pub fn symbolIsAbs(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_ABS;
}

pub fn symbolIsWeakDef(sym: macho.nlist_64) bool {
    return (sym.n_desc & macho.N_WEAK_DEF) != 0;
}

pub fn symbolIsWeakRef(sym: macho.nlist_64) bool {
    return (sym.n_desc & macho.N_WEAK_REF) != 0;
}

pub fn symbolIsTentative(sym: macho.nlist_64) bool {
    if (!symbolIsUndf(sym)) return false;
    return sym.n_value != 0;
}

pub fn symbolIsNull(sym: macho.nlist_64) bool {
    return sym.n_value == 0 and sym.n_desc == 0 and sym.n_type == 0 and sym.n_strx == 0 and sym.n_sect == 0;
}

pub fn symbolIsTemp(sym: macho.nlist_64, sym_name: []const u8) bool {
    if (!symbolIsSect(sym)) return false;
    if (symbolIsExt(sym)) return false;
    return mem.startsWith(u8, sym_name, "l") or mem.startsWith(u8, sym_name, "L");
}

pub fn sectionId(self: MachO, match: MatchingSection) u8 {
    // TODO there might be a more generic way of doing this.
    var section: u8 = 0;
    for (self.load_commands.items) |cmd, cmd_id| {
        if (cmd != .Segment) break;
        if (cmd_id == match.seg) {
            section += @intCast(u8, match.sect) + 1;
            break;
        }
        section += @intCast(u8, cmd.Segment.sections.items.len);
    }
    return section;
}

pub fn unpackSectionId(self: MachO, section_id: u8) MatchingSection {
    var match: MatchingSection = undefined;
    var section: u8 = 0;
    outer: for (self.load_commands.items) |cmd, cmd_id| {
        assert(cmd == .Segment);
        for (cmd.Segment.sections.items) |_, sect_id| {
            section += 1;
            if (section_id == section) {
                match.seg = @intCast(u16, cmd_id);
                match.sect = @intCast(u16, sect_id);
                break :outer;
            }
        }
    }
    return match;
}

fn packDylibOrdinal(ordinal: u16) u16 {
    return ordinal * macho.N_SYMBOL_RESOLVER;
}

fn unpackDylibOrdinal(pack: u16) u16 {
    return @divExact(pack, macho.N_SYMBOL_RESOLVER);
}

pub fn findFirst(comptime T: type, haystack: []T, start: usize, predicate: anytype) usize {
    if (!@hasDecl(@TypeOf(predicate), "predicate"))
        @compileError("Predicate is required to define fn predicate(@This(), T) bool");

    if (start == haystack.len) return start;

    var i = start;
    while (i < haystack.len) : (i += 1) {
        if (predicate.predicate(haystack[i])) break;
    }
    return i;
}
