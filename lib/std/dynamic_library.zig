// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const builtin = @import("builtin");

const std = @import("std.zig");
const mem = std.mem;
const os = std.os;
const assert = std.debug.assert;
const testing = std.testing;
const elf = std.elf;
const windows = std.os.windows;
const system = std.os.system;
const maxInt = std.math.maxInt;
const max = std.math.max;

pub const DynLib = switch (builtin.os.tag) {
    .linux => if (builtin.link_libc) DlDynlib else ElfDynLib,
    .windows => WindowsDynLib,
    .macos, .tvos, .watchos, .ios, .freebsd, .netbsd, .openbsd, .dragonfly => DlDynlib,
    else => void,
};

// The link_map structure is not completely specified beside the fields
// reported below, any libc is free to store additional data in the remaining
// space.
// An iterator is provided in order to traverse the linked list in a idiomatic
// fashion.
const LinkMap = extern struct {
    l_addr: usize,
    l_name: [*:0]const u8,
    l_ld: ?*elf.Dyn,
    l_next: ?*LinkMap,
    l_prev: ?*LinkMap,

    pub const Iterator = struct {
        current: ?*LinkMap,

        pub fn end(self: *Iterator) bool {
            return self.current == null;
        }

        pub fn next(self: *Iterator) ?*LinkMap {
            if (self.current) |it| {
                self.current = it.l_next;
                return it;
            }
            return null;
        }
    };
};

const RDebug = extern struct {
    r_version: i32,
    r_map: ?*LinkMap,
    r_brk: usize,
    r_ldbase: usize,
};

/// TODO make it possible to reference this same external symbol 2x so we don't need this
/// helper function.
pub fn get_DYNAMIC() ?[*]elf.Dyn {
    return @extern([*]elf.Dyn, .{ .name = "_DYNAMIC", .linkage = .Weak });
}

pub fn linkmap_iterator(phdrs: []elf.Phdr) !LinkMap.Iterator {
    _ = phdrs;
    const _DYNAMIC = get_DYNAMIC() orelse {
        // No PT_DYNAMIC means this is either a statically-linked program or a
        // badly corrupted dynamically-linked one.
        return LinkMap.Iterator{ .current = null };
    };

    const link_map_ptr = init: {
        var i: usize = 0;
        while (_DYNAMIC[i].d_tag != elf.DT_NULL) : (i += 1) {
            switch (_DYNAMIC[i].d_tag) {
                elf.DT_DEBUG => {
                    const ptr = @intToPtr(?*RDebug, _DYNAMIC[i].d_val);
                    if (ptr) |r_debug| {
                        if (r_debug.r_version != 1) return error.InvalidExe;
                        break :init r_debug.r_map;
                    }
                },
                elf.DT_PLTGOT => {
                    const ptr = @intToPtr(?[*]usize, _DYNAMIC[i].d_val);
                    if (ptr) |got_table| {
                        // The address to the link_map structure is stored in
                        // the second slot
                        break :init @intToPtr(?*LinkMap, got_table[1]);
                    }
                },
                else => {},
            }
        }
        return LinkMap.Iterator{ .current = null };
    };

    return LinkMap.Iterator{ .current = link_map_ptr };
}

pub const ElfDynLib = struct {
    strings: [*:0]u8,
    syms: [*]elf.Sym,
    hashtab: [*]os.Elf_Symndx,
    versym: ?[*]u16,
    verdef: ?*elf.Verdef,
    memory: []align(mem.page_size) u8,

    pub const Error = error{
        NotElfFile,
        NotDynamicLibrary,
        MissingDynamicLinkingInformation,
        ElfStringSectionNotFound,
        ElfSymSectionNotFound,
        ElfHashTableNotFound,
    };

    /// Trusts the file. Malicious file will be able to execute arbitrary code.
    pub fn open(path: []const u8) !ElfDynLib {
        const fd = try os.open(path, 0, os.O_RDONLY | os.O_CLOEXEC);
        defer os.close(fd);

        const stat = try os.fstat(fd);
        const size = try std.math.cast(usize, stat.size);

        // This one is to read the ELF info. We do more mmapping later
        // corresponding to the actual LOAD sections.
        const file_bytes = try os.mmap(
            null,
            mem.alignForward(size, mem.page_size),
            os.PROT_READ,
            os.MAP_PRIVATE,
            fd,
            0,
        );
        defer os.munmap(file_bytes);

        const eh = @ptrCast(*elf.Ehdr, file_bytes.ptr);
        if (!mem.eql(u8, eh.e_ident[0..4], "\x7fELF")) return error.NotElfFile;
        if (eh.e_type != elf.ET.DYN) return error.NotDynamicLibrary;

        const elf_addr = @ptrToInt(file_bytes.ptr);

        // Iterate over the program header entries to find out the
        // dynamic vector as well as the total size of the virtual memory.
        var maybe_dynv: ?[*]usize = null;
        var virt_addr_end: usize = 0;
        {
            var i: usize = 0;
            var ph_addr: usize = elf_addr + eh.e_phoff;
            while (i < eh.e_phnum) : ({
                i += 1;
                ph_addr += eh.e_phentsize;
            }) {
                const ph = @intToPtr(*elf.Phdr, ph_addr);
                switch (ph.p_type) {
                    elf.PT_LOAD => virt_addr_end = max(virt_addr_end, ph.p_vaddr + ph.p_memsz),
                    elf.PT_DYNAMIC => maybe_dynv = @intToPtr([*]usize, elf_addr + ph.p_offset),
                    else => {},
                }
            }
        }
        const dynv = maybe_dynv orelse return error.MissingDynamicLinkingInformation;

        // Reserve the entire range (with no permissions) so that we can do MAP_FIXED below.
        const all_loaded_mem = try os.mmap(
            null,
            virt_addr_end,
            os.PROT_NONE,
            os.MAP_PRIVATE | os.MAP_ANONYMOUS,
            -1,
            0,
        );
        errdefer os.munmap(all_loaded_mem);

        const base = @ptrToInt(all_loaded_mem.ptr);

        // Now iterate again and actually load all the program sections.
        {
            var i: usize = 0;
            var ph_addr: usize = elf_addr + eh.e_phoff;
            while (i < eh.e_phnum) : ({
                i += 1;
                ph_addr += eh.e_phentsize;
            }) {
                const ph = @intToPtr(*elf.Phdr, ph_addr);
                switch (ph.p_type) {
                    elf.PT_LOAD => {
                        // The VirtAddr may not be page-aligned; in such case there will be
                        // extra nonsense mapped before/after the VirtAddr,MemSiz
                        const aligned_addr = (base + ph.p_vaddr) & ~(@as(usize, mem.page_size) - 1);
                        const extra_bytes = (base + ph.p_vaddr) - aligned_addr;
                        const extended_memsz = mem.alignForward(ph.p_memsz + extra_bytes, mem.page_size);
                        const ptr = @intToPtr([*]align(mem.page_size) u8, aligned_addr);
                        const prot = elfToMmapProt(ph.p_flags);
                        if ((ph.p_flags & elf.PF_W) == 0) {
                            // If it does not need write access, it can be mapped from the fd.
                            _ = try os.mmap(
                                ptr,
                                extended_memsz,
                                prot,
                                os.MAP_PRIVATE | os.MAP_FIXED,
                                fd,
                                ph.p_offset - extra_bytes,
                            );
                        } else {
                            const sect_mem = try os.mmap(
                                ptr,
                                extended_memsz,
                                prot,
                                os.MAP_PRIVATE | os.MAP_FIXED | os.MAP_ANONYMOUS,
                                -1,
                                0,
                            );
                            mem.copy(u8, sect_mem, file_bytes[0..ph.p_filesz]);
                        }
                    },
                    else => {},
                }
            }
        }

        var maybe_strings: ?[*:0]u8 = null;
        var maybe_syms: ?[*]elf.Sym = null;
        var maybe_hashtab: ?[*]os.Elf_Symndx = null;
        var maybe_versym: ?[*]u16 = null;
        var maybe_verdef: ?*elf.Verdef = null;

        {
            var i: usize = 0;
            while (dynv[i] != 0) : (i += 2) {
                const p = base + dynv[i + 1];
                switch (dynv[i]) {
                    elf.DT_STRTAB => maybe_strings = @intToPtr([*:0]u8, p),
                    elf.DT_SYMTAB => maybe_syms = @intToPtr([*]elf.Sym, p),
                    elf.DT_HASH => maybe_hashtab = @intToPtr([*]os.Elf_Symndx, p),
                    elf.DT_VERSYM => maybe_versym = @intToPtr([*]u16, p),
                    elf.DT_VERDEF => maybe_verdef = @intToPtr(*elf.Verdef, p),
                    else => {},
                }
            }
        }

        return ElfDynLib{
            .memory = all_loaded_mem,
            .strings = maybe_strings orelse return error.ElfStringSectionNotFound,
            .syms = maybe_syms orelse return error.ElfSymSectionNotFound,
            .hashtab = maybe_hashtab orelse return error.ElfHashTableNotFound,
            .versym = maybe_versym,
            .verdef = maybe_verdef,
        };
    }

    pub const openC = @compileError("deprecated: renamed to openZ");

    /// Trusts the file. Malicious file will be able to execute arbitrary code.
    pub fn openZ(path_c: [*:0]const u8) !ElfDynLib {
        return open(mem.spanZ(path_c));
    }

    /// Trusts the file
    pub fn close(self: *ElfDynLib) void {
        os.munmap(self.memory);
        self.* = undefined;
    }

    pub fn lookup(self: *ElfDynLib, comptime T: type, name: [:0]const u8) ?T {
        if (self.lookupAddress("", name)) |symbol| {
            return @intToPtr(T, symbol);
        } else {
            return null;
        }
    }

    /// Returns the address of the symbol
    pub fn lookupAddress(self: *const ElfDynLib, vername: []const u8, name: []const u8) ?usize {
        const maybe_versym = if (self.verdef == null) null else self.versym;

        const OK_TYPES = (1 << elf.STT_NOTYPE | 1 << elf.STT_OBJECT | 1 << elf.STT_FUNC | 1 << elf.STT_COMMON);
        const OK_BINDS = (1 << elf.STB_GLOBAL | 1 << elf.STB_WEAK | 1 << elf.STB_GNU_UNIQUE);

        var i: usize = 0;
        while (i < self.hashtab[1]) : (i += 1) {
            if (0 == (@as(u32, 1) << @intCast(u5, self.syms[i].st_info & 0xf) & OK_TYPES)) continue;
            if (0 == (@as(u32, 1) << @intCast(u5, self.syms[i].st_info >> 4) & OK_BINDS)) continue;
            if (0 == self.syms[i].st_shndx) continue;
            if (!mem.eql(u8, name, mem.spanZ(self.strings + self.syms[i].st_name))) continue;
            if (maybe_versym) |versym| {
                if (!checkver(self.verdef.?, versym[i], vername, self.strings))
                    continue;
            }
            return @ptrToInt(self.memory.ptr) + self.syms[i].st_value;
        }

        return null;
    }

    fn elfToMmapProt(elf_prot: u64) u32 {
        var result: u32 = os.PROT_NONE;
        if ((elf_prot & elf.PF_R) != 0) result |= os.PROT_READ;
        if ((elf_prot & elf.PF_W) != 0) result |= os.PROT_WRITE;
        if ((elf_prot & elf.PF_X) != 0) result |= os.PROT_EXEC;
        return result;
    }
};

fn checkver(def_arg: *elf.Verdef, vsym_arg: i32, vername: []const u8, strings: [*:0]u8) bool {
    var def = def_arg;
    const vsym = @bitCast(u32, vsym_arg) & 0x7fff;
    while (true) {
        if (0 == (def.vd_flags & elf.VER_FLG_BASE) and (def.vd_ndx & 0x7fff) == vsym)
            break;
        if (def.vd_next == 0)
            return false;
        def = @intToPtr(*elf.Verdef, @ptrToInt(def) + def.vd_next);
    }
    const aux = @intToPtr(*elf.Verdaux, @ptrToInt(def) + def.vd_aux);
    return mem.eql(u8, vername, mem.spanZ(strings + aux.vda_name));
}

pub const WindowsDynLib = struct {
    pub const Error = error{FileNotFound};

    dll: windows.HMODULE,

    pub fn open(path: []const u8) !WindowsDynLib {
        const path_w = try windows.sliceToPrefixedFileW(path);
        return openW(path_w.span().ptr);
    }

    pub const openC = @compileError("deprecated: renamed to openZ");

    pub fn openZ(path_c: [*:0]const u8) !WindowsDynLib {
        const path_w = try windows.cStrToPrefixedFileW(path_c);
        return openW(path_w.span().ptr);
    }

    pub fn openW(path_w: [*:0]const u16) !WindowsDynLib {
        var offset: usize = 0;
        if (path_w[0] == '\\' and path_w[1] == '?' and path_w[2] == '?' and path_w[3] == '\\') {
            // + 4 to skip over the \??\
            offset = 4;
        }

        return WindowsDynLib{
            .dll = try windows.LoadLibraryW(path_w + offset),
        };
    }

    pub fn close(self: *WindowsDynLib) void {
        windows.FreeLibrary(self.dll);
        self.* = undefined;
    }

    pub fn lookup(self: *WindowsDynLib, comptime T: type, name: [:0]const u8) ?T {
        if (windows.kernel32.GetProcAddress(self.dll, name.ptr)) |addr| {
            return @ptrCast(T, addr);
        } else {
            return null;
        }
    }
};

pub const DlDynlib = struct {
    pub const Error = error{FileNotFound};

    handle: *c_void,

    pub fn open(path: []const u8) !DlDynlib {
        const path_c = try os.toPosixPath(path);
        return openZ(&path_c);
    }

    pub const openC = @compileError("deprecated: renamed to openZ");

    pub fn openZ(path_c: [*:0]const u8) !DlDynlib {
        return DlDynlib{
            .handle = system.dlopen(path_c, system.RTLD_LAZY) orelse {
                return error.FileNotFound;
            },
        };
    }

    pub fn close(self: *DlDynlib) void {
        _ = system.dlclose(self.handle);
        self.* = undefined;
    }

    pub fn lookup(self: *DlDynlib, comptime T: type, name: [:0]const u8) ?T {
        // dlsym (and other dl-functions) secretly take shadow parameter - return address on stack
        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66826
        if (@call(.{ .modifier = .never_tail }, system.dlsym, .{ self.handle, name.ptr })) |symbol| {
            return @ptrCast(T, symbol);
        } else {
            return null;
        }
    }
};

test "dynamic_library" {
    const libname = switch (builtin.os.tag) {
        .linux, .freebsd, .openbsd => "invalid_so.so",
        .windows => "invalid_dll.dll",
        .macos, .tvos, .watchos, .ios => "invalid_dylib.dylib",
        else => return error.SkipZigTest,
    };

    _ = DynLib.open(libname) catch |err| {
        try testing.expect(err == error.FileNotFound);
        return;
    };
}
