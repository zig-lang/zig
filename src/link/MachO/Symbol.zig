const Symbol = @This();

const std = @import("std");
const assert = std.debug.assert;
const commands = @import("commands.zig");
const macho = std.macho;
const mem = std.mem;

const Allocator = mem.Allocator;
const Dylib = @import("Dylib.zig");
const Object = @import("Object.zig");
const StringTable = @import("StringTable.zig");
const Zld = @import("Zld.zig");

/// Symbol name. Owned slice.
name: []const u8,

/// Index in GOT table for indirection.
got_index: ?u32 = null,

/// Index in stubs table for late binding.
stubs_index: ?u32 = null,

payload: union(enum) {
    regular: Regular,
    tentative: Tentative,
    proxy: Proxy,
    undef: Undefined,

    pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        return switch (self) {
            .regular => |p| p.format(fmt, options, writer),
            .tentative => |p| p.format(fmt, options, writer),
            .proxy => |p| p.format(fmt, options, writer),
            .undef => |p| p.format(fmt, options, writer),
        };
    }
},

pub const Regular = struct {
    /// Linkage type.
    linkage: Linkage,

    /// Symbol address.
    address: u64 = 0,

    /// Segment ID
    segment_id: u16 = 0,

    /// Section ID
    section_id: u16 = 0,

    /// Whether the symbol is a weak ref.
    weak_ref: bool = false,

    /// Object file where to locate this symbol.
    /// null means self-reference.
    file: ?*Object = null,

    local_sym_index: u32 = 0,

    pub const Linkage = enum {
        translation_unit,
        linkage_unit,
        global,
    };

    pub fn format(self: Regular, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "Regular {{ ", .{});
        try std.fmt.format(writer, ".linkage = {s},  ", .{self.linkage});
        try std.fmt.format(writer, ".address = 0x{x}, ", .{self.address});
        try std.fmt.format(writer, ".segment_id = {}, ", .{self.segment_id});
        try std.fmt.format(writer, ".section_id = {}, ", .{self.section_id});
        if (self.weak_ref) {
            try std.fmt.format(writer, ".weak_ref, ", .{});
        }
        if (self.file) |file| {
            try std.fmt.format(writer, ".file = {s}, ", .{file.name.?});
        }
        try std.fmt.format(writer, "}}", .{});
    }

    pub fn sectionId(self: Regular, zld: *Zld) u8 {
        // TODO there might be a more generic way of doing this.
        var section: u8 = 0;
        for (zld.load_commands.items) |cmd, cmd_id| {
            if (cmd != .Segment) break;
            if (cmd_id == self.segment_id) {
                section += @intCast(u8, self.section_id) + 1;
                break;
            }
            section += @intCast(u8, cmd.Segment.sections.items.len);
        }
        return section;
    }
};

pub const Tentative = struct {
    /// Symbol size.
    size: u64,

    /// Symbol alignment as power of two.
    alignment: u16,

    /// File where this symbol was referenced.
    file: ?*Object = null,

    pub fn format(self: Tentative, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "Tentative {{ ", .{});
        try std.fmt.format(writer, ".size = 0x{x},  ", .{self.size});
        try std.fmt.format(writer, ".alignment = 0x{x}, ", .{self.alignment});
        if (self.file) |file| {
            try std.fmt.format(writer, ".file = {s}, ", .{file.name.?});
        }
        try std.fmt.format(writer, "}}", .{});
    }
};

pub const Proxy = struct {
    /// Dynamic binding info - spots within the final
    /// executable where this proxy is referenced from.
    bind_info: std.ArrayListUnmanaged(struct {
        local_sym_index: u32,
        offset: u32,
    }) = .{},

    /// Dylib where to locate this symbol.
    /// null means self-reference.
    file: ?*Dylib = null,

    pub fn deinit(proxy: *Proxy, allocator: *Allocator) void {
        proxy.bind_info.deinit(allocator);
    }

    pub fn dylibOrdinal(proxy: Proxy) u16 {
        const dylib = proxy.file orelse return 0;
        return dylib.ordinal.?;
    }

    pub fn format(self: Proxy, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "Proxy {{ ", .{});
        if (self.bind_info.items.len > 0) {
            // TODO
            try std.fmt.format(writer, ".bind_info = {}, ", .{self.bind_info.items.len});
        }
        if (self.file) |file| {
            try std.fmt.format(writer, ".file = {s}, ", .{file.name.?});
        }
        try std.fmt.format(writer, "}}", .{});
    }
};

pub const Undefined = struct {
    /// File where this symbol was referenced.
    /// null means synthetic, e.g., dyld_stub_binder.
    file: ?*Object = null,

    pub fn format(self: Undefined, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "Undefined {{ ", .{});
        if (self.file) |file| {
            try std.fmt.format(writer, ".file = {s}, ", .{file.name.?});
        }
        try std.fmt.format(writer, "}}", .{});
    }
};

/// Create new undefined symbol.
pub fn new(allocator: *Allocator, name: []const u8) !*Symbol {
    const new_sym = try allocator.create(Symbol);
    errdefer allocator.destroy(new_sym);

    new_sym.* = .{
        .name = try allocator.dupe(u8, name),
        .payload = .{
            .undef = .{},
        },
    };

    return new_sym;
}

pub fn format(self: Symbol, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    try std.fmt.format(writer, "Symbol {{", .{});
    try std.fmt.format(writer, ".name = {s}, ", .{self.name});
    if (self.got_index) |got_index| {
        try std.fmt.format(writer, ".got_index = {}, ", .{got_index});
    }
    if (self.stubs_index) |stubs_index| {
        try std.fmt.format(writer, ".stubs_index = {}, ", .{stubs_index});
    }
    try std.fmt.format(writer, "{}, ", .{self.payload});
    try std.fmt.format(writer, "}}", .{});
}

pub fn isTemp(symbol: Symbol) bool {
    switch (symbol.payload) {
        .regular => |regular| {
            if (regular.linkage == .translation_unit) {
                return mem.startsWith(u8, symbol.name, "l") or mem.startsWith(u8, symbol.name, "L");
            }
        },
        else => {},
    }
    return false;
}

pub fn needsTlvOffset(self: Symbol, zld: *Zld) bool {
    if (self.payload != .regular) return false;

    const reg = self.payload.regular;
    const seg = zld.load_command.items[reg.segment_id].Segment;
    const sect = seg.sections.items[reg.section_id];
    const sect_type = commands.sectionType(sect);

    return sect_type == macho.S_THREAD_LOCAL_VARIABLES;
}

pub fn asNlist(symbol: *Symbol, zld: *Zld, strtab: *StringTable) !macho.nlist_64 {
    const n_strx = try strtab.getOrPut(symbol.name);
    const nlist = nlist: {
        switch (symbol.payload) {
            .regular => |regular| {
                var nlist = macho.nlist_64{
                    .n_strx = n_strx,
                    .n_type = macho.N_SECT,
                    .n_sect = regular.sectionId(zld),
                    .n_desc = 0,
                    .n_value = regular.address,
                };

                if (regular.linkage != .translation_unit) {
                    nlist.n_type |= macho.N_EXT;
                }
                if (regular.linkage == .linkage_unit) {
                    nlist.n_type |= macho.N_PEXT;
                    nlist.n_desc |= macho.N_WEAK_DEF;
                }

                break :nlist nlist;
            },
            .tentative => {
                // TODO
                break :nlist macho.nlist_64{
                    .n_strx = n_strx,
                    .n_type = macho.N_UNDF,
                    .n_sect = 0,
                    .n_desc = 0,
                    .n_value = 0,
                };
            },
            .proxy => |proxy| {
                break :nlist macho.nlist_64{
                    .n_strx = n_strx,
                    .n_type = macho.N_UNDF | macho.N_EXT,
                    .n_sect = 0,
                    .n_desc = (proxy.dylibOrdinal() * macho.N_SYMBOL_RESOLVER) | macho.REFERENCE_FLAG_UNDEFINED_NON_LAZY,
                    .n_value = 0,
                };
            },
            .undef => {
                // TODO
                break :nlist macho.nlist_64{
                    .n_strx = n_strx,
                    .n_type = macho.N_UNDF,
                    .n_sect = 0,
                    .n_desc = 0,
                    .n_value = 0,
                };
            },
        }
    };
    return nlist;
}

pub fn deinit(symbol: *Symbol, allocator: *Allocator) void {
    allocator.free(symbol.name);

    switch (symbol.payload) {
        .proxy => |*proxy| proxy.deinit(allocator),
        else => {},
    }
}

pub fn isStab(sym: macho.nlist_64) bool {
    return (macho.N_STAB & sym.n_type) != 0;
}

pub fn isPext(sym: macho.nlist_64) bool {
    return (macho.N_PEXT & sym.n_type) != 0;
}

pub fn isExt(sym: macho.nlist_64) bool {
    return (macho.N_EXT & sym.n_type) != 0;
}

pub fn isSect(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_SECT;
}

pub fn isUndf(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_UNDF;
}

pub fn isIndr(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_INDR;
}

pub fn isAbs(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_ABS;
}

pub fn isWeakDef(sym: macho.nlist_64) bool {
    return (sym.n_desc & macho.N_WEAK_DEF) != 0;
}

pub fn isWeakRef(sym: macho.nlist_64) bool {
    return (sym.n_desc & macho.N_WEAK_REF) != 0;
}
