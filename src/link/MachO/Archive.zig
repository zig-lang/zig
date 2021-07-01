const Archive = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.archive);
const macho = std.macho;
const mem = std.mem;
const fat = @import("fat.zig");

const Allocator = mem.Allocator;
const Arch = std.Target.Cpu.Arch;
const Object = @import("Object.zig");

usingnamespace @import("commands.zig");

allocator: *Allocator,
arch: ?Arch = null,
file: ?fs.File = null,
header: ?ar_hdr = null,
name: ?[]const u8 = null,

// The actual contents we care about linking with will be embedded at
// an offset within a file if we are linking against a fat lib
library_offset: u64 = 0,

/// Parsed table of contents.
/// Each symbol name points to a list of all definition
/// sites within the current static archive.
toc: std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(u32)) = .{},

// Archive files start with the ARMAG identifying string.  Then follows a
// `struct ar_hdr', and as many bytes of member file data as its `ar_size'
// member indicates, for each member file.
/// String that begins an archive file.
const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
/// Size of that string.
const SARMAG: u4 = 8;

/// String in ar_fmag at the end of each header.
const ARFMAG: *const [2:0]u8 = "`\n";

const ar_hdr = extern struct {
    /// Member file name, sometimes / terminated.
    ar_name: [16]u8,

    /// File date, decimal seconds since Epoch.
    ar_date: [12]u8,

    /// User ID, in ASCII format.
    ar_uid: [6]u8,

    /// Group ID, in ASCII format.
    ar_gid: [6]u8,

    /// File mode, in ASCII octal.
    ar_mode: [8]u8,

    /// File size, in ASCII decimal.
    ar_size: [10]u8,

    /// Always contains ARFMAG.
    ar_fmag: [2]u8,

    const NameOrLength = union(enum) {
        Name: []const u8,
        Length: u32,
    };
    fn nameOrLength(self: ar_hdr) !NameOrLength {
        const value = getValue(&self.ar_name);
        const slash_index = mem.indexOf(u8, value, "/") orelse return error.MalformedArchive;
        const len = value.len;
        if (slash_index == len - 1) {
            // Name stored directly
            return NameOrLength{ .Name = value };
        } else {
            // Name follows the header directly and its length is encoded in
            // the name field.
            const length = try std.fmt.parseInt(u32, value[slash_index + 1 ..], 10);
            return NameOrLength{ .Length = length };
        }
    }

    fn date(self: ar_hdr) !u64 {
        const value = getValue(&self.ar_date);
        return std.fmt.parseInt(u64, value, 10);
    }

    fn size(self: ar_hdr) !u32 {
        const value = getValue(&self.ar_size);
        return std.fmt.parseInt(u32, value, 10);
    }

    fn getValue(raw: []const u8) []const u8 {
        return mem.trimRight(u8, raw, &[_]u8{@as(u8, 0x20)});
    }
};

pub fn createAndParseFromPath(allocator: *Allocator, arch: Arch, path: []const u8) !?*Archive {
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    errdefer file.close();

    const archive = try allocator.create(Archive);
    errdefer allocator.destroy(archive);

    const name = try allocator.dupe(u8, path);
    errdefer allocator.free(name);

    archive.* = .{
        .allocator = allocator,
        .arch = arch,
        .name = name,
        .file = file,
    };

    archive.parse() catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit();
            allocator.destroy(archive);
            return null;
        },
        else => |e| return e,
    };

    return archive;
}

pub fn deinit(self: *Archive) void {
    for (self.toc.keys()) |*key| {
        self.allocator.free(key.*);
    }
    for (self.toc.values()) |*value| {
        value.deinit(self.allocator);
    }
    self.toc.deinit(self.allocator);

    if (self.name) |n| {
        self.allocator.free(n);
    }
}

pub fn closeFile(self: Archive) void {
    if (self.file) |f| {
        f.close();
    }
}

pub fn parse(self: *Archive) !void {
    self.library_offset = try fat.getLibraryOffset(self.file.?.reader(), self.arch.?);

    try self.file.?.seekTo(self.library_offset);

    var reader = self.file.?.reader();
    const magic = try reader.readBytesNoEof(SARMAG);

    if (!mem.eql(u8, &magic, ARMAG)) {
        log.debug("invalid magic: expected '{s}', found '{s}'", .{ ARMAG, magic });
        return error.NotArchive;
    }

    self.header = try reader.readStruct(ar_hdr);

    if (!mem.eql(u8, &self.header.?.ar_fmag, ARFMAG)) {
        log.debug("invalid header delimiter: expected '{s}', found '{s}'", .{ ARFMAG, self.header.?.ar_fmag });
        return error.NotArchive;
    }

    var embedded_name = try parseName(self.allocator, self.header.?, reader);
    log.debug("parsing archive '{s}' at '{s}'", .{ embedded_name, self.name.? });
    defer self.allocator.free(embedded_name);

    try self.parseTableOfContents(reader);

    try reader.context.seekTo(0);
}

fn parseName(allocator: *Allocator, header: ar_hdr, reader: anytype) ![]u8 {
    const name_or_length = try header.nameOrLength();
    var name: []u8 = undefined;
    switch (name_or_length) {
        .Name => |n| {
            name = try allocator.dupe(u8, n);
        },
        .Length => |len| {
            var n = try allocator.alloc(u8, len);
            defer allocator.free(n);
            try reader.readNoEof(n);
            const actual_len = mem.indexOfScalar(u8, n, @as(u8, 0)) orelse n.len;
            name = try allocator.dupe(u8, n[0..actual_len]);
        },
    }
    return name;
}

fn parseTableOfContents(self: *Archive, reader: anytype) !void {
    const symtab_size = try reader.readIntLittle(u32);
    var symtab = try self.allocator.alloc(u8, symtab_size);
    defer self.allocator.free(symtab);

    reader.readNoEof(symtab) catch {
        log.err("incomplete symbol table: expected symbol table of length 0x{x}", .{symtab_size});
        return error.MalformedArchive;
    };

    const strtab_size = try reader.readIntLittle(u32);
    var strtab = try self.allocator.alloc(u8, strtab_size);
    defer self.allocator.free(strtab);

    reader.readNoEof(strtab) catch {
        log.err("incomplete symbol table: expected string table of length 0x{x}", .{strtab_size});
        return error.MalformedArchive;
    };

    var symtab_stream = std.io.fixedBufferStream(symtab);
    var symtab_reader = symtab_stream.reader();

    while (true) {
        const n_strx = symtab_reader.readIntLittle(u32) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        const object_offset = try symtab_reader.readIntLittle(u32);

        const sym_name = mem.spanZ(@ptrCast([*:0]const u8, strtab.ptr + n_strx));
        const owned_name = try self.allocator.dupe(u8, sym_name);
        const res = try self.toc.getOrPut(self.allocator, owned_name);
        defer if (res.found_existing) self.allocator.free(owned_name);

        if (!res.found_existing) {
            res.value_ptr.* = .{};
        }

        try res.value_ptr.append(self.allocator, object_offset);
    }
}

/// Caller owns the Object instance.
pub fn parseObject(self: Archive, offset: u32) !*Object {
    var reader = self.file.?.reader();
    try reader.context.seekTo(offset + self.library_offset);

    const object_header = try reader.readStruct(ar_hdr);

    if (!mem.eql(u8, &object_header.ar_fmag, ARFMAG)) {
        log.err("invalid header delimiter: expected '{s}', found '{s}'", .{ ARFMAG, object_header.ar_fmag });
        return error.MalformedArchive;
    }

    const object_name = try parseName(self.allocator, object_header, reader);
    defer self.allocator.free(object_name);

    log.debug("extracting object '{s}' from archive '{s}'", .{ object_name, self.name.? });

    const name = name: {
        var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try std.os.realpath(self.name.?, &buffer);
        break :name try std.fmt.allocPrint(self.allocator, "{s}({s})", .{ path, object_name });
    };

    var object = try self.allocator.create(Object);
    errdefer self.allocator.destroy(object);

    object.* = .{
        .allocator = self.allocator,
        .arch = self.arch.?,
        .file = try fs.cwd().openFile(self.name.?, .{}),
        .name = name,
        .file_offset = @intCast(u32, try reader.context.getPos()),
        .mtime = try self.header.?.date(),
    };
    try object.parse();
    try reader.context.seekTo(0);

    return object;
}
