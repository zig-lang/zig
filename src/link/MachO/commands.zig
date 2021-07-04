const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const meta = std.meta;
const macho = std.macho;
const testing = std.testing;
const assert = std.debug.assert;

const Allocator = std.mem.Allocator;
const MachO = @import("../MachO.zig");
const padToIdeal = MachO.padToIdeal;

pub const HeaderArgs = struct {
    magic: u32 = macho.MH_MAGIC_64,
    cputype: macho.cpu_type_t = 0,
    cpusubtype: macho.cpu_subtype_t = 0,
    filetype: u32 = 0,
    flags: u32 = 0,
    reserved: u32 = 0,
};

pub fn emptyHeader(args: HeaderArgs) macho.mach_header_64 {
    return .{
        .magic = args.magic,
        .cputype = args.cputype,
        .cpusubtype = args.cpusubtype,
        .filetype = args.filetype,
        .ncmds = 0,
        .sizeofcmds = 0,
        .flags = args.flags,
        .reserved = args.reserved,
    };
}

pub const LoadCommand = union(enum) {
    Segment: SegmentCommand,
    DyldInfoOnly: macho.dyld_info_command,
    Symtab: macho.symtab_command,
    Dysymtab: macho.dysymtab_command,
    Dylinker: GenericCommandWithData(macho.dylinker_command),
    Dylib: GenericCommandWithData(macho.dylib_command),
    Main: macho.entry_point_command,
    VersionMin: macho.version_min_command,
    SourceVersion: macho.source_version_command,
    Uuid: macho.uuid_command,
    LinkeditData: macho.linkedit_data_command,
    Rpath: GenericCommandWithData(macho.rpath_command),
    Unknown: GenericCommandWithData(macho.load_command),

    pub fn read(allocator: *Allocator, reader: anytype) !LoadCommand {
        const header = try reader.readStruct(macho.load_command);
        var buffer = try allocator.alloc(u8, header.cmdsize);
        defer allocator.free(buffer);
        mem.copy(u8, buffer, mem.asBytes(&header));
        try reader.readNoEof(buffer[@sizeOf(macho.load_command)..]);
        var stream = io.fixedBufferStream(buffer);

        return switch (header.cmd) {
            macho.LC_SEGMENT_64 => LoadCommand{
                .Segment = try SegmentCommand.read(allocator, stream.reader()),
            },
            macho.LC_DYLD_INFO,
            macho.LC_DYLD_INFO_ONLY,
            => LoadCommand{
                .DyldInfoOnly = try stream.reader().readStruct(macho.dyld_info_command),
            },
            macho.LC_SYMTAB => LoadCommand{
                .Symtab = try stream.reader().readStruct(macho.symtab_command),
            },
            macho.LC_DYSYMTAB => LoadCommand{
                .Dysymtab = try stream.reader().readStruct(macho.dysymtab_command),
            },
            macho.LC_ID_DYLINKER,
            macho.LC_LOAD_DYLINKER,
            macho.LC_DYLD_ENVIRONMENT,
            => LoadCommand{
                .Dylinker = try GenericCommandWithData(macho.dylinker_command).read(allocator, stream.reader()),
            },
            macho.LC_ID_DYLIB,
            macho.LC_LOAD_WEAK_DYLIB,
            macho.LC_LOAD_DYLIB,
            macho.LC_REEXPORT_DYLIB,
            => LoadCommand{
                .Dylib = try GenericCommandWithData(macho.dylib_command).read(allocator, stream.reader()),
            },
            macho.LC_MAIN => LoadCommand{
                .Main = try stream.reader().readStruct(macho.entry_point_command),
            },
            macho.LC_VERSION_MIN_MACOSX,
            macho.LC_VERSION_MIN_IPHONEOS,
            macho.LC_VERSION_MIN_WATCHOS,
            macho.LC_VERSION_MIN_TVOS,
            => LoadCommand{
                .VersionMin = try stream.reader().readStruct(macho.version_min_command),
            },
            macho.LC_SOURCE_VERSION => LoadCommand{
                .SourceVersion = try stream.reader().readStruct(macho.source_version_command),
            },
            macho.LC_UUID => LoadCommand{
                .Uuid = try stream.reader().readStruct(macho.uuid_command),
            },
            macho.LC_FUNCTION_STARTS,
            macho.LC_DATA_IN_CODE,
            macho.LC_CODE_SIGNATURE,
            => LoadCommand{
                .LinkeditData = try stream.reader().readStruct(macho.linkedit_data_command),
            },
            macho.LC_RPATH => LoadCommand{
                .Rpath = try GenericCommandWithData(macho.rpath_command).read(allocator, stream.reader()),
            },
            else => LoadCommand{
                .Unknown = try GenericCommandWithData(macho.load_command).read(allocator, stream.reader()),
            },
        };
    }

    pub fn write(self: LoadCommand, writer: anytype) !void {
        return switch (self) {
            .DyldInfoOnly => |x| writeStruct(x, writer),
            .Symtab => |x| writeStruct(x, writer),
            .Dysymtab => |x| writeStruct(x, writer),
            .Main => |x| writeStruct(x, writer),
            .VersionMin => |x| writeStruct(x, writer),
            .SourceVersion => |x| writeStruct(x, writer),
            .Uuid => |x| writeStruct(x, writer),
            .LinkeditData => |x| writeStruct(x, writer),
            .Segment => |x| x.write(writer),
            .Dylinker => |x| x.write(writer),
            .Dylib => |x| x.write(writer),
            .Rpath => |x| x.write(writer),
            .Unknown => |x| x.write(writer),
        };
    }

    pub fn cmd(self: LoadCommand) u32 {
        return switch (self) {
            .DyldInfoOnly => |x| x.cmd,
            .Symtab => |x| x.cmd,
            .Dysymtab => |x| x.cmd,
            .Main => |x| x.cmd,
            .VersionMin => |x| x.cmd,
            .SourceVersion => |x| x.cmd,
            .Uuid => |x| x.cmd,
            .LinkeditData => |x| x.cmd,
            .Segment => |x| x.inner.cmd,
            .Dylinker => |x| x.inner.cmd,
            .Dylib => |x| x.inner.cmd,
            .Rpath => |x| x.inner.cmd,
            .Unknown => |x| x.inner.cmd,
        };
    }

    pub fn cmdsize(self: LoadCommand) u32 {
        return switch (self) {
            .DyldInfoOnly => |x| x.cmdsize,
            .Symtab => |x| x.cmdsize,
            .Dysymtab => |x| x.cmdsize,
            .Main => |x| x.cmdsize,
            .VersionMin => |x| x.cmdsize,
            .SourceVersion => |x| x.cmdsize,
            .LinkeditData => |x| x.cmdsize,
            .Uuid => |x| x.cmdsize,
            .Segment => |x| x.inner.cmdsize,
            .Dylinker => |x| x.inner.cmdsize,
            .Dylib => |x| x.inner.cmdsize,
            .Rpath => |x| x.inner.cmdsize,
            .Unknown => |x| x.inner.cmdsize,
        };
    }

    pub fn deinit(self: *LoadCommand, allocator: *Allocator) void {
        return switch (self.*) {
            .Segment => |*x| x.deinit(allocator),
            .Dylinker => |*x| x.deinit(allocator),
            .Dylib => |*x| x.deinit(allocator),
            .Rpath => |*x| x.deinit(allocator),
            .Unknown => |*x| x.deinit(allocator),
            else => {},
        };
    }

    fn writeStruct(command: anytype, writer: anytype) !void {
        return writer.writeAll(mem.asBytes(&command));
    }

    fn eql(self: LoadCommand, other: LoadCommand) bool {
        if (@as(meta.Tag(LoadCommand), self) != @as(meta.Tag(LoadCommand), other)) return false;
        return switch (self) {
            .DyldInfoOnly => |x| meta.eql(x, other.DyldInfoOnly),
            .Symtab => |x| meta.eql(x, other.Symtab),
            .Dysymtab => |x| meta.eql(x, other.Dysymtab),
            .Main => |x| meta.eql(x, other.Main),
            .VersionMin => |x| meta.eql(x, other.VersionMin),
            .SourceVersion => |x| meta.eql(x, other.SourceVersion),
            .Uuid => |x| meta.eql(x, other.Uuid),
            .LinkeditData => |x| meta.eql(x, other.LinkeditData),
            .Segment => |x| x.eql(other.Segment),
            .Dylinker => |x| x.eql(other.Dylinker),
            .Dylib => |x| x.eql(other.Dylib),
            .Rpath => |x| x.eql(other.Rpath),
            .Unknown => |x| x.eql(other.Unknown),
        };
    }
};

pub const SegmentCommand = struct {
    inner: macho.segment_command_64,
    sections: std.ArrayListUnmanaged(macho.section_64) = .{},

    const SegmentOptions = struct {
        cmdsize: u32 = @sizeOf(macho.segment_command_64),
        vmaddr: u64 = 0,
        vmsize: u64 = 0,
        fileoff: u64 = 0,
        filesize: u64 = 0,
        maxprot: macho.vm_prot_t = macho.VM_PROT_NONE,
        initprot: macho.vm_prot_t = macho.VM_PROT_NONE,
        nsects: u32 = 0,
        flags: u32 = 0,
    };

    pub fn empty(comptime segname: []const u8, opts: SegmentOptions) SegmentCommand {
        return .{
            .inner = .{
                .cmd = macho.LC_SEGMENT_64,
                .cmdsize = opts.cmdsize,
                .segname = makeStaticString(segname),
                .vmaddr = opts.vmaddr,
                .vmsize = opts.vmsize,
                .fileoff = opts.fileoff,
                .filesize = opts.filesize,
                .maxprot = opts.maxprot,
                .initprot = opts.initprot,
                .nsects = opts.nsects,
                .flags = opts.flags,
            },
        };
    }

    const SectionOptions = struct {
        addr: u64 = 0,
        size: u64 = 0,
        offset: u32 = 0,
        @"align": u32 = 0,
        reloff: u32 = 0,
        nreloc: u32 = 0,
        flags: u32 = macho.S_REGULAR,
        reserved1: u32 = 0,
        reserved2: u32 = 0,
        reserved3: u32 = 0,
    };

    pub fn addSection(
        self: *SegmentCommand,
        alloc: *Allocator,
        comptime sectname: []const u8,
        opts: SectionOptions,
    ) !void {
        var section = macho.section_64{
            .sectname = makeStaticString(sectname),
            .segname = undefined,
            .addr = opts.addr,
            .size = opts.size,
            .offset = opts.offset,
            .@"align" = opts.@"align",
            .reloff = opts.reloff,
            .nreloc = opts.nreloc,
            .flags = opts.flags,
            .reserved1 = opts.reserved1,
            .reserved2 = opts.reserved2,
            .reserved3 = opts.reserved3,
        };
        mem.copy(u8, &section.segname, &self.inner.segname);
        try self.sections.append(alloc, section);
        self.inner.cmdsize += @sizeOf(macho.section_64);
        self.inner.nsects += 1;
    }

    pub fn read(alloc: *Allocator, reader: anytype) !SegmentCommand {
        const inner = try reader.readStruct(macho.segment_command_64);
        var segment = SegmentCommand{
            .inner = inner,
        };
        try segment.sections.ensureCapacity(alloc, inner.nsects);

        var i: usize = 0;
        while (i < inner.nsects) : (i += 1) {
            const section = try reader.readStruct(macho.section_64);
            segment.sections.appendAssumeCapacity(section);
        }

        return segment;
    }

    pub fn write(self: SegmentCommand, writer: anytype) !void {
        try writer.writeAll(mem.asBytes(&self.inner));
        for (self.sections.items) |sect| {
            try writer.writeAll(mem.asBytes(&sect));
        }
    }

    pub fn deinit(self: *SegmentCommand, alloc: *Allocator) void {
        self.sections.deinit(alloc);
    }

    pub fn allocatedSize(self: SegmentCommand, start: u64) u64 {
        assert(start > 0);
        if (start == self.inner.fileoff)
            return 0;
        var min_pos: u64 = std.math.maxInt(u64);
        for (self.sections.items) |section| {
            if (section.offset <= start) continue;
            if (section.offset < min_pos) min_pos = section.offset;
        }
        return min_pos - start;
    }

    fn detectAllocCollision(self: SegmentCommand, start: u64, size: u64) ?u64 {
        const end = start + padToIdeal(size);
        for (self.sections.items) |section| {
            const increased_size = padToIdeal(section.size);
            const test_end = section.offset + increased_size;
            if (end > section.offset and start < test_end) {
                return test_end;
            }
        }
        return null;
    }

    pub fn findFreeSpace(self: SegmentCommand, object_size: u64, min_alignment: u16, start: ?u64) u64 {
        var st: u64 = if (start) |v| v else self.inner.fileoff;
        while (self.detectAllocCollision(st, object_size)) |item_end| {
            st = mem.alignForwardGeneric(u64, item_end, min_alignment);
        }
        return st;
    }

    fn eql(self: SegmentCommand, other: SegmentCommand) bool {
        if (!meta.eql(self.inner, other.inner)) return false;
        const lhs = self.sections.items;
        const rhs = other.sections.items;
        var i: usize = 0;
        while (i < self.inner.nsects) : (i += 1) {
            if (!meta.eql(lhs[i], rhs[i])) return false;
        }
        return true;
    }
};

pub fn emptyGenericCommandWithData(cmd: anytype) GenericCommandWithData(@TypeOf(cmd)) {
    return .{ .inner = cmd };
}

pub fn GenericCommandWithData(comptime Cmd: type) type {
    return struct {
        inner: Cmd,
        /// This field remains undefined until `read` is called.
        data: []u8 = undefined,

        const Self = @This();

        pub fn read(allocator: *Allocator, reader: anytype) !Self {
            const inner = try reader.readStruct(Cmd);
            var data = try allocator.alloc(u8, inner.cmdsize - @sizeOf(Cmd));
            errdefer allocator.free(data);
            try reader.readNoEof(data);
            return Self{
                .inner = inner,
                .data = data,
            };
        }

        pub fn write(self: Self, writer: anytype) !void {
            try writer.writeAll(mem.asBytes(&self.inner));
            try writer.writeAll(self.data);
        }

        pub fn deinit(self: *Self, allocator: *Allocator) void {
            allocator.free(self.data);
        }

        fn eql(self: Self, other: Self) bool {
            if (!meta.eql(self.inner, other.inner)) return false;
            return mem.eql(u8, self.data, other.data);
        }
    };
}

pub fn createLoadDylibCommand(
    allocator: *Allocator,
    name: []const u8,
    timestamp: u32,
    current_version: u32,
    compatibility_version: u32,
) !GenericCommandWithData(macho.dylib_command) {
    const cmdsize = @intCast(u32, mem.alignForwardGeneric(
        u64,
        @sizeOf(macho.dylib_command) + name.len + 1, // +1 for nul
        @sizeOf(u64),
    ));

    var dylib_cmd = emptyGenericCommandWithData(macho.dylib_command{
        .cmd = macho.LC_LOAD_DYLIB,
        .cmdsize = cmdsize,
        .dylib = .{
            .name = @sizeOf(macho.dylib_command),
            .timestamp = timestamp,
            .current_version = current_version,
            .compatibility_version = compatibility_version,
        },
    });
    dylib_cmd.data = try allocator.alloc(u8, cmdsize - dylib_cmd.inner.dylib.name);

    mem.set(u8, dylib_cmd.data, 0);
    mem.copy(u8, dylib_cmd.data, name);

    return dylib_cmd;
}

fn makeStaticString(bytes: []const u8) [16]u8 {
    var buf = [_]u8{0} ** 16;
    assert(bytes.len <= buf.len);
    mem.copy(u8, &buf, bytes);
    return buf;
}

fn parseName(name: *const [16]u8) []const u8 {
    const len = mem.indexOfScalar(u8, name, @as(u8, 0)) orelse name.len;
    return name[0..len];
}

pub fn segmentName(sect: macho.section_64) []const u8 {
    return parseName(&sect.segname);
}

pub fn sectionName(sect: macho.section_64) []const u8 {
    return parseName(&sect.sectname);
}

pub fn sectionType(sect: macho.section_64) u8 {
    return @truncate(u8, sect.flags & 0xff);
}

pub fn sectionAttrs(sect: macho.section_64) u32 {
    return sect.flags & 0xffffff00;
}

pub fn sectionIsCode(sect: macho.section_64) bool {
    const attr = sectionAttrs(sect);
    return attr & macho.S_ATTR_PURE_INSTRUCTIONS != 0 or attr & macho.S_ATTR_SOME_INSTRUCTIONS != 0;
}

pub fn sectionIsDebug(sect: macho.section_64) bool {
    return sectionAttrs(sect) & macho.S_ATTR_DEBUG != 0;
}

pub fn sectionIsDontDeadStrip(sect: macho.section_64) bool {
    return sectionAttrs(sect) & macho.S_ATTR_NO_DEAD_STRIP != 0;
}

pub fn sectionIsDontDeadStripIfReferencesLive(sect: macho.section_64) bool {
    return sectionAttrs(sect) & macho.S_ATTR_LIVE_SUPPORT != 0;
}

fn testRead(allocator: *Allocator, buffer: []const u8, expected: anytype) !void {
    var stream = io.fixedBufferStream(buffer);
    var given = try LoadCommand.read(allocator, stream.reader());
    defer given.deinit(allocator);
    try testing.expect(expected.eql(given));
}

fn testWrite(buffer: []u8, cmd: LoadCommand, expected: []const u8) !void {
    var stream = io.fixedBufferStream(buffer);
    try cmd.write(stream.writer());
    try testing.expect(mem.eql(u8, expected, buffer[0..expected.len]));
}

test "read-write segment command" {
    var gpa = testing.allocator;
    const in_buffer = &[_]u8{
        0x19, 0x00, 0x00, 0x00, // cmd
        0x98, 0x00, 0x00, 0x00, // cmdsize
        0x5f, 0x5f, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // segname
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // vmaddr
        0x00, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // vmsize
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fileoff
        0x00, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // filesize
        0x07, 0x00, 0x00, 0x00, // maxprot
        0x05, 0x00, 0x00, 0x00, // initprot
        0x01, 0x00, 0x00, 0x00, // nsects
        0x00, 0x00, 0x00, 0x00, // flags
        0x5f, 0x5f, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sectname
        0x5f, 0x5f, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // segname
        0x00, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // address
        0xc0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size
        0x00, 0x40, 0x00, 0x00, // offset
        0x02, 0x00, 0x00, 0x00, // alignment
        0x00, 0x00, 0x00, 0x00, // reloff
        0x00, 0x00, 0x00, 0x00, // nreloc
        0x00, 0x04, 0x00, 0x80, // flags
        0x00, 0x00, 0x00, 0x00, // reserved1
        0x00, 0x00, 0x00, 0x00, // reserved2
        0x00, 0x00, 0x00, 0x00, // reserved3
    };
    var cmd = SegmentCommand{
        .inner = .{
            .cmd = macho.LC_SEGMENT_64,
            .cmdsize = 152,
            .segname = makeStaticString("__TEXT"),
            .vmaddr = 4294967296,
            .vmsize = 294912,
            .fileoff = 0,
            .filesize = 294912,
            .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE,
            .initprot = macho.VM_PROT_EXECUTE | macho.VM_PROT_READ,
            .nsects = 1,
            .flags = 0,
        },
    };
    try cmd.sections.append(gpa, .{
        .sectname = makeStaticString("__text"),
        .segname = makeStaticString("__TEXT"),
        .addr = 4294983680,
        .size = 448,
        .offset = 16384,
        .@"align" = 2,
        .reloff = 0,
        .nreloc = 0,
        .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        .reserved1 = 0,
        .reserved2 = 0,
        .reserved3 = 0,
    });
    defer cmd.deinit(gpa);
    try testRead(gpa, in_buffer, LoadCommand{ .Segment = cmd });

    var out_buffer: [in_buffer.len]u8 = undefined;
    try testWrite(&out_buffer, LoadCommand{ .Segment = cmd }, in_buffer);
}

test "read-write generic command with data" {
    var gpa = testing.allocator;
    const in_buffer = &[_]u8{
        0x0c, 0x00, 0x00, 0x00, // cmd
        0x20, 0x00, 0x00, 0x00, // cmdsize
        0x18, 0x00, 0x00, 0x00, // name
        0x02, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // current_version
        0x00, 0x00, 0x00, 0x00, // compatibility_version
        0x2f, 0x75, 0x73, 0x72, 0x00, 0x00, 0x00, 0x00, // data
    };
    var cmd = GenericCommandWithData(macho.dylib_command){
        .inner = .{
            .cmd = macho.LC_LOAD_DYLIB,
            .cmdsize = 32,
            .dylib = .{
                .name = 24,
                .timestamp = 2,
                .current_version = 0,
                .compatibility_version = 0,
            },
        },
    };
    cmd.data = try gpa.alloc(u8, 8);
    defer gpa.free(cmd.data);
    cmd.data[0] = 0x2f;
    cmd.data[1] = 0x75;
    cmd.data[2] = 0x73;
    cmd.data[3] = 0x72;
    cmd.data[4] = 0x0;
    cmd.data[5] = 0x0;
    cmd.data[6] = 0x0;
    cmd.data[7] = 0x0;
    try testRead(gpa, in_buffer, LoadCommand{ .Dylib = cmd });

    var out_buffer: [in_buffer.len]u8 = undefined;
    try testWrite(&out_buffer, LoadCommand{ .Dylib = cmd }, in_buffer);
}

test "read-write C struct command" {
    var gpa = testing.allocator;
    const in_buffer = &[_]u8{
        0x28, 0x00, 0x00, 0x80, // cmd
        0x18, 0x00, 0x00, 0x00, // cmdsize
        0x04, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // entryoff
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // stacksize
    };
    const cmd = .{
        .cmd = macho.LC_MAIN,
        .cmdsize = 24,
        .entryoff = 16644,
        .stacksize = 0,
    };
    try testRead(gpa, in_buffer, LoadCommand{ .Main = cmd });

    var out_buffer: [in_buffer.len]u8 = undefined;
    try testWrite(&out_buffer, LoadCommand{ .Main = cmd }, in_buffer);
}
