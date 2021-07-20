//! This implementation does all the linking work in flush(). A future improvement
//! would be to add incremental linking in a similar way as ELF does.

const Plan9 = @This();

const std = @import("std");
const link = @import("../link.zig");
const Module = @import("../Module.zig");
const Compilation = @import("../Compilation.zig");
const aout = @import("Plan9/aout.zig");
const codegen = @import("../codegen.zig");
const trace = @import("../tracy.zig").trace;
const mem = std.mem;
const File = link.File;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.link);
const assert = std.debug.assert;

base: link.File,
sixtyfour_bit: bool,
error_flags: File.ErrorFlags = File.ErrorFlags{},
bases: Bases,

decl_table: std.AutoArrayHashMapUnmanaged(*Module.Decl, void) = .{},
/// is just casted down when 32 bit
syms: std.ArrayListUnmanaged(aout.Sym) = .{},
text_buf: std.ArrayListUnmanaged(u8) = .{},
data_buf: std.ArrayListUnmanaged(u8) = .{},

hdr: aout.ExecHdr = undefined,

entry_decl: ?*Module.Decl = null,

got: std.ArrayListUnmanaged(u64) = .{},

atoms: std.ArrayListUnmanaged(*Atom) = .{},

const Bases = struct {
    text: u64,
    /// the addr of the got
    data: u64,
};

fn getAddr(self: Plan9, addr: u64, t: aout.Sym.Type) u64 {
    return addr + switch (t) {
        .T, .t, .l, .L => self.bases.text,
        .D, .d, .B, .b => self.bases.data,
        else => unreachable,
    };
}
/// opposite of getAddr
fn takeAddr(self: Plan9, addr: u64, t: aout.Sym.Type) u64 {
    return addr - switch (t) {
        .T, .t, .l, .L => self.bases.text,
        .D, .d, .B, .b => self.bases.data,
        else => unreachable,
    };
}

fn getSymAddr(self: Plan9, s: aout.Sym) u64 {
    return self.getAddr(s.value, s.type);
}

pub const Atom = struct {
    base: File.Atom = .{ .tag = .plan9 },
    type: aout.Sym.Type,
    /// offset in the text or data sects
    offset: ?u64,
    /// offset into syms
    sym_index: ?usize,
    /// offset into got
    got_index: ?usize,

    pub const base_atom_tag: File.Tag = .plan9;

    pub const empty = Atom{
        .type = .t,
        .offset = null,
        .sym_index = null,
        .got_index = null,
    };
};

pub fn defaultBaseAddrs(arch: std.Target.Cpu.Arch) Bases {
    return switch (arch) {
        .x86_64 => .{
            // header size => 40 => 0x28
            .text = 0x200028,
            .data = 0x400000,
        },
        .i386 => .{
            // header size => 32 => 0x20
            .text = 0x200020,
            .data = 0x400000,
        },
        .aarch64 => .{
            // header size => 40 => 0x28
            .text = 0x10028,
            .data = 0x20000,
        },
        else => std.debug.panic("find default base address for {}", .{arch}),
    };
}

pub const PtrWidth = enum { p32, p64 };

pub fn createEmpty(gpa: *Allocator, options: link.Options) !*Plan9 {
    if (options.use_llvm)
        return error.LLVMBackendDoesNotSupportPlan9;
    const sixtyfour_bit: bool = switch (options.target.cpu.arch.ptrBitWidth()) {
        0...32 => false,
        33...64 => true,
        else => return error.UnsupportedP9Architecture,
    };
    const self = try gpa.create(Plan9);
    self.* = .{
        .base = .{
            .tag = .plan9,
            .options = options,
            .allocator = gpa,
            .file = null,
        },
        .sixtyfour_bit = sixtyfour_bit,
        .bases = undefined,
    };
    return self;
}

pub fn updateDecl(self: *Plan9, module: *Module, decl: *Module.Decl) !void {
    _ = module;
    _ = try self.decl_table.getOrPut(self.base.allocator, decl);
}

pub fn flush(self: *Plan9, comp: *Compilation) !void {
    assert(!self.base.options.use_lld);

    switch (self.base.options.effectiveOutputMode()) {
        .Exe => {},
        // plan9 object files are totally different
        .Obj => return error.TODOImplementPlan9Objs,
        .Lib => return error.TODOImplementWritingLibFiles,
    }
    return self.flushModule(comp);
}

pub fn flushModule(self: *Plan9, comp: *Compilation) !void {
    _ = comp;
    const tracy = trace(@src());
    defer tracy.end();

    log.debug("flushModule", .{});

    defer assert(self.hdr.entry != 0x0);

    const module = self.base.options.module orelse return error.LinkingWithoutZigSourceUnimplemented;

    self.text_buf.items.len = 0;
    self.data_buf.items.len = 0;
    // ensure space to write the got later
    assert(self.got.items.len == self.decl_table.count());
    try self.data_buf.appendNTimes(self.base.allocator, 0x69, self.got.items.len * if (!self.sixtyfour_bit) @as(u32, 4) else 8);
    // temporary buffer
    var code_buffer = std.ArrayList(u8).init(self.base.allocator);
    defer code_buffer.deinit();
    {
        for (self.decl_table.keys()) |decl| {
            if (!decl.has_tv) continue;
            const is_fn = (decl.ty.zigTypeTag() == .Fn);

            log.debug("update the symbol table and got for decl {*} ({s})", .{ decl, decl.name });
            decl.link.plan9 = if (is_fn) .{
                .offset = self.getAddr(self.text_buf.items.len, .t),
                .type = .t,
                .sym_index = decl.link.plan9.sym_index,
                .got_index = decl.link.plan9.got_index,
            } else .{
                .offset = self.getAddr(self.data_buf.items.len, .d),
                .type = .d,
                .sym_index = decl.link.plan9.sym_index,
                .got_index = decl.link.plan9.got_index,
            };
            self.got.items[decl.link.plan9.got_index.?] = decl.link.plan9.offset.?;
            if (decl.link.plan9.sym_index) |s| {
                self.syms.items[s] = .{
                    .value = decl.link.plan9.offset.?,
                    .type = decl.link.plan9.type,
                    .name = mem.span(decl.name),
                };
            } else {
                try self.syms.append(self.base.allocator, .{
                    .value = decl.link.plan9.offset.?,
                    .type = decl.link.plan9.type,
                    .name = mem.span(decl.name),
                });
                decl.link.plan9.sym_index = self.syms.items.len - 1;
            }

            if (module.decl_exports.get(decl)) |exports| {
                for (exports) |exp| {
                    // plan9 does not support custom sections
                    if (exp.options.section) |section_name| {
                        if (!mem.eql(u8, section_name, ".text") or !mem.eql(u8, section_name, ".data")) {
                            try module.failed_exports.put(module.gpa, exp, try Module.ErrorMsg.create(self.base.allocator, decl.srcLoc(), "plan9 does not support extra sections", .{}));
                            break;
                        }
                    }
                    if (std.mem.eql(u8, exp.options.name, "_start")) {
                        std.debug.assert(decl.link.plan9.type == .t); // we tried to link a non-function as the entry
                        self.entry_decl = decl;
                    }
                    if (exp.link.plan9) |i| {
                        self.syms.items[i] = .{
                            .value = decl.link.plan9.offset.?,
                            .type = decl.link.plan9.type.toGlobal(),
                            .name = exp.options.name,
                        };
                    } else {
                        try self.syms.append(self.base.allocator, .{
                            .value = decl.link.plan9.offset.?,
                            .type = decl.link.plan9.type.toGlobal(),
                            .name = exp.options.name,
                        });
                        exp.link.plan9 = self.syms.items.len - 1;
                    }
                }
            }

            log.debug("codegen decl {*} ({s})", .{ decl, decl.name });
            const res = try codegen.generateSymbol(&self.base, decl.srcLoc(), .{
                .ty = decl.ty,
                .val = decl.val,
            }, &code_buffer, .{ .none = {} });
            const code = switch (res) {
                .externally_managed => |x| x,
                .appended => code_buffer.items,
                .fail => |em| {
                    decl.analysis = .codegen_failure;
                    try module.failed_decls.put(module.gpa, decl, em);
                    // TODO try to do more decls
                    return;
                },
            };
            if (is_fn) {
                try self.text_buf.appendSlice(self.base.allocator, code);
                code_buffer.items.len = 0;
            } else {
                try self.data_buf.appendSlice(self.base.allocator, code);
                code_buffer.items.len = 0;
            }
        }
    }

    // write the got
    if (!self.sixtyfour_bit) {
        for (self.got.items) |p, i| {
            mem.writeInt(u32, self.data_buf.items[i * 4 ..][0..4], @intCast(u32, p), self.base.options.target.cpu.arch.endian());
        }
    } else {
        for (self.got.items) |p, i| {
            mem.writeInt(u64, self.data_buf.items[i * 8 ..][0..8], p, self.base.options.target.cpu.arch.endian());
        }
    }

    self.hdr.entry = @truncate(u32, self.entry_decl.?.link.plan9.offset.?);

    // edata, end, etext
    self.syms.items[0].value = self.getAddr(0x0, .b);
    self.syms.items[1].value = self.getAddr(0x0, .b);
    self.syms.items[2].value = self.getAddr(self.text_buf.items.len, .t);

    var sym_buf = std.ArrayList(u8).init(self.base.allocator);
    defer sym_buf.deinit();
    try self.writeSyms(&sym_buf);

    // generate the header
    self.hdr = .{
        .magic = try aout.magicFromArch(self.base.options.target.cpu.arch),
        .text = @intCast(u32, self.text_buf.items.len),
        .data = @intCast(u32, self.data_buf.items.len),
        .syms = @intCast(u32, sym_buf.items.len),
        .bss = 0,
        .pcsz = 0,
        .spsz = 0,
        .entry = self.hdr.entry,
    };

    const file = self.base.file.?;

    var hdr_buf = self.hdr.toU8s();
    const hdr_slice: []const u8 = &hdr_buf;
    // account for the fat header
    const hdr_size: u8 = if (!self.sixtyfour_bit) 32 else 40;
    // write the fat header for 64 bit entry points
    if (self.sixtyfour_bit) {
        mem.writeIntSliceBig(u64, hdr_buf[32..40], self.hdr.entry);
    }
    // write it all!
    var vectors: [4]std.os.iovec_const = .{
        .{ .iov_base = hdr_slice.ptr, .iov_len = hdr_size },
        .{ .iov_base = self.text_buf.items.ptr, .iov_len = self.text_buf.items.len },
        .{ .iov_base = self.data_buf.items.ptr, .iov_len = self.data_buf.items.len },
        .{ .iov_base = sym_buf.items.ptr, .iov_len = sym_buf.items.len },
        // TODO spsz, pcsz
    };
    try file.pwritevAll(&vectors, 0);
}
pub fn freeDecl(self: *Plan9, decl: *Module.Decl) void {
    assert(self.decl_table.swapRemove(decl));
}

pub fn updateDeclExports(
    self: *Plan9,
    module: *Module,
    decl: *Module.Decl,
    exports: []const *Module.Export,
) !void {
    // we do all the things in flush
    _ = self;
    _ = module;
    _ = decl;
    _ = exports;
}
pub fn deinit(self: *Plan9) void {
    self.decl_table.deinit(self.base.allocator);
    self.syms.deinit(self.base.allocator);
    self.text_buf.deinit(self.base.allocator);
    self.data_buf.deinit(self.base.allocator);
    self.got.deinit(self.base.allocator);

    for (self.atoms.items) |atom| {
        self.base.allocator.destroy(atom);
    }
    self.atoms.deinit(self.base.allocator);
}

pub const Export = ?usize;
pub const base_tag = .plan9;
pub fn openPath(allocator: *Allocator, sub_path: []const u8, options: link.Options) !*Plan9 {
    if (options.use_llvm)
        return error.LLVMBackendDoesNotSupportPlan9;
    assert(options.object_format == .plan9);
    const file = try options.emit.?.directory.handle.createFile(sub_path, .{
        .truncate = false,
        .read = true,
        .mode = link.determineMode(options),
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer self.base.destroy();

    self.bases = defaultBaseAddrs(options.target.cpu.arch);

    // first 3 symbols in our table are edata, end, etext
    try self.syms.appendSlice(self.base.allocator, &.{
        .{
            .value = 0xcafebabe,
            .type = .B,
            .name = "edata",
        },
        .{
            .value = 0xcafebabe,
            .type = .B,
            .name = "end",
        },
        .{
            .value = 0xcafebabe,
            .type = .T,
            .name = "etext",
        },
    });

    self.base.file = file;
    return self;
}

pub fn writeSyms(self: *Plan9, buf: *std.ArrayList(u8)) !void {
    const writer = buf.writer();
    for (self.syms.items) |sym| {
        if (!self.sixtyfour_bit) {
            try writer.writeIntBig(u32, @intCast(u32, sym.value));
        } else {
            try writer.writeIntBig(u64, sym.value);
        }
        try writer.writeByte(@enumToInt(sym.type));
        try writer.writeAll(std.mem.span(sym.name));
        try writer.writeByte(0);
    }
}

pub fn allocateDeclIndexes(self: *Plan9, decl: *Module.Decl) !void {
    try self.got.append(self.base.allocator, 0xdeadbeef);
    decl.link.plan9.got_index = self.got.items.len - 1;
}

pub fn createAtom(self: *Plan9) !*File.Atom {
    const atom = try self.base.allocator.create(Atom);
    atom.* = Atom.empty;
    try self.atoms.append(self.base.allocator, atom);
    return &atom.base;
}
