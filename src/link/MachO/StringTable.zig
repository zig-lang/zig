const StringTable = @This();

const std = @import("std");
const log = std.log.scoped(.strtab);
const mem = std.mem;

const Allocator = mem.Allocator;

allocator: *Allocator,
buffer: std.ArrayListUnmanaged(u8) = .{},
cache: std.StringHashMapUnmanaged(u32) = .{},

pub const Error = error{OutOfMemory};

pub fn init(allocator: *Allocator) Error!StringTable {
    var strtab = StringTable{
        .allocator = allocator,
    };
    try strtab.buffer.append(allocator, 0);
    return strtab;
}

pub fn deinit(self: *StringTable) void {
    {
        var it = self.cache.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
    }
    self.cache.deinit(self.allocator);
    self.buffer.deinit(self.allocator);
}

pub fn getOrPut(self: *StringTable, string: []const u8) Error!u32 {
    if (self.cache.get(string)) |off| {
        log.debug("reusing string '{s}' at offset 0x{x}", .{ string, off });
        return off;
    }

    try self.buffer.ensureUnusedCapacity(self.allocator, string.len + 1);
    const new_off = @intCast(u32, self.buffer.items.len);

    log.debug("writing new string '{s}' at offset 0x{x}", .{ string, new_off });

    self.buffer.appendSliceAssumeCapacity(string);
    self.buffer.appendAssumeCapacity(0);

    try self.cache.putNoClobber(self.allocator, try self.allocator.dupe(u8, string), new_off);

    return new_off;
}

pub fn get(self: StringTable, off: u32) ?[]const u8 {
    if (off >= self.buffer.items.len) return null;
    return mem.spanZ(@ptrCast([*:0]const u8, self.buffer.items.ptr + off));
}

pub fn asSlice(self: StringTable) []const u8 {
    return self.buffer.items;
}

pub fn size(self: StringTable) u64 {
    return self.buffer.items.len;
}
