const StringTable = @This();

const std = @import("std");
const log = std.log.scoped(.strtab);
const mem = std.mem;

const Allocator = mem.Allocator;

allocator: *Allocator,
buffer: std.ArrayListUnmanaged(u8) = .{},
used_offsets: std.ArrayListUnmanaged(u32) = .{},
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
    self.cache.deinit(self.allocator);
    self.used_offsets.deinit(self.allocator);
    self.buffer.deinit(self.allocator);
}

pub fn getOrPut(self: *StringTable, string: []const u8) Error!u32 {
    if (self.cache.get(string)) |off| {
        log.debug("reusing string '{s}' at offset 0x{x}", .{ string, off });
        return off;
    }

    const invalidate_cache = self.needsToGrow(string.len + 1);

    try self.buffer.ensureUnusedCapacity(self.allocator, string.len + 1);
    const new_off = @intCast(u32, self.buffer.items.len);

    log.debug("writing new string '{s}' at offset 0x{x}", .{ string, new_off });

    self.buffer.appendSliceAssumeCapacity(string);
    self.buffer.appendAssumeCapacity(0);

    if (invalidate_cache) {
        log.debug("invalidating cache", .{});
        // Re-create the cache.
        self.cache.clearRetainingCapacity();
        for (self.used_offsets.items) |off| {
            try self.cache.putNoClobber(self.allocator, self.get(off).?, off);
        }
    }

    {
        log.debug("cache:", .{});
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            log.debug("  | {s} => {}", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
    }

    try self.cache.putNoClobber(self.allocator, self.get(new_off).?, new_off);
    try self.used_offsets.append(self.allocator, new_off);

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

fn needsToGrow(self: StringTable, needed_space: u64) bool {
    return self.buffer.capacity < needed_space + self.size();
}
