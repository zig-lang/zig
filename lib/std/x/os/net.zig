// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");

const os = std.os;
const fmt = std.fmt;
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const native_os = @import("builtin").os;

/// Resolves a network interface name into a scope/zone ID. It returns
/// an error if either resolution fails, or if the interface name is
/// too long.
pub fn resolveScopeID(name: []const u8) !u32 {
    if (@hasDecl(os, "IFNAMESIZE")) {
        if (name.len >= os.IFNAMESIZE - 1) return error.NameTooLong;

        if (native_os.tag == .windows) {
            var interface_name: [os.IFNAMESIZE]u8 = undefined;
            mem.copy(u8, &interface_name, name);
            interface_name[name.len] = 0;

            return os.windows.ws2_32.if_nametoindex(@ptrCast([*:0]const u8, &interface_name));
        }

        const fd = try os.socket(os.AF_UNIX, os.SOCK_DGRAM, 0);
        defer os.closeSocket(fd);

        var f: os.ifreq = undefined;
        mem.copy(u8, &f.ifrn.name, name);
        f.ifrn.name[name.len] = 0;

        try os.ioctl_SIOCGIFINDEX(fd, &f);

        return @bitCast(u32, f.ifru.ivalue);
    }

    return error.Unsupported;
}

/// An IPv4 address comprised of 4 bytes.
pub const IPv4 = extern struct {
    /// A IPv4 host-port pair.
    pub const Address = extern struct {
        host: IPv4,
        port: u16,
    };

    /// Octets of a IPv4 address designating the local host.
    pub const localhost_octets = [_]u8{ 127, 0, 0, 1 };

    /// The IPv4 address of the local host.
    pub const localhost: IPv4 = .{ .octets = localhost_octets };

    /// Octets of an unspecified IPv4 address.
    pub const unspecified_octets = [_]u8{0} ** 4;

    /// An unspecified IPv4 address.
    pub const unspecified: IPv4 = .{ .octets = unspecified_octets };

    /// Octets of a broadcast IPv4 address.
    pub const broadcast_octets = [_]u8{255} ** 4;

    /// An IPv4 broadcast address.
    pub const broadcast: IPv4 = .{ .octets = broadcast_octets };

    /// The prefix octet pattern of a link-local IPv4 address.
    pub const link_local_prefix = [_]u8{ 169, 254 };

    /// The prefix octet patterns of IPv4 addresses intended for
    /// documentation.
    pub const documentation_prefixes = [_][]const u8{
        &[_]u8{ 192, 0, 2 },
        &[_]u8{ 198, 51, 100 },
        &[_]u8{ 203, 0, 113 },
    };

    octets: [4]u8,

    /// Returns whether or not the two addresses are equal to, less than, or
    /// greater than each other.
    pub fn cmp(self: IPv4, other: IPv4) math.Order {
        return mem.order(u8, &self.octets, &other.octets);
    }

    /// Returns true if both addresses are semantically equivalent.
    pub fn eql(self: IPv4, other: IPv4) bool {
        return mem.eql(u8, &self.octets, &other.octets);
    }

    /// Returns true if the address is a loopback address.
    pub fn isLoopback(self: IPv4) bool {
        return self.octets[0] == 127;
    }

    /// Returns true if the address is an unspecified IPv4 address.
    pub fn isUnspecified(self: IPv4) bool {
        return mem.eql(u8, &self.octets, &unspecified_octets);
    }

    /// Returns true if the address is a private IPv4 address.
    pub fn isPrivate(self: IPv4) bool {
        return self.octets[0] == 10 or
            (self.octets[0] == 172 and self.octets[1] >= 16 and self.octets[1] <= 31) or
            (self.octets[0] == 192 and self.octets[1] == 168);
    }

    /// Returns true if the address is a link-local IPv4 address.
    pub fn isLinkLocal(self: IPv4) bool {
        return mem.startsWith(u8, &self.octets, &link_local_prefix);
    }

    /// Returns true if the address is a multicast IPv4 address.
    pub fn isMulticast(self: IPv4) bool {
        return self.octets[0] >= 224 and self.octets[0] <= 239;
    }

    /// Returns true if the address is a IPv4 broadcast address.
    pub fn isBroadcast(self: IPv4) bool {
        return mem.eql(u8, &self.octets, &broadcast_octets);
    }

    /// Returns true if the address is in a range designated for documentation. Refer
    /// to IETF RFC 5737 for more details.
    pub fn isDocumentation(self: IPv4) bool {
        inline for (documentation_prefixes) |prefix| {
            if (mem.startsWith(u8, &self.octets, prefix)) {
                return true;
            }
        }
        return false;
    }

    /// Implements the `std.fmt.format` API.
    pub fn format(
        self: IPv4,
        comptime layout: []const u8,
        opts: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = opts;
        if (comptime layout.len != 0 and layout[0] != 's') {
            @compileError("Unsupported format specifier for IPv4 type '" ++ layout ++ "'.");
        }

        try fmt.format(writer, "{}.{}.{}.{}", .{
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
        });
    }

    /// Set of possible errors that may encountered when parsing an IPv4
    /// address.
    pub const ParseError = error{
        UnexpectedEndOfOctet,
        TooManyOctets,
        OctetOverflow,
        UnexpectedToken,
        IncompleteAddress,
    };

    /// Parses an arbitrary IPv4 address.
    pub fn parse(buf: []const u8) ParseError!IPv4 {
        var octets: [4]u8 = undefined;
        var octet: u8 = 0;

        var index: u8 = 0;
        var saw_any_digits: bool = false;

        for (buf) |c| {
            switch (c) {
                '.' => {
                    if (!saw_any_digits) return error.UnexpectedEndOfOctet;
                    if (index == 3) return error.TooManyOctets;
                    octets[index] = octet;
                    index += 1;
                    octet = 0;
                    saw_any_digits = false;
                },
                '0'...'9' => {
                    saw_any_digits = true;
                    octet = math.mul(u8, octet, 10) catch return error.OctetOverflow;
                    octet = math.add(u8, octet, c - '0') catch return error.OctetOverflow;
                },
                else => return error.UnexpectedToken,
            }
        }

        if (index == 3 and saw_any_digits) {
            octets[index] = octet;
            return IPv4{ .octets = octets };
        }

        return error.IncompleteAddress;
    }

    /// Maps the address to its IPv6 equivalent. In most cases, you would
    /// want to map the address to its IPv6 equivalent rather than directly
    /// re-interpreting the address.
    pub fn mapToIPv6(self: IPv4) IPv6 {
        var octets: [16]u8 = undefined;
        mem.copy(u8, octets[0..12], &IPv6.v4_mapped_prefix);
        mem.copy(u8, octets[12..], &self.octets);
        return IPv6{ .octets = octets, .scope_id = IPv6.no_scope_id };
    }

    /// Directly re-interprets the address to its IPv6 equivalent. In most
    /// cases, you would want to map the address to its IPv6 equivalent rather
    /// than directly re-interpreting the address.
    pub fn toIPv6(self: IPv4) IPv6 {
        var octets: [16]u8 = undefined;
        mem.set(u8, octets[0..12], 0);
        mem.copy(u8, octets[12..], &self.octets);
        return IPv6{ .octets = octets, .scope_id = IPv6.no_scope_id };
    }
};

/// An IPv6 address comprised of 16 bytes for an address, and 4 bytes
/// for a scope ID; cumulatively summing to 20 bytes in total.
pub const IPv6 = extern struct {
    /// A IPv6 host-port pair.
    pub const Address = extern struct {
        host: IPv6,
        port: u16,
    };

    /// Octets of a IPv6 address designating the local host.
    pub const localhost_octets = [_]u8{0} ** 15 ++ [_]u8{0x01};

    /// The IPv6 address of the local host.
    pub const localhost: IPv6 = .{
        .octets = localhost_octets,
        .scope_id = no_scope_id,
    };

    /// Octets of an unspecified IPv6 address.
    pub const unspecified_octets = [_]u8{0} ** 16;

    /// An unspecified IPv6 address.
    pub const unspecified: IPv6 = .{
        .octets = unspecified_octets,
        .scope_id = no_scope_id,
    };

    /// The prefix of a IPv6 address that is mapped to a IPv4 address.
    pub const v4_mapped_prefix = [_]u8{0} ** 10 ++ [_]u8{0xFF} ** 2;

    /// A marker value used to designate an IPv6 address with no
    /// associated scope ID.
    pub const no_scope_id = math.maxInt(u32);

    octets: [16]u8,
    scope_id: u32,

    /// Returns whether or not the two addresses are equal to, less than, or
    /// greater than each other.
    pub fn cmp(self: IPv6, other: IPv6) math.Order {
        return switch (mem.order(u8, self.octets, other.octets)) {
            .eq => math.order(self.scope_id, other.scope_id),
            else => |order| order,
        };
    }

    /// Returns true if both addresses are semantically equivalent.
    pub fn eql(self: IPv6, other: IPv6) bool {
        return self.scope_id == other.scope_id and mem.eql(u8, &self.octets, &other.octets);
    }

    /// Returns true if the address is an unspecified IPv6 address.
    pub fn isUnspecified(self: IPv6) bool {
        return mem.eql(u8, &self.octets, &unspecified_octets);
    }

    /// Returns true if the address is a loopback address.
    pub fn isLoopback(self: IPv6) bool {
        return mem.eql(u8, self.octets[0..3], &[_]u8{ 0, 0, 0 }) and
            mem.eql(u8, self.octets[12..], &[_]u8{ 0, 0, 0, 1 });
    }

    /// Returns true if the address maps to an IPv4 address.
    pub fn mapsToIPv4(self: IPv6) bool {
        return mem.startsWith(u8, &self.octets, &v4_mapped_prefix);
    }

    /// Returns an IPv4 address representative of the address should
    /// it the address be mapped to an IPv4 address. It returns null
    /// otherwise.
    pub fn toIPv4(self: IPv6) ?IPv4 {
        if (!self.mapsToIPv4()) return null;
        return IPv4{ .octets = self.octets[12..][0..4].* };
    }

    /// Returns true if the address is a multicast IPv6 address.
    pub fn isMulticast(self: IPv6) bool {
        return self.octets[0] == 0xFF;
    }

    /// Returns true if the address is a unicast link local IPv6 address.
    pub fn isLinkLocal(self: IPv6) bool {
        return self.octets[0] == 0xFE and self.octets[1] & 0xC0 == 0x80;
    }

    /// Returns true if the address is a deprecated unicast site local
    /// IPv6 address. Refer to IETF RFC 3879 for more details as to
    /// why they are deprecated.
    pub fn isSiteLocal(self: IPv6) bool {
        return self.octets[0] == 0xFE and self.octets[1] & 0xC0 == 0xC0;
    }

    /// IPv6 multicast address scopes.
    pub const Scope = enum(u8) {
        interface = 1,
        link = 2,
        realm = 3,
        admin = 4,
        site = 5,
        organization = 8,
        global = 14,
        unknown = 0xFF,
    };

    /// Returns the multicast scope of the address.
    pub fn scope(self: IPv6) Scope {
        if (!self.isMulticast()) return .unknown;

        return switch (self.octets[0] & 0x0F) {
            1 => .interface,
            2 => .link,
            3 => .realm,
            4 => .admin,
            5 => .site,
            8 => .organization,
            14 => .global,
            else => .unknown,
        };
    }

    /// Implements the `std.fmt.format` API. Specifying 'x' or 's' formats the
    /// address lower-cased octets, while specifying 'X' or 'S' formats the
    /// address using upper-cased ASCII octets.
    ///
    /// The default specifier is 'x'.
    pub fn format(
        self: IPv6,
        comptime layout: []const u8,
        opts: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = opts;
        const specifier = comptime &[_]u8{if (layout.len == 0) 'x' else switch (layout[0]) {
            'x', 'X' => |specifier| specifier,
            's' => 'x',
            'S' => 'X',
            else => @compileError("Unsupported format specifier for IPv6 type '" ++ layout ++ "'."),
        }};

        if (mem.startsWith(u8, &self.octets, &v4_mapped_prefix)) {
            return fmt.format(writer, "::{" ++ specifier ++ "}{" ++ specifier ++ "}:{}.{}.{}.{}", .{
                0xFF,
                0xFF,
                self.octets[12],
                self.octets[13],
                self.octets[14],
                self.octets[15],
            });
        }

        const zero_span = span: {
            var i: usize = 0;
            while (i < self.octets.len) : (i += 2) {
                if (self.octets[i] == 0 and self.octets[i + 1] == 0) break;
            } else break :span .{ .from = 0, .to = 0 };

            const from = i;

            while (i < self.octets.len) : (i += 2) {
                if (self.octets[i] != 0 or self.octets[i + 1] != 0) break;
            }

            break :span .{ .from = from, .to = i };
        };

        var i: usize = 0;
        while (i != 16) : (i += 2) {
            if (zero_span.from != zero_span.to and i == zero_span.from) {
                try writer.writeAll("::");
            } else if (i >= zero_span.from and i < zero_span.to) {} else {
                if (i != 0 and i != zero_span.to) try writer.writeAll(":");

                const val = @as(u16, self.octets[i]) << 8 | self.octets[i + 1];
                try fmt.formatIntValue(val, specifier, .{}, writer);
            }
        }

        if (self.scope_id != no_scope_id and self.scope_id != 0) {
            try fmt.format(writer, "%{d}", .{self.scope_id});
        }
    }

    /// Set of possible errors that may encountered when parsing an IPv6
    /// address.
    pub const ParseError = error{
        MalformedV4Mapping,
        BadScopeID,
    } || IPv4.ParseError;

    /// Parses an arbitrary IPv6 address, including link-local addresses.
    pub fn parse(buf: []const u8) ParseError!IPv6 {
        if (mem.lastIndexOfScalar(u8, buf, '%')) |index| {
            const ip_slice = buf[0..index];
            const scope_id_slice = buf[index + 1 ..];

            if (scope_id_slice.len == 0) return error.BadScopeID;

            const scope_id: u32 = switch (scope_id_slice[0]) {
                '0'...'9' => fmt.parseInt(u32, scope_id_slice, 10),
                else => resolveScopeID(scope_id_slice),
            } catch return error.BadScopeID;

            return parseWithScopeID(ip_slice, scope_id);
        }

        return parseWithScopeID(buf, no_scope_id);
    }

    /// Parses an IPv6 address with a pre-specified scope ID. Presumes
    /// that the address is not a link-local address.
    pub fn parseWithScopeID(buf: []const u8, scope_id: u32) ParseError!IPv6 {
        var octets: [16]u8 = undefined;
        var octet: u16 = 0;
        var tail: [16]u8 = undefined;

        var out: []u8 = &octets;
        var index: u8 = 0;

        var saw_any_digits: bool = false;
        var abbrv: bool = false;

        for (buf) |c, i| {
            switch (c) {
                ':' => {
                    if (!saw_any_digits) {
                        if (abbrv) return error.UnexpectedToken;
                        if (i != 0) abbrv = true;
                        mem.set(u8, out[index..], 0);
                        out = &tail;
                        index = 0;
                        continue;
                    }
                    if (index == 14) return error.TooManyOctets;

                    out[index] = @truncate(u8, octet >> 8);
                    index += 1;
                    out[index] = @truncate(u8, octet);
                    index += 1;

                    octet = 0;
                    saw_any_digits = false;
                },
                '.' => {
                    if (!abbrv or out[0] != 0xFF and out[1] != 0xFF) {
                        return error.MalformedV4Mapping;
                    }
                    const start_index = mem.lastIndexOfScalar(u8, buf[0..i], ':').? + 1;
                    const v4 = try IPv4.parse(buf[start_index..]);
                    octets[10] = 0xFF;
                    octets[11] = 0xFF;
                    mem.copy(u8, octets[12..], &v4.octets);

                    return IPv6{ .octets = octets, .scope_id = scope_id };
                },
                else => {
                    saw_any_digits = true;
                    const digit = fmt.charToDigit(c, 16) catch return error.UnexpectedToken;
                    octet = math.mul(u16, octet, 16) catch return error.OctetOverflow;
                    octet = math.add(u16, octet, digit) catch return error.OctetOverflow;
                },
            }
        }

        if (!saw_any_digits and !abbrv) {
            return error.IncompleteAddress;
        }

        if (index == 14) {
            out[14] = @truncate(u8, octet >> 8);
            out[15] = @truncate(u8, octet);
        } else {
            out[index] = @truncate(u8, octet >> 8);
            index += 1;
            out[index] = @truncate(u8, octet);
            index += 1;
            mem.copy(u8, octets[16 - index ..], out[0..index]);
        }

        return IPv6{ .octets = octets, .scope_id = scope_id };
    }
};

test {
    testing.refAllDecls(@This());
}

test "ip: convert to and from ipv6" {
    try testing.expectFmt("::7f00:1", "{}", .{IPv4.localhost.toIPv6()});
    try testing.expect(!IPv4.localhost.toIPv6().mapsToIPv4());

    try testing.expectFmt("::ffff:127.0.0.1", "{}", .{IPv4.localhost.mapToIPv6()});
    try testing.expect(IPv4.localhost.mapToIPv6().mapsToIPv4());

    try testing.expect(IPv4.localhost.toIPv6().toIPv4() == null);
    try testing.expectFmt("127.0.0.1", "{}", .{IPv4.localhost.mapToIPv6().toIPv4()});
}

test "ipv4: parse & format" {
    const cases = [_][]const u8{
        "0.0.0.0",
        "255.255.255.255",
        "1.2.3.4",
        "123.255.0.91",
        "127.0.0.1",
    };

    for (cases) |case| {
        try testing.expectFmt(case, "{}", .{try IPv4.parse(case)});
    }
}

test "ipv6: parse & format" {
    const inputs = [_][]const u8{
        "FF01:0:0:0:0:0:0:FB",
        "FF01::Fb",
        "::1",
        "::",
        "2001:db8::",
        "::1234:5678",
        "2001:db8::1234:5678",
        "::ffff:123.5.123.5",
    };

    const outputs = [_][]const u8{
        "ff01::fb",
        "ff01::fb",
        "::1",
        "::",
        "2001:db8::",
        "::1234:5678",
        "2001:db8::1234:5678",
        "::ffff:123.5.123.5",
    };

    for (inputs) |input, i| {
        try testing.expectFmt(outputs[i], "{}", .{try IPv6.parse(input)});
    }
}

test "ipv6: parse & format addresses with scope ids" {
    if (!@hasDecl(os, "IFNAMESIZE")) return error.SkipZigTest;

    const inputs = [_][]const u8{
        "FF01::FB%lo",
    };

    const outputs = [_][]const u8{
        "ff01::fb%1",
    };

    for (inputs) |input, i| {
        try testing.expectFmt(outputs[i], "{}", .{try IPv6.parse(input)});
    }
}
