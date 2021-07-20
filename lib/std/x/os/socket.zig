// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("../../std.zig");
const net = @import("net.zig");

const os = std.os;
const fmt = std.fmt;
const mem = std.mem;
const time = std.time;
const meta = std.meta;
const native_target = @import("builtin").target;
const native_os = native_target.os;
const native_endian = native_target.cpu.arch.endian();

const Buffer = std.x.os.Buffer;

const assert = std.debug.assert;

/// A generic, cross-platform socket abstraction.
pub const Socket = struct {
    /// A socket-address pair.
    pub const Connection = struct {
        socket: Socket,
        address: Socket.Address,

        /// Enclose a socket and address into a socket-address pair.
        pub fn from(socket: Socket, address: Socket.Address) Socket.Connection {
            return .{ .socket = socket, .address = address };
        }
    };

    /// A generic socket address abstraction. It is safe to directly access and modify
    /// the fields of a `Socket.Address`.
    pub const Address = union(enum) {
        pub const Native = struct {
            pub const requires_prepended_length = native_os.getVersionRange() == .semver;
            pub const Length = if (requires_prepended_length) u8 else [0]u8;

            pub const Family = if (requires_prepended_length) u8 else c_ushort;

            /// POSIX `sockaddr_storage`. The expected size and alignment is specified in IETF RFC 2553.
            pub const Storage = extern struct {
                pub const expected_size = 128;
                pub const expected_alignment = 8;

                pub const padding_size = expected_size -
                    mem.alignForward(@sizeOf(Address.Native.Length), expected_alignment) -
                    mem.alignForward(@sizeOf(Address.Native.Family), expected_alignment);

                len: Address.Native.Length align(expected_alignment) = undefined,
                family: Address.Native.Family align(expected_alignment) = undefined,
                padding: [padding_size]u8 align(expected_alignment) = undefined,

                comptime {
                    assert(@sizeOf(Storage) == Storage.expected_size);
                    assert(@alignOf(Storage) == Storage.expected_alignment);
                }
            };
        };

        ipv4: net.IPv4.Address,
        ipv6: net.IPv6.Address,

        /// Instantiate a new address with a IPv4 host and port.
        pub fn initIPv4(host: net.IPv4, port: u16) Socket.Address {
            return .{ .ipv4 = .{ .host = host, .port = port } };
        }

        /// Instantiate a new address with a IPv6 host and port.
        pub fn initIPv6(host: net.IPv6, port: u16) Socket.Address {
            return .{ .ipv6 = .{ .host = host, .port = port } };
        }

        /// Parses a `sockaddr` into a generic socket address.
        pub fn fromNative(address: *align(4) const os.sockaddr) Socket.Address {
            switch (address.family) {
                os.AF_INET => {
                    const info = @ptrCast(*const os.sockaddr_in, address);
                    const host = net.IPv4{ .octets = @bitCast([4]u8, info.addr) };
                    const port = mem.bigToNative(u16, info.port);
                    return Socket.Address.initIPv4(host, port);
                },
                os.AF_INET6 => {
                    const info = @ptrCast(*const os.sockaddr_in6, address);
                    const host = net.IPv6{ .octets = info.addr, .scope_id = info.scope_id };
                    const port = mem.bigToNative(u16, info.port);
                    return Socket.Address.initIPv6(host, port);
                },
                else => unreachable,
            }
        }

        /// Encodes a generic socket address into an extern union that may be reliably
        /// casted into a `sockaddr` which may be passed into socket syscalls.
        pub fn toNative(self: Socket.Address) extern union {
            ipv4: os.sockaddr_in,
            ipv6: os.sockaddr_in6,
        } {
            return switch (self) {
                .ipv4 => |address| .{
                    .ipv4 = .{
                        .addr = @bitCast(u32, address.host.octets),
                        .port = mem.nativeToBig(u16, address.port),
                    },
                },
                .ipv6 => |address| .{
                    .ipv6 = .{
                        .addr = address.host.octets,
                        .port = mem.nativeToBig(u16, address.port),
                        .scope_id = address.host.scope_id,
                        .flowinfo = 0,
                    },
                },
            };
        }

        /// Returns the number of bytes that make up the `sockaddr` equivalent to the address.
        pub fn getNativeSize(self: Socket.Address) u32 {
            return switch (self) {
                .ipv4 => @sizeOf(os.sockaddr_in),
                .ipv6 => @sizeOf(os.sockaddr_in6),
            };
        }

        /// Implements the `std.fmt.format` API.
        pub fn format(
            self: Socket.Address,
            comptime layout: []const u8,
            opts: fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = opts;
            _ = layout;
            switch (self) {
                .ipv4 => |address| try fmt.format(writer, "{}:{}", .{ address.host, address.port }),
                .ipv6 => |address| try fmt.format(writer, "{}:{}", .{ address.host, address.port }),
            }
        }
    };

    /// POSIX `msghdr`. Denotes a destination address, set of buffers, control data, and flags. Ported
    /// directly from musl.
    pub const Message = if (native_os.isAtLeast(.windows, .vista) != null and native_os.isAtLeast(.windows, .vista).?)
        extern struct {
            name: usize = @ptrToInt(@as(?[*]u8, null)),
            name_len: c_int = 0,

            buffers: usize = undefined,
            buffers_len: c_ulong = undefined,

            control: Buffer = .{
                .ptr = @ptrToInt(@as(?[*]u8, null)),
                .len = 0,
            },
            flags: c_ulong = 0,

            pub usingnamespace MessageMixin(Message);
        }
    else if (native_os.tag == .windows)
        extern struct {
            name: usize = @ptrToInt(@as(?[*]u8, null)),
            name_len: c_int = 0,

            buffers: usize = undefined,
            buffers_len: u32 = undefined,

            control: Buffer = .{
                .ptr = @ptrToInt(@as(?[*]u8, null)),
                .len = 0,
            },
            flags: u32 = 0,

            pub usingnamespace MessageMixin(Message);
        }
    else if (@sizeOf(usize) > 4 and native_endian == .Big)
        extern struct {
            name: usize = @ptrToInt(@as(?[*]u8, null)),
            name_len: c_uint = 0,

            buffers: usize = undefined,
            _pad_1: c_int = 0,
            buffers_len: c_int = undefined,

            control: usize = @ptrToInt(@as(?[*]u8, null)),
            _pad_2: c_int = 0,
            control_len: c_uint = 0,

            flags: c_int = 0,

            pub usingnamespace MessageMixin(Message);
        }
    else if (@sizeOf(usize) > 4 and native_endian == .Little)
        extern struct {
            name: usize = @ptrToInt(@as(?[*]u8, null)),
            name_len: c_uint = 0,

            buffers: usize = undefined,
            buffers_len: c_int = undefined,
            _pad_1: c_int = 0,

            control: usize = @ptrToInt(@as(?[*]u8, null)),
            control_len: c_uint = 0,
            _pad_2: c_int = 0,

            flags: c_int = 0,

            pub usingnamespace MessageMixin(Message);
        }
    else
        extern struct {
            name: usize = @ptrToInt(@as(?[*]u8, null)),
            name_len: c_uint = 0,

            buffers: usize = undefined,
            buffers_len: c_int = undefined,

            control: usize = @ptrToInt(@as(?[*]u8, null)),
            control_len: c_uint = 0,

            flags: c_int = 0,

            pub usingnamespace MessageMixin(Message);
        };

    fn MessageMixin(comptime Self: type) type {
        return struct {
            pub fn fromBuffers(buffers: []const Buffer) Self {
                var self: Self = .{};
                self.setBuffers(buffers);
                return self;
            }

            pub fn setName(self: *Self, name: []const u8) void {
                self.name = @ptrToInt(name.ptr);
                self.name_len = @intCast(meta.fieldInfo(Self, .name_len).field_type, name.len);
            }

            pub fn setBuffers(self: *Self, buffers: []const Buffer) void {
                self.buffers = @ptrToInt(buffers.ptr);
                self.buffers_len = @intCast(meta.fieldInfo(Self, .buffers_len).field_type, buffers.len);
            }

            pub fn setControl(self: *Self, control: []const u8) void {
                if (native_os.tag == .windows) {
                    self.control = Buffer.from(control);
                } else {
                    self.control = @ptrToInt(control.ptr);
                    self.control_len = @intCast(meta.fieldInfo(Self, .control_len).field_type, control.len);
                }
            }

            pub fn setFlags(self: *Self, flags: u32) void {
                self.flags = @intCast(meta.fieldInfo(Self, .flags).field_type, flags);
            }

            pub fn getName(self: Self) []const u8 {
                return @intToPtr([*]const u8, self.name)[0..@intCast(usize, self.name_len)];
            }

            pub fn getBuffers(self: Self) []const Buffer {
                return @intToPtr([*]const Buffer, self.buffers)[0..@intCast(usize, self.buffers_len)];
            }

            pub fn getControl(self: Self) []const u8 {
                if (native_os.tag == .windows) {
                    return self.control.into();
                } else {
                    return @intToPtr([*]const u8, self.control)[0..@intCast(usize, self.control_len)];
                }
            }

            pub fn getFlags(self: Self) u32 {
                return @intCast(u32, self.flags);
            }
        };
    }

    /// POSIX `linger`, denoting the linger settings of a socket.
    ///
    /// Microsoft's documentation and glibc denote the fields to be unsigned
    /// short's on Windows, whereas glibc and musl denote the fields to be
    /// int's on every other platform.
    pub const Linger = extern struct {
        pub const Field = switch (native_os.tag) {
            .windows => c_ushort,
            else => c_int,
        };

        enabled: Field,
        timeout_seconds: Field,

        pub fn init(timeout_seconds: ?u16) Socket.Linger {
            return .{
                .enabled = @intCast(Socket.Linger.Field, @boolToInt(timeout_seconds != null)),
                .timeout_seconds = if (timeout_seconds) |seconds| @intCast(Socket.Linger.Field, seconds) else 0,
            };
        }
    };

    /// Possible set of flags to initialize a socket with.
    pub const InitFlags = enum {
        // Initialize a socket to be non-blocking.
        nonblocking,

        // Have a socket close itself on exec syscalls.
        close_on_exec,
    };

    /// The underlying handle of a socket.
    fd: os.socket_t,

    /// Enclose a socket abstraction over an existing socket file descriptor.
    pub fn from(fd: os.socket_t) Socket {
        return Socket{ .fd = fd };
    }

    /// Mix in socket syscalls depending on the platform we are compiling against.
    pub usingnamespace switch (native_os.tag) {
        .windows => @import("socket_windows.zig"),
        else => @import("socket_posix.zig"),
    }.Mixin(Socket);
};
