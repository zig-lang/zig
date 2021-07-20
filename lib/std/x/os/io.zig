const std = @import("../../std.zig");

const os = std.os;
const mem = std.mem;
const testing = std.testing;
const native_os = @import("builtin").os;

/// POSIX `iovec`, or Windows `WSABUF`. The difference between the two are the ordering
/// of fields, alongside the length being represented as either a ULONG or a size_t.
pub const Buffer = if (native_os.tag == .windows)
    extern struct {
        len: c_ulong,
        ptr: usize,

        pub fn from(slice: []const u8) Buffer {
            return .{ .len = @intCast(c_ulong, slice.len), .ptr = @ptrToInt(slice.ptr) };
        }

        pub fn into(self: Buffer) []const u8 {
            return @intToPtr([*]const u8, self.ptr)[0..self.len];
        }

        pub fn intoMutable(self: Buffer) []u8 {
            return @intToPtr([*]u8, self.ptr)[0..self.len];
        }
    }
else
    extern struct {
        ptr: usize,
        len: usize,

        pub fn from(slice: []const u8) Buffer {
            return .{ .ptr = @ptrToInt(slice.ptr), .len = slice.len };
        }

        pub fn into(self: Buffer) []const u8 {
            return @intToPtr([*]const u8, self.ptr)[0..self.len];
        }

        pub fn intoMutable(self: Buffer) []u8 {
            return @intToPtr([*]u8, self.ptr)[0..self.len];
        }
    };

pub const Reactor = struct {
    pub const InitFlags = enum {
        close_on_exec,
    };

    pub const Event = struct {
        data: usize,
        is_error: bool,
        is_hup: bool,
        is_readable: bool,
        is_writable: bool,
    };

    pub const Interest = struct {
        hup: bool = false,
        oneshot: bool = false,
        readable: bool = false,
        writable: bool = false,
    };

    fd: os.fd_t,

    pub fn init(flags: std.enums.EnumFieldStruct(Reactor.InitFlags, bool, false)) !Reactor {
        var raw_flags: u32 = 0;
        const set = std.EnumSet(Reactor.InitFlags).init(flags);
        if (set.contains(.close_on_exec)) raw_flags |= os.EPOLL_CLOEXEC;
        return Reactor{ .fd = try os.epoll_create1(raw_flags) };
    }

    pub fn deinit(self: Reactor) void {
        os.close(self.fd);
    }

    pub fn update(self: Reactor, fd: os.fd_t, identifier: usize, interest: Reactor.Interest) !void {
        var flags: u32 = 0;
        flags |= if (interest.oneshot) os.EPOLLONESHOT else os.EPOLLET;
        if (interest.hup) flags |= os.EPOLLRDHUP;
        if (interest.readable) flags |= os.EPOLLIN;
        if (interest.writable) flags |= os.EPOLLOUT;

        const event = &os.epoll_event{
            .events = flags,
            .data = .{ .ptr = identifier },
        };

        os.epoll_ctl(self.fd, os.EPOLL_CTL_MOD, fd, event) catch |err| switch (err) {
            error.FileDescriptorNotRegistered => try os.epoll_ctl(self.fd, os.EPOLL_CTL_ADD, fd, event),
            else => return err,
        };
    }

    pub fn poll(self: Reactor, comptime max_num_events: comptime_int, closure: anytype, timeout_milliseconds: ?u64) !void {
        var events: [max_num_events]os.epoll_event = undefined;

        const num_events = os.epoll_wait(self.fd, &events, if (timeout_milliseconds) |ms| @intCast(i32, ms) else -1);
        for (events[0..num_events]) |ev| {
            const is_error = ev.events & os.EPOLLERR != 0;
            const is_hup = ev.events & (os.EPOLLHUP | os.EPOLLRDHUP) != 0;
            const is_readable = ev.events & os.EPOLLIN != 0;
            const is_writable = ev.events & os.EPOLLOUT != 0;

            try closure.call(Reactor.Event{
                .data = ev.data.ptr,
                .is_error = is_error,
                .is_hup = is_hup,
                .is_readable = is_readable,
                .is_writable = is_writable,
            });
        }
    }
};

test "reactor/linux: drive async tcp client/listener pair" {
    if (native_os.tag != .linux) return error.SkipZigTest;

    const ip = std.x.net.ip;
    const tcp = std.x.net.tcp;

    const IPv4 = std.x.os.IPv4;
    const IPv6 = std.x.os.IPv6;

    const reactor = try Reactor.init(.{ .close_on_exec = true });
    defer reactor.deinit();

    const listener = try tcp.Listener.init(.ip, .{
        .close_on_exec = true,
        .nonblocking = true,
    });
    defer listener.deinit();

    try reactor.update(listener.socket.fd, 0, .{ .readable = true });
    try reactor.poll(1, struct {
        fn call(event: Reactor.Event) !void {
            try testing.expectEqual(Reactor.Event{
                .data = 0,
                .is_error = false,
                .is_hup = true,
                .is_readable = false,
                .is_writable = false,
            }, event);
        }
    }, null);

    try listener.bind(ip.Address.initIPv4(IPv4.unspecified, 0));
    try listener.listen(128);

    var binded_address = try listener.getLocalAddress();
    switch (binded_address) {
        .ipv4 => |*ipv4| ipv4.host = IPv4.localhost,
        .ipv6 => |*ipv6| ipv6.host = IPv6.localhost,
    }

    const client = try tcp.Client.init(.ip, .{
        .close_on_exec = true,
        .nonblocking = true,
    });
    defer client.deinit();

    try reactor.update(client.socket.fd, 1, .{ .readable = true, .writable = true });
    try reactor.poll(1, struct {
        fn call(event: Reactor.Event) !void {
            try testing.expectEqual(Reactor.Event{
                .data = 1,
                .is_error = false,
                .is_hup = true,
                .is_readable = false,
                .is_writable = true,
            }, event);
        }
    }, null);

    client.connect(binded_address) catch |err| switch (err) {
        error.WouldBlock => {},
        else => return err,
    };

    try reactor.poll(1, struct {
        fn call(event: Reactor.Event) !void {
            try testing.expectEqual(Reactor.Event{
                .data = 1,
                .is_error = false,
                .is_hup = false,
                .is_readable = false,
                .is_writable = true,
            }, event);
        }
    }, null);

    try reactor.poll(1, struct {
        fn call(event: Reactor.Event) !void {
            try testing.expectEqual(Reactor.Event{
                .data = 0,
                .is_error = false,
                .is_hup = false,
                .is_readable = true,
                .is_writable = false,
            }, event);
        }
    }, null);
}
