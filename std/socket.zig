pub usingnamespace @import("errors.zig");
usingnamespace @import("errors.zig");

const std = @import("../index.zig");
const builtin = @import("builtin");
const net = std.net;
const os = std.os;

const is_windows = builtin.os == Os.windows;

const is_posix = switch (builtin.os) {
    builtin.Os.linux, builtin.Os.macosx, builtin.Os.freebsd => true,
    else => false,
};

const unexpectedError = switch (builtin.os) {
    builtin.Os.windows => system.unexpectedError,
    else => os.unexpectedErrno,
};

pub const SocketFd = switch (builtin.os) {
    builtin.Os.windows => system.SOCKET,
    else => i32,
};

pub const InvalidSocketFd: SocketFd = switch (builtin.os) {
    builtin.Os.windows => system.INVALID_SOCKET,
    else => -1,
};

pub const Domain = enum {
    Unspecified,
    Unix,
    Inet,
    Inet6,

    fn toInt(self: Domain, comptime T: type) T {
        return @intCast(T, switch (self) {
            Domain.Unspecified => system.AF_UNSPEC,
            Domain.Unix => system.AF_UNIX,
            Domain.Inet => system.AF_INET,
            Domain.Inet6 => system.AF_INET6,
        });
    }
};

pub const SocketType = enum {
    Stream,
    DataGram,
    Raw,
    SeqPacket,

    fn toInt(self: SocketType, comptime T: type) T {
        return @intCast(T, switch (self) {
            SocketType.Stream => system.SOCK_STREAM,
            SocketType.DataGram => system.SOCK_DGRAM,
            SocketType.Raw => system.SOCK_RAW,
            SocketType.SeqPacket => system.SOCK_SEQPACKET,
        });
    }
};

pub const Protocol = enum {
    Unix,
    TCP,
    UDP,
    IP,
    IPV6,
    RAW,
    ICMP,

    fn toInt(self: Protocol, comptime T: type) !T {
        return @intCast(T, switch (self) {
            Protocol.Unix => if (is_posix) 0 else return SocketError.ProtocolNotSupported,
            Protocol.TCP => if (is_posix) system.PROTO_tcp else system.IPPROTO_TCP,
            Protocol.UDP => if (is_posix) system.PROTO_udp else system.IPPROTO_UDP,
            Protocol.IP => if (is_posix) system.PROTO_ip else system.IPPROTO_IP,
            Protocol.IPV6 => if (is_posix) system.PROTO_ipv6 else system.IPPROTO_IPV6,
            Protocol.RAW => if (is_posix) system.PROTO_raw else system.IPPROTO_RAW,
            Protocol.ICMP => if (is_posix) system.PROTO_icmp else system.IPPROTO_ICMP,
        });
    }
};

pub const Shutdown = enum {
    Read = if (is_posix) system.SHUT_RD else system.SD_RECEIVE,
    Write = if (is_posix) system.SHUT_WR else system.SD_SEND,
    Both = if (is_posix) system.SHUT_RDWR else system.SD_BOTH,

    fn toInt(self: Shutdown, comptime T: type) T {
        return @intCast(T, switch (self) {
            Shutdown.Read => if (is_posix) system.SHUT_RD else system.SD_RECEIVE,
            Shutdown.Write => if (is_posix) system.SHUT_WR else system.SD_SEND,
            Shutdown.Both => if (is_posix) system.SHUT_RDWR else system.SD_BOTH,
        });
    }
};

// pub const Level = enum(u32) {
//     IP = if (is_posix) system.SOL_IP ,
//     IPV6 = if (is_posix) system.SOL_IPV6 ,
//     RM = if (is_posix) system. ,
//     TCP = if (is_posix) system. ,
//     UDP = if (is_posix) system. ,
//     IPX = if (is_posix) system. ,
//     AppleTalk = if (is_posix) system. ,
//     IRLMP = if (is_posix) system. ,
//     Socket = if (is_posix) system. ,
// };

fn accept4Windows(fd: SocketFd, addr: ?*net.OsAddress, addrlen: ?*system.socklen_t, flags: u32) SocketFd {
    const result = system.accept(fd, addr, @ptrCast(*c_int, addrlen));
    const ioctl_mode = @boolToInt((@intCast(c_ulong, flags) & system.FIONBIO) == system.FIONBIO);
    const no_inherit = (flags & system.WSA_FLAG_NO_HANDLE_INHERIT);

    if (system.ioctlsocket(result, system.FIONBIO, &@intCast(c_ulong, ioctl_mode)) != 0) {
        return InvalidSocketFd;
    }

    if (no_inherit == system.WSA_FLAG_NO_HANDLE_INHERIT) {
        const handle = @intToPtr(system.HANDLE, result);
        if (system.SetHandleInformation(handle, system.HANDLE_FLAG_INHERIT, 0) == system.FALSE) {
            return InvalidSocketFd;
        }
    }

    return result;
}

// add timeouts

pub const Socket = struct {
    fd: SocketFd,
    domain: Domain,
    socket_type: SocketType,
    protocol: Protocol,

    fn initSocket(fd: SocketFd, domain: Domain, socket_type: SocketType, protocol: Protocol) Socket {
        return Socket{
            .fd = @intCast(SocketFd, rc),
            .domain = domain,
            .socket_type = socket_type,
            .protocol = protocol,
        };
    }

    pub fn new(domain: Domain, socket_type: SocketType, protocol: Protocol) SocketError!Socket {
        if (is_posix) {
            const rc = system.socket(domain.toInt(u32), socket_type.toInt(u32), try protocol.toInt(u32));
            const err = system.getErrno(rc);
            switch (err) {
                0 => return initSocket(@intCast(SocketFd, rc), domain, socket_type, protocol),
                system.EACCES => return SocketError.PermissionDenied,
                system.EAFNOSUPPORT => return SocketError.AddressFamilyNotSupported,
                system.EINVAL => return SocketError.ProtocolFamilyNotAvailable,
                system.EMFILE => return SocketError.ProcessFdQuotaExceeded,
                system.ENFILE => return SocketError.system.emFdQuotaExceeded,
                system.ENOBUFS, system.ENOMEM => return SocketError.system.emResources,
                system.EPROTONOSUPPORT => return SocketError.ProtocolNotSupported,
                else => return unexpectedError(err),
            }
        } else {
            const rc = system.socket(domain.toInt(c_int), sock_type.toInt(c_int), try protocol.toInt(c_int));
            const err = system.WSAGetLastError();
            // TODO check for TOO_MANY_OPEN_FILES?
            switch (err) {
                0 => return initSocket(rc, domain, socket_type, protocol),
                system.ERROR.WSAEACCES => return SocketError.PermissionDenied,
                system.ERROR.WSAEAFNOSUPPORT => return SocketError.AddressFamilyNotSupported,
                system.ERROR.WSAEINVAL => return SocketError.ProtocolFamilyNotAvailable,
                system.ERROR.WSAEMFILE => return SocketError.ProcessFdQuotaExceeded,
                system.ERROR.WSAENOBUFS => return SocketError.system.emResources,
                system.ERROR.WSAEPROTONOSUPPORT, system.ERROR.WSAEPROTOTYPE, system.ERROR.WSAESOCKTNOSUPPORT => return SocketError.ProtocolNotSupported,
                else => return unexpectedError(@intCast(u32, err)),
            }
        }
    }

    pub fn tcp(domain: Domain) SocketError!Socket {
        return Socket.new(domain, SocketType.Stream, Protocol.TCP);
    }

    pub fn udp(domain: Domain) SocketError!Socket {
        return Socket.new(domain, SocketType.DataGram, Protocol.UDP);
    }

    pub fn unix(socket_type: SocketType) SocketError!Socket {
        return Socket.new(Domain.Unix, socket_type, Protocol.Unix);
    }

    pub fn bind(self: Socket, addr: *const net.Address) BindError!void {
        const rc = system.bind(self.fd, &addr.os_addr, @sizeOf(net.OsAddress));

        if (is_posix) {
            const err = system.getErrno(@intCast(usize, rc));
            switch (err) {
                0 => return,
                system.EACCES => return BindError.AccessDenied,
                system.EADDRINUSE => return BindError.AddressInUse,
                system.EBADF => unreachable, // always a race condition if this error is returned
                system.EINVAL => unreachable,
                system.ENOTSOCK => unreachable,
                system.EADDRNOTAVAIL => return BindError.AddressNotAvailable,
                system.EFAULT => unreachable,
                system.ELOOP => return BindError.SymLinkLoop,
                system.ENAMETOOLONG => return BindError.NameTooLong,
                system.ENOENT => return BindError.FileNotFound,
                system.ENOMEM => return BindError.system.emResources,
                system.ENOTDIR => return BindError.NotDir,
                system.EROFS => return BindError.ReadOnlyFilesystem.em,
                else => return unexpectedError(err),
            }
        } else {
            const err = system.WSAGetLastError();
            switch (err) {
                0 => return,
                system.ERROR.WSAEACCES => return BindError.AccessDenied,
                system.ERROR.WSAEADDRINUSE => return BindError.AddressInUse,
                system.ERROR.WSAEINVAL => unreachable,
                system.ERROR.WSAENOTSOCK => unreachable,
                system.ERROR.WSAEADDRNOTAVAIL => return BindError.AddressNotAvailable,
                system.ERROR.WSAEFAULT => unreachable,
                else => return unexpectedError(@intCast(u32, err)),
            }
        }
    }

    pub fn listen(self: Socket, backlog: u32) ListenError!void {
        if (is_posix) {
            const rc = system.listen(self.fd, backlog);
            const err = system.getErrno(@intCast(usize, rc));
            switch (err) {
                0 => return,
                system.EADDRINUSE => return ListenError.AddressInUse,
                system.EBADF => unreachable,
                system.ENOTSOCK => return ListenError.FileDescriptorNotASocket,
                system.EOPNOTSUPP => return ListenError.OperationNotSupported,
                else => return unexpectedError(err),
            }
        } else {
            const rc = system.listen(self.fd, @intCast(c_int, backlog));
            const err = system.WSAGetLastError();
            switch (err) {
                0 => return,
                system.ERROR.WSAEADDRINUSE => return ListenError.AddressInUse,
                system.ERROR.WSAENOTSOCK => return ListenError.FileDescriptorNotASocket,
                // these are technically protocol/domain errors
                system.ERROR.WSAEPROTOTYPE, system.ERROR.WSAEPROTONOSUPPORT, system.ERROR.WSAESOCKTNOSUPPORT => return ListenError.OperationNotSupported,
                system.ERROR.WSAENOBUFS, system.ERROR.WSAEMFILE => unreachable, // return error for this? (system.em resources)
                system.ERROR.WSAEISCONN => unreachable, // return error for this? (already connected)
                system.ERROR.WSAEINVAL => unreachable, // return error for this? (not bound)
                else => return unexpectedError(@intCast(u32, err)),
            }
        }
    }

    pub fn accept(self: Socket, addr: *net.Address, flags: u32) AcceptError!Socket {
        if (is_posix) {
            while (true) {
                var sockaddr_size = system.socklen_t(@sizeOf(net.OsAddress));
                const rc = system.accept4(self.fd, &addr.os_addr, &sockaddr_size, flags);
                const err = system.getErrno(rc);
                switch (err) {
                    0 => return initSocket(@intCast(SocketFd, rc), self.domain, self.socket_type, self.protocol),
                    system.EINTR => continue,
                    else => return unexpectedError(err),
                    system.EAGAIN => unreachable, // use asyncAccept for non-blocking
                    system.EBADF => unreachable, // always a race condition
                    system.ECONNABORTED => return AcceptError.ConnectionAborted,
                    system.EFAULT => unreachable,
                    system.EINVAL => unreachable,
                    system.EMFILE => return AcceptError.ProcessFdQuotaExceeded,
                    system.ENFILE => return AcceptError.system.emFdQuotaExceeded,
                    system.ENOBUFS => return AcceptError.system.emResources,
                    system.ENOMEM => return AcceptError.system.emResources,
                    system.ENOTSOCK => return AcceptError.FileDescriptorNotASocket,
                    system.EOPNOTSUPP => return AcceptError.OperationNotSupported,
                    system.EPROTO => return AcceptError.ProtocolFailure,
                    system.EPERM => return AcceptError.BlockedByFirewall,
                }
            }
        } else {
            while (true) {
                var sockaddr_size = system.socklen_t(@sizeOf(net.OsAddress));
                // port accept4
                const rc = accept4Windows(self.fd, &addr.os_addr, &sockaddr_size, flags);
                const err = system.WSAGetLastError();
                switch (err) {
                    0 => {
                        if (rc == InvalidSocketFd) {
                            return unexpectedError(@intCast(u32, system.GetLastError()));
                        } else {
                            return initSocket(rc, self.domain, self.socket_type, self.protocol);
                        }
                    },
                    system.ERROR.WSAEINTR => continue,
                    else => return unexpectedError(@intCast(u32, err)),
                    // TODO check for TOO_MANY_OPEN_FILES?
                    system.ERROR.WSAEWOULDBLOCK => unreachable, // use asyncAccept for non-blocking
                    system.ERROR.WSAECONNRESET => return AcceptError.ConnectionAborted,
                    system.ERROR.WSAEFAULT => unreachable,
                    system.ERROR.WSAEINVAL => unreachable,
                    system.ERROR.WSAEMFILE => return AcceptError.ProcessFdQuotaExceeded,
                    system.ERROR.WSAENOBUFS => return AcceptError.system.emResources,
                    system.ERROR.WSAENOTSOCK => return AcceptError.FileDescriptorNotASocket,
                    system.ERROR.WSAEOPNOTSUPP => return AcceptError.OperationNotSupported,
                }
            }
        }
    }

    /// Returns InvalidSocketFd if would block.
    pub fn asyncAccept(self: Socket, addr: *net.Address, flags: u32) AcceptError!Socket {
        if (is_posix) {
            while (true) {
                var sockaddr_size = system.socklen_t(@sizeOf(net.OsAddress));
                const rc = system.accept4(self.fd, &addr.os_addr, &sockaddr_size, flags);
                const err = system.getErrno(rc);
                switch (err) {
                    0 => return initSocket(@intCast(SocketFd, rc), self.domain, self.socket_type, self.protocol),
                    system.EINTR => continue,
                    else => return unexpectedError(err),
                    system.EAGAIN => return InvalidSocketFd,
                    system.EBADF => unreachable, // always a race condition
                    system.ECONNABORTED => return AcceptError.ConnectionAborted,
                    system.EFAULT => unreachable,
                    system.EINVAL => unreachable,
                    system.EMFILE => return AcceptError.ProcessFdQuotaExceeded,
                    system.ENFILE => return AcceptError.system.emFdQuotaExceeded,
                    system.ENOBUFS => return AcceptError.system.emResources,
                    system.ENOMEM => return AcceptError.system.emResources,
                    system.ENOTSOCK => return AcceptError.FileDescriptorNotASocket,
                    system.EOPNOTSUPP => return AcceptError.OperationNotSupported,
                    system.EPROTO => return AcceptError.ProtocolFailure,
                    system.EPERM => return AcceptError.BlockedByFirewall,
                }
            }
        } else {
            while (true) {
                var sockaddr_size = system.socklen_t(@sizeOf(net.OsAddress));
                const rc = accept4Windows(self.fd, &addr.os_addr, &sockaddr_size, flags);
                const err = system.WSAGetLastError();
                // TODO check for TOO_MANY_OPEN_FILES?
                switch (err) {
                    0 => return initSocket(rc, self.domain, self.socket_type, self.protocol),
                    system.ERROR.WSAEINTR => continue,
                    else => return unexpectedError(@intCast(u32, err)),
                    system.ERROR.WSAEWOULDBLOCK => return InvalidSocketFd,
                    system.ERROR.WSAECONNRESET => return AcceptError.ConnectionAborted,
                    system.ERROR.WSAEFAULT => unreachable,
                    system.ERROR.WSAEINVAL => unreachable,
                    system.ERROR.WSAEMFILE => return AcceptError.ProcessFdQuotaExceeded,
                    system.ERROR.WSAENOBUFS => return AcceptError.system.emResources,
                    system.ERROR.WSAENOTSOCK => return AcceptError.FileDescriptorNotASocket,
                    system.ERROR.WSAEOPNOTSUPP => return AcceptError.OperationNotSupported,
                    system.ERROR.WSAEACCES => return AcceptError.BlockedByFirewall,
                }
            }
        }
    }

    pub fn connect(self: Socket, addr: *const net.Address) ConnectError!void {
        if (is_posix) {
            while (true) {
                const rc = system.connect(self.fd, &addr.os_addr, @sizeOf(net.OsAddress));
                const err = system.getErrno(rc);
                switch (err) {
                    0 => return,
                    system.EPERM => return AcceptError.BlockedByFirewall,
                    system.EACCES => return ConnectError.PermissionDenied,
                    system.EADDRINUSE => return ConnectError.AddressInUse,
                    system.EADDRNOTAVAIL => return ConnectError.AddressNotAvailable,
                    system.EAFNOSUPPORT => return ConnectError.AddressFamilyNotSupported,
                    system.EAGAIN => return ConnectError.system.emResources,
                    system.EALREADY => unreachable, // The socket is nonblocking and a previous connection attempt has not yet been completed.
                    system.EBADF => unreachable, // socket is not a valid open file descriptor.
                    system.ECONNREFUSED => return ConnectError.ConnectionRefused,
                    system.EFAULT => unreachable, // The socket structure address is outside the user's address space.
                    system.EINPROGRESS => unreachable, // The socket is nonblocking and the connection cannot be completed immediately.
                    system.EINTR => continue,
                    system.EISCONN => unreachable, // The socket is already connected.
                    system.ENETUNREACH => return ConnectError.NetworkUnreachable,
                    system.ENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
                    system.EPROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
                    system.ETIMEDOUT => return ConnectError.ConnectionTimedOut,
                    else => return unexpectedError(err),
                }
            }
        } else {
            while (true) {
                const rc = system.connect(self.fd, &addr.os_addr, @sizeOf(net.OsAddress));
                const err = system.WSAGetLastError();
                switch (err) {
                    0 => return,
                    system.ERROR.WSAEACCES => return ConnectError.PermissionDenied,
                    system.ERROR.WSAEADDRINUSE => return ConnectError.AddressInUse,
                    system.ERROR.WSAEADDRNOTAVAIL => return ConnectError.AddressNotAvailable,
                    system.ERROR.WSAEAFNOSUPPORT => return ConnectError.AddressFamilyNotSupported,
                    system.ERROR.WSAEWOULDBLOCK => return ConnectError.system.emResources,
                    system.ERROR.WSAEALREADY => unreachable, // The socket is nonblocking and a previous connection attempt has not yet been completed.
                    system.ERROR.WSAECONNREFUSED => return ConnectError.ConnectionRefused,
                    system.ERROR.WSAEFAULT => unreachable, // The socket structure address is outside the user's address space.
                    system.ERROR.WSAEINPROGRESS => unreachable, // The socket is nonblocking and the connection cannot be completed immediately.
                    system.ERROR.WSAEINTR => continue,
                    system.ERROR.WSAEISCONN => unreachable, // The socket is already connected.
                    system.ERROR.WSAENETUNREACH => return ConnectError.NetworkUnreachable,
                    system.ERROR.WSAEHOSTUNREACH => unreachable, // return error for this? (unreachable host)
                    system.ERROR.WSAENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
                    system.ERROR.WSAETIMEDOUT => return ConnectError.ConnectionTimedOut,
                    system.ERROR.WSAENOBUFS => ConnectError.system.emResources,
                    else => return unexpectedError(@intCast(u32, err)),
                }
            }
        }
    }

    /// Same as connect except it is for blocking socket file descriptors.
    /// It expects to receive EINPROGRESS.
    pub fn connectAsync(self: Sokcet, addr: *const net.Address) ConnectError!void {
        if (is_posix) {
            while (true) {
                const rc = system.connect(self.fd, &addr.os_addr, @sizeOf(net.OsAddress));
                const err = system.getErrno(rc);
                switch (err) {
                    0, system.EINPROGRESS => return,
                    system.EPERM => return AcceptError.BlockedByFirewall,
                    system.EACCES => return ConnectError.PermissionDenied,
                    system.EADDRINUSE => return ConnectError.AddressInUse,
                    system.EADDRNOTAVAIL => return ConnectError.AddressNotAvailable,
                    system.EAFNOSUPPORT => return ConnectError.AddressFamilyNotSupported,
                    system.EAGAIN => return ConnectError.system.emResources,
                    system.EALREADY => unreachable, // The socket is nonblocking and a previous connection attempt has not yet been completed.
                    system.EBADF => unreachable, // socket is not a valid open file descriptor.
                    system.ECONNREFUSED => return ConnectError.ConnectionRefused,
                    system.EFAULT => unreachable, // The socket structure address is outside the user's address space.
                    system.EINTR => continue,
                    system.EISCONN => unreachable, // The socket is already connected.
                    system.ENETUNREACH => return ConnectError.NetworkUnreachable,
                    system.ENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
                    system.EPROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
                    system.ETIMEDOUT => return ConnectError.ConnectionTimedOut,
                    else => return unexpectedError(err),
                }
            }
        } else {
            while (true) {
                const rc = system.connect(self.fd, &addr.os_addr, @sizeOf(net.OsAddress));
                const err = system.WSAGetLastError();
                switch (err) {
                    0, system.ERROR.WSAEINPROGRESS => return,
                    system.ERROR.WSAEACCES => return ConnectError.PermissionDenied,
                    system.ERROR.WSAEADDRINUSE => return ConnectError.AddressInUse,
                    system.ERROR.WSAEADDRNOTAVAIL => return ConnectError.AddressNotAvailable,
                    system.ERROR.WSAEAFNOSUPPORT => return ConnectError.AddressFamilyNotSupported,
                    system.ERROR.WSAEWOULDBLOCK => return ConnectError.system.emResources,
                    system.ERROR.WSAEALREADY => unreachable, // The socket is nonblocking and a previous connection attempt has not yet been completed.
                    system.ERROR.WSAECONNREFUSED => return ConnectError.ConnectionRefused,
                    system.ERROR.WSAEFAULT => unreachable, // The socket structure address is outside the user's address space.
                    system.ERROR.WSAEINTR => continue,
                    system.ERROR.WSAEISCONN => unreachable, // The socket is already connected.
                    system.ERROR.WSAENETUNREACH => return ConnectError.NetworkUnreachable,
                    system.ERROR.WSAEHOSTUNREACH => unreachable, // return error for this? (unreachable host)
                    system.ERROR.WSAENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
                    system.ERROR.WSAETIMEDOUT => return ConnectError.ConnectionTimedOut,
                    system.ERROR.WSAENOBUFS => ConnectError.system.emResources,
                    else => return unexpectedError(@intCast(u32, err)),
                }
            }
        }
    }

    pub fn getSockOptConnectError(self: Socket) ConnectError!void {
        var err_code: i32 = undefined;
        var size: u32 = @sizeOf(i32);
        const rc = system.getsockopt(self.fd, system.SOL_SOCKET, system.SO_ERROR, @ptrCast([*]u8, &err_code), &size);
        assert(size == 4);
        if (is_posix) {
            const err = system.getErrno(rc);
            switch (err) {
                0 => switch (err_code) {
                    0 => return,
                    system.EPERM => return AcceptError.BlockedByFirewall,
                    system.EACCES => return ConnectError.PermissionDenied,
                    system.EADDRINUSE => return ConnectError.AddressInUse,
                    system.EADDRNOTAVAIL => return ConnectError.AddressNotAvailable,
                    system.EAFNOSUPPORT => return ConnectError.AddressFamilyNotSupported,
                    system.EAGAIN => return ConnectError.system.emResources,
                    system.EALREADY => unreachable, // The socket is nonblocking and a previous connection attempt has not yet been completed.
                    system.EBADF => unreachable, // socket is not a valid open file descriptor.
                    system.ECONNREFUSED => return ConnectError.ConnectionRefused,
                    system.EFAULT => unreachable, // The socket structure address is outside the user's address space.
                    system.EISCONN => unreachable, // The socket is already connected.
                    system.ENETUNREACH => return ConnectError.NetworkUnreachable,
                    system.ENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
                    system.EPROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
                    system.ETIMEDOUT => return ConnectError.ConnectionTimedOut,
                    else => return unexpectedError(err),
                },
                else => return unexpectedError(err),
                system.EBADF => unreachable, // The argument socket is not a valid file descriptor.
                system.EFAULT => unreachable, // The address pointed to by optval or optlen is not in a valid part of the process address space.
                system.EINVAL => unreachable,
                system.ENOPROTOOPT => unreachable, // The option is unknown at the level indicated.
                system.ENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
            }
        } else {
            const err = system.WSAGetLastError();
            switch (err) {
                0 => switch (err_code) {
                    0 => return,
                    system.ERROR.WSAEACCES => return ConnectError.PermissionDenied,
                    system.ERROR.WSAEADDRINUSE => return ConnectError.AddressInUse,
                    system.ERROR.WSAEADDRNOTAVAIL => return ConnectError.AddressNotAvailable,
                    system.ERROR.WSAEAFNOSUPPORT => return ConnectError.AddressFamilyNotSupported,
                    system.ERROR.WSAEWOULDBLOCK => return ConnectError.system.emResources,
                    system.ERROR.WSAEALREADY => unreachable, // The socket is nonblocking and a previous connection attempt has not yet been completed.
                    system.ERROR.WSAEBADF => unreachable, // socket is not a valid open file descriptor.
                    system.ERROR.WSAECONNREFUSED => return ConnectError.ConnectionRefused,
                    system.ERROR.WSAEFAULT => unreachable, // The socket structure address is outside the user's address space.
                    system.ERROR.WSAEISCONN => unreachable, // The socket is already connected.
                    system.ERROR.WSAENETUNREACH => return ConnectError.NetworkUnreachable,
                    system.ERROR.WSAENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
                    system.ERROR.WSAEPROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
                    system.ERROR.WSAETIMEDOUT => return ConnectError.ConnectionTimedOut,
                    else => return unexpectedError(@intCast(u32, err)),
                },
                else => return unexpectedError(@intCast(u32, err)),
                system.ERROR.WSAEBADF => unreachable, // The argument socket is not a valid file descriptor.
                system.ERROR.WSAEFAULT => unreachable, // The address pointed to by optval or optlen is not in a valid part of the process address space.
                system.ERROR.WSAEINVAL => unreachable,
                system.ERROR.WSAENOPROTOOPT => unreachable, // The option is unknown at the level indicated.
                system.ERROR.WSAENOTSOCK => unreachable, // The file descriptor socket does not refer to a socket.
            }
        }
    }

    pub fn getSockName(self: Socket) GetSockNameError!net.Address {
        var addr: net.OsAddress = undefined;
        var addrlen: system.socklen_t = @sizeOf(net.OsAddress);
        const rc = system.getsockname(self.fd, &addr, &addrlen);

        if (is_posix) {
            const err = system.getErrno(rc);
            switch (err) {
                0 => return net.Address.init(addr),
                else => return unexpectedError(err),
                system.EBADF => unreachable,
                system.EFAULT => unreachable,
                system.EINVAL => unreachable,
                system.ENOTSOCK => return GetSockNameError.FileDescriptorNotASocket,
                system.ENOBUFS => return GetSockNameError.system.emResources,
            }
        } else {
            const err = system.WSAGetLastError();
            switch (err) {
                0 => return net.Address.init(addr),
                else => return unexpectedError(@intCast(u32, err)),
                system.ERROR.WSAEFAULT => unreachable,
                system.ERROR.WSAEINVAL => unreachable,
                system.ERROR.WSAENOTSOCK => return GetSockNameError.FileDescriptorNotASocket,
            }
        }
    }

    pub fn getPeerName(self: Socket) GetPeerNameError!net.Address {
        var addr: net.OsAddress = undefined;
        var addrlen: system.socklen_t = @sizeOf(net.OsAddress);
        const rc = system.getpeername(self.fd, &addr, &addrlen);

        if (is_posix) {
            const err = system.getErrno(rc);
            switch (err) {
                0 => return net.Address.init(addr),
                else => return unexpectedError(err),
                system.EBADF => unreachable,
                system.EFAULT => unreachable,
                system.EINVAL => unreachable,
                system.ENOTSOCK => return GetPeerNameError.FileDescriptorNotASocket,
                system.ENOTCONN => return GetPeerNameError.NotConnected,
                system.ENOBUFS => return GetPeerNameError.system.emResources,
            }
        } else {
            const err = system.WSAGetLastError();
            switch (err) {
                0 => return net.Address.init(addr),
                else => return unexpectedError(@intCast(u32, err)),
                system.ERROR.WSAEFAULT => unreachable,
                system.ERROR.WSAEINVAL => unreachable,
                system.ERROR.WSAENOTSOCK => return GetPeerNameError.FileDescriptorNotASocket,
                system.ERROR.WSAENOTCONN => return GetPeerNameError.NotConnected,
                system.ERROR.WSAENOBUFS => return GetPeerNameError.system.emResources,
            }
        }
    }

    pub fn shutdown(self: Socket, how: Shutdown) ShutdownError!void {
        if (is_posix) {
            const rc = system.shutdown(self.fd, how.toInt(u32));
            const err = system.getErrno(rc);
            switch (err) {
                0 => {},
                else => return unexpectedError(err),
                system.EBADF => unreachable,
                system.EINVAL => unreachable,
                system.ENOTCONN => return ShutdownError.NotConnected,
                system.ENOTSOCK => return ShutdownError.FileDescriptorNotASocket,
            }
        } else {
            const rc = system.shutdown(self.fd, how.toInt(c_int));
            const err = system.WSAGetLastError();
            switch (err) {
                0 => {},
                else => return unexpectedError(@intCast(u32, err)),
                system.ERROR.WSAEINVAL => unreachable,
                system.ERROR.WSAEINPROGRESS => unreachable,
                system.ERROR.WSAENOTCONN => return ShutdownError.NotConnected,
                system.ERROR.WSAENOTSOCK => return ShutdownError.FileDescriptorNotASocket,
            }
        }
    }

    pub fn close(self: Socket) void {
        if (is_posix) {
            os.close(self.fd);
        } else {
            _ = system.closesocket(self.fd);
        }
    }

    // pub fn getSockOpt(self: Socket) {
    // }

    // pub fn setSockOpt(self: Socket) {
    // }

    // pub fn send(self: Socket, buf: []const u8) {
    // }

    // pub fn recv(self: Socket, buf: []u8) {
    // }

    // pub fn sendTo(self: Socket) {
    // }

    // pub fn recvFrom(self: Socket) {
    // }

    pub fn setBlocking(self: Self, blocking: bool) SocketAttributeError!void {
        if (is_posix) {
            const flags = system.fcntl(self.fd, system.F_GETFL, 0);
            var err = system.getErrno(flags);
            switch (err) {
                0 => {
                    const mode = if (blocking) flags & ~system.O_NONBLOCK else flags | system.O_NONBLOCK;
                    const rc = system.fcntl(self.fd, system.F_SETFL, mode);
                    err = system.getErrno(flags);
                    switch (err) {
                        0 => {},
                        else => return unexpectedError(err),
                    }
                },
                else => return unexpectedError(err),
            }
        } else {
            const mode = @intCast(c_ulong, @boolToInt(!blocking));
            const rc = system.ioctlsocket(self.fd, system.FIONBIO, &mode);
            const err = system.WSAGetLastError();

            switch (err) {
                0 => {},
                else => return unexpectedError(@intCast(u32, err)),
                system.ERROR.WSAENOTSOCK => return SocketAttributeError.FileDescriptorNotASocket,
                system.ERROR.WSAEINPROGRESS => unreachable,
                system.ERROR.WSAEFAULT => unreachable,
            }
        }
    }
};
