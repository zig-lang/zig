// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
// This file contains thin wrappers around Windows-specific APIs, with these
// specific goals in mind:
// * Convert "errno"-style error codes into Zig errors.
// * When null-terminated or UTF16LE byte buffers are required, provide APIs which accept
//   slices as well as APIs which accept null-terminated UTF16LE byte buffers.

const builtin = @import("builtin");
const std = @import("../std.zig");
const mem = std.mem;
const assert = std.debug.assert;
const math = std.math;
const maxInt = std.math.maxInt;

pub const advapi32 = @import("windows/advapi32.zig");
pub const kernel32 = @import("windows/kernel32.zig");
pub const ntdll = @import("windows/ntdll.zig");
pub const ole32 = @import("windows/ole32.zig");
pub const psapi = @import("windows/psapi.zig");
pub const shell32 = @import("windows/shell32.zig");
pub const user32 = @import("windows/user32.zig");
pub const ws2_32 = @import("windows/ws2_32.zig");
pub const gdi32 = @import("windows/gdi32.zig");
pub const winmm = @import("windows/winmm.zig");

pub usingnamespace @import("windows/bits.zig");

pub const self_process_handle = @intToPtr(HANDLE, maxInt(usize));

pub const OpenError = error{
    IsDir,
    NotDir,
    FileNotFound,
    NoDevice,
    AccessDenied,
    PipeBusy,
    PathAlreadyExists,
    Unexpected,
    NameTooLong,
    WouldBlock,
};

pub const OpenFileOptions = struct {
    access_mask: ACCESS_MASK,
    dir: ?HANDLE = null,
    sa: ?*SECURITY_ATTRIBUTES = null,
    share_access: ULONG = FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
    creation: ULONG,
    io_mode: std.io.ModeOverride,
    /// If true, tries to open path as a directory.
    /// Defaults to false.
    open_dir: bool = false,
    /// If false, tries to open path as a reparse point without dereferencing it.
    /// Defaults to true.
    follow_symlinks: bool = true,
};

pub fn OpenFile(sub_path_w: []const u16, options: OpenFileOptions) OpenError!HANDLE {
    if (mem.eql(u16, sub_path_w, &[_]u16{'.'}) and !options.open_dir) {
        return error.IsDir;
    }
    if (mem.eql(u16, sub_path_w, &[_]u16{ '.', '.' }) and !options.open_dir) {
        return error.IsDir;
    }

    var result: HANDLE = undefined;

    const path_len_bytes = math.cast(u16, sub_path_w.len * 2) catch |err| switch (err) {
        error.Overflow => return error.NameTooLong,
    };
    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @intToPtr([*]u16, @ptrToInt(sub_path_w.ptr)),
    };
    var attr = OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = if (std.fs.path.isAbsoluteWindowsWTF16(sub_path_w)) null else options.dir,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = if (options.sa) |ptr| ptr.lpSecurityDescriptor else null,
        .SecurityQualityOfService = null,
    };
    var io: IO_STATUS_BLOCK = undefined;
    const blocking_flag: ULONG = if (options.io_mode == .blocking) FILE_SYNCHRONOUS_IO_NONALERT else 0;
    const file_or_dir_flag: ULONG = if (options.open_dir) FILE_DIRECTORY_FILE else FILE_NON_DIRECTORY_FILE;
    // If we're not following symlinks, we need to ensure we don't pass in any synchronization flags such as FILE_SYNCHRONOUS_IO_NONALERT.
    const flags: ULONG = if (options.follow_symlinks) file_or_dir_flag | blocking_flag else file_or_dir_flag | FILE_OPEN_REPARSE_POINT;

    const rc = ntdll.NtCreateFile(
        &result,
        options.access_mask,
        &attr,
        &io,
        null,
        FILE_ATTRIBUTE_NORMAL,
        options.share_access,
        options.creation,
        flags,
        null,
        0,
    );
    switch (rc) {
        .SUCCESS => {
            if (std.io.is_async and options.io_mode == .evented) {
                _ = CreateIoCompletionPort(result, std.event.Loop.instance.?.os_data.io_port, undefined, undefined) catch undefined;
            }
            return result;
        },
        .OBJECT_NAME_INVALID => unreachable,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NO_MEDIA_IN_DEVICE => return error.NoDevice,
        .INVALID_PARAMETER => unreachable,
        .SHARING_VIOLATION => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        .PIPE_BUSY => return error.PipeBusy,
        .OBJECT_PATH_SYNTAX_BAD => unreachable,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        else => return unexpectedStatus(rc),
    }
}

pub const CreatePipeError = error{Unexpected};

pub fn CreatePipe(rd: *HANDLE, wr: *HANDLE, sattr: *const SECURITY_ATTRIBUTES) CreatePipeError!void {
    if (kernel32.CreatePipe(rd, wr, sattr, 0) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub fn CreateEventEx(attributes: ?*SECURITY_ATTRIBUTES, name: []const u8, flags: DWORD, desired_access: DWORD) !HANDLE {
    const nameW = try sliceToPrefixedFileW(name);
    return CreateEventExW(attributes, nameW.span().ptr, flags, desired_access);
}

pub fn CreateEventExW(attributes: ?*SECURITY_ATTRIBUTES, nameW: [*:0]const u16, flags: DWORD, desired_access: DWORD) !HANDLE {
    const handle = kernel32.CreateEventExW(attributes, nameW, flags, desired_access);
    if (handle) |h| {
        return h;
    } else {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const DeviceIoControlError = error{ AccessDenied, Unexpected };

/// A Zig wrapper around `NtDeviceIoControlFile` and `NtFsControlFile` syscalls.
/// It implements similar behavior to `DeviceIoControl` and is meant to serve
/// as a direct substitute for that call.
/// TODO work out if we need to expose other arguments to the underlying syscalls.
pub fn DeviceIoControl(
    h: HANDLE,
    ioControlCode: ULONG,
    in: ?[]const u8,
    out: ?[]u8,
) DeviceIoControlError!void {
    // Logic from: https://doxygen.reactos.org/d3/d74/deviceio_8c.html
    const is_fsctl = (ioControlCode >> 16) == FILE_DEVICE_FILE_SYSTEM;

    var io: IO_STATUS_BLOCK = undefined;
    const in_ptr = if (in) |i| i.ptr else null;
    const in_len = if (in) |i| @intCast(ULONG, i.len) else 0;
    const out_ptr = if (out) |o| o.ptr else null;
    const out_len = if (out) |o| @intCast(ULONG, o.len) else 0;

    const rc = blk: {
        if (is_fsctl) {
            break :blk ntdll.NtFsControlFile(
                h,
                null,
                null,
                null,
                &io,
                ioControlCode,
                in_ptr,
                in_len,
                out_ptr,
                out_len,
            );
        } else {
            break :blk ntdll.NtDeviceIoControlFile(
                h,
                null,
                null,
                null,
                &io,
                ioControlCode,
                in_ptr,
                in_len,
                out_ptr,
                out_len,
            );
        }
    };
    switch (rc) {
        .SUCCESS => {},
        .PRIVILEGE_NOT_HELD => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_PARAMETER => unreachable,
        else => return unexpectedStatus(rc),
    }
}

pub fn GetOverlappedResult(h: HANDLE, overlapped: *OVERLAPPED, wait: bool) !DWORD {
    var bytes: DWORD = undefined;
    if (kernel32.GetOverlappedResult(h, overlapped, &bytes, @boolToInt(wait)) == 0) {
        switch (kernel32.GetLastError()) {
            .IO_INCOMPLETE => if (!wait) return error.WouldBlock else unreachable,
            else => |err| return unexpectedError(err),
        }
    }
    return bytes;
}

pub const SetHandleInformationError = error{Unexpected};

pub fn SetHandleInformation(h: HANDLE, mask: DWORD, flags: DWORD) SetHandleInformationError!void {
    if (kernel32.SetHandleInformation(h, mask, flags) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const RtlGenRandomError = error{Unexpected};

/// Call RtlGenRandom() instead of CryptGetRandom() on Windows
/// https://github.com/rust-lang-nursery/rand/issues/111
/// https://bugzilla.mozilla.org/show_bug.cgi?id=504270
pub fn RtlGenRandom(output: []u8) RtlGenRandomError!void {
    var total_read: usize = 0;
    var buff: []u8 = output[0..];
    const max_read_size: ULONG = maxInt(ULONG);

    while (total_read < output.len) {
        const to_read: ULONG = math.min(buff.len, max_read_size);

        if (advapi32.RtlGenRandom(buff.ptr, to_read) == 0) {
            return unexpectedError(kernel32.GetLastError());
        }

        total_read += to_read;
        buff = buff[to_read..];
    }
}

pub const WaitForSingleObjectError = error{
    WaitAbandoned,
    WaitTimeOut,
    Unexpected,
};

pub fn WaitForSingleObject(handle: HANDLE, milliseconds: DWORD) WaitForSingleObjectError!void {
    return WaitForSingleObjectEx(handle, milliseconds, false);
}

pub fn WaitForSingleObjectEx(handle: HANDLE, milliseconds: DWORD, alertable: bool) WaitForSingleObjectError!void {
    switch (kernel32.WaitForSingleObjectEx(handle, milliseconds, @boolToInt(alertable))) {
        WAIT_ABANDONED => return error.WaitAbandoned,
        WAIT_OBJECT_0 => return,
        WAIT_TIMEOUT => return error.WaitTimeOut,
        WAIT_FAILED => switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        },
        else => return error.Unexpected,
    }
}

pub fn WaitForMultipleObjectsEx(handles: []const HANDLE, waitAll: bool, milliseconds: DWORD, alertable: bool) !u32 {
    assert(handles.len < MAXIMUM_WAIT_OBJECTS);
    const nCount: DWORD = @intCast(DWORD, handles.len);
    switch (kernel32.WaitForMultipleObjectsEx(
        nCount,
        handles.ptr,
        @boolToInt(waitAll),
        milliseconds,
        @boolToInt(alertable),
    )) {
        WAIT_OBJECT_0...WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS => |n| {
            const handle_index = n - WAIT_OBJECT_0;
            assert(handle_index < nCount);
            return handle_index;
        },
        WAIT_ABANDONED_0...WAIT_ABANDONED_0 + MAXIMUM_WAIT_OBJECTS => |n| {
            const handle_index = n - WAIT_ABANDONED_0;
            assert(handle_index < nCount);
            return error.WaitAbandoned;
        },
        WAIT_TIMEOUT => return error.WaitTimeOut,
        WAIT_FAILED => switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        },
        else => return error.Unexpected,
    }
}

pub const CreateIoCompletionPortError = error{Unexpected};

pub fn CreateIoCompletionPort(
    file_handle: HANDLE,
    existing_completion_port: ?HANDLE,
    completion_key: usize,
    concurrent_thread_count: DWORD,
) CreateIoCompletionPortError!HANDLE {
    const handle = kernel32.CreateIoCompletionPort(file_handle, existing_completion_port, completion_key, concurrent_thread_count) orelse {
        switch (kernel32.GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            else => |err| return unexpectedError(err),
        }
    };
    return handle;
}

pub const PostQueuedCompletionStatusError = error{Unexpected};

pub fn PostQueuedCompletionStatus(
    completion_port: HANDLE,
    bytes_transferred_count: DWORD,
    completion_key: usize,
    lpOverlapped: ?*OVERLAPPED,
) PostQueuedCompletionStatusError!void {
    if (kernel32.PostQueuedCompletionStatus(completion_port, bytes_transferred_count, completion_key, lpOverlapped) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const GetQueuedCompletionStatusResult = enum {
    Normal,
    Aborted,
    Cancelled,
    EOF,
};

pub fn GetQueuedCompletionStatus(
    completion_port: HANDLE,
    bytes_transferred_count: *DWORD,
    lpCompletionKey: *usize,
    lpOverlapped: *?*OVERLAPPED,
    dwMilliseconds: DWORD,
) GetQueuedCompletionStatusResult {
    if (kernel32.GetQueuedCompletionStatus(
        completion_port,
        bytes_transferred_count,
        lpCompletionKey,
        lpOverlapped,
        dwMilliseconds,
    ) == FALSE) {
        switch (kernel32.GetLastError()) {
            .ABANDONED_WAIT_0 => return GetQueuedCompletionStatusResult.Aborted,
            .OPERATION_ABORTED => return GetQueuedCompletionStatusResult.Cancelled,
            .HANDLE_EOF => return GetQueuedCompletionStatusResult.EOF,
            else => |err| {
                if (std.debug.runtime_safety) {
                    @setEvalBranchQuota(2500);
                    std.debug.panic("unexpected error: {}\n", .{err});
                }
            },
        }
    }
    return GetQueuedCompletionStatusResult.Normal;
}

pub const GetQueuedCompletionStatusError = error{
    Aborted,
    Cancelled,
    EOF,
    Timeout,
} || std.os.UnexpectedError;

pub fn GetQueuedCompletionStatusEx(
    completion_port: HANDLE,
    completion_port_entries: []OVERLAPPED_ENTRY,
    timeout_ms: ?DWORD,
    alertable: bool,
) GetQueuedCompletionStatusError!u32 {
    var num_entries_removed: u32 = 0;

    const success = kernel32.GetQueuedCompletionStatusEx(
        completion_port,
        completion_port_entries.ptr,
        @intCast(ULONG, completion_port_entries.len),
        &num_entries_removed,
        timeout_ms orelse INFINITE,
        @boolToInt(alertable),
    );

    if (success == FALSE) {
        return switch (kernel32.GetLastError()) {
            .ABANDONED_WAIT_0 => error.Aborted,
            .OPERATION_ABORTED => error.Cancelled,
            .HANDLE_EOF => error.EOF,
            .IMEOUT => error.Timeout,
            else => |err| unexpectedError(err),
        };
    }

    return num_entries_removed;
}

pub fn CloseHandle(hObject: HANDLE) void {
    assert(ntdll.NtClose(hObject) == .SUCCESS);
}

pub fn FindClose(hFindFile: HANDLE) void {
    assert(kernel32.FindClose(hFindFile) != 0);
}

pub const ReadFileError = error{
    OperationAborted,
    BrokenPipe,
    Unexpected,
};

/// If buffer's length exceeds what a Windows DWORD integer can hold, it will be broken into
/// multiple non-atomic reads.
pub fn ReadFile(in_hFile: HANDLE, buffer: []u8, offset: ?u64, io_mode: std.io.ModeOverride) ReadFileError!usize {
    if (io_mode != .blocking) {
        const loop = std.event.Loop.instance.?;
        // TODO make getting the file position non-blocking
        const off = if (offset) |o| o else try SetFilePointerEx_CURRENT_get(in_hFile);
        var resume_node = std.event.Loop.ResumeNode.Basic{
            .base = .{
                .id = .Basic,
                .handle = @frame(),
                .overlapped = OVERLAPPED{
                    .Internal = 0,
                    .InternalHigh = 0,
                    .DUMMYUNIONNAME = .{
                        .DUMMYSTRUCTNAME = .{
                            .Offset = @truncate(u32, off),
                            .OffsetHigh = @truncate(u32, off >> 32),
                        },
                    },
                    .hEvent = null,
                },
            },
        };
        loop.beginOneEvent();
        suspend {
            // TODO handle buffer bigger than DWORD can hold
            _ = kernel32.ReadFile(in_hFile, buffer.ptr, @intCast(DWORD, buffer.len), null, &resume_node.base.overlapped);
        }
        var bytes_transferred: DWORD = undefined;
        if (kernel32.GetOverlappedResult(in_hFile, &resume_node.base.overlapped, &bytes_transferred, FALSE) == 0) {
            switch (kernel32.GetLastError()) {
                .IO_PENDING => unreachable,
                .OPERATION_ABORTED => return error.OperationAborted,
                .BROKEN_PIPE => return error.BrokenPipe,
                .HANDLE_EOF => return @as(usize, bytes_transferred),
                else => |err| return unexpectedError(err),
            }
        }
        if (offset == null) {
            // TODO make setting the file position non-blocking
            const new_off = off + bytes_transferred;
            try SetFilePointerEx_CURRENT(in_hFile, @bitCast(i64, new_off));
        }
        return @as(usize, bytes_transferred);
    } else {
        while (true) {
            const want_read_count = @intCast(DWORD, math.min(@as(DWORD, maxInt(DWORD)), buffer.len));
            var amt_read: DWORD = undefined;
            var overlapped_data: OVERLAPPED = undefined;
            const overlapped: ?*OVERLAPPED = if (offset) |off| blk: {
                overlapped_data = .{
                    .Internal = 0,
                    .InternalHigh = 0,
                    .DUMMYUNIONNAME = .{
                        .DUMMYSTRUCTNAME = .{
                            .Offset = @truncate(u32, off),
                            .OffsetHigh = @truncate(u32, off >> 32),
                        },
                    },
                    .hEvent = null,
                };
                break :blk &overlapped_data;
            } else null;
            if (kernel32.ReadFile(in_hFile, buffer.ptr, want_read_count, &amt_read, overlapped) == 0) {
                switch (kernel32.GetLastError()) {
                    .OPERATION_ABORTED => continue,
                    .BROKEN_PIPE => return 0,
                    .HANDLE_EOF => return 0,
                    else => |err| return unexpectedError(err),
                }
            }
            return amt_read;
        }
    }
}

pub const WriteFileError = error{
    SystemResources,
    OperationAborted,
    BrokenPipe,
    NotOpenForWriting,
    Unexpected,
};

pub fn WriteFile(
    handle: HANDLE,
    bytes: []const u8,
    offset: ?u64,
    io_mode: std.io.ModeOverride,
) WriteFileError!usize {
    if (std.event.Loop.instance != null and io_mode != .blocking) {
        const loop = std.event.Loop.instance.?;
        // TODO make getting the file position non-blocking
        const off = if (offset) |o| o else try SetFilePointerEx_CURRENT_get(handle);
        var resume_node = std.event.Loop.ResumeNode.Basic{
            .base = .{
                .id = .Basic,
                .handle = @frame(),
                .overlapped = OVERLAPPED{
                    .Internal = 0,
                    .InternalHigh = 0,
                    .DUMMYUNIONNAME = .{
                        .DUMMYSTRUCTNAME = .{
                            .Offset = @truncate(u32, off),
                            .OffsetHigh = @truncate(u32, off >> 32),
                        },
                    },
                    .hEvent = null,
                },
            },
        };
        loop.beginOneEvent();
        suspend {
            const adjusted_len = math.cast(DWORD, bytes.len) catch maxInt(DWORD);
            _ = kernel32.WriteFile(handle, bytes.ptr, adjusted_len, null, &resume_node.base.overlapped);
        }
        var bytes_transferred: DWORD = undefined;
        if (kernel32.GetOverlappedResult(handle, &resume_node.base.overlapped, &bytes_transferred, FALSE) == 0) {
            switch (kernel32.GetLastError()) {
                .IO_PENDING => unreachable,
                .INVALID_USER_BUFFER => return error.SystemResources,
                .NOT_ENOUGH_MEMORY => return error.SystemResources,
                .OPERATION_ABORTED => return error.OperationAborted,
                .NOT_ENOUGH_QUOTA => return error.SystemResources,
                .BROKEN_PIPE => return error.BrokenPipe,
                else => |err| return unexpectedError(err),
            }
        }
        if (offset == null) {
            // TODO make setting the file position non-blocking
            const new_off = off + bytes_transferred;
            try SetFilePointerEx_CURRENT(handle, @bitCast(i64, new_off));
        }
        return bytes_transferred;
    } else {
        var bytes_written: DWORD = undefined;
        var overlapped_data: OVERLAPPED = undefined;
        const overlapped: ?*OVERLAPPED = if (offset) |off| blk: {
            overlapped_data = .{
                .Internal = 0,
                .InternalHigh = 0,
                .DUMMYUNIONNAME = .{
                    .DUMMYSTRUCTNAME = .{
                        .Offset = @truncate(u32, off),
                        .OffsetHigh = @truncate(u32, off >> 32),
                    },
                },
                .hEvent = null,
            };
            break :blk &overlapped_data;
        } else null;
        const adjusted_len = math.cast(u32, bytes.len) catch maxInt(u32);
        if (kernel32.WriteFile(handle, bytes.ptr, adjusted_len, &bytes_written, overlapped) == 0) {
            switch (kernel32.GetLastError()) {
                .INVALID_USER_BUFFER => return error.SystemResources,
                .NOT_ENOUGH_MEMORY => return error.SystemResources,
                .OPERATION_ABORTED => return error.OperationAborted,
                .NOT_ENOUGH_QUOTA => return error.SystemResources,
                .IO_PENDING => unreachable,
                .BROKEN_PIPE => return error.BrokenPipe,
                .INVALID_HANDLE => return error.NotOpenForWriting,
                else => |err| return unexpectedError(err),
            }
        }
        return bytes_written;
    }
}

pub const SetCurrentDirectoryError = error{
    NameTooLong,
    InvalidUtf8,
    FileNotFound,
    NotDir,
    AccessDenied,
    NoDevice,
    BadPathName,
    Unexpected,
};

pub fn SetCurrentDirectory(path_name: []const u16) SetCurrentDirectoryError!void {
    const path_len_bytes = math.cast(u16, path_name.len * 2) catch |err| switch (err) {
        error.Overflow => return error.NameTooLong,
    };

    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @intToPtr([*]u16, @ptrToInt(path_name.ptr)),
    };

    const rc = ntdll.RtlSetCurrentDirectory_U(&nt_name);
    switch (rc) {
        .SUCCESS => {},
        .OBJECT_NAME_INVALID => return error.BadPathName,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NO_MEDIA_IN_DEVICE => return error.NoDevice,
        .INVALID_PARAMETER => unreachable,
        .ACCESS_DENIED => return error.AccessDenied,
        .OBJECT_PATH_SYNTAX_BAD => unreachable,
        .NOT_A_DIRECTORY => return error.NotDir,
        else => return unexpectedStatus(rc),
    }
}

pub const GetCurrentDirectoryError = error{
    NameTooLong,
    Unexpected,
};

/// The result is a slice of `buffer`, indexed from 0.
pub fn GetCurrentDirectory(buffer: []u8) GetCurrentDirectoryError![]u8 {
    var utf16le_buf: [PATH_MAX_WIDE]u16 = undefined;
    const result = kernel32.GetCurrentDirectoryW(utf16le_buf.len, &utf16le_buf);
    if (result == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    assert(result <= utf16le_buf.len);
    const utf16le_slice = utf16le_buf[0..result];
    // Trust that Windows gives us valid UTF-16LE.
    var end_index: usize = 0;
    var it = std.unicode.Utf16LeIterator.init(utf16le_slice);
    while (it.nextCodepoint() catch unreachable) |codepoint| {
        const seq_len = std.unicode.utf8CodepointSequenceLength(codepoint) catch unreachable;
        if (end_index + seq_len >= buffer.len)
            return error.NameTooLong;
        end_index += std.unicode.utf8Encode(codepoint, buffer[end_index..]) catch unreachable;
    }
    return buffer[0..end_index];
}

pub const CreateSymbolicLinkError = error{
    AccessDenied,
    PathAlreadyExists,
    FileNotFound,
    NameTooLong,
    NoDevice,
    Unexpected,
};

/// Needs either:
/// - `SeCreateSymbolicLinkPrivilege` privilege
/// or
/// - Developper mode on Windows 10
/// otherwise fails with `error.AccessDenied`. In which case `sym_link_path` may still
/// be created on the file system but will lack reparse processing data applied to it.
pub fn CreateSymbolicLink(
    dir: ?HANDLE,
    sym_link_path: []const u16,
    target_path: []const u16,
    is_directory: bool,
) CreateSymbolicLinkError!void {
    const SYMLINK_DATA = extern struct {
        ReparseTag: ULONG,
        ReparseDataLength: USHORT,
        Reserved: USHORT,
        SubstituteNameOffset: USHORT,
        SubstituteNameLength: USHORT,
        PrintNameOffset: USHORT,
        PrintNameLength: USHORT,
        Flags: ULONG,
    };

    const symlink_handle = OpenFile(sym_link_path, .{
        .access_mask = SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        .dir = dir,
        .creation = FILE_CREATE,
        .io_mode = .blocking,
        .open_dir = is_directory,
    }) catch |err| switch (err) {
        error.IsDir => return error.PathAlreadyExists,
        error.NotDir => unreachable,
        error.WouldBlock => unreachable,
        error.PipeBusy => unreachable,
        else => |e| return e,
    };
    defer CloseHandle(symlink_handle);

    // prepare reparse data buffer
    var buffer: [MAXIMUM_REPARSE_DATA_BUFFER_SIZE]u8 = undefined;
    const buf_len = @sizeOf(SYMLINK_DATA) + target_path.len * 4;
    const header_len = @sizeOf(ULONG) + @sizeOf(USHORT) * 2;
    const symlink_data = SYMLINK_DATA{
        .ReparseTag = IO_REPARSE_TAG_SYMLINK,
        .ReparseDataLength = @intCast(u16, buf_len - header_len),
        .Reserved = 0,
        .SubstituteNameOffset = @intCast(u16, target_path.len * 2),
        .SubstituteNameLength = @intCast(u16, target_path.len * 2),
        .PrintNameOffset = 0,
        .PrintNameLength = @intCast(u16, target_path.len * 2),
        .Flags = if (dir) |_| SYMLINK_FLAG_RELATIVE else 0,
    };

    std.mem.copy(u8, buffer[0..], std.mem.asBytes(&symlink_data));
    @memcpy(buffer[@sizeOf(SYMLINK_DATA)..], @ptrCast([*]const u8, target_path), target_path.len * 2);
    const paths_start = @sizeOf(SYMLINK_DATA) + target_path.len * 2;
    @memcpy(buffer[paths_start..].ptr, @ptrCast([*]const u8, target_path), target_path.len * 2);
    _ = try DeviceIoControl(symlink_handle, FSCTL_SET_REPARSE_POINT, buffer[0..buf_len], null);
}

pub const ReadLinkError = error{
    FileNotFound,
    AccessDenied,
    Unexpected,
    NameTooLong,
    UnsupportedReparsePointType,
};

pub fn ReadLink(dir: ?HANDLE, sub_path_w: []const u16, out_buffer: []u8) ReadLinkError![]u8 {
    // Here, we use `NtCreateFile` to shave off one syscall if we were to use `OpenFile` wrapper.
    // With the latter, we'd need to call `NtCreateFile` twice, once for file symlink, and if that
    // failed, again for dir symlink. Omitting any mention of file/dir flags makes it possible
    // to open the symlink there and then.
    const path_len_bytes = math.cast(u16, sub_path_w.len * 2) catch |err| switch (err) {
        error.Overflow => return error.NameTooLong,
    };
    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @intToPtr([*]u16, @ptrToInt(sub_path_w.ptr)),
    };
    var attr = OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = if (std.fs.path.isAbsoluteWindowsWTF16(sub_path_w)) null else dir,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var result_handle: HANDLE = undefined;
    var io: IO_STATUS_BLOCK = undefined;

    const rc = ntdll.NtCreateFile(
        &result_handle,
        FILE_READ_ATTRIBUTES,
        &attr,
        &io,
        null,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT,
        null,
        0,
    );
    switch (rc) {
        .SUCCESS => {},
        .OBJECT_NAME_INVALID => unreachable,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NO_MEDIA_IN_DEVICE => return error.FileNotFound,
        .INVALID_PARAMETER => unreachable,
        .SHARING_VIOLATION => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        .PIPE_BUSY => return error.AccessDenied,
        .OBJECT_PATH_SYNTAX_BAD => unreachable,
        .OBJECT_NAME_COLLISION => unreachable,
        .FILE_IS_A_DIRECTORY => unreachable,
        else => return unexpectedStatus(rc),
    }
    defer CloseHandle(result_handle);

    var reparse_buf: [MAXIMUM_REPARSE_DATA_BUFFER_SIZE]u8 = undefined;
    _ = DeviceIoControl(result_handle, FSCTL_GET_REPARSE_POINT, null, reparse_buf[0..]) catch |err| switch (err) {
        error.AccessDenied => unreachable,
        else => |e| return e,
    };

    const reparse_struct = @ptrCast(*const REPARSE_DATA_BUFFER, @alignCast(@alignOf(REPARSE_DATA_BUFFER), &reparse_buf[0]));
    switch (reparse_struct.ReparseTag) {
        IO_REPARSE_TAG_SYMLINK => {
            const buf = @ptrCast(*const SYMBOLIC_LINK_REPARSE_BUFFER, @alignCast(@alignOf(SYMBOLIC_LINK_REPARSE_BUFFER), &reparse_struct.DataBuffer[0]));
            const offset = buf.SubstituteNameOffset >> 1;
            const len = buf.SubstituteNameLength >> 1;
            const path_buf = @as([*]const u16, &buf.PathBuffer);
            const is_relative = buf.Flags & SYMLINK_FLAG_RELATIVE != 0;
            return parseReadlinkPath(path_buf[offset .. offset + len], is_relative, out_buffer);
        },
        IO_REPARSE_TAG_MOUNT_POINT => {
            const buf = @ptrCast(*const MOUNT_POINT_REPARSE_BUFFER, @alignCast(@alignOf(MOUNT_POINT_REPARSE_BUFFER), &reparse_struct.DataBuffer[0]));
            const offset = buf.SubstituteNameOffset >> 1;
            const len = buf.SubstituteNameLength >> 1;
            const path_buf = @as([*]const u16, &buf.PathBuffer);
            return parseReadlinkPath(path_buf[offset .. offset + len], false, out_buffer);
        },
        else => |value| {
            std.debug.warn("unsupported symlink type: {}", .{value});
            return error.UnsupportedReparsePointType;
        },
    }
}

fn parseReadlinkPath(path: []const u16, is_relative: bool, out_buffer: []u8) []u8 {
    const prefix = [_]u16{ '\\', '?', '?', '\\' };
    var start_index: usize = 0;
    if (!is_relative and std.mem.startsWith(u16, path, &prefix)) {
        start_index = prefix.len;
    }
    const out_len = std.unicode.utf16leToUtf8(out_buffer, path[start_index..]) catch unreachable;
    return out_buffer[0..out_len];
}

pub const DeleteFileError = error{
    FileNotFound,
    AccessDenied,
    NameTooLong,
    /// Also known as sharing violation.
    FileBusy,
    Unexpected,
    NotDir,
    IsDir,
};

pub const DeleteFileOptions = struct {
    dir: ?HANDLE,
    remove_dir: bool = false,
};

pub fn DeleteFile(sub_path_w: []const u16, options: DeleteFileOptions) DeleteFileError!void {
    const create_options_flags: ULONG = if (options.remove_dir)
        FILE_DELETE_ON_CLOSE | FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
    else
        FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT; // would we ever want to delete the target instead?

    const path_len_bytes = @intCast(u16, sub_path_w.len * 2);
    var nt_name = UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        // The Windows API makes this mutable, but it will not mutate here.
        .Buffer = @intToPtr([*]u16, @ptrToInt(sub_path_w.ptr)),
    };

    if (sub_path_w[0] == '.' and sub_path_w[1] == 0) {
        // Windows does not recognize this, but it does work with empty string.
        nt_name.Length = 0;
    }
    if (sub_path_w[0] == '.' and sub_path_w[1] == '.' and sub_path_w[2] == 0) {
        // Can't remove the parent directory with an open handle.
        return error.FileBusy;
    }

    var attr = OBJECT_ATTRIBUTES{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = if (std.fs.path.isAbsoluteWindowsWTF16(sub_path_w)) null else options.dir,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var io: IO_STATUS_BLOCK = undefined;
    var tmp_handle: HANDLE = undefined;
    var rc = ntdll.NtCreateFile(
        &tmp_handle,
        SYNCHRONIZE | DELETE,
        &attr,
        &io,
        null,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        create_options_flags,
        null,
        0,
    );
    switch (rc) {
        .SUCCESS => return CloseHandle(tmp_handle),
        .OBJECT_NAME_INVALID => unreachable,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .INVALID_PARAMETER => unreachable,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        .SHARING_VIOLATION => return error.FileBusy,
        else => return unexpectedStatus(rc),
    }
}

pub const MoveFileError = error{ FileNotFound, AccessDenied, Unexpected };

pub fn MoveFileEx(old_path: []const u8, new_path: []const u8, flags: DWORD) MoveFileError!void {
    const old_path_w = try sliceToPrefixedFileW(old_path);
    const new_path_w = try sliceToPrefixedFileW(new_path);
    return MoveFileExW(old_path_w.span().ptr, new_path_w.span().ptr, flags);
}

pub fn MoveFileExW(old_path: [*:0]const u16, new_path: [*:0]const u16, flags: DWORD) MoveFileError!void {
    if (kernel32.MoveFileExW(old_path, new_path, flags) == 0) {
        switch (kernel32.GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .ACCESS_DENIED => return error.AccessDenied,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const GetStdHandleError = error{
    NoStandardHandleAttached,
    Unexpected,
};

pub fn GetStdHandle(handle_id: DWORD) GetStdHandleError!HANDLE {
    const handle = kernel32.GetStdHandle(handle_id) orelse return error.NoStandardHandleAttached;
    if (handle == INVALID_HANDLE_VALUE) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return handle;
}

pub const SetFilePointerError = error{Unexpected};

/// The SetFilePointerEx function with the `dwMoveMethod` parameter set to `FILE_BEGIN`.
pub fn SetFilePointerEx_BEGIN(handle: HANDLE, offset: u64) SetFilePointerError!void {
    // "The starting point is zero or the beginning of the file. If [FILE_BEGIN]
    // is specified, then the liDistanceToMove parameter is interpreted as an unsigned value."
    // https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-setfilepointerex
    const ipos = @bitCast(LARGE_INTEGER, offset);
    if (kernel32.SetFilePointerEx(handle, ipos, null, FILE_BEGIN) == 0) {
        switch (kernel32.GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
}

/// The SetFilePointerEx function with the `dwMoveMethod` parameter set to `FILE_CURRENT`.
pub fn SetFilePointerEx_CURRENT(handle: HANDLE, offset: i64) SetFilePointerError!void {
    if (kernel32.SetFilePointerEx(handle, offset, null, FILE_CURRENT) == 0) {
        switch (kernel32.GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
}

/// The SetFilePointerEx function with the `dwMoveMethod` parameter set to `FILE_END`.
pub fn SetFilePointerEx_END(handle: HANDLE, offset: i64) SetFilePointerError!void {
    if (kernel32.SetFilePointerEx(handle, offset, null, FILE_END) == 0) {
        switch (kernel32.GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
}

/// The SetFilePointerEx function with parameters to get the current offset.
pub fn SetFilePointerEx_CURRENT_get(handle: HANDLE) SetFilePointerError!u64 {
    var result: LARGE_INTEGER = undefined;
    if (kernel32.SetFilePointerEx(handle, 0, &result, FILE_CURRENT) == 0) {
        switch (kernel32.GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .INVALID_HANDLE => unreachable,
            else => |err| return unexpectedError(err),
        }
    }
    // Based on the docs for FILE_BEGIN, it seems that the returned signed integer
    // should be interpreted as an unsigned integer.
    return @bitCast(u64, result);
}

pub fn QueryObjectName(
    handle: HANDLE,
    out_buffer: []u16,
) ![]u16 {
    const out_buffer_aligned = mem.alignInSlice(out_buffer, @alignOf(OBJECT_NAME_INFORMATION)) orelse return error.NameTooLong;

    const info = @ptrCast(*OBJECT_NAME_INFORMATION, out_buffer_aligned);
    //buffer size is specified in bytes
    const out_buffer_len = std.math.cast(ULONG, out_buffer_aligned.len * 2) catch |e| switch (e) {
        error.Overflow => std.math.maxInt(ULONG),
    };
    //last argument would return the length required for full_buffer, not exposed here
    const rc = ntdll.NtQueryObject(handle, .ObjectNameInformation, info, out_buffer_len, null);
    switch (rc) {
        .SUCCESS => {
            // info.Name.Buffer from ObQueryNameString is documented to be null (and MaximumLength == 0)
            // if the object was "unnamed", not sure if this can happen for file handles
            if (info.Name.MaximumLength == 0) return error.Unexpected;
            // resulting string length is specified in bytes
            const path_length_unterminated = @divExact(info.Name.Length, 2);
            return info.Name.Buffer[0..path_length_unterminated];
        },
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_HANDLE => return error.InvalidHandle,
        // triggered when the buffer is too small for the OBJECT_NAME_INFORMATION object (.INFO_LENGTH_MISMATCH),
        // or if the buffer is too small for the file path returned (.BUFFER_OVERFLOW, .BUFFER_TOO_SMALL)
        .INFO_LENGTH_MISMATCH, .BUFFER_OVERFLOW, .BUFFER_TOO_SMALL => return error.NameTooLong,
        else => |e| return unexpectedStatus(e),
    }
}
test "QueryObjectName" {
    if (comptime builtin.os.tag != .windows)
        return;

    //any file will do; canonicalization works on NTFS junctions and symlinks, hardlinks remain separate paths.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const handle = tmp.dir.fd;
    var out_buffer: [PATH_MAX_WIDE]u16 = undefined;

    var result_path = try QueryObjectName(handle, &out_buffer);
    const required_len_in_u16 = result_path.len + @divExact(@ptrToInt(result_path.ptr) - @ptrToInt(&out_buffer), 2) + 1;
    //insufficient size
    try std.testing.expectError(error.NameTooLong, QueryObjectName(handle, out_buffer[0 .. required_len_in_u16 - 1]));
    //exactly-sufficient size
    _ = try QueryObjectName(handle, out_buffer[0..required_len_in_u16]);
}

pub const GetFinalPathNameByHandleError = error{
    AccessDenied,
    BadPathName,
    FileNotFound,
    NameTooLong,
    Unexpected,
};

/// Specifies how to format volume path in the result of `GetFinalPathNameByHandle`.
/// Defaults to DOS volume names.
pub const GetFinalPathNameByHandleFormat = struct {
    volume_name: enum {
        /// Format as DOS volume name
        Dos,
        /// Format as NT volume name
        Nt,
    } = .Dos,
};

/// Returns canonical (normalized) path of handle.
/// Use `GetFinalPathNameByHandleFormat` to specify whether the path is meant to include
/// NT or DOS volume name (e.g., `\Device\HarddiskVolume0\foo.txt` versus `C:\foo.txt`).
/// If DOS volume name format is selected, note that this function does *not* prepend
/// `\\?\` prefix to the resultant path.
pub fn GetFinalPathNameByHandle(
    hFile: HANDLE,
    fmt: GetFinalPathNameByHandleFormat,
    out_buffer: []u16,
) GetFinalPathNameByHandleError![]u16 {
    const final_path = QueryObjectName(hFile, out_buffer) catch |err| switch (err) {
        // we assume InvalidHandle is close enough to FileNotFound in semantics
        // to not further complicate the error set
        error.InvalidHandle => return error.FileNotFound,
        else => |e| return e,
    };

    switch (fmt.volume_name) {
        .Nt => {
            // the returned path is already in .Nt format
            return final_path;
        },
        .Dos => {
            // parse the string to separate volume path from file path
            const expected_prefix = std.unicode.utf8ToUtf16LeStringLiteral("\\Device\\");

            // TODO find out if a path can start with something besides `\Device\<volume name>`,
            // and if we need to handle it differently
            // (i.e. how to determine the start and end of the volume name in that case)
            if (!mem.eql(u16, expected_prefix, final_path[0..expected_prefix.len])) return error.Unexpected;

            const file_path_begin_index = mem.indexOfPos(u16, final_path, expected_prefix.len, &[_]u16{'\\'}) orelse unreachable;
            const volume_name_u16 = final_path[0..file_path_begin_index];
            const file_name_u16 = final_path[file_path_begin_index..];

            // Get DOS volume name. DOS volume names are actually symbolic link objects to the
            // actual NT volume. For example:
            // (NT) \Device\HarddiskVolume4 => (DOS) \DosDevices\C: == (DOS) C:
            const MIN_SIZE = @sizeOf(MOUNTMGR_MOUNT_POINT) + MAX_PATH;
            // We initialize the input buffer to all zeros for convenience since
            // `DeviceIoControl` with `IOCTL_MOUNTMGR_QUERY_POINTS` expects this.
            var input_buf: [MIN_SIZE]u8 align(@alignOf(MOUNTMGR_MOUNT_POINT)) = [_]u8{0} ** MIN_SIZE;
            var output_buf: [MIN_SIZE * 4]u8 align(@alignOf(MOUNTMGR_MOUNT_POINTS)) = undefined;

            // This surprising path is a filesystem path to the mount manager on Windows.
            // Source: https://stackoverflow.com/questions/3012828/using-ioctl-mountmgr-query-points
            const mgmt_path = "\\MountPointManager";
            const mgmt_path_u16 = sliceToPrefixedFileW(mgmt_path) catch unreachable;
            const mgmt_handle = OpenFile(mgmt_path_u16.span(), .{
                .access_mask = SYNCHRONIZE,
                .share_access = FILE_SHARE_READ | FILE_SHARE_WRITE,
                .creation = FILE_OPEN,
                .io_mode = .blocking,
            }) catch |err| switch (err) {
                error.IsDir => unreachable,
                error.NotDir => unreachable,
                error.NoDevice => unreachable,
                error.AccessDenied => unreachable,
                error.PipeBusy => unreachable,
                error.PathAlreadyExists => unreachable,
                error.WouldBlock => unreachable,
                else => |e| return e,
            };
            defer CloseHandle(mgmt_handle);

            var input_struct = @ptrCast(*MOUNTMGR_MOUNT_POINT, &input_buf[0]);
            input_struct.DeviceNameOffset = @sizeOf(MOUNTMGR_MOUNT_POINT);
            input_struct.DeviceNameLength = @intCast(USHORT, volume_name_u16.len * 2);
            @memcpy(input_buf[@sizeOf(MOUNTMGR_MOUNT_POINT)..], @ptrCast([*]const u8, volume_name_u16.ptr), volume_name_u16.len * 2);

            DeviceIoControl(mgmt_handle, IOCTL_MOUNTMGR_QUERY_POINTS, &input_buf, &output_buf) catch |err| switch (err) {
                error.AccessDenied => unreachable,
                else => |e| return e,
            };
            const mount_points_struct = @ptrCast(*const MOUNTMGR_MOUNT_POINTS, &output_buf[0]);

            const mount_points = @ptrCast(
                [*]const MOUNTMGR_MOUNT_POINT,
                &mount_points_struct.MountPoints[0],
            )[0..mount_points_struct.NumberOfMountPoints];

            for (mount_points) |mount_point| {
                const symlink = @ptrCast(
                    [*]const u16,
                    @alignCast(@alignOf(u16), &output_buf[mount_point.SymbolicLinkNameOffset]),
                )[0 .. mount_point.SymbolicLinkNameLength / 2];

                // Look for `\DosDevices\` prefix. We don't really care if there are more than one symlinks
                // with traditional DOS drive letters, so pick the first one available.
                var prefix_buf = std.unicode.utf8ToUtf16LeStringLiteral("\\DosDevices\\");
                const prefix = prefix_buf[0..prefix_buf.len];

                if (mem.startsWith(u16, symlink, prefix)) {
                    const drive_letter = symlink[prefix.len..];

                    if (out_buffer.len < drive_letter.len + file_name_u16.len) return error.NameTooLong;

                    mem.copy(u16, out_buffer, drive_letter);
                    mem.copy(u16, out_buffer[drive_letter.len..], file_name_u16);
                    const total_len = drive_letter.len + file_name_u16.len;

                    // Validate that DOS does not contain any spurious nul bytes.
                    if (mem.indexOfScalar(u16, out_buffer[0..total_len], 0)) |_| {
                        return error.BadPathName;
                    }

                    return out_buffer[0..total_len];
                }
            }

            // If we've ended up here, then something went wrong/is corrupted in the OS,
            // so error out!
            return error.FileNotFound;
        },
    }
}

test "GetFinalPathNameByHandle" {
    if (comptime builtin.os.tag != .windows)
        return;

    //any file will do
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const handle = tmp.dir.fd;
    var buffer: [PATH_MAX_WIDE]u16 = undefined;

    //check with sufficient size
    const nt_path = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, &buffer);
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, &buffer);

    const required_len_in_u16 = nt_path.len + @divExact(@ptrToInt(nt_path.ptr) - @ptrToInt(&buffer), 2) + 1;
    //check with insufficient size
    try std.testing.expectError(error.NameTooLong, GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, buffer[0 .. required_len_in_u16 - 1]));
    try std.testing.expectError(error.NameTooLong, GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, buffer[0 .. required_len_in_u16 - 1]));

    //check with exactly-sufficient size
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, buffer[0..required_len_in_u16]);
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, buffer[0..required_len_in_u16]);
}

pub const QueryInformationFileError = error{Unexpected};

pub fn QueryInformationFile(
    handle: HANDLE,
    info_class: FILE_INFORMATION_CLASS,
    out_buffer: []u8,
) QueryInformationFileError!void {
    var io: IO_STATUS_BLOCK = undefined;
    const len_bytes = std.math.cast(u32, out_buffer.len) catch unreachable;
    const rc = ntdll.NtQueryInformationFile(handle, &io, out_buffer.ptr, len_bytes, info_class);
    switch (rc) {
        .SUCCESS => {},
        .INVALID_PARAMETER => unreachable,
        else => return unexpectedStatus(rc),
    }
}

pub const GetFileSizeError = error{Unexpected};

pub fn GetFileSizeEx(hFile: HANDLE) GetFileSizeError!u64 {
    var file_size: LARGE_INTEGER = undefined;
    if (kernel32.GetFileSizeEx(hFile, &file_size) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return @bitCast(u64, file_size);
}

pub const GetFileAttributesError = error{
    FileNotFound,
    PermissionDenied,
    Unexpected,
};

pub fn GetFileAttributes(filename: []const u8) GetFileAttributesError!DWORD {
    const filename_w = try sliceToPrefixedFileW(filename);
    return GetFileAttributesW(filename_w.span().ptr);
}

pub fn GetFileAttributesW(lpFileName: [*:0]const u16) GetFileAttributesError!DWORD {
    const rc = kernel32.GetFileAttributesW(lpFileName);
    if (rc == INVALID_FILE_ATTRIBUTES) {
        switch (kernel32.GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .ACCESS_DENIED => return error.PermissionDenied,
            else => |err| return unexpectedError(err),
        }
    }
    return rc;
}

pub fn WSAStartup(majorVersion: u8, minorVersion: u8) !ws2_32.WSADATA {
    var wsadata: ws2_32.WSADATA = undefined;
    return switch (ws2_32.WSAStartup((@as(WORD, minorVersion) << 8) | majorVersion, &wsadata)) {
        0 => wsadata,
        else => |err_int| switch (@intToEnum(ws2_32.WinsockError, @intCast(u16, err_int))) {
            .WSASYSNOTREADY => return error.SystemNotAvailable,
            .WSAVERNOTSUPPORTED => return error.VersionNotSupported,
            .WSAEINPROGRESS => return error.BlockingOperationInProgress,
            .WSAEPROCLIM => return error.ProcessFdQuotaExceeded,
            else => |err| return unexpectedWSAError(err),
        },
    };
}

pub fn WSACleanup() !void {
    return switch (ws2_32.WSACleanup()) {
        0 => {},
        ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
            .WSANOTINITIALISED => return error.NotInitialized,
            .WSAENETDOWN => return error.NetworkNotAvailable,
            .WSAEINPROGRESS => return error.BlockingOperationInProgress,
            else => |err| return unexpectedWSAError(err),
        },
        else => unreachable,
    };
}

var wsa_startup_mutex: std.Thread.Mutex = .{};

/// Microsoft requires WSAStartup to be called to initialize, or else
/// WSASocketW will return WSANOTINITIALISED.
/// Since this is a standard library, we do not have the luxury of
/// putting initialization code anywhere, because we would not want
/// to pay the cost of calling WSAStartup if there ended up being no
/// networking. Also, if Zig code is used as a library, Zig is not in
/// charge of the start code, and we couldn't put in any initialization
/// code even if we wanted to.
/// The documentation for WSAStartup mentions that there must be a
/// matching WSACleanup call. It is not possible for the Zig Standard
/// Library to honor this for the same reason - there is nowhere to put
/// deinitialization code.
/// So, API users of the zig std lib have two options:
///  * (recommended) The simple, cross-platform way: just call `WSASocketW`
///    and don't worry about it. Zig will call WSAStartup() in a thread-safe
///    manner and never deinitialize networking. This is ideal for an
///    application which has the capability to do networking.
///  * The getting-your-hands-dirty way: call `WSAStartup()` before doing
///    networking, so that the error handling code for WSANOTINITIALISED never
///    gets run, which then allows the application or library to call `WSACleanup()`.
///    This could make sense for a library, which has init and deinit
///    functions for the whole library's lifetime.
pub fn WSASocketW(
    af: i32,
    socket_type: i32,
    protocol: i32,
    protocolInfo: ?*ws2_32.WSAPROTOCOL_INFOW,
    g: ws2_32.GROUP,
    dwFlags: DWORD,
) !ws2_32.SOCKET {
    var first = true;
    while (true) {
        const rc = ws2_32.WSASocketW(af, socket_type, protocol, protocolInfo, g, dwFlags);
        if (rc == ws2_32.INVALID_SOCKET) {
            switch (ws2_32.WSAGetLastError()) {
                .WSAEAFNOSUPPORT => return error.AddressFamilyNotSupported,
                .WSAEMFILE => return error.ProcessFdQuotaExceeded,
                .WSAENOBUFS => return error.SystemResources,
                .WSAEPROTONOSUPPORT => return error.ProtocolNotSupported,
                .WSANOTINITIALISED => {
                    if (!first) return error.Unexpected;
                    first = false;

                    var held = wsa_startup_mutex.acquire();
                    defer held.release();

                    // Here we could use a flag to prevent multiple threads to prevent
                    // multiple calls to WSAStartup, but it doesn't matter. We're globally
                    // leaking the resource intentionally, and the mutex already prevents
                    // data races within the WSAStartup function.
                    _ = WSAStartup(2, 2) catch |err| switch (err) {
                        error.SystemNotAvailable => return error.SystemResources,
                        error.VersionNotSupported => return error.Unexpected,
                        error.BlockingOperationInProgress => return error.Unexpected,
                        error.ProcessFdQuotaExceeded => return error.ProcessFdQuotaExceeded,
                        error.Unexpected => return error.Unexpected,
                    };
                    continue;
                },
                else => |err| return unexpectedWSAError(err),
            }
        }
        return rc;
    }
}

pub fn bind(s: ws2_32.SOCKET, name: *const ws2_32.sockaddr, namelen: ws2_32.socklen_t) i32 {
    return ws2_32.bind(s, name, @intCast(i32, namelen));
}

pub fn listen(s: ws2_32.SOCKET, backlog: u31) i32 {
    return ws2_32.listen(s, backlog);
}

pub fn closesocket(s: ws2_32.SOCKET) !void {
    switch (ws2_32.closesocket(s)) {
        0 => {},
        ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
            else => |err| return unexpectedWSAError(err),
        },
        else => unreachable,
    }
}

pub fn accept(s: ws2_32.SOCKET, name: ?*ws2_32.sockaddr, namelen: ?*ws2_32.socklen_t) ws2_32.SOCKET {
    assert((name == null) == (namelen == null));
    return ws2_32.accept(s, name, @ptrCast(?*i32, namelen));
}

pub fn getsockname(s: ws2_32.SOCKET, name: *ws2_32.sockaddr, namelen: *ws2_32.socklen_t) i32 {
    return ws2_32.getsockname(s, name, @ptrCast(*i32, namelen));
}

pub fn getpeername(s: ws2_32.SOCKET, name: *ws2_32.sockaddr, namelen: *ws2_32.socklen_t) i32 {
    return ws2_32.getpeername(s, name, @ptrCast(*i32, namelen));
}

pub fn sendmsg(
    s: ws2_32.SOCKET,
    msg: *const ws2_32.WSAMSG,
    flags: u32,
) i32 {
    var bytes_send: DWORD = undefined;
    if (ws2_32.WSASendMsg(s, msg, flags, &bytes_send, null, null) == ws2_32.SOCKET_ERROR) {
        return ws2_32.SOCKET_ERROR;
    } else {
        return @as(i32, @intCast(u31, bytes_send));
    }
}

pub fn sendto(s: ws2_32.SOCKET, buf: [*]const u8, len: usize, flags: u32, to: ?*const ws2_32.sockaddr, to_len: ws2_32.socklen_t) i32 {
    var buffer = ws2_32.WSABUF{ .len = @truncate(u31, len), .buf = @intToPtr([*]u8, @ptrToInt(buf)) };
    var bytes_send: DWORD = undefined;
    if (ws2_32.WSASendTo(s, @ptrCast([*]ws2_32.WSABUF, &buffer), 1, &bytes_send, flags, to, @intCast(i32, to_len), null, null) == ws2_32.SOCKET_ERROR) {
        return ws2_32.SOCKET_ERROR;
    } else {
        return @as(i32, @intCast(u31, bytes_send));
    }
}

pub fn recvfrom(s: ws2_32.SOCKET, buf: [*]u8, len: usize, flags: u32, from: ?*ws2_32.sockaddr, from_len: ?*ws2_32.socklen_t) i32 {
    var buffer = ws2_32.WSABUF{ .len = @truncate(u31, len), .buf = buf };
    var bytes_received: DWORD = undefined;
    var flags_inout = flags;
    if (ws2_32.WSARecvFrom(s, @ptrCast([*]ws2_32.WSABUF, &buffer), 1, &bytes_received, &flags_inout, from, @ptrCast(?*i32, from_len), null, null) == ws2_32.SOCKET_ERROR) {
        return ws2_32.SOCKET_ERROR;
    } else {
        return @as(i32, @intCast(u31, bytes_received));
    }
}

pub fn poll(fds: [*]ws2_32.pollfd, n: c_ulong, timeout: i32) i32 {
    return ws2_32.WSAPoll(fds, n, timeout);
}

pub fn WSAIoctl(
    s: ws2_32.SOCKET,
    dwIoControlCode: DWORD,
    inBuffer: ?[]const u8,
    outBuffer: []u8,
    overlapped: ?*ws2_32.WSAOVERLAPPED,
    completionRoutine: ?ws2_32.WSAOVERLAPPED_COMPLETION_ROUTINE,
) !DWORD {
    var bytes: DWORD = undefined;
    switch (ws2_32.WSAIoctl(
        s,
        dwIoControlCode,
        if (inBuffer) |i| i.ptr else null,
        if (inBuffer) |i| @intCast(DWORD, i.len) else 0,
        outBuffer.ptr,
        @intCast(DWORD, outBuffer.len),
        &bytes,
        overlapped,
        completionRoutine,
    )) {
        0 => {},
        ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
            else => |err| return unexpectedWSAError(err),
        },
        else => unreachable,
    }
    return bytes;
}

const GetModuleFileNameError = error{Unexpected};

pub fn GetModuleFileNameW(hModule: ?HMODULE, buf_ptr: [*]u16, buf_len: DWORD) GetModuleFileNameError![:0]u16 {
    const rc = kernel32.GetModuleFileNameW(hModule, buf_ptr, buf_len);
    if (rc == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return buf_ptr[0..rc :0];
}

pub const TerminateProcessError = error{Unexpected};

pub fn TerminateProcess(hProcess: HANDLE, uExitCode: UINT) TerminateProcessError!void {
    if (kernel32.TerminateProcess(hProcess, uExitCode) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const VirtualAllocError = error{Unexpected};

pub fn VirtualAlloc(addr: ?LPVOID, size: usize, alloc_type: DWORD, flProtect: DWORD) VirtualAllocError!LPVOID {
    return kernel32.VirtualAlloc(addr, size, alloc_type, flProtect) orelse {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    };
}

pub fn VirtualFree(lpAddress: ?LPVOID, dwSize: usize, dwFreeType: DWORD) void {
    assert(kernel32.VirtualFree(lpAddress, dwSize, dwFreeType) != 0);
}

pub const SetConsoleTextAttributeError = error{Unexpected};

pub fn SetConsoleTextAttribute(hConsoleOutput: HANDLE, wAttributes: WORD) SetConsoleTextAttributeError!void {
    if (kernel32.SetConsoleTextAttribute(hConsoleOutput, wAttributes) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub fn SetConsoleCtrlHandler(handler_routine: ?HANDLER_ROUTINE, add: bool) !void {
    const success = kernel32.SetConsoleCtrlHandler(
        handler_routine,
        if (add) TRUE else FALSE,
    );

    if (success == FALSE) {
        return switch (kernel32.GetLastError()) {
            else => |err| unexpectedError(err),
        };
    }
}

pub fn SetFileCompletionNotificationModes(handle: HANDLE, flags: UCHAR) !void {
    const success = kernel32.SetFileCompletionNotificationModes(handle, flags);
    if (success == FALSE) {
        return switch (kernel32.GetLastError()) {
            else => |err| unexpectedError(err),
        };
    }
}

pub const GetEnvironmentStringsError = error{OutOfMemory};

pub fn GetEnvironmentStringsW() GetEnvironmentStringsError![*:0]u16 {
    return kernel32.GetEnvironmentStringsW() orelse return error.OutOfMemory;
}

pub fn FreeEnvironmentStringsW(penv: [*:0]u16) void {
    assert(kernel32.FreeEnvironmentStringsW(penv) != 0);
}

pub const GetEnvironmentVariableError = error{
    EnvironmentVariableNotFound,
    Unexpected,
};

pub fn GetEnvironmentVariableW(lpName: LPWSTR, lpBuffer: [*]u16, nSize: DWORD) GetEnvironmentVariableError!DWORD {
    const rc = kernel32.GetEnvironmentVariableW(lpName, lpBuffer, nSize);
    if (rc == 0) {
        switch (kernel32.GetLastError()) {
            .ENVVAR_NOT_FOUND => return error.EnvironmentVariableNotFound,
            else => |err| return unexpectedError(err),
        }
    }
    return rc;
}

pub const CreateProcessError = error{
    FileNotFound,
    AccessDenied,
    InvalidName,
    Unexpected,
};

pub fn CreateProcessW(
    lpApplicationName: ?LPWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: ?*c_void,
    lpCurrentDirectory: ?LPWSTR,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) CreateProcessError!void {
    if (kernel32.CreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
    ) == 0) {
        switch (kernel32.GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .ACCESS_DENIED => return error.AccessDenied,
            .INVALID_PARAMETER => unreachable,
            .INVALID_NAME => return error.InvalidName,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const LoadLibraryError = error{
    FileNotFound,
    Unexpected,
};

pub fn LoadLibraryW(lpLibFileName: [*:0]const u16) LoadLibraryError!HMODULE {
    return kernel32.LoadLibraryW(lpLibFileName) orelse {
        switch (kernel32.GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .MOD_NOT_FOUND => return error.FileNotFound,
            else => |err| return unexpectedError(err),
        }
    };
}

pub fn FreeLibrary(hModule: HMODULE) void {
    assert(kernel32.FreeLibrary(hModule) != 0);
}

pub fn QueryPerformanceFrequency() u64 {
    // "On systems that run Windows XP or later, the function will always succeed"
    // https://docs.microsoft.com/en-us/windows/desktop/api/profileapi/nf-profileapi-queryperformancefrequency
    var result: LARGE_INTEGER = undefined;
    assert(kernel32.QueryPerformanceFrequency(&result) != 0);
    // The kernel treats this integer as unsigned.
    return @bitCast(u64, result);
}

pub fn QueryPerformanceCounter() u64 {
    // "On systems that run Windows XP or later, the function will always succeed"
    // https://docs.microsoft.com/en-us/windows/desktop/api/profileapi/nf-profileapi-queryperformancecounter
    var result: LARGE_INTEGER = undefined;
    assert(kernel32.QueryPerformanceCounter(&result) != 0);
    // The kernel treats this integer as unsigned.
    return @bitCast(u64, result);
}

pub fn InitOnceExecuteOnce(InitOnce: *INIT_ONCE, InitFn: INIT_ONCE_FN, Parameter: ?*c_void, Context: ?*c_void) void {
    assert(kernel32.InitOnceExecuteOnce(InitOnce, InitFn, Parameter, Context) != 0);
}

pub fn HeapFree(hHeap: HANDLE, dwFlags: DWORD, lpMem: *c_void) void {
    assert(kernel32.HeapFree(hHeap, dwFlags, lpMem) != 0);
}

pub fn HeapDestroy(hHeap: HANDLE) void {
    assert(kernel32.HeapDestroy(hHeap) != 0);
}

pub const GetFileInformationByHandleError = error{Unexpected};

pub fn GetFileInformationByHandle(
    hFile: HANDLE,
) GetFileInformationByHandleError!BY_HANDLE_FILE_INFORMATION {
    var info: BY_HANDLE_FILE_INFORMATION = undefined;
    const rc = ntdll.GetFileInformationByHandle(hFile, &info);
    if (rc == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return info;
}

pub const SetFileTimeError = error{Unexpected};

pub fn SetFileTime(
    hFile: HANDLE,
    lpCreationTime: ?*const FILETIME,
    lpLastAccessTime: ?*const FILETIME,
    lpLastWriteTime: ?*const FILETIME,
) SetFileTimeError!void {
    const rc = kernel32.SetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
    if (rc == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const LockFileError = error{
    SystemResources,
    WouldBlock,
} || std.os.UnexpectedError;

pub fn LockFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?*IO_APC_ROUTINE,
    ApcContext: ?*c_void,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ByteOffset: *const LARGE_INTEGER,
    Length: *const LARGE_INTEGER,
    Key: ?*ULONG,
    FailImmediately: BOOLEAN,
    ExclusiveLock: BOOLEAN,
) !void {
    const rc = ntdll.NtLockFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        ByteOffset,
        Length,
        Key,
        FailImmediately,
        ExclusiveLock,
    );
    switch (rc) {
        .SUCCESS => return,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .LOCK_NOT_GRANTED => return error.WouldBlock,
        .ACCESS_VIOLATION => unreachable, // bad io_status_block pointer
        else => return unexpectedStatus(rc),
    }
}

pub const UnlockFileError = error{
    RangeNotLocked,
} || std.os.UnexpectedError;

pub fn UnlockFile(
    FileHandle: HANDLE,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ByteOffset: *const LARGE_INTEGER,
    Length: *const LARGE_INTEGER,
    Key: ?*ULONG,
) !void {
    const rc = ntdll.NtUnlockFile(FileHandle, IoStatusBlock, ByteOffset, Length, Key);
    switch (rc) {
        .SUCCESS => return,
        .RANGE_NOT_LOCKED => return error.RangeNotLocked,
        .ACCESS_VIOLATION => unreachable, // bad io_status_block pointer
        else => return unexpectedStatus(rc),
    }
}

pub fn teb() *TEB {
    return switch (builtin.cpu.arch) {
        .i386 => asm volatile (
            \\ movl %%fs:0x18, %[ptr]
            : [ptr] "=r" (-> *TEB)
        ),
        .x86_64 => asm volatile (
            \\ movq %%gs:0x30, %[ptr]
            : [ptr] "=r" (-> *TEB)
        ),
        .aarch64 => asm volatile (
            \\ mov %[ptr], x18
            : [ptr] "=r" (-> *TEB)
        ),
        else => @compileError("unsupported arch"),
    };
}

pub fn peb() *PEB {
    return teb().ProcessEnvironmentBlock;
}

/// A file time is a 64-bit value that represents the number of 100-nanosecond
/// intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated
/// Universal Time (UTC).
/// This function returns the number of nanoseconds since the canonical epoch,
/// which is the POSIX one (Jan 01, 1970 AD).
pub fn fromSysTime(hns: i64) i128 {
    const adjusted_epoch: i128 = hns + std.time.epoch.windows * (std.time.ns_per_s / 100);
    return adjusted_epoch * 100;
}

pub fn toSysTime(ns: i128) i64 {
    const hns = @divFloor(ns, 100);
    return @intCast(i64, hns) - std.time.epoch.windows * (std.time.ns_per_s / 100);
}

pub fn fileTimeToNanoSeconds(ft: FILETIME) i128 {
    const hns = (@as(i64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return fromSysTime(hns);
}

/// Converts a number of nanoseconds since the POSIX epoch to a Windows FILETIME.
pub fn nanoSecondsToFileTime(ns: i128) FILETIME {
    const adjusted = @bitCast(u64, toSysTime(ns));
    return FILETIME{
        .dwHighDateTime = @truncate(u32, adjusted >> 32),
        .dwLowDateTime = @truncate(u32, adjusted),
    };
}

pub const PathSpace = struct {
    data: [PATH_MAX_WIDE:0]u16,
    len: usize,

    pub fn span(self: PathSpace) [:0]const u16 {
        return self.data[0..self.len :0];
    }
};

/// The error type for `removeDotDirsSanitized`
pub const RemoveDotDirsError = error{TooManyParentDirs};

/// Removes '.' and '..' path components from a "sanitized relative path".
/// A "sanitized path" is one where:
///    1) all forward slashes have been replaced with back slashes
///    2) all repeating back slashes have been collapsed
///    3) the path is a relative one (does not start with a back slash)
pub fn removeDotDirsSanitized(comptime T: type, path: []T) RemoveDotDirsError!usize {
    std.debug.assert(path.len == 0 or path[0] != '\\');

    var write_idx: usize = 0;
    var read_idx: usize = 0;
    while (read_idx < path.len) {
        if (path[read_idx] == '.') {
            if (read_idx + 1 == path.len)
                return write_idx;

            const after_dot = path[read_idx + 1];
            if (after_dot == '\\') {
                read_idx += 2;
                continue;
            }
            if (after_dot == '.' and (read_idx + 2 == path.len or path[read_idx + 2] == '\\')) {
                if (write_idx == 0) return error.TooManyParentDirs;
                std.debug.assert(write_idx >= 2);
                write_idx -= 1;
                while (true) {
                    write_idx -= 1;
                    if (write_idx == 0) break;
                    if (path[write_idx] == '\\') {
                        write_idx += 1;
                        break;
                    }
                }
                if (read_idx + 2 == path.len)
                    return write_idx;
                read_idx += 3;
                continue;
            }
        }

        // skip to the next path separator
        while (true) : (read_idx += 1) {
            if (read_idx == path.len)
                return write_idx;
            path[write_idx] = path[read_idx];
            write_idx += 1;
            if (path[read_idx] == '\\')
                break;
        }
        read_idx += 1;
    }
    return write_idx;
}

/// Normalizes a Windows path with the following steps:
///     1) convert all forward slashes to back slashes
///     2) collapse duplicate back slashes
///     3) remove '.' and '..' directory parts
/// Returns the length of the new path.
pub fn normalizePath(comptime T: type, path: []T) RemoveDotDirsError!usize {
    mem.replaceScalar(T, path, '/', '\\');
    const new_len = mem.collapseRepeatsLen(T, path, '\\');

    const prefix_len: usize = init: {
        if (new_len >= 1 and path[0] == '\\') break :init 1;
        if (new_len >= 2 and path[1] == ':')
            break :init if (new_len >= 3 and path[2] == '\\') @as(usize, 3) else @as(usize, 2);
        break :init 0;
    };

    return prefix_len + try removeDotDirsSanitized(T, path[prefix_len..new_len]);
}

/// Same as `sliceToPrefixedFileW` but accepts a pointer
/// to a null-terminated path.
pub fn cStrToPrefixedFileW(s: [*:0]const u8) !PathSpace {
    return sliceToPrefixedFileW(mem.spanZ(s));
}

/// Converts the path `s` to WTF16, null-terminated. If the path is absolute,
/// it will get NT-style prefix `\??\` prepended automatically.
pub fn sliceToPrefixedFileW(s: []const u8) !PathSpace {
    // TODO https://github.com/ziglang/zig/issues/2765
    var path_space: PathSpace = undefined;
    const prefix = "\\??\\";
    const prefix_index: usize = if (mem.startsWith(u8, s, prefix)) prefix.len else 0;
    for (s[prefix_index..]) |byte| {
        switch (byte) {
            '*', '?', '"', '<', '>', '|' => return error.BadPathName,
            else => {},
        }
    }
    const prefix_u16 = [_]u16{ '\\', '?', '?', '\\' };
    const start_index = if (prefix_index > 0 or !std.fs.path.isAbsolute(s)) 0 else blk: {
        mem.copy(u16, path_space.data[0..], prefix_u16[0..]);
        break :blk prefix_u16.len;
    };
    path_space.len = start_index + try std.unicode.utf8ToUtf16Le(path_space.data[start_index..], s);
    if (path_space.len > path_space.data.len) return error.NameTooLong;
    path_space.len = start_index + (normalizePath(u16, path_space.data[start_index..path_space.len]) catch |err| switch (err) {
        error.TooManyParentDirs => {
            if (!std.fs.path.isAbsolute(s)) {
                var temp_path: PathSpace = undefined;
                temp_path.len = try std.unicode.utf8ToUtf16Le(&temp_path.data, s);
                std.debug.assert(temp_path.len == path_space.len);
                temp_path.data[path_space.len] = 0;
                path_space.len = prefix_u16.len + try getFullPathNameW(&temp_path.data, path_space.data[prefix_u16.len..]);
                mem.copy(u16, &path_space.data, &prefix_u16);
                std.debug.assert(path_space.data[path_space.len] == 0);
                return path_space;
            }
            return error.BadPathName;
        },
    });
    path_space.data[path_space.len] = 0;
    return path_space;
}

fn getFullPathNameW(path: [*:0]const u16, out: []u16) !usize {
    const result = kernel32.GetFullPathNameW(path, @intCast(u32, out.len), std.meta.assumeSentinel(out.ptr, 0), null);
    if (result == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return result;
}

/// Assumes an absolute path.
pub fn wToPrefixedFileW(s: []const u16) !PathSpace {
    // TODO https://github.com/ziglang/zig/issues/2765
    var path_space: PathSpace = undefined;

    const start_index = if (mem.startsWith(u16, s, &[_]u16{ '\\', '?' })) 0 else blk: {
        const prefix = [_]u16{ '\\', '?', '?', '\\' };
        mem.copy(u16, path_space.data[0..], &prefix);
        break :blk prefix.len;
    };
    path_space.len = start_index + s.len;
    if (path_space.len > path_space.data.len) return error.NameTooLong;
    mem.copy(u16, path_space.data[start_index..], s);
    // > File I/O functions in the Windows API convert "/" to "\" as part of
    // > converting the name to an NT-style name, except when using the "\\?\"
    // > prefix as detailed in the following sections.
    // from https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#maximum-path-length-limitation
    // Because we want the larger maximum path length for absolute paths, we
    // convert forward slashes to backward slashes here.
    for (path_space.data[0..path_space.len]) |*elem| {
        if (elem.* == '/') {
            elem.* = '\\';
        }
    }
    path_space.data[path_space.len] = 0;
    return path_space;
}

inline fn MAKELANGID(p: c_ushort, s: c_ushort) LANGID {
    return (s << 10) | p;
}

/// Loads a Winsock extension function in runtime specified by a GUID.
pub fn loadWinsockExtensionFunction(comptime T: type, sock: ws2_32.SOCKET, guid: GUID) !T {
    var function: T = undefined;
    var num_bytes: DWORD = undefined;

    const rc = ws2_32.WSAIoctl(
        sock,
        ws2_32.SIO_GET_EXTENSION_FUNCTION_POINTER,
        @ptrCast(*const c_void, &guid),
        @sizeOf(GUID),
        &function,
        @sizeOf(T),
        &num_bytes,
        null,
        null,
    );

    if (rc == ws2_32.SOCKET_ERROR) {
        return switch (ws2_32.WSAGetLastError()) {
            .WSAEOPNOTSUPP => error.OperationNotSupported,
            .WSAENOTSOCK => error.FileDescriptorNotASocket,
            else => |err| unexpectedWSAError(err),
        };
    }

    if (num_bytes != @sizeOf(T)) {
        return error.ShortRead;
    }

    return function;
}

/// Call this when you made a windows DLL call or something that does SetLastError
/// and you get an unexpected error.
pub fn unexpectedError(err: Win32Error) std.os.UnexpectedError {
    if (std.os.unexpected_error_tracing) {
        // 614 is the length of the longest windows error desciption
        var buf_wstr: [614]WCHAR = undefined;
        var buf_utf8: [614]u8 = undefined;
        const len = kernel32.FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null,
            err,
            MAKELANGID(LANG.NEUTRAL, SUBLANG.DEFAULT),
            &buf_wstr,
            buf_wstr.len,
            null,
        );
        _ = std.unicode.utf16leToUtf8(&buf_utf8, buf_wstr[0..len]) catch unreachable;
        std.debug.warn("error.Unexpected: GetLastError({}): {s}\n", .{ @enumToInt(err), buf_utf8[0..len] });
        std.debug.dumpCurrentStackTrace(null);
    }
    return error.Unexpected;
}

pub fn unexpectedWSAError(err: ws2_32.WinsockError) std.os.UnexpectedError {
    return unexpectedError(@intToEnum(Win32Error, @enumToInt(err)));
}

/// Call this when you made a windows NtDll call
/// and you get an unexpected status.
pub fn unexpectedStatus(status: NTSTATUS) std.os.UnexpectedError {
    if (std.os.unexpected_error_tracing) {
        std.debug.warn("error.Unexpected NTSTATUS=0x{x}\n", .{@enumToInt(status)});
        std.debug.dumpCurrentStackTrace(null);
    }
    return error.Unexpected;
}

test "" {
    if (builtin.os.tag == .windows) {
        _ = @import("windows/test.zig");
    }
}
