// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std.zig");
const root = @import("root");
const builtin = @import("builtin");
const debug = std.debug;
const assert = debug.assert;
const testing = std.testing;
const mem = std.mem;
const os = std.os;
const c = std.c;
const maxInt = std.math.maxInt;

pub const LoggingAllocator = @import("heap/logging_allocator.zig").LoggingAllocator;
pub const loggingAllocator = @import("heap/logging_allocator.zig").loggingAllocator;
pub const ScopedLoggingAllocator = @import("heap/logging_allocator.zig").ScopedLoggingAllocator;
pub const LogToWriterAllocator = @import("heap/log_to_writer_allocator.zig").LogToWriterAllocator;
pub const logToWriterAllocator = @import("heap/log_to_writer_allocator.zig").logToWriterAllocator;
pub const ArenaAllocator = @import("heap/arena_allocator.zig").ArenaAllocator;
pub const GeneralPurposeAllocator = @import("heap/general_purpose_allocator.zig").GeneralPurposeAllocator;

const Allocator = mem.Allocator;

const CAllocator = struct {
    comptime {
        if (!builtin.link_libc) {
            @compileError("C allocator is only available when linking against libc");
        }
    }

    usingnamespace if (@hasDecl(c, "malloc_size"))
        struct {
            pub const supports_malloc_size = true;
            pub const malloc_size = c.malloc_size;
        }
    else if (@hasDecl(c, "malloc_usable_size"))
        struct {
            pub const supports_malloc_size = true;
            pub const malloc_size = c.malloc_usable_size;
        }
    else if (@hasDecl(c, "_msize"))
        struct {
            pub const supports_malloc_size = true;
            pub const malloc_size = c._msize;
        }
    else
        struct {
            pub const supports_malloc_size = false;
        };

    pub const supports_posix_memalign = @hasDecl(c, "posix_memalign");

    fn getHeader(ptr: [*]u8) *[*]u8 {
        return @intToPtr(*[*]u8, @ptrToInt(ptr) - @sizeOf(usize));
    }

    fn alignedAlloc(len: usize, alignment: usize) ?[*]u8 {
        if (supports_posix_memalign) {
            // The posix_memalign only accepts alignment values that are a
            // multiple of the pointer size
            const eff_alignment = std.math.max(alignment, @sizeOf(usize));

            var aligned_ptr: ?*c_void = undefined;
            if (c.posix_memalign(&aligned_ptr, eff_alignment, len) != 0)
                return null;

            return @ptrCast([*]u8, aligned_ptr);
        }

        // Thin wrapper around regular malloc, overallocate to account for
        // alignment padding and store the orignal malloc()'ed pointer before
        // the aligned address.
        var unaligned_ptr = @ptrCast([*]u8, c.malloc(len + alignment - 1 + @sizeOf(usize)) orelse return null);
        const unaligned_addr = @ptrToInt(unaligned_ptr);
        const aligned_addr = mem.alignForward(unaligned_addr + @sizeOf(usize), alignment);
        var aligned_ptr = unaligned_ptr + (aligned_addr - unaligned_addr);
        getHeader(aligned_ptr).* = unaligned_ptr;

        return aligned_ptr;
    }

    fn alignedFree(ptr: [*]u8) void {
        if (supports_posix_memalign) {
            return c.free(ptr);
        }

        const unaligned_ptr = getHeader(ptr).*;
        c.free(unaligned_ptr);
    }

    fn alignedAllocSize(ptr: [*]u8) usize {
        if (supports_posix_memalign) {
            return malloc_size(ptr);
        }

        const unaligned_ptr = getHeader(ptr).*;
        const delta = @ptrToInt(ptr) - @ptrToInt(unaligned_ptr);
        return malloc_size(unaligned_ptr) - delta;
    }

    fn alloc(
        allocator: *Allocator,
        len: usize,
        alignment: u29,
        len_align: u29,
        return_address: usize,
    ) error{OutOfMemory}![]u8 {
        _ = allocator;
        _ = return_address;
        assert(len > 0);
        assert(std.math.isPowerOfTwo(alignment));

        var ptr = alignedAlloc(len, alignment) orelse return error.OutOfMemory;
        if (len_align == 0) {
            return ptr[0..len];
        }
        const full_len = init: {
            if (supports_malloc_size) {
                const s = alignedAllocSize(ptr);
                assert(s >= len);
                break :init s;
            }
            break :init len;
        };
        return ptr[0..mem.alignBackwardAnyAlign(full_len, len_align)];
    }

    fn resize(
        allocator: *Allocator,
        buf: []u8,
        buf_align: u29,
        new_len: usize,
        len_align: u29,
        return_address: usize,
    ) Allocator.Error!usize {
        _ = allocator;
        _ = buf_align;
        _ = return_address;
        if (new_len == 0) {
            alignedFree(buf.ptr);
            return 0;
        }
        if (new_len <= buf.len) {
            return mem.alignAllocLen(buf.len, new_len, len_align);
        }
        if (supports_malloc_size) {
            const full_len = alignedAllocSize(buf.ptr);
            if (new_len <= full_len) {
                return mem.alignAllocLen(full_len, new_len, len_align);
            }
        }
        return error.OutOfMemory;
    }
};

/// Supports the full Allocator interface, including alignment, and exploiting
/// `malloc_usable_size` if available. For an allocator that directly calls
/// `malloc`/`free`, see `raw_c_allocator`.
pub const c_allocator = &c_allocator_state;
var c_allocator_state = Allocator{
    .allocFn = CAllocator.alloc,
    .resizeFn = CAllocator.resize,
};

/// Asserts allocations are within `@alignOf(std.c.max_align_t)` and directly calls
/// `malloc`/`free`. Does not attempt to utilize `malloc_usable_size`.
/// This allocator is safe to use as the backing allocator with
/// `ArenaAllocator` for example and is more optimal in such a case
/// than `c_allocator`.
pub const raw_c_allocator = &raw_c_allocator_state;
var raw_c_allocator_state = Allocator{
    .allocFn = rawCAlloc,
    .resizeFn = rawCResize,
};

fn rawCAlloc(
    self: *Allocator,
    len: usize,
    ptr_align: u29,
    len_align: u29,
    ret_addr: usize,
) Allocator.Error![]u8 {
    _ = self;
    _ = len_align;
    _ = ret_addr;
    assert(ptr_align <= @alignOf(std.c.max_align_t));
    const ptr = @ptrCast([*]u8, c.malloc(len) orelse return error.OutOfMemory);
    return ptr[0..len];
}

fn rawCResize(
    self: *Allocator,
    buf: []u8,
    old_align: u29,
    new_len: usize,
    len_align: u29,
    ret_addr: usize,
) Allocator.Error!usize {
    _ = self;
    _ = old_align;
    _ = ret_addr;
    if (new_len == 0) {
        c.free(buf.ptr);
        return 0;
    }
    if (new_len <= buf.len) {
        return mem.alignAllocLen(buf.len, new_len, len_align);
    }
    return error.OutOfMemory;
}

/// This allocator makes a syscall directly for every allocation and free.
/// Thread-safe and lock-free.
pub const page_allocator = if (builtin.target.isWasm())
    &wasm_page_allocator_state
else if (builtin.os.tag == .freestanding)
    root.os.heap.page_allocator
else
    &page_allocator_state;

var page_allocator_state = Allocator{
    .allocFn = PageAllocator.alloc,
    .resizeFn = PageAllocator.resize,
};
var wasm_page_allocator_state = Allocator{
    .allocFn = WasmPageAllocator.alloc,
    .resizeFn = WasmPageAllocator.resize,
};

/// Verifies that the adjusted length will still map to the full length
pub fn alignPageAllocLen(full_len: usize, len: usize, len_align: u29) usize {
    const aligned_len = mem.alignAllocLen(full_len, len, len_align);
    assert(mem.alignForward(aligned_len, mem.page_size) == full_len);
    return aligned_len;
}

/// TODO Utilize this on Windows.
pub var next_mmap_addr_hint: ?[*]align(mem.page_size) u8 = null;

const PageAllocator = struct {
    fn alloc(allocator: *Allocator, n: usize, alignment: u29, len_align: u29, ra: usize) error{OutOfMemory}![]u8 {
        _ = allocator;
        _ = ra;
        assert(n > 0);
        const aligned_len = mem.alignForward(n, mem.page_size);

        if (builtin.os.tag == .windows) {
            const w = os.windows;

            // Although officially it's at least aligned to page boundary,
            // Windows is known to reserve pages on a 64K boundary. It's
            // even more likely that the requested alignment is <= 64K than
            // 4K, so we're just allocating blindly and hoping for the best.
            // see https://devblogs.microsoft.com/oldnewthing/?p=42223
            const addr = w.VirtualAlloc(
                null,
                aligned_len,
                w.MEM_COMMIT | w.MEM_RESERVE,
                w.PAGE_READWRITE,
            ) catch return error.OutOfMemory;

            // If the allocation is sufficiently aligned, use it.
            if (mem.isAligned(@ptrToInt(addr), alignment)) {
                return @ptrCast([*]u8, addr)[0..alignPageAllocLen(aligned_len, n, len_align)];
            }

            // If it wasn't, actually do an explicitely aligned allocation.
            w.VirtualFree(addr, 0, w.MEM_RELEASE);
            const alloc_size = n + alignment - mem.page_size;

            while (true) {
                // Reserve a range of memory large enough to find a sufficiently
                // aligned address.
                const reserved_addr = w.VirtualAlloc(
                    null,
                    alloc_size,
                    w.MEM_RESERVE,
                    w.PAGE_NOACCESS,
                ) catch return error.OutOfMemory;
                const aligned_addr = mem.alignForward(@ptrToInt(reserved_addr), alignment);

                // Release the reserved pages (not actually used).
                w.VirtualFree(reserved_addr, 0, w.MEM_RELEASE);

                // At this point, it is possible that another thread has
                // obtained some memory space that will cause the next
                // VirtualAlloc call to fail. To handle this, we will retry
                // until it succeeds.
                const ptr = w.VirtualAlloc(
                    @intToPtr(*c_void, aligned_addr),
                    aligned_len,
                    w.MEM_COMMIT | w.MEM_RESERVE,
                    w.PAGE_READWRITE,
                ) catch continue;

                return @ptrCast([*]u8, ptr)[0..alignPageAllocLen(aligned_len, n, len_align)];
            }
        }

        const max_drop_len = alignment - std.math.min(alignment, mem.page_size);
        const alloc_len = if (max_drop_len <= aligned_len - n)
            aligned_len
        else
            mem.alignForward(aligned_len + max_drop_len, mem.page_size);
        const hint = @atomicLoad(@TypeOf(next_mmap_addr_hint), &next_mmap_addr_hint, .Unordered);
        const slice = os.mmap(
            hint,
            alloc_len,
            os.PROT_READ | os.PROT_WRITE,
            os.MAP_PRIVATE | os.MAP_ANONYMOUS,
            -1,
            0,
        ) catch return error.OutOfMemory;
        assert(mem.isAligned(@ptrToInt(slice.ptr), mem.page_size));

        const result_ptr = mem.alignPointer(slice.ptr, alignment) orelse
            return error.OutOfMemory;

        // Unmap the extra bytes that were only requested in order to guarantee
        // that the range of memory we were provided had a proper alignment in
        // it somewhere. The extra bytes could be at the beginning, or end, or both.
        const drop_len = @ptrToInt(result_ptr) - @ptrToInt(slice.ptr);
        if (drop_len != 0) {
            os.munmap(slice[0..drop_len]);
        }

        // Unmap extra pages
        const aligned_buffer_len = alloc_len - drop_len;
        if (aligned_buffer_len > aligned_len) {
            os.munmap(result_ptr[aligned_len..aligned_buffer_len]);
        }

        const new_hint = @alignCast(mem.page_size, result_ptr + aligned_len);
        _ = @cmpxchgStrong(@TypeOf(next_mmap_addr_hint), &next_mmap_addr_hint, hint, new_hint, .Monotonic, .Monotonic);

        return result_ptr[0..alignPageAllocLen(aligned_len, n, len_align)];
    }

    fn resize(
        allocator: *Allocator,
        buf_unaligned: []u8,
        buf_align: u29,
        new_size: usize,
        len_align: u29,
        return_address: usize,
    ) Allocator.Error!usize {
        _ = allocator;
        _ = buf_align;
        _ = return_address;
        const new_size_aligned = mem.alignForward(new_size, mem.page_size);

        if (builtin.os.tag == .windows) {
            const w = os.windows;
            if (new_size == 0) {
                // From the docs:
                // "If the dwFreeType parameter is MEM_RELEASE, this parameter
                // must be 0 (zero). The function frees the entire region that
                // is reserved in the initial allocation call to VirtualAlloc."
                // So we can only use MEM_RELEASE when actually releasing the
                // whole allocation.
                w.VirtualFree(buf_unaligned.ptr, 0, w.MEM_RELEASE);
                return 0;
            }
            if (new_size <= buf_unaligned.len) {
                const base_addr = @ptrToInt(buf_unaligned.ptr);
                const old_addr_end = base_addr + buf_unaligned.len;
                const new_addr_end = mem.alignForward(base_addr + new_size, mem.page_size);
                if (old_addr_end > new_addr_end) {
                    // For shrinking that is not releasing, we will only
                    // decommit the pages not needed anymore.
                    w.VirtualFree(
                        @intToPtr(*c_void, new_addr_end),
                        old_addr_end - new_addr_end,
                        w.MEM_DECOMMIT,
                    );
                }
                return alignPageAllocLen(new_size_aligned, new_size, len_align);
            }
            const old_size_aligned = mem.alignForward(buf_unaligned.len, mem.page_size);
            if (new_size_aligned <= old_size_aligned) {
                return alignPageAllocLen(new_size_aligned, new_size, len_align);
            }
            return error.OutOfMemory;
        }

        const buf_aligned_len = mem.alignForward(buf_unaligned.len, mem.page_size);
        if (new_size_aligned == buf_aligned_len)
            return alignPageAllocLen(new_size_aligned, new_size, len_align);

        if (new_size_aligned < buf_aligned_len) {
            const ptr = @alignCast(mem.page_size, buf_unaligned.ptr + new_size_aligned);
            // TODO: if the next_mmap_addr_hint is within the unmapped range, update it
            os.munmap(ptr[0 .. buf_aligned_len - new_size_aligned]);
            if (new_size_aligned == 0)
                return 0;
            return alignPageAllocLen(new_size_aligned, new_size, len_align);
        }

        // TODO: call mremap
        // TODO: if the next_mmap_addr_hint is within the remapped range, update it
        return error.OutOfMemory;
    }
};

const WasmPageAllocator = struct {
    comptime {
        if (!builtin.target.isWasm()) {
            @compileError("WasmPageAllocator is only available for wasm32 arch");
        }
    }

    const PageStatus = enum(u1) {
        used = 0,
        free = 1,

        pub const none_free: u8 = 0;
    };

    const FreeBlock = struct {
        data: []u128,

        const Io = std.packed_int_array.PackedIntIo(u1, .Little);

        fn totalPages(self: FreeBlock) usize {
            return self.data.len * 128;
        }

        fn isInitialized(self: FreeBlock) bool {
            return self.data.len > 0;
        }

        fn getBit(self: FreeBlock, idx: usize) PageStatus {
            const bit_offset = 0;
            return @intToEnum(PageStatus, Io.get(mem.sliceAsBytes(self.data), idx, bit_offset));
        }

        fn setBits(self: FreeBlock, start_idx: usize, len: usize, val: PageStatus) void {
            const bit_offset = 0;
            var i: usize = 0;
            while (i < len) : (i += 1) {
                Io.set(mem.sliceAsBytes(self.data), start_idx + i, bit_offset, @enumToInt(val));
            }
        }

        // Use '0xFFFFFFFF' as a _missing_ sentinel
        // This saves ~50 bytes compared to returning a nullable

        // We can guarantee that conventional memory never gets this big,
        // and wasm32 would not be able to address this memory (32 GB > usize).

        // Revisit if this is settled: https://github.com/ziglang/zig/issues/3806
        const not_found = std.math.maxInt(usize);

        fn useRecycled(self: FreeBlock, num_pages: usize, alignment: u29) usize {
            @setCold(true);
            for (self.data) |segment, i| {
                const spills_into_next = @bitCast(i128, segment) < 0;
                const has_enough_bits = @popCount(u128, segment) >= num_pages;

                if (!spills_into_next and !has_enough_bits) continue;

                var j: usize = i * 128;
                while (j < (i + 1) * 128) : (j += 1) {
                    var count: usize = 0;
                    while (j + count < self.totalPages() and self.getBit(j + count) == .free) {
                        count += 1;
                        const addr = j * mem.page_size;
                        if (count >= num_pages and mem.isAligned(addr, alignment)) {
                            self.setBits(j, num_pages, .used);
                            return j;
                        }
                    }
                    j += count;
                }
            }
            return not_found;
        }

        fn recycle(self: FreeBlock, start_idx: usize, len: usize) void {
            self.setBits(start_idx, len, .free);
        }
    };

    var _conventional_data = [_]u128{0} ** 16;
    // Marking `conventional` as const saves ~40 bytes
    const conventional = FreeBlock{ .data = &_conventional_data };
    var extended = FreeBlock{ .data = &[_]u128{} };

    fn extendedOffset() usize {
        return conventional.totalPages();
    }

    fn nPages(memsize: usize) usize {
        return mem.alignForward(memsize, mem.page_size) / mem.page_size;
    }

    fn alloc(allocator: *Allocator, len: usize, alignment: u29, len_align: u29, ra: usize) error{OutOfMemory}![]u8 {
        _ = allocator;
        _ = ra;
        const page_count = nPages(len);
        const page_idx = try allocPages(page_count, alignment);
        return @intToPtr([*]u8, page_idx * mem.page_size)[0..alignPageAllocLen(page_count * mem.page_size, len, len_align)];
    }
    fn allocPages(page_count: usize, alignment: u29) !usize {
        {
            const idx = conventional.useRecycled(page_count, alignment);
            if (idx != FreeBlock.not_found) {
                return idx;
            }
        }

        const idx = extended.useRecycled(page_count, alignment);
        if (idx != FreeBlock.not_found) {
            return idx + extendedOffset();
        }

        const next_page_idx = @wasmMemorySize(0);
        const next_page_addr = next_page_idx * mem.page_size;
        const aligned_addr = mem.alignForward(next_page_addr, alignment);
        const drop_page_count = @divExact(aligned_addr - next_page_addr, mem.page_size);
        const result = @wasmMemoryGrow(0, @intCast(u32, drop_page_count + page_count));
        if (result <= 0)
            return error.OutOfMemory;
        assert(result == next_page_idx);
        const aligned_page_idx = next_page_idx + drop_page_count;
        if (drop_page_count > 0) {
            freePages(next_page_idx, aligned_page_idx);
        }
        return @intCast(usize, aligned_page_idx);
    }

    fn freePages(start: usize, end: usize) void {
        if (start < extendedOffset()) {
            conventional.recycle(start, std.math.min(extendedOffset(), end) - start);
        }
        if (end > extendedOffset()) {
            var new_end = end;
            if (!extended.isInitialized()) {
                // Steal the last page from the memory currently being recycled
                // TODO: would it be better if we use the first page instead?
                new_end -= 1;

                extended.data = @intToPtr([*]u128, new_end * mem.page_size)[0 .. mem.page_size / @sizeOf(u128)];
                // Since this is the first page being freed and we consume it, assume *nothing* is free.
                mem.set(u128, extended.data, PageStatus.none_free);
            }
            const clamped_start = std.math.max(extendedOffset(), start);
            extended.recycle(clamped_start - extendedOffset(), new_end - clamped_start);
        }
    }

    fn resize(
        allocator: *Allocator,
        buf: []u8,
        buf_align: u29,
        new_len: usize,
        len_align: u29,
        return_address: usize,
    ) error{OutOfMemory}!usize {
        _ = allocator;
        _ = buf_align;
        _ = return_address;
        const aligned_len = mem.alignForward(buf.len, mem.page_size);
        if (new_len > aligned_len) return error.OutOfMemory;
        const current_n = nPages(aligned_len);
        const new_n = nPages(new_len);
        if (new_n != current_n) {
            const base = nPages(@ptrToInt(buf.ptr));
            freePages(base + new_n, base + current_n);
        }
        return if (new_len == 0) 0 else alignPageAllocLen(new_n * mem.page_size, new_len, len_align);
    }
};

pub const HeapAllocator = switch (builtin.os.tag) {
    .windows => struct {
        allocator: Allocator,
        heap_handle: ?HeapHandle,

        const HeapHandle = os.windows.HANDLE;

        pub fn init() HeapAllocator {
            return HeapAllocator{
                .allocator = Allocator{
                    .allocFn = alloc,
                    .resizeFn = resize,
                },
                .heap_handle = null,
            };
        }

        pub fn deinit(self: *HeapAllocator) void {
            if (self.heap_handle) |heap_handle| {
                os.windows.HeapDestroy(heap_handle);
            }
        }

        fn getRecordPtr(buf: []u8) *align(1) usize {
            return @intToPtr(*align(1) usize, @ptrToInt(buf.ptr) + buf.len);
        }

        fn alloc(
            allocator: *Allocator,
            n: usize,
            ptr_align: u29,
            len_align: u29,
            return_address: usize,
        ) error{OutOfMemory}![]u8 {
            _ = return_address;
            const self = @fieldParentPtr(HeapAllocator, "allocator", allocator);

            const amt = n + ptr_align - 1 + @sizeOf(usize);
            const optional_heap_handle = @atomicLoad(?HeapHandle, &self.heap_handle, std.builtin.AtomicOrder.SeqCst);
            const heap_handle = optional_heap_handle orelse blk: {
                const options = if (builtin.single_threaded) os.windows.HEAP_NO_SERIALIZE else 0;
                const hh = os.windows.kernel32.HeapCreate(options, amt, 0) orelse return error.OutOfMemory;
                const other_hh = @cmpxchgStrong(?HeapHandle, &self.heap_handle, null, hh, std.builtin.AtomicOrder.SeqCst, std.builtin.AtomicOrder.SeqCst) orelse break :blk hh;
                os.windows.HeapDestroy(hh);
                break :blk other_hh.?; // can't be null because of the cmpxchg
            };
            const ptr = os.windows.kernel32.HeapAlloc(heap_handle, 0, amt) orelse return error.OutOfMemory;
            const root_addr = @ptrToInt(ptr);
            const aligned_addr = mem.alignForward(root_addr, ptr_align);
            const return_len = init: {
                if (len_align == 0) break :init n;
                const full_len = os.windows.kernel32.HeapSize(heap_handle, 0, ptr);
                assert(full_len != std.math.maxInt(usize));
                assert(full_len >= amt);
                break :init mem.alignBackwardAnyAlign(full_len - (aligned_addr - root_addr) - @sizeOf(usize), len_align);
            };
            const buf = @intToPtr([*]u8, aligned_addr)[0..return_len];
            getRecordPtr(buf).* = root_addr;
            return buf;
        }

        fn resize(
            allocator: *Allocator,
            buf: []u8,
            buf_align: u29,
            new_size: usize,
            len_align: u29,
            return_address: usize,
        ) error{OutOfMemory}!usize {
            _ = buf_align;
            _ = return_address;
            const self = @fieldParentPtr(HeapAllocator, "allocator", allocator);
            if (new_size == 0) {
                os.windows.HeapFree(self.heap_handle.?, 0, @intToPtr(*c_void, getRecordPtr(buf).*));
                return 0;
            }

            const root_addr = getRecordPtr(buf).*;
            const align_offset = @ptrToInt(buf.ptr) - root_addr;
            const amt = align_offset + new_size + @sizeOf(usize);
            const new_ptr = os.windows.kernel32.HeapReAlloc(
                self.heap_handle.?,
                os.windows.HEAP_REALLOC_IN_PLACE_ONLY,
                @intToPtr(*c_void, root_addr),
                amt,
            ) orelse return error.OutOfMemory;
            assert(new_ptr == @intToPtr(*c_void, root_addr));
            const return_len = init: {
                if (len_align == 0) break :init new_size;
                const full_len = os.windows.kernel32.HeapSize(self.heap_handle.?, 0, new_ptr);
                assert(full_len != std.math.maxInt(usize));
                assert(full_len >= amt);
                break :init mem.alignBackwardAnyAlign(full_len - align_offset, len_align);
            };
            getRecordPtr(buf.ptr[0..return_len]).* = root_addr;
            return return_len;
        }
    },
    else => @compileError("Unsupported OS"),
};

fn sliceContainsPtr(container: []u8, ptr: [*]u8) bool {
    return @ptrToInt(ptr) >= @ptrToInt(container.ptr) and
        @ptrToInt(ptr) < (@ptrToInt(container.ptr) + container.len);
}

fn sliceContainsSlice(container: []u8, slice: []u8) bool {
    return @ptrToInt(slice.ptr) >= @ptrToInt(container.ptr) and
        (@ptrToInt(slice.ptr) + slice.len) <= (@ptrToInt(container.ptr) + container.len);
}

pub const FixedBufferAllocator = struct {
    allocator: Allocator,
    end_index: usize,
    buffer: []u8,

    pub fn init(buffer: []u8) FixedBufferAllocator {
        return FixedBufferAllocator{
            .allocator = Allocator{
                .allocFn = alloc,
                .resizeFn = resize,
            },
            .buffer = buffer,
            .end_index = 0,
        };
    }

    pub fn ownsPtr(self: *FixedBufferAllocator, ptr: [*]u8) bool {
        return sliceContainsPtr(self.buffer, ptr);
    }

    pub fn ownsSlice(self: *FixedBufferAllocator, slice: []u8) bool {
        return sliceContainsSlice(self.buffer, slice);
    }

    /// NOTE: this will not work in all cases, if the last allocation had an adjusted_index
    ///       then we won't be able to determine what the last allocation was.  This is because
    ///       the alignForward operation done in alloc is not reverisible.
    pub fn isLastAllocation(self: *FixedBufferAllocator, buf: []u8) bool {
        return buf.ptr + buf.len == self.buffer.ptr + self.end_index;
    }

    fn alloc(allocator: *Allocator, n: usize, ptr_align: u29, len_align: u29, ra: usize) ![]u8 {
        _ = len_align;
        _ = ra;
        const self = @fieldParentPtr(FixedBufferAllocator, "allocator", allocator);
        const adjust_off = mem.alignPointerOffset(self.buffer.ptr + self.end_index, ptr_align) orelse
            return error.OutOfMemory;
        const adjusted_index = self.end_index + adjust_off;
        const new_end_index = adjusted_index + n;
        if (new_end_index > self.buffer.len) {
            return error.OutOfMemory;
        }
        const result = self.buffer[adjusted_index..new_end_index];
        self.end_index = new_end_index;

        return result;
    }

    fn resize(
        allocator: *Allocator,
        buf: []u8,
        buf_align: u29,
        new_size: usize,
        len_align: u29,
        return_address: usize,
    ) Allocator.Error!usize {
        _ = buf_align;
        _ = return_address;
        const self = @fieldParentPtr(FixedBufferAllocator, "allocator", allocator);
        assert(self.ownsSlice(buf)); // sanity check

        if (!self.isLastAllocation(buf)) {
            if (new_size > buf.len)
                return error.OutOfMemory;
            return if (new_size == 0) 0 else mem.alignAllocLen(buf.len, new_size, len_align);
        }

        if (new_size <= buf.len) {
            const sub = buf.len - new_size;
            self.end_index -= sub;
            return if (new_size == 0) 0 else mem.alignAllocLen(buf.len - sub, new_size, len_align);
        }

        const add = new_size - buf.len;
        if (add + self.end_index > self.buffer.len) {
            return error.OutOfMemory;
        }
        self.end_index += add;
        return new_size;
    }

    pub fn reset(self: *FixedBufferAllocator) void {
        self.end_index = 0;
    }
};

pub const ThreadSafeFixedBufferAllocator = blk: {
    if (builtin.single_threaded) {
        break :blk FixedBufferAllocator;
    } else {
        // lock free
        break :blk struct {
            allocator: Allocator,
            end_index: usize,
            buffer: []u8,

            pub fn init(buffer: []u8) ThreadSafeFixedBufferAllocator {
                return ThreadSafeFixedBufferAllocator{
                    .allocator = Allocator{
                        .allocFn = alloc,
                        .resizeFn = Allocator.noResize,
                    },
                    .buffer = buffer,
                    .end_index = 0,
                };
            }

            fn alloc(allocator: *Allocator, n: usize, ptr_align: u29, len_align: u29, ra: usize) ![]u8 {
                _ = len_align;
                _ = ra;
                const self = @fieldParentPtr(ThreadSafeFixedBufferAllocator, "allocator", allocator);
                var end_index = @atomicLoad(usize, &self.end_index, std.builtin.AtomicOrder.SeqCst);
                while (true) {
                    const adjust_off = mem.alignPointerOffset(self.buffer.ptr + end_index, ptr_align) orelse
                        return error.OutOfMemory;
                    const adjusted_index = end_index + adjust_off;
                    const new_end_index = adjusted_index + n;
                    if (new_end_index > self.buffer.len) {
                        return error.OutOfMemory;
                    }
                    end_index = @cmpxchgWeak(usize, &self.end_index, end_index, new_end_index, std.builtin.AtomicOrder.SeqCst, std.builtin.AtomicOrder.SeqCst) orelse return self.buffer[adjusted_index..new_end_index];
                }
            }

            pub fn reset(self: *ThreadSafeFixedBufferAllocator) void {
                self.end_index = 0;
            }
        };
    }
};

pub fn stackFallback(comptime size: usize, fallback_allocator: *Allocator) StackFallbackAllocator(size) {
    return StackFallbackAllocator(size){
        .buffer = undefined,
        .fallback_allocator = fallback_allocator,
        .fixed_buffer_allocator = undefined,
        .allocator = Allocator{
            .allocFn = StackFallbackAllocator(size).alloc,
            .resizeFn = StackFallbackAllocator(size).resize,
        },
    };
}

pub fn StackFallbackAllocator(comptime size: usize) type {
    return struct {
        const Self = @This();

        buffer: [size]u8,
        allocator: Allocator,
        fallback_allocator: *Allocator,
        fixed_buffer_allocator: FixedBufferAllocator,

        pub fn get(self: *Self) *Allocator {
            self.fixed_buffer_allocator = FixedBufferAllocator.init(self.buffer[0..]);
            return &self.allocator;
        }

        fn alloc(
            allocator: *Allocator,
            len: usize,
            ptr_align: u29,
            len_align: u29,
            return_address: usize,
        ) error{OutOfMemory}![]u8 {
            const self = @fieldParentPtr(Self, "allocator", allocator);
            return FixedBufferAllocator.alloc(&self.fixed_buffer_allocator.allocator, len, ptr_align, len_align, return_address) catch
                return self.fallback_allocator.allocFn(self.fallback_allocator, len, ptr_align, len_align, return_address);
        }

        fn resize(
            allocator: *Allocator,
            buf: []u8,
            buf_align: u29,
            new_len: usize,
            len_align: u29,
            return_address: usize,
        ) error{OutOfMemory}!usize {
            const self = @fieldParentPtr(Self, "allocator", allocator);
            if (self.fixed_buffer_allocator.ownsPtr(buf.ptr)) {
                return FixedBufferAllocator.resize(&self.fixed_buffer_allocator.allocator, buf, buf_align, new_len, len_align, return_address);
            } else {
                return self.fallback_allocator.resizeFn(self.fallback_allocator, buf, buf_align, new_len, len_align, return_address);
            }
        }
    };
}

test "c_allocator" {
    if (builtin.link_libc) {
        try testAllocator(c_allocator);
        try testAllocatorAligned(c_allocator);
        try testAllocatorLargeAlignment(c_allocator);
        try testAllocatorAlignedShrink(c_allocator);
    }
}

test "raw_c_allocator" {
    if (builtin.link_libc) {
        try testAllocator(raw_c_allocator);
    }
}

test "WasmPageAllocator internals" {
    if (comptime builtin.target.isWasm()) {
        const conventional_memsize = WasmPageAllocator.conventional.totalPages() * mem.page_size;
        const initial = try page_allocator.alloc(u8, mem.page_size);
        try testing.expect(@ptrToInt(initial.ptr) < conventional_memsize); // If this isn't conventional, the rest of these tests don't make sense. Also we have a serious memory leak in the test suite.

        var inplace = try page_allocator.realloc(initial, 1);
        try testing.expectEqual(initial.ptr, inplace.ptr);
        inplace = try page_allocator.realloc(inplace, 4);
        try testing.expectEqual(initial.ptr, inplace.ptr);
        page_allocator.free(inplace);

        const reuse = try page_allocator.alloc(u8, 1);
        try testing.expectEqual(initial.ptr, reuse.ptr);
        page_allocator.free(reuse);

        // This segment may span conventional and extended which has really complex rules so we're just ignoring it for now.
        const padding = try page_allocator.alloc(u8, conventional_memsize);
        page_allocator.free(padding);

        const extended = try page_allocator.alloc(u8, conventional_memsize);
        try testing.expect(@ptrToInt(extended.ptr) >= conventional_memsize);

        const use_small = try page_allocator.alloc(u8, 1);
        try testing.expectEqual(initial.ptr, use_small.ptr);
        page_allocator.free(use_small);

        inplace = try page_allocator.realloc(extended, 1);
        try testing.expectEqual(extended.ptr, inplace.ptr);
        page_allocator.free(inplace);

        const reuse_extended = try page_allocator.alloc(u8, conventional_memsize);
        try testing.expectEqual(extended.ptr, reuse_extended.ptr);
        page_allocator.free(reuse_extended);
    }
}

test "PageAllocator" {
    const allocator = page_allocator;
    try testAllocator(allocator);
    try testAllocatorAligned(allocator);
    if (!builtin.target.isWasm()) {
        try testAllocatorLargeAlignment(allocator);
        try testAllocatorAlignedShrink(allocator);
    }

    if (builtin.os.tag == .windows) {
        // Trying really large alignment. As mentionned in the implementation,
        // VirtualAlloc returns 64K aligned addresses. We want to make sure
        // PageAllocator works beyond that, as it's not tested by
        // `testAllocatorLargeAlignment`.
        const slice = try allocator.alignedAlloc(u8, 1 << 20, 128);
        slice[0] = 0x12;
        slice[127] = 0x34;
        allocator.free(slice);
    }
    {
        var buf = try allocator.alloc(u8, mem.page_size + 1);
        defer allocator.free(buf);
        buf = try allocator.realloc(buf, 1); // shrink past the page boundary
    }
}

test "HeapAllocator" {
    if (builtin.os.tag == .windows) {
        var heap_allocator = HeapAllocator.init();
        defer heap_allocator.deinit();

        const allocator = &heap_allocator.allocator;
        try testAllocator(allocator);
        try testAllocatorAligned(allocator);
        try testAllocatorLargeAlignment(allocator);
        try testAllocatorAlignedShrink(allocator);
    }
}

test "ArenaAllocator" {
    var arena_allocator = ArenaAllocator.init(page_allocator);
    defer arena_allocator.deinit();

    try testAllocator(&arena_allocator.allocator);
    try testAllocatorAligned(&arena_allocator.allocator);
    try testAllocatorLargeAlignment(&arena_allocator.allocator);
    try testAllocatorAlignedShrink(&arena_allocator.allocator);
}

var test_fixed_buffer_allocator_memory: [800000 * @sizeOf(u64)]u8 = undefined;
test "FixedBufferAllocator" {
    var fixed_buffer_allocator = mem.validationWrap(FixedBufferAllocator.init(test_fixed_buffer_allocator_memory[0..]));

    try testAllocator(&fixed_buffer_allocator.allocator);
    try testAllocatorAligned(&fixed_buffer_allocator.allocator);
    try testAllocatorLargeAlignment(&fixed_buffer_allocator.allocator);
    try testAllocatorAlignedShrink(&fixed_buffer_allocator.allocator);
}

test "FixedBufferAllocator.reset" {
    var buf: [8]u8 align(@alignOf(u64)) = undefined;
    var fba = FixedBufferAllocator.init(buf[0..]);

    const X = 0xeeeeeeeeeeeeeeee;
    const Y = 0xffffffffffffffff;

    var x = try fba.allocator.create(u64);
    x.* = X;
    try testing.expectError(error.OutOfMemory, fba.allocator.create(u64));

    fba.reset();
    var y = try fba.allocator.create(u64);
    y.* = Y;

    // we expect Y to have overwritten X.
    try testing.expect(x.* == y.*);
    try testing.expect(y.* == Y);
}

test "StackFallbackAllocator" {
    const fallback_allocator = page_allocator;
    var stack_allocator = stackFallback(4096, fallback_allocator);

    try testAllocator(stack_allocator.get());
    try testAllocatorAligned(stack_allocator.get());
    try testAllocatorLargeAlignment(stack_allocator.get());
    try testAllocatorAlignedShrink(stack_allocator.get());
}

test "FixedBufferAllocator Reuse memory on realloc" {
    var small_fixed_buffer: [10]u8 = undefined;
    // check if we re-use the memory
    {
        var fixed_buffer_allocator = FixedBufferAllocator.init(small_fixed_buffer[0..]);

        var slice0 = try fixed_buffer_allocator.allocator.alloc(u8, 5);
        try testing.expect(slice0.len == 5);
        var slice1 = try fixed_buffer_allocator.allocator.realloc(slice0, 10);
        try testing.expect(slice1.ptr == slice0.ptr);
        try testing.expect(slice1.len == 10);
        try testing.expectError(error.OutOfMemory, fixed_buffer_allocator.allocator.realloc(slice1, 11));
    }
    // check that we don't re-use the memory if it's not the most recent block
    {
        var fixed_buffer_allocator = FixedBufferAllocator.init(small_fixed_buffer[0..]);

        var slice0 = try fixed_buffer_allocator.allocator.alloc(u8, 2);
        slice0[0] = 1;
        slice0[1] = 2;
        var slice1 = try fixed_buffer_allocator.allocator.alloc(u8, 2);
        var slice2 = try fixed_buffer_allocator.allocator.realloc(slice0, 4);
        try testing.expect(slice0.ptr != slice2.ptr);
        try testing.expect(slice1.ptr != slice2.ptr);
        try testing.expect(slice2[0] == 1);
        try testing.expect(slice2[1] == 2);
    }
}

test "ThreadSafeFixedBufferAllocator" {
    var fixed_buffer_allocator = ThreadSafeFixedBufferAllocator.init(test_fixed_buffer_allocator_memory[0..]);

    try testAllocator(&fixed_buffer_allocator.allocator);
    try testAllocatorAligned(&fixed_buffer_allocator.allocator);
    try testAllocatorLargeAlignment(&fixed_buffer_allocator.allocator);
    try testAllocatorAlignedShrink(&fixed_buffer_allocator.allocator);
}

/// This one should not try alignments that exceed what C malloc can handle.
pub fn testAllocator(base_allocator: *mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = &validationAllocator.allocator;

    var slice = try allocator.alloc(*i32, 100);
    try testing.expect(slice.len == 100);
    for (slice) |*item, i| {
        item.* = try allocator.create(i32);
        item.*.* = @intCast(i32, i);
    }

    slice = try allocator.realloc(slice, 20000);
    try testing.expect(slice.len == 20000);

    for (slice[0..100]) |item, i| {
        try testing.expect(item.* == @intCast(i32, i));
        allocator.destroy(item);
    }

    slice = allocator.shrink(slice, 50);
    try testing.expect(slice.len == 50);
    slice = allocator.shrink(slice, 25);
    try testing.expect(slice.len == 25);
    slice = allocator.shrink(slice, 0);
    try testing.expect(slice.len == 0);
    slice = try allocator.realloc(slice, 10);
    try testing.expect(slice.len == 10);

    allocator.free(slice);

    // Zero-length allocation
    var empty = try allocator.alloc(u8, 0);
    allocator.free(empty);
    // Allocation with zero-sized types
    const zero_bit_ptr = try allocator.create(u0);
    zero_bit_ptr.* = 0;
    allocator.destroy(zero_bit_ptr);

    const oversize = try allocator.allocAdvanced(u32, null, 5, .at_least);
    try testing.expect(oversize.len >= 5);
    for (oversize) |*item| {
        item.* = 0xDEADBEEF;
    }
    allocator.free(oversize);
}

pub fn testAllocatorAligned(base_allocator: *mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = &validationAllocator.allocator;

    // Test a few alignment values, smaller and bigger than the type's one
    inline for ([_]u29{ 1, 2, 4, 8, 16, 32, 64 }) |alignment| {
        // initial
        var slice = try allocator.alignedAlloc(u8, alignment, 10);
        try testing.expect(slice.len == 10);
        // grow
        slice = try allocator.realloc(slice, 100);
        try testing.expect(slice.len == 100);
        // shrink
        slice = allocator.shrink(slice, 10);
        try testing.expect(slice.len == 10);
        // go to zero
        slice = allocator.shrink(slice, 0);
        try testing.expect(slice.len == 0);
        // realloc from zero
        slice = try allocator.realloc(slice, 100);
        try testing.expect(slice.len == 100);
        // shrink with shrink
        slice = allocator.shrink(slice, 10);
        try testing.expect(slice.len == 10);
        // shrink to zero
        slice = allocator.shrink(slice, 0);
        try testing.expect(slice.len == 0);
    }
}

pub fn testAllocatorLargeAlignment(base_allocator: *mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = &validationAllocator.allocator;

    //Maybe a platform's page_size is actually the same as or
    //  very near usize?
    if (mem.page_size << 2 > maxInt(usize)) return;

    const USizeShift = std.meta.Int(.unsigned, std.math.log2(std.meta.bitCount(usize)));
    const large_align = @as(u29, mem.page_size << 2);

    var align_mask: usize = undefined;
    _ = @shlWithOverflow(usize, ~@as(usize, 0), @as(USizeShift, @ctz(u29, large_align)), &align_mask);

    var slice = try allocator.alignedAlloc(u8, large_align, 500);
    try testing.expect(@ptrToInt(slice.ptr) & align_mask == @ptrToInt(slice.ptr));

    slice = allocator.shrink(slice, 100);
    try testing.expect(@ptrToInt(slice.ptr) & align_mask == @ptrToInt(slice.ptr));

    slice = try allocator.realloc(slice, 5000);
    try testing.expect(@ptrToInt(slice.ptr) & align_mask == @ptrToInt(slice.ptr));

    slice = allocator.shrink(slice, 10);
    try testing.expect(@ptrToInt(slice.ptr) & align_mask == @ptrToInt(slice.ptr));

    slice = try allocator.realloc(slice, 20000);
    try testing.expect(@ptrToInt(slice.ptr) & align_mask == @ptrToInt(slice.ptr));

    allocator.free(slice);
}

pub fn testAllocatorAlignedShrink(base_allocator: *mem.Allocator) !void {
    var validationAllocator = mem.validationWrap(base_allocator);
    const allocator = &validationAllocator.allocator;

    var debug_buffer: [1000]u8 = undefined;
    const debug_allocator = &FixedBufferAllocator.init(&debug_buffer).allocator;

    const alloc_size = mem.page_size * 2 + 50;
    var slice = try allocator.alignedAlloc(u8, 16, alloc_size);
    defer allocator.free(slice);

    var stuff_to_free = std.ArrayList([]align(16) u8).init(debug_allocator);
    // On Windows, VirtualAlloc returns addresses aligned to a 64K boundary,
    // which is 16 pages, hence the 32. This test may require to increase
    // the size of the allocations feeding the `allocator` parameter if they
    // fail, because of this high over-alignment we want to have.
    while (@ptrToInt(slice.ptr) == mem.alignForward(@ptrToInt(slice.ptr), mem.page_size * 32)) {
        try stuff_to_free.append(slice);
        slice = try allocator.alignedAlloc(u8, 16, alloc_size);
    }
    while (stuff_to_free.popOrNull()) |item| {
        allocator.free(item);
    }
    slice[0] = 0x12;
    slice[60] = 0x34;

    // realloc to a smaller size but with a larger alignment
    slice = try allocator.reallocAdvanced(slice, mem.page_size * 32, alloc_size / 2, .exact);
    try testing.expect(slice[0] == 0x12);
    try testing.expect(slice[60] == 0x34);
}

test "heap" {
    _ = @import("heap/logging_allocator.zig");
    _ = @import("heap/log_to_writer_allocator.zig");
}
