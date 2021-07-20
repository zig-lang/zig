// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
// zig run benchmark.zig --release-fast --zig-lib-dir ..

const builtin = @import("builtin");
const std = @import("std");
const time = std.time;
const Timer = time.Timer;
const hash = std.hash;

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

var prng = std.rand.DefaultPrng.init(0);

const Hash = struct {
    ty: type,
    name: []const u8,
    has_iterative_api: bool = true,
    init_u8s: ?[]const u8 = null,
    init_u64: ?u64 = null,
};

const hashes = [_]Hash{
    Hash{
        .ty = hash.Wyhash,
        .name = "wyhash",
        .init_u64 = 0,
    },
    Hash{
        .ty = hash.Fnv1a_64,
        .name = "fnv1a",
    },
    Hash{
        .ty = hash.Adler32,
        .name = "adler32",
    },
    Hash{
        .ty = hash.crc.Crc32WithPoly(.IEEE),
        .name = "crc32-slicing-by-8",
    },
    Hash{
        .ty = hash.crc.Crc32SmallWithPoly(.IEEE),
        .name = "crc32-half-byte-lookup",
    },
    Hash{
        .ty = hash.CityHash32,
        .name = "cityhash-32",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.CityHash64,
        .name = "cityhash-64",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.Murmur2_32,
        .name = "murmur2-32",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.Murmur2_64,
        .name = "murmur2-64",
        .has_iterative_api = false,
    },
    Hash{
        .ty = hash.Murmur3_32,
        .name = "murmur3-32",
        .has_iterative_api = false,
    },
};

const Result = struct {
    hash: u64,
    throughput: u64,
};

const block_size: usize = 8 * 8192;

pub fn benchmarkHash(comptime H: anytype, bytes: usize) !Result {
    var h = blk: {
        if (H.init_u8s) |init| {
            break :blk H.ty.init(init);
        }
        if (H.init_u64) |init| {
            break :blk H.ty.init(init);
        }
        break :blk H.ty.init();
    };

    var block: [block_size]u8 = undefined;
    prng.random.bytes(block[0..]);

    var offset: usize = 0;
    var timer = try Timer.start();
    const start = timer.lap();
    while (offset < bytes) : (offset += block.len) {
        h.update(block[0..]);
    }
    const end = timer.read();

    const elapsed_s = @intToFloat(f64, end - start) / time.ns_per_s;
    const throughput = @floatToInt(u64, @intToFloat(f64, bytes) / elapsed_s);

    return Result{
        .hash = h.final(),
        .throughput = throughput,
    };
}

pub fn benchmarkHashSmallKeys(comptime H: anytype, key_size: usize, bytes: usize) !Result {
    const key_count = bytes / key_size;
    var block: [block_size]u8 = undefined;
    prng.random.bytes(block[0..]);

    var i: usize = 0;
    var timer = try Timer.start();
    const start = timer.lap();

    var sum: u64 = 0;
    while (i < key_count) : (i += 1) {
        const small_key = block[0..key_size];
        sum +%= blk: {
            if (H.init_u8s) |init| {
                break :blk H.ty.hash(init, small_key);
            }
            if (H.init_u64) |init| {
                break :blk H.ty.hash(init, small_key);
            }
            break :blk H.ty.hash(small_key);
        };
    }
    const end = timer.read();

    const elapsed_s = @intToFloat(f64, end - start) / time.ns_per_s;
    const throughput = @floatToInt(u64, @intToFloat(f64, bytes) / elapsed_s);

    return Result{
        .hash = sum,
        .throughput = throughput,
    };
}

fn usage() void {
    std.debug.warn(
        \\throughput_test [options]
        \\
        \\Options:
        \\  --filter    [test-name]
        \\  --seed      [int]
        \\  --count     [int]
        \\  --key-size  [int]
        \\  --iterative-only
        \\  --help
        \\
    , .{});
}

fn mode(comptime x: comptime_int) comptime_int {
    return if (builtin.mode == .Debug) x / 64 else x;
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var buffer: [1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(buffer[0..]);
    const args = try std.process.argsAlloc(&fixed.allocator);

    var filter: ?[]u8 = "";
    var count: usize = mode(128 * MiB);
    var key_size: usize = 32;
    var seed: u32 = 0;
    var test_iterative_only = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--mode")) {
            try stdout.print("{}\n", .{builtin.mode});
            return;
        } else if (std.mem.eql(u8, args[i], "--seed")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.os.exit(1);
            }

            seed = try std.fmt.parseUnsigned(u32, args[i], 10);
            // we seed later
        } else if (std.mem.eql(u8, args[i], "--filter")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.os.exit(1);
            }

            filter = args[i];
        } else if (std.mem.eql(u8, args[i], "--count")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.os.exit(1);
            }

            const c = try std.fmt.parseUnsigned(usize, args[i], 10);
            count = c * MiB;
        } else if (std.mem.eql(u8, args[i], "--key-size")) {
            i += 1;
            if (i == args.len) {
                usage();
                std.os.exit(1);
            }

            key_size = try std.fmt.parseUnsigned(usize, args[i], 10);
            if (key_size > block_size) {
                try stdout.print("key_size cannot exceed block size of {}\n", .{block_size});
                std.os.exit(1);
            }
        } else if (std.mem.eql(u8, args[i], "--iterative-only")) {
            test_iterative_only = true;
        } else if (std.mem.eql(u8, args[i], "--help")) {
            usage();
            return;
        } else {
            usage();
            std.os.exit(1);
        }
    }

    inline for (hashes) |H| {
        if (filter == null or std.mem.indexOf(u8, H.name, filter.?) != null) {
            if (!test_iterative_only or H.has_iterative_api) {
                try stdout.print("{}\n", .{H.name});

                // Always reseed prior to every call so we are hashing the same buffer contents.
                // This allows easier comparison between different implementations.
                if (H.has_iterative_api) {
                    prng.seed(seed);
                    const result = try benchmarkHash(H, count);
                    try stdout.print("   iterative: {:5} MiB/s [{x:0<16}]\n", .{ result.throughput / (1 * MiB), result.hash });
                }

                if (!test_iterative_only) {
                    prng.seed(seed);
                    const result_small = try benchmarkHashSmallKeys(H, key_size, count);
                    try stdout.print("  small keys: {:5} MiB/s [{x:0<16}]\n", .{ result_small.throughput / (1 * MiB), result_small.hash });
                }
            }
        }
    }
}
