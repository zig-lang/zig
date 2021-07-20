// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("std");
const builtin = std.builtin;
const common = @import("../common.zig");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;

const Field = common.Field;

const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// Number of bytes required to encode a scalar.
pub const encoded_length = 32;

/// A compressed scalar, in canonical form.
pub const CompressedScalar = [encoded_length]u8;

const Fe = Field(.{
    .fiat = @import("p256_scalar_64.zig"),
    .field_order = 115792089210356248762697446949407573529996955224135760342422259061068512044369,
    .field_bits = 256,
    .saturated_bits = 255,
    .encoded_length = encoded_length,
});

/// Reject a scalar whose encoding is not canonical.
pub fn rejectNonCanonical(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!void {
    return Fe.rejectNonCanonical(s, endian);
}

/// Reduce a 48-bytes scalar to the field size.
pub fn reduce48(s: [48]u8, endian: std.builtin.Endian) CompressedScalar {
    return Scalar.fromBytes48(s, endian).toBytes(endian);
}

/// Reduce a 64-bytes scalar to the field size.
pub fn reduce64(s: [64]u8, endian: std.builtin.Endian) CompressedScalar {
    return ScalarDouble.fromBytes64(s, endian).toBytes(endian);
}

/// Return a*b (mod L)
pub fn mul(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return a*b+c (mod L)
pub fn mulAdd(a: CompressedScalar, b: CompressedScalar, c: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).add(try Scalar.fromBytes(c, endian)).toBytes(endian);
}

/// Return a+b (mod L)
pub fn add(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).add(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// Return -s (mod L)
pub fn neg(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(s, endian)).neg().toBytes(endian);
}

/// Return (a-b) (mod L)
pub fn sub(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).sub(try Scalar.fromBytes(b.endian)).toBytes(endian);
}

/// Return a random scalar
pub fn random(endian: std.builtin.Endian) CompressedScalar {
    return Scalar.random().toBytes(endian);
}

/// A scalar in unpacked representation.
pub const Scalar = struct {
    fe: Fe,

    /// Zero.
    pub const zero = Scalar{ .fe = Fe.zero };

    /// One.
    pub const one = Scalar{ .fe = Fe.one };

    /// Unpack a serialized representation of a scalar.
    pub fn fromBytes(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!Scalar {
        return Scalar{ .fe = try Fe.fromBytes(s, endian) };
    }

    /// Reduce a 384 bit input to the field size.
    pub fn fromBytes48(s: [48]u8, endian: std.builtin.Endian) Scalar {
        const t = ScalarDouble.fromBytes(384, s, endian);
        return t.reduce(384);
    }

    /// Reduce a 512 bit input to the field size.
    pub fn fromBytes64(s: [64]u8, endian: std.builtin.Endian) Scalar {
        const t = ScalarDouble.fromBytes(512, s, endian);
        return t.reduce(512);
    }

    /// Pack a scalar into bytes.
    pub fn toBytes(n: Scalar, endian: std.builtin.Endian) CompressedScalar {
        return n.fe.toBytes(endian);
    }

    /// Return true if the scalar is zero..
    pub fn isZero(n: Scalar) bool {
        return n.fe.isZero();
    }

    /// Return true if a and b are equivalent.
    pub fn equivalent(a: Scalar, b: Scalar) bool {
        return a.fe.equivalent(b.fe);
    }

    /// Compute x+y (mod L)
    pub fn add(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.add(y.fe) };
    }

    /// Compute x-y (mod L)
    pub fn sub(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.sub(y.fe) };
    }

    /// Compute 2n (mod L)
    pub fn dbl(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.dbl() };
    }

    /// Compute x*y (mod L)
    pub fn mul(x: Scalar, y: Scalar) Scalar {
        return Scalar{ .fe = x.fe.mul(y.fe) };
    }

    /// Compute x^2 (mod L)
    pub fn sq(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.sq() };
    }

    /// Compute x^n (mod L)
    pub fn pow(a: Scalar, comptime T: type, comptime n: T) Scalar {
        return Scalar{ .fe = a.fe.pow(n) };
    }

    /// Compute -x (mod L)
    pub fn neg(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.neg() };
    }

    /// Compute x^-1 (mod L)
    pub fn invert(n: Scalar) Scalar {
        return Scalar{ .fe = n.fe.invert() };
    }

    /// Return true if n is a quadratic residue mod L.
    pub fn isSquare(n: Scalar) Scalar {
        return n.fe.isSquare();
    }

    /// Return the square root of L, or NotSquare if there isn't any solutions.
    pub fn sqrt(n: Scalar) NotSquareError!Scalar {
        return Scalar{ .fe = try n.fe.sqrt() };
    }

    /// Return a random scalar < L.
    pub fn random() Scalar {
        var s: [48]u8 = undefined;
        while (true) {
            crypto.random.bytes(&s);
            const n = Scalar.fromBytes48(s, .Little);
            if (!n.isZero()) {
                return n;
            }
        }
    }
};

const ScalarDouble = struct {
    x1: Fe,
    x2: Fe,
    x3: Fe,

    fn fromBytes(comptime bits: usize, s_: [bits / 8]u8, endian: std.builtin.Endian) ScalarDouble {
        debug.assert(bits > 0 and bits <= 512 and bits >= Fe.saturated_bits and bits <= Fe.saturated_bits * 3);

        var s = s_;
        if (endian == .Big) {
            for (s_) |x, i| s[s.len - 1 - i] = x;
        }
        var t = ScalarDouble{ .x1 = undefined, .x2 = Fe.zero, .x3 = Fe.zero };
        {
            var b = [_]u8{0} ** encoded_length;
            const len = math.min(s.len, 24);
            mem.copy(u8, b[0..len], s[0..len]);
            t.x1 = Fe.fromBytes(b, .Little) catch unreachable;
        }
        if (s_.len >= 24) {
            var b = [_]u8{0} ** encoded_length;
            const len = math.min(s.len - 24, 24);
            mem.copy(u8, b[0..len], s[24..][0..len]);
            t.x2 = Fe.fromBytes(b, .Little) catch unreachable;
        }
        if (s_.len >= 48) {
            var b = [_]u8{0} ** encoded_length;
            const len = s.len - 48;
            mem.copy(u8, b[0..len], s[48..][0..len]);
            t.x3 = Fe.fromBytes(b, .Little) catch unreachable;
        }
        return t;
    }

    fn reduce(expanded: ScalarDouble, comptime bits: usize) Scalar {
        debug.assert(bits > 0 and bits <= Fe.saturated_bits * 3 and bits <= 512);
        var fe = expanded.x1;
        if (bits >= 192) {
            const st1 = Fe.fromInt(1 << 192) catch unreachable;
            fe = fe.add(expanded.x2.mul(st1));
            if (bits >= 384) {
                const st2 = st1.sq();
                fe = fe.add(expanded.x3.mul(st2));
            }
        }
        return Scalar{ .fe = fe };
    }
};
