const std = @import("std");
const builtin = std.builtin;
const crypto = std.crypto;
const debug = std.debug;
const mem = std.mem;
const meta = std.meta;

const NonCanonicalError = crypto.errors.NonCanonicalError;
const NotSquareError = crypto.errors.NotSquareError;

/// Parameters to create a finite field type.
pub const FieldParams = struct {
    fiat: type,
    field_order: comptime_int,
    field_bits: comptime_int,
    saturated_bits: comptime_int,
    encoded_length: comptime_int,
};

/// A field element, internally stored in Montgomery domain.
pub fn Field(comptime params: FieldParams) type {
    const fiat = params.fiat;
    const MontgomeryDomainFieldElement = fiat.MontgomeryDomainFieldElement;
    const NonMontgomeryDomainFieldElement = fiat.NonMontgomeryDomainFieldElement;

    return struct {
        const Fe = @This();

        limbs: MontgomeryDomainFieldElement,

        /// Field size.
        pub const field_order = params.field_order;

        /// Number of bits to represent the set of all elements.
        pub const field_bits = params.field_bits;

        /// Number of bits that can be saturated without overflowing.
        pub const saturated_bits = params.saturated_bits;

        /// Number of bytes required to encode an element.
        pub const encoded_length = params.encoded_length;

        /// Zero.
        pub const zero: Fe = Fe{ .limbs = mem.zeroes(MontgomeryDomainFieldElement) };

        /// One.
        pub const one = one: {
            var fe: Fe = undefined;
            fiat.setOne(&fe.limbs);
            break :one fe;
        };

        /// Reject non-canonical encodings of an element.
        pub fn rejectNonCanonical(s_: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!void {
            var s = if (endian == .Little) s_ else orderSwap(s_);
            const field_order_s = comptime fos: {
                var fos: [encoded_length]u8 = undefined;
                mem.writeIntLittle(std.meta.Int(.unsigned, encoded_length * 8), &fos, field_order);
                break :fos fos;
            };
            if (crypto.utils.timingSafeCompare(u8, &s, &field_order_s, .Little) != .lt) {
                return error.NonCanonical;
            }
        }

        /// Swap the endianness of an encoded element.
        pub fn orderSwap(s: [encoded_length]u8) [encoded_length]u8 {
            var t = s;
            for (s) |x, i| t[t.len - 1 - i] = x;
            return t;
        }

        /// Unpack a field element.
        pub fn fromBytes(s_: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!Fe {
            var s = if (endian == .Little) s_ else orderSwap(s_);
            try rejectNonCanonical(s, .Little);
            var limbs_z: NonMontgomeryDomainFieldElement = undefined;
            fiat.fromBytes(&limbs_z, s);
            var limbs: MontgomeryDomainFieldElement = undefined;
            fiat.toMontgomery(&limbs, limbs_z);
            return Fe{ .limbs = limbs };
        }

        /// Pack a field element.
        pub fn toBytes(fe: Fe, endian: std.builtin.Endian) [encoded_length]u8 {
            var limbs_z: NonMontgomeryDomainFieldElement = undefined;
            fiat.fromMontgomery(&limbs_z, fe.limbs);
            var s: [encoded_length]u8 = undefined;
            fiat.toBytes(&s, limbs_z);
            return if (endian == .Little) s else orderSwap(s);
        }

        /// Element as an integer.
        pub const IntRepr = meta.Int(.unsigned, params.field_bits);

        /// Create a field element from an integer.
        pub fn fromInt(comptime x: IntRepr) NonCanonicalError!Fe {
            var s: [encoded_length]u8 = undefined;
            mem.writeIntLittle(IntRepr, &s, x);
            return fromBytes(s, .Little);
        }

        /// Return the field element as an integer.
        pub fn toInt(fe: Fe) IntRepr {
            const s = fe.toBytes(.Little);
            return mem.readIntLittle(IntRepr, &s);
        }

        /// Return true if the field element is zero.
        pub fn isZero(fe: Fe) bool {
            var z: @TypeOf(fe.limbs[0]) = undefined;
            fiat.nonzero(&z, fe.limbs);
            return z == 0;
        }

        /// Return true if both field elements are equivalent.
        pub fn equivalent(a: Fe, b: Fe) bool {
            return a.sub(b).isZero();
        }

        /// Return true if the element is odd.
        pub fn isOdd(fe: Fe) bool {
            const s = fe.toBytes(.Little);
            return @truncate(u1, s[0]) != 0;
        }

        /// Conditonally replace a field element with `a` if `c` is positive.
        pub fn cMov(fe: *Fe, a: Fe, c: u1) void {
            fiat.selectznz(&fe.limbs, c, fe.limbs, a.limbs);
        }

        /// Add field elements.
        pub fn add(a: Fe, b: Fe) Fe {
            var fe: Fe = undefined;
            fiat.add(&fe.limbs, a.limbs, b.limbs);
            return fe;
        }

        /// Subtract field elements.
        pub fn sub(a: Fe, b: Fe) Fe {
            var fe: Fe = undefined;
            fiat.sub(&fe.limbs, a.limbs, b.limbs);
            return fe;
        }

        /// Double a field element.
        pub fn dbl(a: Fe) Fe {
            var fe: Fe = undefined;
            fiat.add(&fe.limbs, a.limbs, a.limbs);
            return fe;
        }

        /// Multiply field elements.
        pub fn mul(a: Fe, b: Fe) Fe {
            var fe: Fe = undefined;
            fiat.mul(&fe.limbs, a.limbs, b.limbs);
            return fe;
        }

        /// Square a field element.
        pub fn sq(a: Fe) Fe {
            var fe: Fe = undefined;
            fiat.square(&fe.limbs, a.limbs);
            return fe;
        }

        /// Square a field element n times.
        fn sqn(a: Fe, comptime n: comptime_int) Fe {
            var i: usize = 0;
            var fe = a;
            while (i < n) : (i += 1) {
                fe = fe.sq();
            }
            return fe;
        }

        /// Compute a^n.
        pub fn pow(a: Fe, comptime T: type, comptime n: T) Fe {
            var fe = one;
            var x: T = n;
            var t = a;
            while (true) {
                if (@truncate(u1, x) != 0) fe = fe.mul(t);
                x >>= 1;
                if (x == 0) break;
                t = t.sq();
            }
            return fe;
        }

        /// Negate a field element.
        pub fn neg(a: Fe) Fe {
            var fe: Fe = undefined;
            fiat.opp(&fe.limbs, a.limbs);
            return fe;
        }

        /// Return the inverse of a field element, or 0 if a=0.
        // Field inversion from https://eprint.iacr.org/2021/549.pdf
        pub fn invert(a: Fe) Fe {
            const iterations = (49 * field_bits + 57) / 17;
            const Limbs = @TypeOf(a.limbs);
            const Word = @TypeOf(a.limbs[0]);
            const XLimbs = [a.limbs.len + 1]Word;

            var d: Word = 1;
            var f: XLimbs = undefined;
            fiat.msat(&f);

            var g: XLimbs = undefined;
            fiat.fromMontgomery(g[0..a.limbs.len], a.limbs);
            g[g.len - 1] = 0;

            var r: Limbs = undefined;
            fiat.setOne(&r);
            var v = mem.zeroes(Limbs);

            var precomp: Limbs = undefined;
            fiat.divstepPrecomp(&precomp);

            var out1: Word = undefined;
            var out2: XLimbs = undefined;
            var out3: XLimbs = undefined;
            var out4: Limbs = undefined;
            var out5: Limbs = undefined;

            var i: usize = 0;
            while (i < iterations - iterations % 2) : (i += 2) {
                fiat.divstep(&out1, &out2, &out3, &out4, &out5, d, f, g, v, r);
                fiat.divstep(&d, &f, &g, &v, &r, out1, out2, out3, out4, out5);
            }
            if (iterations % 2 != 0) {
                fiat.divstep(&out1, &out2, &out3, &out4, &out5, d, f, g, v, r);
                mem.copy(Word, &v, &out4);
                mem.copy(Word, &f, &out2);
            }
            var v_opp: Limbs = undefined;
            fiat.opp(&v_opp, v);
            fiat.selectznz(&v, @truncate(u1, f[f.len - 1] >> (meta.bitCount(Word) - 1)), v, v_opp);
            var fe: Fe = undefined;
            fiat.mul(&fe.limbs, v, precomp);
            return fe;
        }

        /// Return true if the field element is a square.
        pub fn isSquare(x2: Fe) bool {
            if (field_order == 115792089210356248762697446949407573530086143415290314195533631308867097853951) {
                const t110 = x2.mul(x2.sq()).sq();
                const t111 = x2.mul(t110);
                const t111111 = t111.mul(x2.mul(t110).sqn(3));
                const x15 = t111111.sqn(6).mul(t111111).sqn(3).mul(t111);
                const x16 = x15.sq().mul(x2);
                const x53 = x16.sqn(16).mul(x16).sqn(15);
                const x47 = x15.mul(x53);
                const ls = x47.mul(((x53.sqn(17).mul(x2)).sqn(143).mul(x47)).sqn(47)).sq().mul(x2);
                return ls.equivalent(Fe.one);
            } else {
                const ls = x2.pow(std.meta.Int(.unsigned, field_bits), (field_order - 1) / 2); // Legendre symbol
                return ls.equivalent(Fe.one);
            }
        }

        // x=x2^((field_order+1)/4) w/ field order=3 (mod 4).
        fn uncheckedSqrt(x2: Fe) Fe {
            comptime debug.assert(field_order % 4 == 3);
            if (field_order == 115792089210356248762697446949407573530086143415290314195533631308867097853951) {
                const t11 = x2.mul(x2.sq());
                const t1111 = t11.mul(t11.sqn(2));
                const t11111111 = t1111.mul(t1111.sqn(4));
                const x16 = t11111111.sqn(8).mul(t11111111);
                return x16.sqn(16).mul(x16).sqn(32).mul(x2).sqn(96).mul(x2).sqn(94);
            } else {
                return x2.pow(std.meta.Int(.unsigned, field_bits), (field_order + 1) / 4);
            }
        }

        /// Compute the square root of `x2`, returning `error.NotSquare` if `x2` was not a square.
        pub fn sqrt(x2: Fe) NotSquareError!Fe {
            const x = x2.uncheckedSqrt();
            if (x.sq().equivalent(x2)) {
                return x;
            }
            return error.NotSquare;
        }
    };
}
