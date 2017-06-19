const math = @import("index.zig");
const assert = @import("../debug.zig").assert;
const expo2 = @import("_expo2.zig").expo2;

// TODO issue #393
pub const tanh = tanh_workaround;

pub fn tanh_workaround(x: var) -> @typeOf(x) {
    const T = @typeOf(x);
    switch (T) {
        f32 => @inlineCall(tanh32, x),
        f64 => @inlineCall(tanh64, x),
        else => @compileError("tanh not implemented for " ++ @typeName(T)),
    }
}

// tanh(x) = (exp(x) - exp(-x)) / (exp(x) + exp(-x))
//         = (exp(2x) - 1) / (exp(2x) - 1 + 2)
//         = (1 - exp(-2x)) / (exp(-2x) - 1 + 2)
fn tanh32(x: f32) -> f32 {
    const u = @bitCast(u32, x);
    const ux = u & 0x7FFFFFFF;
    const ax = @bitCast(f32, ux);

    var t: f32 = undefined;

    // |x| < log(3) / 2 ~= 0.5493 or nan
    if (ux > 0x3F0C9F54) {
        // |x| > 10
        if (ux > 0x41200000) {
            t = 1.0 + 0 / x;
        } else {
            t = math.expm1(2 * x);
            t = 1 - 2 / (t + 2);
        }
    }
    // |x| > log(5 / 3) / 2 ~= 0.2554
    else if (ux > 0x3E82C578) {
        t = math.expm1(2 * x);
        t = t / (t + 2);
    }
    // |x| >= 0x1.0p-126
    else if (ux >= 0x00800000) {
        t = math.expm1(-2 * x);
        t = -t / (t + 2);
    }
    // |x| is subnormal
    else {
        math.forceEval(x * x);
        t = x;
    }

    if (u >> 31 != 0) {
        -t
    } else {
        t
    }
}

fn tanh64(x: f64) -> f64 {
    const u = @bitCast(u64, x);
    const w = u32(u >> 32);
    const ax = @bitCast(f64, u & (@maxValue(u64) >> 1));

    var t: f64 = undefined;

    // |x| < log(3) / 2 ~= 0.5493 or nan
    if (w > 0x3Fe193EA) {
        // |x| > 20 or nan
        if (w > 0x40340000) {
            t = 1.0 + 0 / x;
        } else {
            t = math.expm1(2 * x);
            t = 1 - 2 / (t + 2);
        }
    }
    // |x| > log(5 / 3) / 2 ~= 0.2554
    else if (w > 0x3FD058AE) {
        t = math.expm1(2 * x);
        t = t / (t + 2);
    }
    // |x| >= 0x1.0p-1022
    else if (w >= 0x00100000) {
        t = math.expm1(-2 * x);
        t = -t / (t + 2);
    }
    // |x| is subnormal
    else {
        math.forceEval(f32(x));
        t = x;
    }

    if (u >> 63 != 0) {
        -t
    } else {
        t
    }
}

test "math.tanh" {
    assert(tanh(f32(1.5)) == tanh32(1.5));
    assert(tanh(f64(1.5)) == tanh64(1.5));
}

test "math.tanh32" {
    const epsilon = 0.000001;

    assert(math.approxEq(f32, tanh32(0.0), 0.0, epsilon));
    assert(math.approxEq(f32, tanh32(0.2), 0.197375, epsilon));
    assert(math.approxEq(f32, tanh32(0.8923), 0.712528, epsilon));
    assert(math.approxEq(f32, tanh32(1.5), 0.905148, epsilon));
    assert(math.approxEq(f32, tanh32(37.45), 1.0, epsilon));
}

test "math.tanh64" {
    const epsilon = 0.000001;

    assert(math.approxEq(f64, tanh64(0.0), 0.0, epsilon));
    assert(math.approxEq(f64, tanh64(0.2), 0.197375, epsilon));
    assert(math.approxEq(f64, tanh64(0.8923), 0.712528, epsilon));
    assert(math.approxEq(f64, tanh64(1.5), 0.905148, epsilon));
    assert(math.approxEq(f64, tanh64(37.45), 1.0, epsilon));
}
