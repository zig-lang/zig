const math = @import("index.zig");

pub const nan = nan_workaround;

pub fn nan_workaround(comptime T: type) -> T {
    switch (T) {
        f32 => @bitCast(f32, math.nan_u32),
        f64 => @bitCast(f64, math.nan_u64),
        else => @compileError("nan not implemented for " ++ @typeName(T)),
    }
}
