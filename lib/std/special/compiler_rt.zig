// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const builtin = @import("builtin");
const is_test = builtin.is_test;
const os_tag = builtin.os.tag;
const arch = builtin.cpu.arch;
const abi = builtin.abi;

const is_gnu = abi.isGnu();
const is_mingw = os_tag == .windows and is_gnu;

comptime {
    const linkage = if (is_test) std.builtin.GlobalLinkage.Internal else std.builtin.GlobalLinkage.Weak;
    const strong_linkage = if (is_test) std.builtin.GlobalLinkage.Internal else std.builtin.GlobalLinkage.Strong;

    switch (arch) {
        .i386,
        .x86_64,
        => {
            const zig_probe_stack = @import("compiler_rt/stack_probe.zig").zig_probe_stack;
            @export(zig_probe_stack, .{
                .name = "__zig_probe_stack",
                .linkage = linkage,
            });
        },

        else => {},
    }

    // __clear_cache manages its own logic about whether to be exported or not.
    _ = @import("compiler_rt/clear_cache.zig").clear_cache;

    const __lesf2 = @import("compiler_rt/compareXf2.zig").__lesf2;
    @export(__lesf2, .{ .name = "__lesf2", .linkage = linkage });
    const __ledf2 = @import("compiler_rt/compareXf2.zig").__ledf2;
    @export(__ledf2, .{ .name = "__ledf2", .linkage = linkage });
    const __letf2 = @import("compiler_rt/compareXf2.zig").__letf2;
    @export(__letf2, .{ .name = "__letf2", .linkage = linkage });

    const __gesf2 = @import("compiler_rt/compareXf2.zig").__gesf2;
    @export(__gesf2, .{ .name = "__gesf2", .linkage = linkage });
    const __gedf2 = @import("compiler_rt/compareXf2.zig").__gedf2;
    @export(__gedf2, .{ .name = "__gedf2", .linkage = linkage });
    const __getf2 = @import("compiler_rt/compareXf2.zig").__getf2;
    @export(__getf2, .{ .name = "__getf2", .linkage = linkage });

    if (!is_test) {
        @export(__lesf2, .{ .name = "__cmpsf2", .linkage = linkage });
        @export(__ledf2, .{ .name = "__cmpdf2", .linkage = linkage });
        @export(__letf2, .{ .name = "__cmptf2", .linkage = linkage });

        const __eqsf2 = @import("compiler_rt/compareXf2.zig").__eqsf2;
        @export(__eqsf2, .{ .name = "__eqsf2", .linkage = linkage });
        const __eqdf2 = @import("compiler_rt/compareXf2.zig").__eqdf2;
        @export(__eqdf2, .{ .name = "__eqdf2", .linkage = linkage });
        @export(__letf2, .{ .name = "__eqtf2", .linkage = linkage });

        const __ltsf2 = @import("compiler_rt/compareXf2.zig").__ltsf2;
        @export(__ltsf2, .{ .name = "__ltsf2", .linkage = linkage });
        const __ltdf2 = @import("compiler_rt/compareXf2.zig").__ltdf2;
        @export(__ltdf2, .{ .name = "__ltdf2", .linkage = linkage });
        @export(__letf2, .{ .name = "__lttf2", .linkage = linkage });

        const __nesf2 = @import("compiler_rt/compareXf2.zig").__nesf2;
        @export(__nesf2, .{ .name = "__nesf2", .linkage = linkage });
        const __nedf2 = @import("compiler_rt/compareXf2.zig").__nedf2;
        @export(__nedf2, .{ .name = "__nedf2", .linkage = linkage });
        @export(__letf2, .{ .name = "__netf2", .linkage = linkage });

        const __gtsf2 = @import("compiler_rt/compareXf2.zig").__gtsf2;
        @export(__gtsf2, .{ .name = "__gtsf2", .linkage = linkage });
        const __gtdf2 = @import("compiler_rt/compareXf2.zig").__gtdf2;
        @export(__gtdf2, .{ .name = "__gtdf2", .linkage = linkage });
        @export(__getf2, .{ .name = "__gttf2", .linkage = linkage });

        const __extendhfsf2 = @import("compiler_rt/extendXfYf2.zig").__extendhfsf2;
        @export(__extendhfsf2, .{ .name = "__gnu_h2f_ieee", .linkage = linkage });
        const __truncsfhf2 = @import("compiler_rt/truncXfYf2.zig").__truncsfhf2;
        @export(__truncsfhf2, .{ .name = "__gnu_f2h_ieee", .linkage = linkage });
    }

    const __unordsf2 = @import("compiler_rt/compareXf2.zig").__unordsf2;
    @export(__unordsf2, .{ .name = "__unordsf2", .linkage = linkage });
    const __unorddf2 = @import("compiler_rt/compareXf2.zig").__unorddf2;
    @export(__unorddf2, .{ .name = "__unorddf2", .linkage = linkage });
    const __unordtf2 = @import("compiler_rt/compareXf2.zig").__unordtf2;
    @export(__unordtf2, .{ .name = "__unordtf2", .linkage = linkage });

    const __addsf3 = @import("compiler_rt/addXf3.zig").__addsf3;
    @export(__addsf3, .{ .name = "__addsf3", .linkage = linkage });
    const __adddf3 = @import("compiler_rt/addXf3.zig").__adddf3;
    @export(__adddf3, .{ .name = "__adddf3", .linkage = linkage });
    const __addtf3 = @import("compiler_rt/addXf3.zig").__addtf3;
    @export(__addtf3, .{ .name = "__addtf3", .linkage = linkage });
    const __subsf3 = @import("compiler_rt/addXf3.zig").__subsf3;
    @export(__subsf3, .{ .name = "__subsf3", .linkage = linkage });
    const __subdf3 = @import("compiler_rt/addXf3.zig").__subdf3;
    @export(__subdf3, .{ .name = "__subdf3", .linkage = linkage });
    const __subtf3 = @import("compiler_rt/addXf3.zig").__subtf3;
    @export(__subtf3, .{ .name = "__subtf3", .linkage = linkage });

    const __mulsf3 = @import("compiler_rt/mulXf3.zig").__mulsf3;
    @export(__mulsf3, .{ .name = "__mulsf3", .linkage = linkage });
    const __muldf3 = @import("compiler_rt/mulXf3.zig").__muldf3;
    @export(__muldf3, .{ .name = "__muldf3", .linkage = linkage });
    const __multf3 = @import("compiler_rt/mulXf3.zig").__multf3;
    @export(__multf3, .{ .name = "__multf3", .linkage = linkage });

    const __divsf3 = @import("compiler_rt/divsf3.zig").__divsf3;
    @export(__divsf3, .{ .name = "__divsf3", .linkage = linkage });
    const __divdf3 = @import("compiler_rt/divdf3.zig").__divdf3;
    @export(__divdf3, .{ .name = "__divdf3", .linkage = linkage });
    const __divtf3 = @import("compiler_rt/divtf3.zig").__divtf3;
    @export(__divtf3, .{ .name = "__divtf3", .linkage = linkage });

    const __ashldi3 = @import("compiler_rt/shift.zig").__ashldi3;
    @export(__ashldi3, .{ .name = "__ashldi3", .linkage = linkage });
    const __ashlti3 = @import("compiler_rt/shift.zig").__ashlti3;
    @export(__ashlti3, .{ .name = "__ashlti3", .linkage = linkage });
    const __ashrdi3 = @import("compiler_rt/shift.zig").__ashrdi3;
    @export(__ashrdi3, .{ .name = "__ashrdi3", .linkage = linkage });
    const __ashrti3 = @import("compiler_rt/shift.zig").__ashrti3;
    @export(__ashrti3, .{ .name = "__ashrti3", .linkage = linkage });
    const __lshrdi3 = @import("compiler_rt/shift.zig").__lshrdi3;
    @export(__lshrdi3, .{ .name = "__lshrdi3", .linkage = linkage });
    const __lshrti3 = @import("compiler_rt/shift.zig").__lshrti3;
    @export(__lshrti3, .{ .name = "__lshrti3", .linkage = linkage });

    const __floatsidf = @import("compiler_rt/floatsiXf.zig").__floatsidf;
    @export(__floatsidf, .{ .name = "__floatsidf", .linkage = linkage });
    const __floatsisf = @import("compiler_rt/floatsiXf.zig").__floatsisf;
    @export(__floatsisf, .{ .name = "__floatsisf", .linkage = linkage });
    const __floatdidf = @import("compiler_rt/floatdidf.zig").__floatdidf;
    @export(__floatdidf, .{ .name = "__floatdidf", .linkage = linkage });
    const __floatsitf = @import("compiler_rt/floatsiXf.zig").__floatsitf;
    @export(__floatsitf, .{ .name = "__floatsitf", .linkage = linkage });

    const __floatunsisf = @import("compiler_rt/floatunsisf.zig").__floatunsisf;
    @export(__floatunsisf, .{ .name = "__floatunsisf", .linkage = linkage });
    const __floatundisf = @import("compiler_rt/floatundisf.zig").__floatundisf;
    @export(__floatundisf, .{ .name = "__floatundisf", .linkage = linkage });
    const __floatunsidf = @import("compiler_rt/floatunsidf.zig").__floatunsidf;
    @export(__floatunsidf, .{ .name = "__floatunsidf", .linkage = linkage });
    const __floatundidf = @import("compiler_rt/floatundidf.zig").__floatundidf;
    @export(__floatundidf, .{ .name = "__floatundidf", .linkage = linkage });

    const __floatditf = @import("compiler_rt/floatditf.zig").__floatditf;
    @export(__floatditf, .{ .name = "__floatditf", .linkage = linkage });
    const __floattitf = @import("compiler_rt/floattitf.zig").__floattitf;
    @export(__floattitf, .{ .name = "__floattitf", .linkage = linkage });
    const __floattidf = @import("compiler_rt/floattidf.zig").__floattidf;
    @export(__floattidf, .{ .name = "__floattidf", .linkage = linkage });
    const __floattisf = @import("compiler_rt/floatXisf.zig").__floattisf;
    @export(__floattisf, .{ .name = "__floattisf", .linkage = linkage });
    const __floatdisf = @import("compiler_rt/floatXisf.zig").__floatdisf;
    @export(__floatdisf, .{ .name = "__floatdisf", .linkage = linkage });

    const __floatunditf = @import("compiler_rt/floatunditf.zig").__floatunditf;
    @export(__floatunditf, .{ .name = "__floatunditf", .linkage = linkage });
    const __floatunsitf = @import("compiler_rt/floatunsitf.zig").__floatunsitf;
    @export(__floatunsitf, .{ .name = "__floatunsitf", .linkage = linkage });

    const __floatuntitf = @import("compiler_rt/floatuntitf.zig").__floatuntitf;
    @export(__floatuntitf, .{ .name = "__floatuntitf", .linkage = linkage });
    const __floatuntidf = @import("compiler_rt/floatuntidf.zig").__floatuntidf;
    @export(__floatuntidf, .{ .name = "__floatuntidf", .linkage = linkage });
    const __floatuntisf = @import("compiler_rt/floatuntisf.zig").__floatuntisf;
    @export(__floatuntisf, .{ .name = "__floatuntisf", .linkage = linkage });

    const __extenddftf2 = @import("compiler_rt/extendXfYf2.zig").__extenddftf2;
    @export(__extenddftf2, .{ .name = "__extenddftf2", .linkage = linkage });
    const __extendsftf2 = @import("compiler_rt/extendXfYf2.zig").__extendsftf2;
    @export(__extendsftf2, .{ .name = "__extendsftf2", .linkage = linkage });
    const __extendhfsf2 = @import("compiler_rt/extendXfYf2.zig").__extendhfsf2;
    @export(__extendhfsf2, .{ .name = "__extendhfsf2", .linkage = linkage });
    const __extendhftf2 = @import("compiler_rt/extendXfYf2.zig").__extendhftf2;
    @export(__extendhftf2, .{ .name = "__extendhftf2", .linkage = linkage });

    const __truncsfhf2 = @import("compiler_rt/truncXfYf2.zig").__truncsfhf2;
    @export(__truncsfhf2, .{ .name = "__truncsfhf2", .linkage = linkage });
    const __truncdfhf2 = @import("compiler_rt/truncXfYf2.zig").__truncdfhf2;
    @export(__truncdfhf2, .{ .name = "__truncdfhf2", .linkage = linkage });
    const __trunctfhf2 = @import("compiler_rt/truncXfYf2.zig").__trunctfhf2;
    @export(__trunctfhf2, .{ .name = "__trunctfhf2", .linkage = linkage });
    const __trunctfdf2 = @import("compiler_rt/truncXfYf2.zig").__trunctfdf2;
    @export(__trunctfdf2, .{ .name = "__trunctfdf2", .linkage = linkage });
    const __trunctfsf2 = @import("compiler_rt/truncXfYf2.zig").__trunctfsf2;
    @export(__trunctfsf2, .{ .name = "__trunctfsf2", .linkage = linkage });

    const __truncdfsf2 = @import("compiler_rt/truncXfYf2.zig").__truncdfsf2;
    @export(__truncdfsf2, .{ .name = "__truncdfsf2", .linkage = linkage });

    const __extendsfdf2 = @import("compiler_rt/extendXfYf2.zig").__extendsfdf2;
    @export(__extendsfdf2, .{ .name = "__extendsfdf2", .linkage = linkage });

    const __fixunssfsi = @import("compiler_rt/fixunssfsi.zig").__fixunssfsi;
    @export(__fixunssfsi, .{ .name = "__fixunssfsi", .linkage = linkage });
    const __fixunssfdi = @import("compiler_rt/fixunssfdi.zig").__fixunssfdi;
    @export(__fixunssfdi, .{ .name = "__fixunssfdi", .linkage = linkage });
    const __fixunssfti = @import("compiler_rt/fixunssfti.zig").__fixunssfti;
    @export(__fixunssfti, .{ .name = "__fixunssfti", .linkage = linkage });

    const __fixunsdfsi = @import("compiler_rt/fixunsdfsi.zig").__fixunsdfsi;
    @export(__fixunsdfsi, .{ .name = "__fixunsdfsi", .linkage = linkage });
    const __fixunsdfdi = @import("compiler_rt/fixunsdfdi.zig").__fixunsdfdi;
    @export(__fixunsdfdi, .{ .name = "__fixunsdfdi", .linkage = linkage });
    const __fixunsdfti = @import("compiler_rt/fixunsdfti.zig").__fixunsdfti;
    @export(__fixunsdfti, .{ .name = "__fixunsdfti", .linkage = linkage });

    const __fixunstfsi = @import("compiler_rt/fixunstfsi.zig").__fixunstfsi;
    @export(__fixunstfsi, .{ .name = "__fixunstfsi", .linkage = linkage });
    const __fixunstfdi = @import("compiler_rt/fixunstfdi.zig").__fixunstfdi;
    @export(__fixunstfdi, .{ .name = "__fixunstfdi", .linkage = linkage });
    const __fixunstfti = @import("compiler_rt/fixunstfti.zig").__fixunstfti;
    @export(__fixunstfti, .{ .name = "__fixunstfti", .linkage = linkage });

    const __fixdfdi = @import("compiler_rt/fixdfdi.zig").__fixdfdi;
    @export(__fixdfdi, .{ .name = "__fixdfdi", .linkage = linkage });
    const __fixdfsi = @import("compiler_rt/fixdfsi.zig").__fixdfsi;
    @export(__fixdfsi, .{ .name = "__fixdfsi", .linkage = linkage });
    const __fixdfti = @import("compiler_rt/fixdfti.zig").__fixdfti;
    @export(__fixdfti, .{ .name = "__fixdfti", .linkage = linkage });
    const __fixsfdi = @import("compiler_rt/fixsfdi.zig").__fixsfdi;
    @export(__fixsfdi, .{ .name = "__fixsfdi", .linkage = linkage });
    const __fixsfsi = @import("compiler_rt/fixsfsi.zig").__fixsfsi;
    @export(__fixsfsi, .{ .name = "__fixsfsi", .linkage = linkage });
    const __fixsfti = @import("compiler_rt/fixsfti.zig").__fixsfti;
    @export(__fixsfti, .{ .name = "__fixsfti", .linkage = linkage });
    const __fixtfdi = @import("compiler_rt/fixtfdi.zig").__fixtfdi;
    @export(__fixtfdi, .{ .name = "__fixtfdi", .linkage = linkage });
    const __fixtfsi = @import("compiler_rt/fixtfsi.zig").__fixtfsi;
    @export(__fixtfsi, .{ .name = "__fixtfsi", .linkage = linkage });
    const __fixtfti = @import("compiler_rt/fixtfti.zig").__fixtfti;
    @export(__fixtfti, .{ .name = "__fixtfti", .linkage = linkage });

    const __udivmoddi4 = @import("compiler_rt/int.zig").__udivmoddi4;
    @export(__udivmoddi4, .{ .name = "__udivmoddi4", .linkage = linkage });
    const __popcountdi2 = @import("compiler_rt/popcountdi2.zig").__popcountdi2;
    @export(__popcountdi2, .{ .name = "__popcountdi2", .linkage = linkage });

    const __mulsi3 = @import("compiler_rt/int.zig").__mulsi3;
    @export(__mulsi3, .{ .name = "__mulsi3", .linkage = linkage });
    const __muldi3 = @import("compiler_rt/muldi3.zig").__muldi3;
    @export(__muldi3, .{ .name = "__muldi3", .linkage = linkage });
    const __divmoddi4 = @import("compiler_rt/int.zig").__divmoddi4;
    @export(__divmoddi4, .{ .name = "__divmoddi4", .linkage = linkage });
    const __divsi3 = @import("compiler_rt/int.zig").__divsi3;
    @export(__divsi3, .{ .name = "__divsi3", .linkage = linkage });
    const __divdi3 = @import("compiler_rt/int.zig").__divdi3;
    @export(__divdi3, .{ .name = "__divdi3", .linkage = linkage });
    const __udivsi3 = @import("compiler_rt/int.zig").__udivsi3;
    @export(__udivsi3, .{ .name = "__udivsi3", .linkage = linkage });
    const __udivdi3 = @import("compiler_rt/int.zig").__udivdi3;
    @export(__udivdi3, .{ .name = "__udivdi3", .linkage = linkage });
    const __modsi3 = @import("compiler_rt/int.zig").__modsi3;
    @export(__modsi3, .{ .name = "__modsi3", .linkage = linkage });
    const __moddi3 = @import("compiler_rt/int.zig").__moddi3;
    @export(__moddi3, .{ .name = "__moddi3", .linkage = linkage });
    const __umodsi3 = @import("compiler_rt/int.zig").__umodsi3;
    @export(__umodsi3, .{ .name = "__umodsi3", .linkage = linkage });
    const __umoddi3 = @import("compiler_rt/int.zig").__umoddi3;
    @export(__umoddi3, .{ .name = "__umoddi3", .linkage = linkage });
    const __divmodsi4 = @import("compiler_rt/int.zig").__divmodsi4;
    @export(__divmodsi4, .{ .name = "__divmodsi4", .linkage = linkage });
    const __udivmodsi4 = @import("compiler_rt/int.zig").__udivmodsi4;
    @export(__udivmodsi4, .{ .name = "__udivmodsi4", .linkage = linkage });

    const __negsf2 = @import("compiler_rt/negXf2.zig").__negsf2;
    @export(__negsf2, .{ .name = "__negsf2", .linkage = linkage });
    const __negdf2 = @import("compiler_rt/negXf2.zig").__negdf2;
    @export(__negdf2, .{ .name = "__negdf2", .linkage = linkage });

    const __clzsi2 = @import("compiler_rt/clzsi2.zig").__clzsi2;
    @export(__clzsi2, .{ .name = "__clzsi2", .linkage = linkage });

    if (builtin.link_libc and os_tag == .openbsd) {
        const __emutls_get_address = @import("compiler_rt/emutls.zig").__emutls_get_address;
        @export(__emutls_get_address, .{ .name = "__emutls_get_address", .linkage = linkage });
    }

    if ((arch.isARM() or arch.isThumb()) and !is_test) {
        const __aeabi_unwind_cpp_pr0 = @import("compiler_rt/arm.zig").__aeabi_unwind_cpp_pr0;
        @export(__aeabi_unwind_cpp_pr0, .{ .name = "__aeabi_unwind_cpp_pr0", .linkage = linkage });
        const __aeabi_unwind_cpp_pr1 = @import("compiler_rt/arm.zig").__aeabi_unwind_cpp_pr1;
        @export(__aeabi_unwind_cpp_pr1, .{ .name = "__aeabi_unwind_cpp_pr1", .linkage = linkage });
        const __aeabi_unwind_cpp_pr2 = @import("compiler_rt/arm.zig").__aeabi_unwind_cpp_pr2;
        @export(__aeabi_unwind_cpp_pr2, .{ .name = "__aeabi_unwind_cpp_pr2", .linkage = linkage });

        @export(__muldi3, .{ .name = "__aeabi_lmul", .linkage = linkage });

        const __aeabi_ldivmod = @import("compiler_rt/arm.zig").__aeabi_ldivmod;
        @export(__aeabi_ldivmod, .{ .name = "__aeabi_ldivmod", .linkage = linkage });
        const __aeabi_uldivmod = @import("compiler_rt/arm.zig").__aeabi_uldivmod;
        @export(__aeabi_uldivmod, .{ .name = "__aeabi_uldivmod", .linkage = linkage });

        @export(__divsi3, .{ .name = "__aeabi_idiv", .linkage = linkage });
        const __aeabi_idivmod = @import("compiler_rt/arm.zig").__aeabi_idivmod;
        @export(__aeabi_idivmod, .{ .name = "__aeabi_idivmod", .linkage = linkage });
        @export(__udivsi3, .{ .name = "__aeabi_uidiv", .linkage = linkage });
        const __aeabi_uidivmod = @import("compiler_rt/arm.zig").__aeabi_uidivmod;
        @export(__aeabi_uidivmod, .{ .name = "__aeabi_uidivmod", .linkage = linkage });

        const __aeabi_memcpy = @import("compiler_rt/arm.zig").__aeabi_memcpy;
        @export(__aeabi_memcpy, .{ .name = "__aeabi_memcpy", .linkage = linkage });
        @export(__aeabi_memcpy, .{ .name = "__aeabi_memcpy4", .linkage = linkage });
        @export(__aeabi_memcpy, .{ .name = "__aeabi_memcpy8", .linkage = linkage });

        const __aeabi_memmove = @import("compiler_rt/arm.zig").__aeabi_memmove;
        @export(__aeabi_memmove, .{ .name = "__aeabi_memmove", .linkage = linkage });
        @export(__aeabi_memmove, .{ .name = "__aeabi_memmove4", .linkage = linkage });
        @export(__aeabi_memmove, .{ .name = "__aeabi_memmove8", .linkage = linkage });

        const __aeabi_memset = @import("compiler_rt/arm.zig").__aeabi_memset;
        @export(__aeabi_memset, .{ .name = "__aeabi_memset", .linkage = linkage });
        @export(__aeabi_memset, .{ .name = "__aeabi_memset4", .linkage = linkage });
        @export(__aeabi_memset, .{ .name = "__aeabi_memset8", .linkage = linkage });

        const __aeabi_memclr = @import("compiler_rt/arm.zig").__aeabi_memclr;
        @export(__aeabi_memclr, .{ .name = "__aeabi_memclr", .linkage = linkage });
        @export(__aeabi_memclr, .{ .name = "__aeabi_memclr4", .linkage = linkage });
        @export(__aeabi_memclr, .{ .name = "__aeabi_memclr8", .linkage = linkage });

        if (os_tag == .linux) {
            const __aeabi_read_tp = @import("compiler_rt/arm.zig").__aeabi_read_tp;
            @export(__aeabi_read_tp, .{ .name = "__aeabi_read_tp", .linkage = linkage });
        }

        const __aeabi_f2d = @import("compiler_rt/extendXfYf2.zig").__aeabi_f2d;
        @export(__aeabi_f2d, .{ .name = "__aeabi_f2d", .linkage = linkage });
        const __aeabi_i2d = @import("compiler_rt/floatsiXf.zig").__aeabi_i2d;
        @export(__aeabi_i2d, .{ .name = "__aeabi_i2d", .linkage = linkage });
        const __aeabi_l2d = @import("compiler_rt/floatdidf.zig").__aeabi_l2d;
        @export(__aeabi_l2d, .{ .name = "__aeabi_l2d", .linkage = linkage });
        const __aeabi_l2f = @import("compiler_rt/floatXisf.zig").__aeabi_l2f;
        @export(__aeabi_l2f, .{ .name = "__aeabi_l2f", .linkage = linkage });
        const __aeabi_ui2d = @import("compiler_rt/floatunsidf.zig").__aeabi_ui2d;
        @export(__aeabi_ui2d, .{ .name = "__aeabi_ui2d", .linkage = linkage });
        const __aeabi_ul2d = @import("compiler_rt/floatundidf.zig").__aeabi_ul2d;
        @export(__aeabi_ul2d, .{ .name = "__aeabi_ul2d", .linkage = linkage });
        const __aeabi_ui2f = @import("compiler_rt/floatunsisf.zig").__aeabi_ui2f;
        @export(__aeabi_ui2f, .{ .name = "__aeabi_ui2f", .linkage = linkage });
        const __aeabi_ul2f = @import("compiler_rt/floatundisf.zig").__aeabi_ul2f;
        @export(__aeabi_ul2f, .{ .name = "__aeabi_ul2f", .linkage = linkage });

        const __aeabi_fneg = @import("compiler_rt/negXf2.zig").__aeabi_fneg;
        @export(__aeabi_fneg, .{ .name = "__aeabi_fneg", .linkage = linkage });
        const __aeabi_dneg = @import("compiler_rt/negXf2.zig").__aeabi_dneg;
        @export(__aeabi_dneg, .{ .name = "__aeabi_dneg", .linkage = linkage });

        const __aeabi_fmul = @import("compiler_rt/mulXf3.zig").__aeabi_fmul;
        @export(__aeabi_fmul, .{ .name = "__aeabi_fmul", .linkage = linkage });
        const __aeabi_dmul = @import("compiler_rt/mulXf3.zig").__aeabi_dmul;
        @export(__aeabi_dmul, .{ .name = "__aeabi_dmul", .linkage = linkage });

        const __aeabi_d2h = @import("compiler_rt/truncXfYf2.zig").__aeabi_d2h;
        @export(__aeabi_d2h, .{ .name = "__aeabi_d2h", .linkage = linkage });

        const __aeabi_f2ulz = @import("compiler_rt/fixunssfdi.zig").__aeabi_f2ulz;
        @export(__aeabi_f2ulz, .{ .name = "__aeabi_f2ulz", .linkage = linkage });
        const __aeabi_d2ulz = @import("compiler_rt/fixunsdfdi.zig").__aeabi_d2ulz;
        @export(__aeabi_d2ulz, .{ .name = "__aeabi_d2ulz", .linkage = linkage });

        const __aeabi_f2lz = @import("compiler_rt/fixsfdi.zig").__aeabi_f2lz;
        @export(__aeabi_f2lz, .{ .name = "__aeabi_f2lz", .linkage = linkage });
        const __aeabi_d2lz = @import("compiler_rt/fixdfdi.zig").__aeabi_d2lz;
        @export(__aeabi_d2lz, .{ .name = "__aeabi_d2lz", .linkage = linkage });

        const __aeabi_d2uiz = @import("compiler_rt/fixunsdfsi.zig").__aeabi_d2uiz;
        @export(__aeabi_d2uiz, .{ .name = "__aeabi_d2uiz", .linkage = linkage });

        const __aeabi_h2f = @import("compiler_rt/extendXfYf2.zig").__aeabi_h2f;
        @export(__aeabi_h2f, .{ .name = "__aeabi_h2f", .linkage = linkage });
        const __aeabi_f2h = @import("compiler_rt/truncXfYf2.zig").__aeabi_f2h;
        @export(__aeabi_f2h, .{ .name = "__aeabi_f2h", .linkage = linkage });

        const __aeabi_i2f = @import("compiler_rt/floatsiXf.zig").__aeabi_i2f;
        @export(__aeabi_i2f, .{ .name = "__aeabi_i2f", .linkage = linkage });
        const __aeabi_d2f = @import("compiler_rt/truncXfYf2.zig").__aeabi_d2f;
        @export(__aeabi_d2f, .{ .name = "__aeabi_d2f", .linkage = linkage });

        const __aeabi_fadd = @import("compiler_rt/addXf3.zig").__aeabi_fadd;
        @export(__aeabi_fadd, .{ .name = "__aeabi_fadd", .linkage = linkage });
        const __aeabi_dadd = @import("compiler_rt/addXf3.zig").__aeabi_dadd;
        @export(__aeabi_dadd, .{ .name = "__aeabi_dadd", .linkage = linkage });
        const __aeabi_fsub = @import("compiler_rt/addXf3.zig").__aeabi_fsub;
        @export(__aeabi_fsub, .{ .name = "__aeabi_fsub", .linkage = linkage });
        const __aeabi_dsub = @import("compiler_rt/addXf3.zig").__aeabi_dsub;
        @export(__aeabi_dsub, .{ .name = "__aeabi_dsub", .linkage = linkage });

        const __aeabi_f2uiz = @import("compiler_rt/fixunssfsi.zig").__aeabi_f2uiz;
        @export(__aeabi_f2uiz, .{ .name = "__aeabi_f2uiz", .linkage = linkage });

        const __aeabi_f2iz = @import("compiler_rt/fixsfsi.zig").__aeabi_f2iz;
        @export(__aeabi_f2iz, .{ .name = "__aeabi_f2iz", .linkage = linkage });
        const __aeabi_d2iz = @import("compiler_rt/fixdfsi.zig").__aeabi_d2iz;
        @export(__aeabi_d2iz, .{ .name = "__aeabi_d2iz", .linkage = linkage });

        const __aeabi_fdiv = @import("compiler_rt/divsf3.zig").__aeabi_fdiv;
        @export(__aeabi_fdiv, .{ .name = "__aeabi_fdiv", .linkage = linkage });
        const __aeabi_ddiv = @import("compiler_rt/divdf3.zig").__aeabi_ddiv;
        @export(__aeabi_ddiv, .{ .name = "__aeabi_ddiv", .linkage = linkage });

        const __aeabi_llsl = @import("compiler_rt/shift.zig").__aeabi_llsl;
        @export(__aeabi_llsl, .{ .name = "__aeabi_llsl", .linkage = linkage });
        const __aeabi_lasr = @import("compiler_rt/shift.zig").__aeabi_lasr;
        @export(__aeabi_lasr, .{ .name = "__aeabi_lasr", .linkage = linkage });
        const __aeabi_llsr = @import("compiler_rt/shift.zig").__aeabi_llsr;
        @export(__aeabi_llsr, .{ .name = "__aeabi_llsr", .linkage = linkage });

        const __aeabi_fcmpeq = @import("compiler_rt/compareXf2.zig").__aeabi_fcmpeq;
        @export(__aeabi_fcmpeq, .{ .name = "__aeabi_fcmpeq", .linkage = linkage });
        const __aeabi_fcmplt = @import("compiler_rt/compareXf2.zig").__aeabi_fcmplt;
        @export(__aeabi_fcmplt, .{ .name = "__aeabi_fcmplt", .linkage = linkage });
        const __aeabi_fcmple = @import("compiler_rt/compareXf2.zig").__aeabi_fcmple;
        @export(__aeabi_fcmple, .{ .name = "__aeabi_fcmple", .linkage = linkage });
        const __aeabi_fcmpge = @import("compiler_rt/compareXf2.zig").__aeabi_fcmpge;
        @export(__aeabi_fcmpge, .{ .name = "__aeabi_fcmpge", .linkage = linkage });
        const __aeabi_fcmpgt = @import("compiler_rt/compareXf2.zig").__aeabi_fcmpgt;
        @export(__aeabi_fcmpgt, .{ .name = "__aeabi_fcmpgt", .linkage = linkage });
        const __aeabi_fcmpun = @import("compiler_rt/compareXf2.zig").__aeabi_fcmpun;
        @export(__aeabi_fcmpun, .{ .name = "__aeabi_fcmpun", .linkage = linkage });

        const __aeabi_dcmpeq = @import("compiler_rt/compareXf2.zig").__aeabi_dcmpeq;
        @export(__aeabi_dcmpeq, .{ .name = "__aeabi_dcmpeq", .linkage = linkage });
        const __aeabi_dcmplt = @import("compiler_rt/compareXf2.zig").__aeabi_dcmplt;
        @export(__aeabi_dcmplt, .{ .name = "__aeabi_dcmplt", .linkage = linkage });
        const __aeabi_dcmple = @import("compiler_rt/compareXf2.zig").__aeabi_dcmple;
        @export(__aeabi_dcmple, .{ .name = "__aeabi_dcmple", .linkage = linkage });
        const __aeabi_dcmpge = @import("compiler_rt/compareXf2.zig").__aeabi_dcmpge;
        @export(__aeabi_dcmpge, .{ .name = "__aeabi_dcmpge", .linkage = linkage });
        const __aeabi_dcmpgt = @import("compiler_rt/compareXf2.zig").__aeabi_dcmpgt;
        @export(__aeabi_dcmpgt, .{ .name = "__aeabi_dcmpgt", .linkage = linkage });
        const __aeabi_dcmpun = @import("compiler_rt/compareXf2.zig").__aeabi_dcmpun;
        @export(__aeabi_dcmpun, .{ .name = "__aeabi_dcmpun", .linkage = linkage });
    }

    if (arch == .i386 and abi == .msvc) {
        // Don't let LLVM apply the stdcall name mangling on those MSVC builtins
        const _alldiv = @import("compiler_rt/aulldiv.zig")._alldiv;
        @export(_alldiv, .{ .name = "\x01__alldiv", .linkage = strong_linkage });
        const _aulldiv = @import("compiler_rt/aulldiv.zig")._aulldiv;
        @export(_aulldiv, .{ .name = "\x01__aulldiv", .linkage = strong_linkage });
        const _allrem = @import("compiler_rt/aullrem.zig")._allrem;
        @export(_allrem, .{ .name = "\x01__allrem", .linkage = strong_linkage });
        const _aullrem = @import("compiler_rt/aullrem.zig")._aullrem;
        @export(_aullrem, .{ .name = "\x01__aullrem", .linkage = strong_linkage });
    }

    if (arch.isSPARC()) {
        // SPARC systems use a different naming scheme
        const _Qp_add = @import("compiler_rt/sparc.zig")._Qp_add;
        @export(_Qp_add, .{ .name = "_Qp_add", .linkage = linkage });
        const _Qp_div = @import("compiler_rt/sparc.zig")._Qp_div;
        @export(_Qp_div, .{ .name = "_Qp_div", .linkage = linkage });
        const _Qp_mul = @import("compiler_rt/sparc.zig")._Qp_mul;
        @export(_Qp_mul, .{ .name = "_Qp_mul", .linkage = linkage });
        const _Qp_sub = @import("compiler_rt/sparc.zig")._Qp_sub;
        @export(_Qp_sub, .{ .name = "_Qp_sub", .linkage = linkage });

        const _Qp_cmp = @import("compiler_rt/sparc.zig")._Qp_cmp;
        @export(_Qp_cmp, .{ .name = "_Qp_cmp", .linkage = linkage });
        const _Qp_feq = @import("compiler_rt/sparc.zig")._Qp_feq;
        @export(_Qp_feq, .{ .name = "_Qp_feq", .linkage = linkage });
        const _Qp_fne = @import("compiler_rt/sparc.zig")._Qp_fne;
        @export(_Qp_fne, .{ .name = "_Qp_fne", .linkage = linkage });
        const _Qp_flt = @import("compiler_rt/sparc.zig")._Qp_flt;
        @export(_Qp_flt, .{ .name = "_Qp_flt", .linkage = linkage });
        const _Qp_fle = @import("compiler_rt/sparc.zig")._Qp_fle;
        @export(_Qp_fle, .{ .name = "_Qp_fle", .linkage = linkage });
        const _Qp_fgt = @import("compiler_rt/sparc.zig")._Qp_fgt;
        @export(_Qp_fgt, .{ .name = "_Qp_fgt", .linkage = linkage });
        const _Qp_fge = @import("compiler_rt/sparc.zig")._Qp_fge;
        @export(_Qp_fge, .{ .name = "_Qp_fge", .linkage = linkage });

        const _Qp_itoq = @import("compiler_rt/sparc.zig")._Qp_itoq;
        @export(_Qp_itoq, .{ .name = "_Qp_itoq", .linkage = linkage });
        const _Qp_uitoq = @import("compiler_rt/sparc.zig")._Qp_uitoq;
        @export(_Qp_uitoq, .{ .name = "_Qp_uitoq", .linkage = linkage });
        const _Qp_xtoq = @import("compiler_rt/sparc.zig")._Qp_xtoq;
        @export(_Qp_xtoq, .{ .name = "_Qp_xtoq", .linkage = linkage });
        const _Qp_uxtoq = @import("compiler_rt/sparc.zig")._Qp_uxtoq;
        @export(_Qp_uxtoq, .{ .name = "_Qp_uxtoq", .linkage = linkage });
        const _Qp_stoq = @import("compiler_rt/sparc.zig")._Qp_stoq;
        @export(_Qp_stoq, .{ .name = "_Qp_stoq", .linkage = linkage });
        const _Qp_dtoq = @import("compiler_rt/sparc.zig")._Qp_dtoq;
        @export(_Qp_dtoq, .{ .name = "_Qp_dtoq", .linkage = linkage });
        const _Qp_qtoi = @import("compiler_rt/sparc.zig")._Qp_qtoi;
        @export(_Qp_qtoi, .{ .name = "_Qp_qtoi", .linkage = linkage });
        const _Qp_qtoui = @import("compiler_rt/sparc.zig")._Qp_qtoui;
        @export(_Qp_qtoui, .{ .name = "_Qp_qtoui", .linkage = linkage });
        const _Qp_qtox = @import("compiler_rt/sparc.zig")._Qp_qtox;
        @export(_Qp_qtox, .{ .name = "_Qp_qtox", .linkage = linkage });
        const _Qp_qtoux = @import("compiler_rt/sparc.zig")._Qp_qtoux;
        @export(_Qp_qtoux, .{ .name = "_Qp_qtoux", .linkage = linkage });
        const _Qp_qtos = @import("compiler_rt/sparc.zig")._Qp_qtos;
        @export(_Qp_qtos, .{ .name = "_Qp_qtos", .linkage = linkage });
        const _Qp_qtod = @import("compiler_rt/sparc.zig")._Qp_qtod;
        @export(_Qp_qtod, .{ .name = "_Qp_qtod", .linkage = linkage });
    }

    if ((arch == .powerpc or arch.isPPC64()) and !is_test) {
        @export(__addtf3, .{ .name = "__addkf3", .linkage = linkage });
        @export(__subtf3, .{ .name = "__subkf3", .linkage = linkage });
        @export(__multf3, .{ .name = "__mulkf3", .linkage = linkage });
        @export(__divtf3, .{ .name = "__divkf3", .linkage = linkage });
        @export(__extendsftf2, .{ .name = "__extendsfkf2", .linkage = linkage });
        @export(__extenddftf2, .{ .name = "__extenddfkf2", .linkage = linkage });
        @export(__trunctfsf2, .{ .name = "__trunckfsf2", .linkage = linkage });
        @export(__trunctfdf2, .{ .name = "__trunckfdf2", .linkage = linkage });
        @export(__fixtfdi, .{ .name = "__fixkfdi", .linkage = linkage });
        @export(__fixtfsi, .{ .name = "__fixkfsi", .linkage = linkage });
        @export(__fixunstfsi, .{ .name = "__fixunskfsi", .linkage = linkage });
        @export(__fixunstfdi, .{ .name = "__fixunskfdi", .linkage = linkage });
        @export(__floatsitf, .{ .name = "__floatsikf", .linkage = linkage });
        @export(__floatditf, .{ .name = "__floatdikf", .linkage = linkage });
        @export(__floatunditf, .{ .name = "__floatundikf", .linkage = linkage });
        @export(__floatunsitf, .{ .name = "__floatunsikf", .linkage = linkage });

        @export(__letf2, .{ .name = "__eqkf2", .linkage = linkage });
        @export(__letf2, .{ .name = "__nekf2", .linkage = linkage });
        @export(__getf2, .{ .name = "__gekf2", .linkage = linkage });
        @export(__letf2, .{ .name = "__ltkf2", .linkage = linkage });
        @export(__letf2, .{ .name = "__lekf2", .linkage = linkage });
        @export(__getf2, .{ .name = "__gtkf2", .linkage = linkage });
        @export(__unordtf2, .{ .name = "__unordkf2", .linkage = linkage });
    }

    if (builtin.os.tag == .windows) {
        // Default stack-probe functions emitted by LLVM
        if (is_mingw) {
            const _chkstk = @import("compiler_rt/stack_probe.zig")._chkstk;
            @export(_chkstk, .{ .name = "_alloca", .linkage = strong_linkage });
            const ___chkstk_ms = @import("compiler_rt/stack_probe.zig").___chkstk_ms;
            @export(___chkstk_ms, .{ .name = "___chkstk_ms", .linkage = strong_linkage });
        } else if (!builtin.link_libc) {
            // This symbols are otherwise exported by MSVCRT.lib
            const _chkstk = @import("compiler_rt/stack_probe.zig")._chkstk;
            @export(_chkstk, .{ .name = "_chkstk", .linkage = strong_linkage });
            const __chkstk = @import("compiler_rt/stack_probe.zig").__chkstk;
            @export(__chkstk, .{ .name = "__chkstk", .linkage = strong_linkage });
        }

        switch (arch) {
            .i386 => {
                const __divti3 = @import("compiler_rt/divti3.zig").__divti3;
                @export(__divti3, .{ .name = "__divti3", .linkage = linkage });
                const __modti3 = @import("compiler_rt/modti3.zig").__modti3;
                @export(__modti3, .{ .name = "__modti3", .linkage = linkage });
                const __multi3 = @import("compiler_rt/multi3.zig").__multi3;
                @export(__multi3, .{ .name = "__multi3", .linkage = linkage });
                const __udivti3 = @import("compiler_rt/udivti3.zig").__udivti3;
                @export(__udivti3, .{ .name = "__udivti3", .linkage = linkage });
                const __udivmodti4 = @import("compiler_rt/udivmodti4.zig").__udivmodti4;
                @export(__udivmodti4, .{ .name = "__udivmodti4", .linkage = linkage });
                const __umodti3 = @import("compiler_rt/umodti3.zig").__umodti3;
                @export(__umodti3, .{ .name = "__umodti3", .linkage = linkage });
            },
            .x86_64 => {
                // The "ti" functions must use Vector(2, u64) parameter types to adhere to the ABI
                // that LLVM expects compiler-rt to have.
                const __divti3_windows_x86_64 = @import("compiler_rt/divti3.zig").__divti3_windows_x86_64;
                @export(__divti3_windows_x86_64, .{ .name = "__divti3", .linkage = linkage });
                const __modti3_windows_x86_64 = @import("compiler_rt/modti3.zig").__modti3_windows_x86_64;
                @export(__modti3_windows_x86_64, .{ .name = "__modti3", .linkage = linkage });
                const __multi3_windows_x86_64 = @import("compiler_rt/multi3.zig").__multi3_windows_x86_64;
                @export(__multi3_windows_x86_64, .{ .name = "__multi3", .linkage = linkage });
                const __udivti3_windows_x86_64 = @import("compiler_rt/udivti3.zig").__udivti3_windows_x86_64;
                @export(__udivti3_windows_x86_64, .{ .name = "__udivti3", .linkage = linkage });
                const __udivmodti4_windows_x86_64 = @import("compiler_rt/udivmodti4.zig").__udivmodti4_windows_x86_64;
                @export(__udivmodti4_windows_x86_64, .{ .name = "__udivmodti4", .linkage = linkage });
                const __umodti3_windows_x86_64 = @import("compiler_rt/umodti3.zig").__umodti3_windows_x86_64;
                @export(__umodti3_windows_x86_64, .{ .name = "__umodti3", .linkage = linkage });
            },
            else => {},
        }
    } else {
        const __divti3 = @import("compiler_rt/divti3.zig").__divti3;
        @export(__divti3, .{ .name = "__divti3", .linkage = linkage });
        const __modti3 = @import("compiler_rt/modti3.zig").__modti3;
        @export(__modti3, .{ .name = "__modti3", .linkage = linkage });
        const __multi3 = @import("compiler_rt/multi3.zig").__multi3;
        @export(__multi3, .{ .name = "__multi3", .linkage = linkage });
        const __udivti3 = @import("compiler_rt/udivti3.zig").__udivti3;
        @export(__udivti3, .{ .name = "__udivti3", .linkage = linkage });
        const __udivmodti4 = @import("compiler_rt/udivmodti4.zig").__udivmodti4;
        @export(__udivmodti4, .{ .name = "__udivmodti4", .linkage = linkage });
        const __umodti3 = @import("compiler_rt/umodti3.zig").__umodti3;
        @export(__umodti3, .{ .name = "__umodti3", .linkage = linkage });
    }
    const __muloti4 = @import("compiler_rt/muloti4.zig").__muloti4;
    @export(__muloti4, .{ .name = "__muloti4", .linkage = linkage });
    const __mulodi4 = @import("compiler_rt/mulodi4.zig").__mulodi4;
    @export(__mulodi4, .{ .name = "__mulodi4", .linkage = linkage });
}

pub usingnamespace @import("compiler_rt/atomics.zig");

// Avoid dragging in the runtime safety mechanisms into this .o file,
// unless we're trying to test this file.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace) noreturn {
    _ = error_return_trace;
    @setCold(true);
    if (is_test) {
        std.debug.panic("{s}", .{msg});
    } else {
        unreachable;
    }
}
