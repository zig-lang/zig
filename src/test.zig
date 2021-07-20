const std = @import("std");
const builtin = @import("builtin");
const link = @import("link.zig");
const Compilation = @import("Compilation.zig");
const Allocator = std.mem.Allocator;
const Package = @import("Package.zig");
const introspect = @import("introspect.zig");
const build_options = @import("build_options");
const enable_qemu: bool = build_options.enable_qemu;
const enable_wine: bool = build_options.enable_wine;
const enable_wasmtime: bool = build_options.enable_wasmtime;
const enable_darling: bool = build_options.enable_darling;
const glibc_multi_install_dir: ?[]const u8 = build_options.glibc_multi_install_dir;
const skip_compile_errors = build_options.skip_compile_errors;
const ThreadPool = @import("ThreadPool.zig");
const CrossTarget = std.zig.CrossTarget;
const print = std.debug.print;
const assert = std.debug.assert;

const zig_h = link.File.C.zig_h;

const hr = "=" ** 80;

test {
    if (build_options.is_stage1) {
        @import("stage1.zig").os_init();
    }

    var ctx = TestContext.init();
    defer ctx.deinit();

    try @import("test_cases").addCases(&ctx);

    try ctx.run();
}

const ErrorMsg = union(enum) {
    src: struct {
        src_path: []const u8,
        msg: []const u8,
        // maxint means match anything
        // this is a workaround for stage1 compiler bug I ran into when making it ?u32
        line: u32,
        // maxint means match anything
        // this is a workaround for stage1 compiler bug I ran into when making it ?u32
        column: u32,
        kind: Kind,
    },
    plain: struct {
        msg: []const u8,
        kind: Kind,
    },

    const Kind = enum {
        @"error",
        note,
    };

    fn init(other: Compilation.AllErrors.Message, kind: Kind) ErrorMsg {
        switch (other) {
            .src => |src| return .{
                .src = .{
                    .src_path = src.src_path,
                    .msg = src.msg,
                    .line = @intCast(u32, src.line),
                    .column = @intCast(u32, src.column),
                    .kind = kind,
                },
            },
            .plain => |plain| return .{
                .plain = .{
                    .msg = plain.msg,
                    .kind = kind,
                },
            },
        }
    }

    pub fn format(
        self: ErrorMsg,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .src => |src| {
                if (!std.mem.eql(u8, src.src_path, "?") or
                    src.line != std.math.maxInt(u32) or
                    src.column != std.math.maxInt(u32))
                {
                    try writer.print("{s}:", .{src.src_path});
                    if (src.line != std.math.maxInt(u32)) {
                        try writer.print("{d}:", .{src.line + 1});
                    } else {
                        try writer.writeAll("?:");
                    }
                    if (src.column != std.math.maxInt(u32)) {
                        try writer.print("{d}: ", .{src.column + 1});
                    } else {
                        try writer.writeAll("?: ");
                    }
                }
                return writer.print("{s}: {s}", .{ @tagName(src.kind), src.msg });
            },
            .plain => |plain| {
                return writer.print("{s}: {s}", .{ @tagName(plain.kind), plain.msg });
            },
        }
    }
};

pub const TestContext = struct {
    cases: std.ArrayList(Case),

    pub const Update = struct {
        /// The input to the current update. We simulate an incremental update
        /// with the file's contents changed to this value each update.
        ///
        /// This value can change entirely between updates, which would be akin
        /// to deleting the source file and creating a new one from scratch; or
        /// you can keep it mostly consistent, with small changes, testing the
        /// effects of the incremental compilation.
        src: [:0]const u8,
        case: union(enum) {
            /// Check the main binary output file against an expected set of bytes.
            /// This is most useful with, for example, `-ofmt=c`.
            CompareObjectFile: []const u8,
            /// An error update attempts to compile bad code, and ensures that it
            /// fails to compile, and for the expected reasons.
            /// A slice containing the expected errors *in sequential order*.
            Error: []const ErrorMsg,
            /// An execution update compiles and runs the input, testing the
            /// stdout against the expected results
            /// This is a slice containing the expected message.
            Execution: []const u8,
            /// A header update compiles the input with the equivalent of
            /// `-femit-h` and tests the produced header against the
            /// expected result
            Header: []const u8,
        },
    };

    pub const File = struct {
        /// Contents of the importable file. Doesn't yet support incremental updates.
        src: [:0]const u8,
        path: []const u8,
    };

    pub const Backend = enum {
        stage1,
        stage2,
        llvm,
    };

    /// A `Case` consists of a list of `Update`. The same `Compilation` is used for each
    /// update, so each update's source is treated as a single file being
    /// updated by the test harness and incrementally compiled.
    pub const Case = struct {
        /// The name of the test case. This is shown if a test fails, and
        /// otherwise ignored.
        name: []const u8,
        /// The platform the test targets. For non-native platforms, an emulator
        /// such as QEMU is required for tests to complete.
        target: CrossTarget,
        /// In order to be able to run e.g. Execution updates, this must be set
        /// to Executable.
        output_mode: std.builtin.OutputMode,
        optimize_mode: std.builtin.Mode = .Debug,
        updates: std.ArrayList(Update),
        object_format: ?std.Target.ObjectFormat = null,
        emit_h: bool = false,
        is_test: bool = false,
        expect_exact: bool = false,
        backend: Backend = .stage2,

        files: std.ArrayList(File),

        pub fn addSourceFile(case: *Case, name: []const u8, src: [:0]const u8) void {
            case.files.append(.{ .path = name, .src = src }) catch @panic("out of memory");
        }

        /// Adds a subcase in which the module is updated with `src`, and a C
        /// header is generated.
        pub fn addHeader(self: *Case, src: [:0]const u8, result: [:0]const u8) void {
            self.emit_h = true;
            self.updates.append(.{
                .src = src,
                .case = .{ .Header = result },
            }) catch @panic("out of memory");
        }

        /// Adds a subcase in which the module is updated with `src`, compiled,
        /// run, and the output is tested against `result`.
        pub fn addCompareOutput(self: *Case, src: [:0]const u8, result: []const u8) void {
            self.updates.append(.{
                .src = src,
                .case = .{ .Execution = result },
            }) catch @panic("out of memory");
        }

        /// Adds a subcase in which the module is updated with `src`, compiled,
        /// and the object file data is compared against `result`.
        pub fn addCompareObjectFile(self: *Case, src: [:0]const u8, result: []const u8) void {
            self.updates.append(.{
                .src = src,
                .case = .{ .CompareObjectFile = result },
            }) catch @panic("out of memory");
        }

        /// Adds a subcase in which the module is updated with `src`, which
        /// should contain invalid input, and ensures that compilation fails
        /// for the expected reasons, given in sequential order in `errors` in
        /// the form `:line:column: error: message`.
        pub fn addError(self: *Case, src: [:0]const u8, errors: []const []const u8) void {
            var array = self.updates.allocator.alloc(ErrorMsg, errors.len) catch @panic("out of memory");
            for (errors) |err_msg_line, i| {
                if (std.mem.startsWith(u8, err_msg_line, "error: ")) {
                    array[i] = .{
                        .plain = .{ .msg = err_msg_line["error: ".len..], .kind = .@"error" },
                    };
                    continue;
                } else if (std.mem.startsWith(u8, err_msg_line, "note: ")) {
                    array[i] = .{
                        .plain = .{ .msg = err_msg_line["note: ".len..], .kind = .note },
                    };
                    continue;
                }
                // example: "file.zig:1:2: error: bad thing happened"
                var it = std.mem.split(err_msg_line, ":");
                const src_path = it.next() orelse @panic("missing colon");
                const line_text = it.next() orelse @panic("missing line");
                const col_text = it.next() orelse @panic("missing column");
                const kind_text = it.next() orelse @panic("missing 'error'/'note'");
                const msg = it.rest()[1..]; // skip over the space at end of "error: "

                const line: ?u32 = if (std.mem.eql(u8, line_text, "?"))
                    null
                else
                    std.fmt.parseInt(u32, line_text, 10) catch @panic("bad line number");
                const column: ?u32 = if (std.mem.eql(u8, line_text, "?"))
                    null
                else
                    std.fmt.parseInt(u32, col_text, 10) catch @panic("bad column number");
                const kind: ErrorMsg.Kind = if (std.mem.eql(u8, kind_text, " error"))
                    .@"error"
                else if (std.mem.eql(u8, kind_text, " note"))
                    .note
                else
                    @panic("expected 'error'/'note'");

                const line_0based: u32 = if (line) |n| blk: {
                    if (n == 0) {
                        print("{s}: line must be specified starting at one\n", .{self.name});
                        return;
                    }
                    break :blk n - 1;
                } else std.math.maxInt(u32);

                const column_0based: u32 = if (column) |n| blk: {
                    if (n == 0) {
                        print("{s}: line must be specified starting at one\n", .{self.name});
                        return;
                    }
                    break :blk n - 1;
                } else std.math.maxInt(u32);

                array[i] = .{
                    .src = .{
                        .src_path = src_path,
                        .msg = msg,
                        .line = line_0based,
                        .column = column_0based,
                        .kind = kind,
                    },
                };
            }
            self.updates.append(.{ .src = src, .case = .{ .Error = array } }) catch @panic("out of memory");
        }

        /// Adds a subcase in which the module is updated with `src`, and
        /// asserts that it compiles without issue
        pub fn compiles(self: *Case, src: [:0]const u8) void {
            self.addError(src, &[_][]const u8{});
        }
    };

    pub fn addExe(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
    ) *Case {
        ctx.cases.append(Case{
            .name = name,
            .target = target,
            .updates = std.ArrayList(Update).init(ctx.cases.allocator),
            .output_mode = .Exe,
            .files = std.ArrayList(File).init(ctx.cases.allocator),
        }) catch @panic("out of memory");
        return &ctx.cases.items[ctx.cases.items.len - 1];
    }

    /// Adds a test case for Zig input, producing an executable
    pub fn exe(ctx: *TestContext, name: []const u8, target: CrossTarget) *Case {
        return ctx.addExe(name, target);
    }

    pub fn exeFromCompiledC(ctx: *TestContext, name: []const u8, target: CrossTarget) *Case {
        const prefixed_name = std.fmt.allocPrint(ctx.cases.allocator, "CBE: {s}", .{name}) catch
            @panic("out of memory");
        ctx.cases.append(Case{
            .name = prefixed_name,
            .target = target,
            .updates = std.ArrayList(Update).init(ctx.cases.allocator),
            .output_mode = .Exe,
            .object_format = .c,
            .files = std.ArrayList(File).init(ctx.cases.allocator),
        }) catch @panic("out of memory");
        return &ctx.cases.items[ctx.cases.items.len - 1];
    }

    /// Adds a test case that uses the LLVM backend to emit an executable.
    /// Currently this implies linking libc, because only then we can generate a testable executable.
    pub fn exeUsingLlvmBackend(ctx: *TestContext, name: []const u8, target: CrossTarget) *Case {
        ctx.cases.append(Case{
            .name = name,
            .target = target,
            .updates = std.ArrayList(Update).init(ctx.cases.allocator),
            .output_mode = .Exe,
            .files = std.ArrayList(File).init(ctx.cases.allocator),
            .backend = .llvm,
        }) catch @panic("out of memory");
        return &ctx.cases.items[ctx.cases.items.len - 1];
    }

    pub fn addObj(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
    ) *Case {
        ctx.cases.append(Case{
            .name = name,
            .target = target,
            .updates = std.ArrayList(Update).init(ctx.cases.allocator),
            .output_mode = .Obj,
            .files = std.ArrayList(File).init(ctx.cases.allocator),
        }) catch @panic("out of memory");
        return &ctx.cases.items[ctx.cases.items.len - 1];
    }

    pub fn addTest(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
    ) *Case {
        ctx.cases.append(Case{
            .name = name,
            .target = target,
            .updates = std.ArrayList(Update).init(ctx.cases.allocator),
            .output_mode = .Exe,
            .is_test = true,
            .files = std.ArrayList(File).init(ctx.cases.allocator),
        }) catch @panic("out of memory");
        return &ctx.cases.items[ctx.cases.items.len - 1];
    }

    /// Adds a test case for Zig input, producing an object file.
    pub fn obj(ctx: *TestContext, name: []const u8, target: CrossTarget) *Case {
        return ctx.addObj(name, target);
    }

    /// Adds a test case for ZIR input, producing an object file.
    pub fn objZIR(ctx: *TestContext, name: []const u8, target: CrossTarget) *Case {
        return ctx.addObj(name, target, .ZIR);
    }

    /// Adds a test case for Zig or ZIR input, producing C code.
    pub fn addC(ctx: *TestContext, name: []const u8, target: CrossTarget) *Case {
        ctx.cases.append(Case{
            .name = name,
            .target = target,
            .updates = std.ArrayList(Update).init(ctx.cases.allocator),
            .output_mode = .Obj,
            .object_format = .c,
            .files = std.ArrayList(File).init(ctx.cases.allocator),
        }) catch @panic("out of memory");
        return &ctx.cases.items[ctx.cases.items.len - 1];
    }

    pub fn c(ctx: *TestContext, name: []const u8, target: CrossTarget, src: [:0]const u8, comptime out: [:0]const u8) void {
        ctx.addC(name, target).addCompareObjectFile(src, zig_h ++ out);
    }

    pub fn h(ctx: *TestContext, name: []const u8, target: CrossTarget, src: [:0]const u8, comptime out: [:0]const u8) void {
        ctx.addC(name, target).addHeader(src, zig_h ++ out);
    }

    pub fn objErrStage1(
        ctx: *TestContext,
        name: []const u8,
        src: [:0]const u8,
        expected_errors: []const []const u8,
    ) void {
        if (skip_compile_errors) return;

        const case = ctx.addObj(name, .{});
        case.backend = .stage1;
        case.addError(src, expected_errors);
    }

    pub fn testErrStage1(
        ctx: *TestContext,
        name: []const u8,
        src: [:0]const u8,
        expected_errors: []const []const u8,
    ) void {
        if (skip_compile_errors) return;

        const case = ctx.addTest(name, .{});
        case.backend = .stage1;
        case.addError(src, expected_errors);
    }

    pub fn exeErrStage1(
        ctx: *TestContext,
        name: []const u8,
        src: [:0]const u8,
        expected_errors: []const []const u8,
    ) void {
        if (skip_compile_errors) return;

        const case = ctx.addExe(name, .{});
        case.backend = .stage1;
        case.addError(src, expected_errors);
    }

    pub fn addCompareOutput(
        ctx: *TestContext,
        name: []const u8,
        src: [:0]const u8,
        expected_stdout: []const u8,
    ) void {
        ctx.addExe(name, .{}).addCompareOutput(src, expected_stdout);
    }

    /// Adds a test case that compiles the Zig source given in `src`, executes
    /// it, runs it, and tests the output against `expected_stdout`
    pub fn compareOutput(
        ctx: *TestContext,
        name: []const u8,
        src: [:0]const u8,
        expected_stdout: []const u8,
    ) void {
        return ctx.addCompareOutput(name, src, expected_stdout);
    }

    /// Adds a test case that compiles the ZIR source given in `src`, executes
    /// it, runs it, and tests the output against `expected_stdout`
    pub fn compareOutputZIR(
        ctx: *TestContext,
        name: []const u8,
        src: [:0]const u8,
        expected_stdout: []const u8,
    ) void {
        ctx.addCompareOutput(name, .ZIR, src, expected_stdout);
    }

    pub fn addTransform(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
        result: [:0]const u8,
    ) void {
        ctx.addObj(name, target).addTransform(src, result);
    }

    /// Adds a test case that compiles the Zig given in `src` to ZIR and tests
    /// the ZIR against `result`
    pub fn transform(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
        result: [:0]const u8,
    ) void {
        ctx.addTransform(name, target, src, result);
    }

    pub fn addError(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
        expected_errors: []const []const u8,
    ) void {
        ctx.addObj(name, target).addError(src, expected_errors);
    }

    /// Adds a test case that ensures that the Zig given in `src` fails to
    /// compile for the expected reasons, given in sequential order in
    /// `expected_errors` in the form `:line:column: error: message`.
    pub fn compileError(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
        expected_errors: []const []const u8,
    ) void {
        ctx.addError(name, target, src, expected_errors);
    }

    /// Adds a test case that ensures that the ZIR given in `src` fails to
    /// compile for the expected reasons, given in sequential order in
    /// `expected_errors` in the form `:line:column: error: message`.
    pub fn compileErrorZIR(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
        expected_errors: []const []const u8,
    ) void {
        ctx.addError(name, target, .ZIR, src, expected_errors);
    }

    pub fn addCompiles(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
    ) void {
        ctx.addObj(name, target).compiles(src);
    }

    /// Adds a test case that asserts that the Zig given in `src` compiles
    /// without any errors.
    pub fn compiles(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
    ) void {
        ctx.addCompiles(name, target, src);
    }

    /// Adds a test case that asserts that the ZIR given in `src` compiles
    /// without any errors.
    pub fn compilesZIR(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
    ) void {
        ctx.addCompiles(name, target, .ZIR, src);
    }

    /// Adds a test case that first ensures that the Zig given in `src` fails
    /// to compile for the reasons given in sequential order in
    /// `expected_errors` in the form `:line:column: error: message`, then
    /// asserts that fixing the source (updating with `fixed_src`) isn't broken
    /// by incremental compilation.
    pub fn incrementalFailure(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
        expected_errors: []const []const u8,
        fixed_src: [:0]const u8,
    ) void {
        var case = ctx.addObj(name, target);
        case.addError(src, expected_errors);
        case.compiles(fixed_src);
    }

    /// Adds a test case that first ensures that the ZIR given in `src` fails
    /// to compile for the reasons given in sequential order in
    /// `expected_errors` in the form `:line:column: error: message`, then
    /// asserts that fixing the source (updating with `fixed_src`) isn't broken
    /// by incremental compilation.
    pub fn incrementalFailureZIR(
        ctx: *TestContext,
        name: []const u8,
        target: CrossTarget,
        src: [:0]const u8,
        expected_errors: []const []const u8,
        fixed_src: [:0]const u8,
    ) void {
        var case = ctx.addObj(name, target, .ZIR);
        case.addError(src, expected_errors);
        case.compiles(fixed_src);
    }

    fn init() TestContext {
        const allocator = std.heap.page_allocator;
        return .{ .cases = std.ArrayList(Case).init(allocator) };
    }

    fn deinit(self: *TestContext) void {
        for (self.cases.items) |case| {
            for (case.updates.items) |u| {
                if (u.case == .Error) {
                    case.updates.allocator.free(u.case.Error);
                }
            }
            case.updates.deinit();
        }
        self.cases.deinit();
        self.* = undefined;
    }

    fn run(self: *TestContext) !void {
        var progress = std.Progress{};
        const root_node = try progress.start("tests", self.cases.items.len);
        defer root_node.end();

        var zig_lib_directory = try introspect.findZigLibDir(std.testing.allocator);
        defer zig_lib_directory.handle.close();
        defer std.testing.allocator.free(zig_lib_directory.path.?);

        var thread_pool: ThreadPool = undefined;
        try thread_pool.init(std.testing.allocator);
        defer thread_pool.deinit();

        // Use the same global cache dir for all the tests, such that we for example don't have to
        // rebuild musl libc for every case (when LLVM backend is enabled).
        var global_tmp = std.testing.tmpDir(.{});
        defer global_tmp.cleanup();

        var cache_dir = try global_tmp.dir.makeOpenPath("zig-cache", .{});
        defer cache_dir.close();
        const tmp_dir_path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ ".", "zig-cache", "tmp", &global_tmp.sub_path });
        defer std.testing.allocator.free(tmp_dir_path);

        const global_cache_directory: Compilation.Directory = .{
            .handle = cache_dir,
            .path = try std.fs.path.join(std.testing.allocator, &[_][]const u8{ tmp_dir_path, "zig-cache" }),
        };
        defer std.testing.allocator.free(global_cache_directory.path.?);

        var fail_count: usize = 0;

        for (self.cases.items) |case| {
            if (build_options.skip_non_native and case.target.getCpuArch() != builtin.cpu.arch)
                continue;

            // Skip tests that require LLVM backend when it is not available
            if (!build_options.have_llvm and case.backend == .llvm)
                continue;

            var prg_node = root_node.start(case.name, case.updates.items.len);
            prg_node.activate();
            defer prg_node.end();

            // So that we can see which test case failed when the leak checker goes off,
            // or there's an internal error
            progress.initial_delay_ns = 0;
            progress.refresh_rate_ns = 0;

            runOneCase(
                std.testing.allocator,
                &prg_node,
                case,
                zig_lib_directory,
                &thread_pool,
                global_cache_directory,
            ) catch |err| {
                fail_count += 1;
                print("test '{s}' failed: {s}\n\n", .{ case.name, @errorName(err) });
            };
        }
        if (fail_count != 0) {
            print("{d} tests failed\n", .{fail_count});
            return error.TestFailed;
        }
    }

    fn runOneCase(
        allocator: *Allocator,
        root_node: *std.Progress.Node,
        case: Case,
        zig_lib_directory: Compilation.Directory,
        thread_pool: *ThreadPool,
        global_cache_directory: Compilation.Directory,
    ) !void {
        const target_info = try std.zig.system.NativeTargetInfo.detect(allocator, case.target);
        const target = target_info.target;

        var arena_allocator = std.heap.ArenaAllocator.init(allocator);
        defer arena_allocator.deinit();
        const arena = &arena_allocator.allocator;

        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        var cache_dir = try tmp.dir.makeOpenPath("zig-cache", .{});
        defer cache_dir.close();

        const tmp_dir_path = try std.fs.path.join(
            arena,
            &[_][]const u8{ ".", "zig-cache", "tmp", &tmp.sub_path },
        );
        const tmp_dir_path_plus_slash = try std.fmt.allocPrint(
            arena,
            "{s}" ++ std.fs.path.sep_str,
            .{tmp_dir_path},
        );
        const local_cache_path = try std.fs.path.join(
            arena,
            &[_][]const u8{ tmp_dir_path, "zig-cache" },
        );

        for (case.files.items) |file| {
            try tmp.dir.writeFile(file.path, file.src);
        }

        if (case.backend == .stage1) {
            // stage1 backend has limitations:
            // * leaks memory
            // * calls exit() when a compile error happens
            // * cannot handle updates
            // because of this we must spawn a child process rather than
            // using Compilation directly.
            assert(case.updates.items.len == 1);
            const update = case.updates.items[0];
            try tmp.dir.writeFile(tmp_src_path, update.src);

            var zig_args = std.ArrayList([]const u8).init(arena);
            try zig_args.append(std.testing.zig_exe_path);

            if (case.is_test) {
                try zig_args.append("test");
            } else switch (case.output_mode) {
                .Obj => try zig_args.append("build-obj"),
                .Exe => try zig_args.append("build-exe"),
                .Lib => try zig_args.append("build-lib"),
            }

            try zig_args.append(try std.fs.path.join(arena, &.{ tmp_dir_path, tmp_src_path }));

            try zig_args.append("--name");
            try zig_args.append("test");

            try zig_args.append("--cache-dir");
            try zig_args.append(local_cache_path);

            try zig_args.append("--global-cache-dir");
            try zig_args.append(global_cache_directory.path orelse ".");

            if (!case.target.isNative()) {
                try zig_args.append("-target");
                try zig_args.append(try target.zigTriple(arena));
            }

            try zig_args.append("-O");
            try zig_args.append(@tagName(case.optimize_mode));

            const result = try std.ChildProcess.exec(.{
                .allocator = arena,
                .argv = zig_args.items,
            });
            switch (update.case) {
                .Error => |case_error_list| {
                    switch (result.term) {
                        .Exited => |code| {
                            if (code == 0) {
                                dumpArgs(zig_args.items);
                                return error.CompilationIncorrectlySucceeded;
                            }
                        },
                        else => {
                            dumpArgs(zig_args.items);
                            return error.CompilationCrashed;
                        },
                    }
                    var ok = true;
                    if (case.expect_exact) {
                        var err_iter = std.mem.split(result.stderr, "\n");
                        var i: usize = 0;
                        ok = while (err_iter.next()) |line| : (i += 1) {
                            if (i >= case_error_list.len) break false;
                            const expected = try std.mem.replaceOwned(
                                u8,
                                arena,
                                try std.fmt.allocPrint(arena, "{s}", .{case_error_list[i]}),
                                "${DIR}",
                                tmp_dir_path_plus_slash,
                            );

                            if (std.mem.indexOf(u8, line, expected) == null) break false;
                            continue;
                        } else true;

                        ok = ok and i == case_error_list.len;

                        if (!ok) {
                            print("\n======== Expected these compile errors: ========\n", .{});
                            for (case_error_list) |msg| {
                                const expected = try std.fmt.allocPrint(arena, "{s}", .{msg});
                                print("{s}\n", .{expected});
                            }
                        }
                    } else {
                        for (case_error_list) |msg| {
                            const expected = try std.mem.replaceOwned(
                                u8,
                                arena,
                                try std.fmt.allocPrint(arena, "{s}", .{msg}),
                                "${DIR}",
                                tmp_dir_path_plus_slash,
                            );
                            if (std.mem.indexOf(u8, result.stderr, expected) == null) {
                                print(
                                    \\
                                    \\=========== Expected compile error: ============
                                    \\{s}
                                    \\
                                , .{expected});
                                ok = false;
                                break;
                            }
                        }
                    }

                    if (!ok) {
                        print(
                            \\================= Full output: =================
                            \\{s}
                            \\================================================
                            \\
                        , .{result.stderr});
                        return error.TestFailed;
                    }
                },
                .CompareObjectFile => @panic("TODO implement in the test harness"),
                .Execution => @panic("TODO implement in the test harness"),
                .Header => @panic("TODO implement in the test harness"),
            }
            return;
        }

        const zig_cache_directory: Compilation.Directory = .{
            .handle = cache_dir,
            .path = local_cache_path,
        };

        var root_pkg: Package = .{
            .root_src_directory = .{ .path = tmp_dir_path, .handle = tmp.dir },
            .root_src_path = tmp_src_path,
        };
        defer root_pkg.table.deinit(allocator);

        const bin_name = try std.zig.binNameAlloc(arena, .{
            .root_name = "test_case",
            .target = target,
            .output_mode = case.output_mode,
            .object_format = case.object_format,
        });

        const emit_directory: Compilation.Directory = .{
            .path = tmp_dir_path,
            .handle = tmp.dir,
        };
        const emit_bin: Compilation.EmitLoc = .{
            .directory = emit_directory,
            .basename = bin_name,
        };
        const emit_h: ?Compilation.EmitLoc = if (case.emit_h) .{
            .directory = emit_directory,
            .basename = "test_case.h",
        } else null;
        const use_llvm: ?bool = switch (case.backend) {
            .llvm => true,
            else => null,
        };
        const use_stage1: ?bool = switch (case.backend) {
            .stage1 => true,
            else => null,
        };
        const comp = try Compilation.create(allocator, .{
            .local_cache_directory = zig_cache_directory,
            .global_cache_directory = global_cache_directory,
            .zig_lib_directory = zig_lib_directory,
            .thread_pool = thread_pool,
            .root_name = "test_case",
            .target = target,
            // TODO: support tests for object file building, and library builds
            // and linking. This will require a rework to support multi-file
            // tests.
            .output_mode = case.output_mode,
            .is_test = case.is_test,
            .optimize_mode = case.optimize_mode,
            .emit_bin = emit_bin,
            .emit_h = emit_h,
            .root_pkg = &root_pkg,
            .keep_source_files_loaded = true,
            .object_format = case.object_format,
            .is_native_os = case.target.isNativeOs(),
            .is_native_abi = case.target.isNativeAbi(),
            .dynamic_linker = target_info.dynamic_linker.get(),
            .link_libc = case.backend == .llvm,
            .use_llvm = use_llvm,
            .use_stage1 = use_stage1,
            .self_exe_path = std.testing.zig_exe_path,
        });
        defer comp.destroy();

        for (case.updates.items) |update, update_index| {
            var update_node = root_node.start("update", 3);
            update_node.activate();
            defer update_node.end();

            var sync_node = update_node.start("write", 0);
            sync_node.activate();
            try tmp.dir.writeFile(tmp_src_path, update.src);
            sync_node.end();

            var module_node = update_node.start("parse/analysis/codegen", 0);
            module_node.activate();
            try comp.makeBinFileWritable();
            try comp.update();
            module_node.end();

            if (update.case != .Error) {
                var all_errors = try comp.getAllErrorsAlloc();
                defer all_errors.deinit(allocator);
                if (all_errors.list.len != 0) {
                    print(
                        "\nCase '{s}': unexpected errors at update_index={d}:\n{s}\n",
                        .{ case.name, update_index, hr },
                    );
                    for (all_errors.list) |err_msg| {
                        switch (err_msg) {
                            .src => |src| {
                                print("{s}:{d}:{d}: error: {s}\n{s}\n", .{
                                    src.src_path, src.line + 1, src.column + 1, src.msg, hr,
                                });
                            },
                            .plain => |plain| {
                                print("error: {s}\n{s}\n", .{ plain.msg, hr });
                            },
                        }
                    }
                    // TODO print generated C code
                    return error.UnexpectedCompileErrors;
                }
            }

            switch (update.case) {
                .Header => |expected_output| {
                    var file = try tmp.dir.openFile("test_case.h", .{ .read = true });
                    defer file.close();
                    const out = try file.reader().readAllAlloc(arena, 5 * 1024 * 1024);

                    try std.testing.expectEqualStrings(expected_output, out);
                },
                .CompareObjectFile => |expected_output| {
                    var file = try tmp.dir.openFile(bin_name, .{ .read = true });
                    defer file.close();
                    const out = try file.reader().readAllAlloc(arena, 5 * 1024 * 1024);

                    try std.testing.expectEqualStrings(expected_output, out);
                },
                .Error => |case_error_list| {
                    var test_node = update_node.start("assert", 0);
                    test_node.activate();
                    defer test_node.end();

                    const handled_errors = try arena.alloc(bool, case_error_list.len);
                    std.mem.set(bool, handled_errors, false);

                    var actual_errors = try comp.getAllErrorsAlloc();
                    defer actual_errors.deinit(allocator);

                    var any_failed = false;
                    var notes_to_check = std.ArrayList(*const Compilation.AllErrors.Message).init(allocator);
                    defer notes_to_check.deinit();

                    for (actual_errors.list) |actual_error| {
                        for (case_error_list) |case_msg, i| {
                            const ex_tag: std.meta.Tag(@TypeOf(case_msg)) = case_msg;
                            switch (actual_error) {
                                .src => |actual_msg| {
                                    for (actual_msg.notes) |*note| {
                                        try notes_to_check.append(note);
                                    }

                                    if (ex_tag != .src) continue;

                                    const src_path_ok = case_msg.src.src_path.len == 0 or
                                        std.mem.eql(u8, case_msg.src.src_path, actual_msg.src_path);

                                    const expected_msg = try std.mem.replaceOwned(
                                        u8,
                                        arena,
                                        case_msg.src.msg,
                                        "${DIR}",
                                        tmp_dir_path_plus_slash,
                                    );

                                    if (src_path_ok and
                                        (case_msg.src.line == std.math.maxInt(u32) or
                                        actual_msg.line == case_msg.src.line) and
                                        (case_msg.src.column == std.math.maxInt(u32) or
                                        actual_msg.column == case_msg.src.column) and
                                        std.mem.eql(u8, expected_msg, actual_msg.msg) and
                                        case_msg.src.kind == .@"error")
                                    {
                                        handled_errors[i] = true;
                                        break;
                                    }
                                },
                                .plain => |plain| {
                                    if (ex_tag != .plain) continue;

                                    if (std.mem.eql(u8, case_msg.plain.msg, plain.msg) and
                                        case_msg.plain.kind == .@"error")
                                    {
                                        handled_errors[i] = true;
                                        break;
                                    }
                                },
                            }
                        } else {
                            print(
                                "\nUnexpected error:\n{s}\n{}\n{s}",
                                .{ hr, ErrorMsg.init(actual_error, .@"error"), hr },
                            );
                            any_failed = true;
                        }
                    }
                    while (notes_to_check.popOrNull()) |note| {
                        for (case_error_list) |case_msg, i| {
                            const ex_tag: std.meta.Tag(@TypeOf(case_msg)) = case_msg;
                            switch (note.*) {
                                .src => |actual_msg| {
                                    for (actual_msg.notes) |*sub_note| {
                                        try notes_to_check.append(sub_note);
                                    }
                                    if (ex_tag != .src) continue;

                                    const expected_msg = try std.mem.replaceOwned(
                                        u8,
                                        arena,
                                        case_msg.src.msg,
                                        "${DIR}",
                                        tmp_dir_path_plus_slash,
                                    );

                                    if ((case_msg.src.line == std.math.maxInt(u32) or
                                        actual_msg.line == case_msg.src.line) and
                                        (case_msg.src.column == std.math.maxInt(u32) or
                                        actual_msg.column == case_msg.src.column) and
                                        std.mem.eql(u8, expected_msg, actual_msg.msg) and
                                        case_msg.src.kind == .note)
                                    {
                                        handled_errors[i] = true;
                                        break;
                                    }
                                },
                                .plain => |plain| {
                                    if (ex_tag != .plain) continue;

                                    if (std.mem.eql(u8, case_msg.plain.msg, plain.msg) and
                                        case_msg.plain.kind == .note)
                                    {
                                        handled_errors[i] = true;
                                        break;
                                    }
                                },
                            }
                        } else {
                            print(
                                "\nUnexpected note:\n{s}\n{}\n{s}",
                                .{ hr, ErrorMsg.init(note.*, .note), hr },
                            );
                            any_failed = true;
                        }
                    }

                    for (handled_errors) |handled, i| {
                        if (!handled) {
                            print(
                                "\nExpected error not found:\n{s}\n{}\n{s}",
                                .{ hr, case_error_list[i], hr },
                            );
                            any_failed = true;
                        }
                    }

                    if (any_failed) {
                        print("\nupdate_index={d} ", .{update_index});
                        return error.WrongCompileErrors;
                    }
                },
                .Execution => |expected_stdout| {
                    update_node.setEstimatedTotalItems(4);

                    var argv = std.ArrayList([]const u8).init(allocator);
                    defer argv.deinit();

                    var exec_result = x: {
                        var exec_node = update_node.start("execute", 0);
                        exec_node.activate();
                        defer exec_node.end();

                        // We use relative to cwd here because we pass a new cwd to the
                        // child process.
                        const exe_path = try std.fmt.allocPrint(arena, "." ++ std.fs.path.sep_str ++ "{s}", .{bin_name});
                        if (case.object_format != null and case.object_format.? == .c) {
                            if (case.target.getExternalExecutor() != .native) {
                                // We wouldn't be able to run the compiled C code.
                                return; // Pass test.
                            }
                            try argv.appendSlice(&[_][]const u8{
                                std.testing.zig_exe_path,
                                "run",
                                "-cflags",
                                "-std=c99",
                                "-pedantic",
                                "-Werror",
                                "-Wno-incompatible-library-redeclaration", // https://github.com/ziglang/zig/issues/875
                                "--",
                                "-lc",
                                exe_path,
                            });
                        } else switch (case.target.getExternalExecutor()) {
                            .native => try argv.append(exe_path),
                            .unavailable => return, // Pass test.

                            .qemu => |qemu_bin_name| if (enable_qemu) {
                                // TODO Ability for test cases to specify whether to link libc.
                                const need_cross_glibc = false; // target.isGnuLibC() and self.is_linking_libc;
                                const glibc_dir_arg = if (need_cross_glibc)
                                    glibc_multi_install_dir orelse return // glibc dir not available; pass test
                                else
                                    null;
                                try argv.append(qemu_bin_name);
                                if (glibc_dir_arg) |dir| {
                                    const linux_triple = try target.linuxTriple(arena);
                                    const full_dir = try std.fs.path.join(arena, &[_][]const u8{
                                        dir,
                                        linux_triple,
                                    });

                                    try argv.append("-L");
                                    try argv.append(full_dir);
                                }
                                try argv.append(exe_path);
                            } else {
                                return; // QEMU not available; pass test.
                            },

                            .wine => |wine_bin_name| if (enable_wine) {
                                try argv.append(wine_bin_name);
                                try argv.append(exe_path);
                            } else {
                                return; // Wine not available; pass test.
                            },

                            .wasmtime => |wasmtime_bin_name| if (enable_wasmtime) {
                                try argv.append(wasmtime_bin_name);
                                try argv.append("--dir=.");
                                try argv.append(exe_path);
                            } else {
                                return; // wasmtime not available; pass test.
                            },

                            .darling => |darling_bin_name| if (enable_darling) {
                                try argv.append(darling_bin_name);
                                // Since we use relative to cwd here, we invoke darling with
                                // "shell" subcommand.
                                try argv.append("shell");
                                try argv.append(exe_path);
                            } else {
                                return; // Darling not available; pass test.
                            },
                        }

                        try comp.makeBinFileExecutable();

                        break :x std.ChildProcess.exec(.{
                            .allocator = allocator,
                            .argv = argv.items,
                            .cwd_dir = tmp.dir,
                            .cwd = tmp_dir_path,
                        }) catch |err| {
                            print("\nupdate_index={d} The following command failed with {s}:\n", .{
                                update_index, @errorName(err),
                            });
                            dumpArgs(argv.items);
                            return error.ChildProcessExecution;
                        };
                    };
                    var test_node = update_node.start("test", 0);
                    test_node.activate();
                    defer test_node.end();
                    defer allocator.free(exec_result.stdout);
                    defer allocator.free(exec_result.stderr);
                    switch (exec_result.term) {
                        .Exited => |code| {
                            if (code != 0) {
                                print("\n{s}\n{s}: execution exited with code {d}:\n", .{
                                    exec_result.stderr, case.name, code,
                                });
                                dumpArgs(argv.items);
                                return error.ChildProcessExecution;
                            }
                        },
                        else => {
                            print("\n{s}\n{s}: execution crashed:\n", .{
                                exec_result.stderr, case.name,
                            });
                            dumpArgs(argv.items);
                            return error.ChildProcessExecution;
                        },
                    }
                    try std.testing.expectEqualStrings(expected_stdout, exec_result.stdout);
                    // We allow stderr to have garbage in it because wasmtime prints a
                    // warning about --invoke even though we don't pass it.
                    //std.testing.expectEqualStrings("", exec_result.stderr);
                },
            }
        }
    }
};

fn dumpArgs(argv: []const []const u8) void {
    for (argv) |arg| {
        print("{s} ", .{arg});
    }
    print("\n", .{});
}

const tmp_src_path = "tmp.zig";
