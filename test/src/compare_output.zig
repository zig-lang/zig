// This is the implementation of the test harness.
// For the actual test cases, see test/compare_output.zig.
const std = @import("std");
const builtin = std.builtin;
const build = std.build;
const ArrayList = std.ArrayList;
const fmt = std.fmt;
const mem = std.mem;
const fs = std.fs;
const warn = std.debug.warn;
const Mode = std.builtin.Mode;

pub const CompareOutputContext = struct {
    b: *build.Builder,
    step: *build.Step,
    test_index: usize,
    test_filter: ?[]const u8,
    modes: []const Mode,

    const Special = enum {
        None,
        Asm,
        RuntimeSafety,
    };

    const TestCase = struct {
        name: []const u8,
        sources: ArrayList(SourceFile),
        expected_output: []const u8,
        link_libc: bool,
        special: Special,
        cli_args: []const []const u8,

        const SourceFile = struct {
            filename: []const u8,
            source: []const u8,
        };

        pub fn addSourceFile(self: *TestCase, filename: []const u8, source: []const u8) void {
            self.sources.append(SourceFile{
                .filename = filename,
                .source = source,
            }) catch unreachable;
        }

        pub fn setCommandLineArgs(self: *TestCase, args: []const []const u8) void {
            self.cli_args = args;
        }
    };

    pub fn createExtra(self: *CompareOutputContext, name: []const u8, source: []const u8, expected_output: []const u8, special: Special) TestCase {
        var tc = TestCase{
            .name = name,
            .sources = ArrayList(TestCase.SourceFile).init(self.b.allocator),
            .expected_output = expected_output,
            .link_libc = false,
            .special = special,
            .cli_args = &[_][]const u8{},
        };
        const root_src_name = if (special == Special.Asm) "source.s" else "source.zig";
        tc.addSourceFile(root_src_name, source);
        return tc;
    }

    pub fn create(self: *CompareOutputContext, name: []const u8, source: []const u8, expected_output: []const u8) TestCase {
        return createExtra(self, name, source, expected_output, Special.None);
    }

    pub fn addC(self: *CompareOutputContext, name: []const u8, source: []const u8, expected_output: []const u8) void {
        var tc = self.create(name, source, expected_output);
        tc.link_libc = true;
        self.addCase(tc);
    }

    pub fn add(self: *CompareOutputContext, name: []const u8, source: []const u8, expected_output: []const u8) void {
        const tc = self.create(name, source, expected_output);
        self.addCase(tc);
    }

    pub fn addAsm(self: *CompareOutputContext, name: []const u8, source: []const u8, expected_output: []const u8) void {
        const tc = self.createExtra(name, source, expected_output, Special.Asm);
        self.addCase(tc);
    }

    pub fn addRuntimeSafety(self: *CompareOutputContext, name: []const u8, source: []const u8) void {
        const tc = self.createExtra(name, source, undefined, Special.RuntimeSafety);
        self.addCase(tc);
    }

    pub fn addCase(self: *CompareOutputContext, case: TestCase) void {
        const b = self.b;

        const write_src = b.addWriteFiles();
        for (case.sources.items) |src_file| {
            write_src.add(src_file.filename, src_file.source);
        }

        switch (case.special) {
            Special.Asm => {
                const annotated_case_name = fmt.allocPrint(self.b.allocator, "assemble-and-link {s}", .{
                    case.name,
                }) catch unreachable;
                if (self.test_filter) |filter| {
                    if (mem.indexOf(u8, annotated_case_name, filter) == null) return;
                }

                const exe = b.addExecutable("test", null);
                exe.addAssemblyFileSource(write_src.getFileSource(case.sources.items[0].filename).?);

                const run = exe.run();
                run.addArgs(case.cli_args);
                run.expectStdErrEqual("");
                run.expectStdOutEqual(case.expected_output);

                self.step.dependOn(&run.step);
            },
            Special.None => {
                for (self.modes) |mode| {
                    const annotated_case_name = fmt.allocPrint(self.b.allocator, "{s} {s} ({s})", .{
                        "compare-output",
                        case.name,
                        @tagName(mode),
                    }) catch unreachable;
                    if (self.test_filter) |filter| {
                        if (mem.indexOf(u8, annotated_case_name, filter) == null) continue;
                    }

                    const basename = case.sources.items[0].filename;
                    const exe = b.addExecutableSource("test", write_src.getFileSource(basename).?);
                    exe.setBuildMode(mode);
                    if (case.link_libc) {
                        exe.linkSystemLibrary("c");
                    }

                    const run = exe.run();
                    run.addArgs(case.cli_args);
                    run.expectStdErrEqual("");
                    run.expectStdOutEqual(case.expected_output);

                    self.step.dependOn(&run.step);
                }
            },
            Special.RuntimeSafety => {
                const annotated_case_name = fmt.allocPrint(self.b.allocator, "safety {s}", .{case.name}) catch unreachable;
                if (self.test_filter) |filter| {
                    if (mem.indexOf(u8, annotated_case_name, filter) == null) return;
                }

                const basename = case.sources.items[0].filename;
                const exe = b.addExecutableSource("test", write_src.getFileSource(basename).?);
                if (case.link_libc) {
                    exe.linkSystemLibrary("c");
                }

                const run = exe.run();
                run.addArgs(case.cli_args);
                run.stderr_action = .ignore;
                run.stdout_action = .ignore;
                run.expected_exit_code = 126;

                self.step.dependOn(&run.step);
            },
        }
    }
};
