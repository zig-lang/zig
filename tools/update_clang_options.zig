//! To get started, run this tool with no args and read the help message.
//!
//! Clang has a file "options.td" which describes all of its command line parameter options.
//! When using `zig cc`, Zig acts as a proxy between the user and Clang. It does not need
//! to understand all the parameters, but it does need to understand some of them, such as
//! the target. This means that Zig must understand when a C command line parameter expects
//! to "consume" the next parameter on the command line.
//!
//! For example, `-z -target` would mean to pass `-target` to the linker, whereas `-E -target`
//! would mean that the next parameter specifies the target.

const std = @import("std");
const fs = std.fs;
const assert = std.debug.assert;
const json = std.json;

const KnownOpt = struct {
    name: []const u8,

    /// Corresponds to stage.zig ClangArgIterator.Kind
    ident: []const u8,
};

const known_options = [_]KnownOpt{
    .{
        .name = "target",
        .ident = "target",
    },
    .{
        .name = "o",
        .ident = "o",
    },
    .{
        .name = "c",
        .ident = "c",
    },
    .{
        .name = "l",
        .ident = "l",
    },
    .{
        .name = "pipe",
        .ident = "ignore",
    },
    .{
        .name = "help",
        .ident = "driver_punt",
    },
    .{
        .name = "fPIC",
        .ident = "pic",
    },
    .{
        .name = "fpic",
        .ident = "pic",
    },
    .{
        .name = "fno-PIC",
        .ident = "no_pic",
    },
    .{
        .name = "fno-pic",
        .ident = "no_pic",
    },
    .{
        .name = "fPIE",
        .ident = "pie",
    },
    .{
        .name = "fpie",
        .ident = "pie",
    },
    .{
        .name = "pie",
        .ident = "pie",
    },
    .{
        .name = "fno-PIE",
        .ident = "no_pie",
    },
    .{
        .name = "fno-pie",
        .ident = "no_pie",
    },
    .{
        .name = "no-pie",
        .ident = "no_pie",
    },
    .{
        .name = "nopie",
        .ident = "no_pie",
    },
    .{
        .name = "flto",
        .ident = "lto",
    },
    .{
        .name = "fno-lto",
        .ident = "no_lto",
    },
    .{
        .name = "funwind-tables",
        .ident = "unwind_tables",
    },
    .{
        .name = "fno-unwind-tables",
        .ident = "no_unwind_tables",
    },
    .{
        .name = "nolibc",
        .ident = "nostdlib",
    },
    .{
        .name = "nostdlib",
        .ident = "nostdlib",
    },
    .{
        .name = "no-standard-libraries",
        .ident = "nostdlib",
    },
    .{
        .name = "nostdlib++",
        .ident = "nostdlib_cpp",
    },
    .{
        .name = "nostdinc++",
        .ident = "nostdlib_cpp",
    },
    .{
        .name = "nostdlibinc",
        .ident = "nostdlibinc",
    },
    .{
        .name = "nostdinc",
        .ident = "nostdlibinc",
    },
    .{
        .name = "no-standard-includes",
        .ident = "nostdlibinc",
    },
    .{
        .name = "shared",
        .ident = "shared",
    },
    .{
        .name = "rdynamic",
        .ident = "rdynamic",
    },
    .{
        .name = "Wl,",
        .ident = "wl",
    },
    .{
        .name = "Xlinker",
        .ident = "for_linker",
    },
    .{
        .name = "for-linker",
        .ident = "for_linker",
    },
    .{
        .name = "for-linker=",
        .ident = "for_linker",
    },
    .{
        .name = "z",
        .ident = "linker_input_z",
    },
    .{
        .name = "E",
        .ident = "preprocess_only",
    },
    .{
        .name = "preprocess",
        .ident = "preprocess_only",
    },
    .{
        .name = "S",
        .ident = "asm_only",
    },
    .{
        .name = "assemble",
        .ident = "asm_only",
    },
    .{
        .name = "O0",
        .ident = "optimize",
    },
    .{
        .name = "O1",
        .ident = "optimize",
    },
    .{
        .name = "O2",
        .ident = "optimize",
    },
    // O3 is only detected from the joined "-O" option
    .{
        .name = "O4",
        .ident = "optimize",
    },
    .{
        .name = "Og",
        .ident = "optimize",
    },
    .{
        .name = "Os",
        .ident = "optimize",
    },
    // Oz is only detected from the joined "-O" option
    .{
        .name = "O",
        .ident = "optimize",
    },
    .{
        .name = "Ofast",
        .ident = "optimize",
    },
    .{
        .name = "optimize",
        .ident = "optimize",
    },
    .{
        .name = "g1",
        .ident = "debug",
    },
    .{
        .name = "gline-tables-only",
        .ident = "debug",
    },
    .{
        .name = "g",
        .ident = "debug",
    },
    .{
        .name = "debug",
        .ident = "debug",
    },
    .{
        .name = "g-dwarf",
        .ident = "debug",
    },
    .{
        .name = "g-dwarf-2",
        .ident = "debug",
    },
    .{
        .name = "g-dwarf-3",
        .ident = "debug",
    },
    .{
        .name = "g-dwarf-4",
        .ident = "debug",
    },
    .{
        .name = "g-dwarf-5",
        .ident = "debug",
    },
    .{
        .name = "fsanitize",
        .ident = "sanitize",
    },
    .{
        .name = "T",
        .ident = "linker_script",
    },
    .{
        .name = "###",
        .ident = "dry_run",
    },
    .{
        .name = "v",
        .ident = "verbose",
    },
    .{
        .name = "L",
        .ident = "lib_dir",
    },
    .{
        .name = "library-directory",
        .ident = "lib_dir",
    },
    .{
        .name = "mcpu",
        .ident = "mcpu",
    },
    .{
        .name = "march",
        .ident = "mcpu",
    },
    .{
        .name = "mtune",
        .ident = "mcpu",
    },
    .{
        .name = "mred-zone",
        .ident = "red_zone",
    },
    .{
        .name = "mno-red-zone",
        .ident = "no_red_zone",
    },
    .{
        .name = "MD",
        .ident = "dep_file",
    },
    .{
        .name = "write-dependencies",
        .ident = "dep_file",
    },
    .{
        .name = "MV",
        .ident = "dep_file",
    },
    .{
        .name = "MF",
        .ident = "dep_file",
    },
    .{
        .name = "MT",
        .ident = "dep_file",
    },
    .{
        .name = "MG",
        .ident = "dep_file",
    },
    .{
        .name = "print-missing-file-dependencies",
        .ident = "dep_file",
    },
    .{
        .name = "MJ",
        .ident = "dep_file",
    },
    .{
        .name = "MM",
        .ident = "dep_file_mm",
    },
    .{
        .name = "user-dependencies",
        .ident = "dep_file_mm",
    },
    .{
        .name = "MMD",
        .ident = "dep_file",
    },
    .{
        .name = "write-user-dependencies",
        .ident = "dep_file",
    },
    .{
        .name = "MP",
        .ident = "dep_file",
    },
    .{
        .name = "MQ",
        .ident = "dep_file",
    },
    .{
        .name = "F",
        .ident = "framework_dir",
    },
    .{
        .name = "framework",
        .ident = "framework",
    },
    .{
        .name = "s",
        .ident = "strip",
    },
    .{
        .name = "dynamiclib",
        .ident = "shared",
    },
    .{
        .name = "mexec-model",
        .ident = "exec_model",
    },
    .{
        .name = "x",
        .ident = "force_language",
    },
    .{
        .name = "language",
        .ident = "force_language",
    },
};

const blacklisted_options = [_][]const u8{};

fn knownOption(name: []const u8) ?[]const u8 {
    const chopped_name = if (std.mem.endsWith(u8, name, "=")) name[0 .. name.len - 1] else name;
    for (known_options) |item| {
        if (std.mem.eql(u8, chopped_name, item.name)) {
            return item.ident;
        }
    }
    return null;
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = &arena.allocator;
    const args = try std.process.argsAlloc(allocator);

    if (args.len <= 1) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }
    if (std.mem.eql(u8, args[1], "--help")) {
        usageAndExit(std.io.getStdOut(), args[0], 0);
    }
    if (args.len < 3) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }

    const llvm_tblgen_exe = args[1];
    if (std.mem.startsWith(u8, llvm_tblgen_exe, "-")) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }

    const llvm_src_root = args[2];
    if (std.mem.startsWith(u8, llvm_src_root, "-")) {
        usageAndExit(std.io.getStdErr(), args[0], 1);
    }

    const child_args = [_][]const u8{
        llvm_tblgen_exe,
        "--dump-json",
        try std.fmt.allocPrint(allocator, "{s}/clang/include/clang/Driver/Options.td", .{llvm_src_root}),
        try std.fmt.allocPrint(allocator, "-I={s}/llvm/include", .{llvm_src_root}),
        try std.fmt.allocPrint(allocator, "-I={s}/clang/include/clang/Driver", .{llvm_src_root}),
    };

    const child_result = try std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = &child_args,
        .max_output_bytes = 100 * 1024 * 1024,
    });

    std.debug.warn("{s}\n", .{child_result.stderr});

    const json_text = switch (child_result.term) {
        .Exited => |code| if (code == 0) child_result.stdout else {
            std.debug.warn("llvm-tblgen exited with code {d}\n", .{code});
            std.process.exit(1);
        },
        else => {
            std.debug.warn("llvm-tblgen crashed\n", .{});
            std.process.exit(1);
        },
    };

    var parser = json.Parser.init(allocator, false);
    const tree = try parser.parse(json_text);
    const root_map = &tree.root.Object;

    var all_objects = std.ArrayList(*json.ObjectMap).init(allocator);
    {
        var it = root_map.iterator();
        it_map: while (it.next()) |kv| {
            if (kv.key_ptr.len == 0) continue;
            if (kv.key_ptr.*[0] == '!') continue;
            if (kv.value_ptr.* != .Object) continue;
            if (!kv.value_ptr.Object.contains("NumArgs")) continue;
            if (!kv.value_ptr.Object.contains("Name")) continue;
            for (blacklisted_options) |blacklisted_key| {
                if (std.mem.eql(u8, blacklisted_key, kv.key_ptr.*)) continue :it_map;
            }
            if (kv.value_ptr.Object.get("Name").?.String.len == 0) continue;
            try all_objects.append(&kv.value_ptr.Object);
        }
    }
    // Some options have multiple matches. As an example, "-Wl,foo" matches both
    // "W" and "Wl,". So we sort this list in order of descending priority.
    std.sort.sort(*json.ObjectMap, all_objects.items, {}, objectLessThan);

    var buffered_stdout = std.io.bufferedWriter(std.io.getStdOut().writer());
    const stdout = buffered_stdout.writer();
    try stdout.writeAll(
        \\// This file is generated by tools/update_clang_options.zig.
        \\// zig fmt: off
        \\usingnamespace @import("clang_options.zig");
        \\pub const data = blk: { @setEvalBranchQuota(6000); break :blk &[_]CliArg{
        \\
    );

    for (all_objects.items) |obj| {
        const name = obj.get("Name").?.String;
        var pd1 = false;
        var pd2 = false;
        var pslash = false;
        for (obj.get("Prefixes").?.Array.items) |prefix_json| {
            const prefix = prefix_json.String;
            if (std.mem.eql(u8, prefix, "-")) {
                pd1 = true;
            } else if (std.mem.eql(u8, prefix, "--")) {
                pd2 = true;
            } else if (std.mem.eql(u8, prefix, "/")) {
                pslash = true;
            } else {
                std.debug.warn("{s} has unrecognized prefix '{s}'\n", .{ name, prefix });
                std.process.exit(1);
            }
        }
        const syntax = objSyntax(obj);

        if (std.mem.eql(u8, name, "MT") and syntax == .flag) {
            // `-MT foo` is ambiguous because there is also an -MT flag
            // The canonical way to specify the flag is with `/MT` and so we make this
            // the only way.
            try stdout.print("flagpsl(\"{s}\"),\n", .{name});
        } else if (knownOption(name)) |ident| {

            // Workaround the fact that in 'Options.td'  -Ofast is listed as 'joined'
            const final_syntax = if (std.mem.eql(u8, name, "Ofast")) .flag else syntax;

            try stdout.print(
                \\.{{
                \\    .name = "{s}",
                \\    .syntax = {s},
                \\    .zig_equivalent = .{s},
                \\    .pd1 = {s},
                \\    .pd2 = {s},
                \\    .psl = {s},
                \\}},
                \\
            , .{ name, final_syntax, ident, pd1, pd2, pslash });
        } else if (pd1 and !pd2 and !pslash and syntax == .flag) {
            try stdout.print("flagpd1(\"{s}\"),\n", .{name});
        } else if (!pd1 and !pd2 and pslash and syntax == .flag) {
            try stdout.print("flagpsl(\"{s}\"),\n", .{name});
        } else if (pd1 and !pd2 and !pslash and syntax == .joined) {
            try stdout.print("joinpd1(\"{s}\"),\n", .{name});
        } else if (pd1 and !pd2 and !pslash and syntax == .joined_or_separate) {
            try stdout.print("jspd1(\"{s}\"),\n", .{name});
        } else if (pd1 and !pd2 and !pslash and syntax == .separate) {
            try stdout.print("sepd1(\"{s}\"),\n", .{name});
        } else {
            try stdout.print(
                \\.{{
                \\    .name = "{s}",
                \\    .syntax = {s},
                \\    .zig_equivalent = .other,
                \\    .pd1 = {s},
                \\    .pd2 = {s},
                \\    .psl = {s},
                \\}},
                \\
            , .{ name, syntax, pd1, pd2, pslash });
        }
    }

    try stdout.writeAll(
        \\};};
        \\
    );

    try buffered_stdout.flush();
}

// TODO we should be able to import clang_options.zig but currently this is problematic because it will
// import stage2.zig and that causes a bunch of stuff to get exported
const Syntax = union(enum) {
    /// A flag with no values.
    flag,

    /// An option which prefixes its (single) value.
    joined,

    /// An option which is followed by its value.
    separate,

    /// An option which is either joined to its (non-empty) value, or followed by its value.
    joined_or_separate,

    /// An option which is both joined to its (first) value, and followed by its (second) value.
    joined_and_separate,

    /// An option followed by its values, which are separated by commas.
    comma_joined,

    /// An option which consumes an optional joined argument and any other remaining arguments.
    remaining_args_joined,

    /// An option which is which takes multiple (separate) arguments.
    multi_arg: u8,

    pub fn format(
        self: Syntax,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .multi_arg => |n| return out_stream.print(".{{.{s}={}}}", .{ @tagName(self), n }),
            else => return out_stream.print(".{s}", .{@tagName(self)}),
        }
    }
};

fn objSyntax(obj: *json.ObjectMap) Syntax {
    const num_args = @intCast(u8, obj.get("NumArgs").?.Integer);
    for (obj.get("!superclasses").?.Array.items) |superclass_json| {
        const superclass = superclass_json.String;
        if (std.mem.eql(u8, superclass, "Joined")) {
            return .joined;
        } else if (std.mem.eql(u8, superclass, "CLJoined")) {
            return .joined;
        } else if (std.mem.eql(u8, superclass, "CLIgnoredJoined")) {
            return .joined;
        } else if (std.mem.eql(u8, superclass, "CLCompileJoined")) {
            return .joined;
        } else if (std.mem.eql(u8, superclass, "JoinedOrSeparate")) {
            return .joined_or_separate;
        } else if (std.mem.eql(u8, superclass, "CLJoinedOrSeparate")) {
            return .joined_or_separate;
        } else if (std.mem.eql(u8, superclass, "CLCompileJoinedOrSeparate")) {
            return .joined_or_separate;
        } else if (std.mem.eql(u8, superclass, "Flag")) {
            return .flag;
        } else if (std.mem.eql(u8, superclass, "CLFlag")) {
            return .flag;
        } else if (std.mem.eql(u8, superclass, "CLIgnoredFlag")) {
            return .flag;
        } else if (std.mem.eql(u8, superclass, "Separate")) {
            return .separate;
        } else if (std.mem.eql(u8, superclass, "JoinedAndSeparate")) {
            return .joined_and_separate;
        } else if (std.mem.eql(u8, superclass, "CommaJoined")) {
            return .comma_joined;
        } else if (std.mem.eql(u8, superclass, "CLRemainingArgsJoined")) {
            return .remaining_args_joined;
        } else if (std.mem.eql(u8, superclass, "MultiArg")) {
            return .{ .multi_arg = num_args };
        }
    }
    const name = obj.get("Name").?.String;
    if (std.mem.eql(u8, name, "<input>")) {
        return .flag;
    } else if (std.mem.eql(u8, name, "<unknown>")) {
        return .flag;
    }
    const kind_def = obj.get("Kind").?.Object.get("def").?.String;
    if (std.mem.eql(u8, kind_def, "KIND_FLAG")) {
        return .flag;
    }
    const key = obj.get("!name").?.String;
    std.debug.warn("{s} (key {s}) has unrecognized superclasses:\n", .{ name, key });
    for (obj.get("!superclasses").?.Array.items) |superclass_json| {
        std.debug.warn(" {s}\n", .{superclass_json.String});
    }
    std.process.exit(1);
}

fn syntaxMatchesWithEql(syntax: Syntax) bool {
    return switch (syntax) {
        .flag,
        .separate,
        .multi_arg,
        => true,

        .joined,
        .joined_or_separate,
        .joined_and_separate,
        .comma_joined,
        .remaining_args_joined,
        => false,
    };
}

fn objectLessThan(context: void, a: *json.ObjectMap, b: *json.ObjectMap) bool {
    _ = context;
    // Priority is determined by exact matches first, followed by prefix matches in descending
    // length, with key as a final tiebreaker.
    const a_syntax = objSyntax(a);
    const b_syntax = objSyntax(b);

    const a_match_with_eql = syntaxMatchesWithEql(a_syntax);
    const b_match_with_eql = syntaxMatchesWithEql(b_syntax);

    if (a_match_with_eql and !b_match_with_eql) {
        return true;
    } else if (!a_match_with_eql and b_match_with_eql) {
        return false;
    }

    if (!a_match_with_eql and !b_match_with_eql) {
        const a_name = a.get("Name").?.String;
        const b_name = b.get("Name").?.String;
        if (a_name.len != b_name.len) {
            return a_name.len > b_name.len;
        }
    }

    const a_key = a.get("!name").?.String;
    const b_key = b.get("!name").?.String;
    return std.mem.lessThan(u8, a_key, b_key);
}

fn usageAndExit(file: fs.File, arg0: []const u8, code: u8) noreturn {
    file.writer().print(
        \\Usage: {s} /path/to/llvm-tblgen /path/to/git/llvm/llvm-project
        \\Alternative Usage: zig run /path/to/git/zig/tools/update_clang_options.zig -- /path/to/llvm-tblgen /path/to/git/llvm/llvm-project
        \\
        \\Prints to stdout Zig code which you can use to replace the file src/clang_options_data.zig.
        \\
    , .{arg0}) catch std.process.exit(1);
    std.process.exit(code);
}
