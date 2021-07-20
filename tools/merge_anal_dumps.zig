const builtin = @import("builtin");
const std = @import("std");
const json = std.json;
const mem = std.mem;
const fieldIndex = std.meta.fieldIndex;
const TypeId = std.builtin.TypeId;

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = &arena.allocator;

    const args = try std.process.argsAlloc(allocator);

    var parser: json.Parser = undefined;
    var dump = Dump.init(allocator);
    for (args[1..]) |arg| {
        parser = json.Parser.init(allocator, false);
        const json_text = try std.fs.cwd().readFileAlloc(allocator, arg, std.math.maxInt(usize));
        const tree = try parser.parse(json_text);
        try dump.mergeJson(tree.root);
    }

    const stdout = try std.io.getStdOut();
    try dump.render(stdout.writer());
}

/// AST source node
const Node = struct {
    file: usize,
    line: usize,
    col: usize,
    fields: []usize,

    fn hash(n: Node) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, n.file);
        std.hash.autoHash(&hasher, n.line);
        std.hash.autoHash(&hasher, n.col);
        return hasher.final();
    }

    fn eql(a: Node, b: Node) bool {
        return a.file == b.file and
            a.line == b.line and
            a.col == b.col;
    }
};

const Error = struct {
    src: usize,
    name: []const u8,

    fn hash(n: Error) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, n.src);
        return hasher.final();
    }

    fn eql(a: Error, b: Error) bool {
        return a.src == b.src;
    }
};

const simple_types = [_][]const u8{
    "Type",
    "Void",
    "Bool",
    "NoReturn",
    "ComptimeFloat",
    "ComptimeInt",
    "Undefined",
    "Null",
    "AnyFrame",
    "EnumLiteral",
};

const Type = union(builtin.TypeId) {
    Type,
    Void,
    Bool,
    NoReturn,
    ComptimeFloat,
    ComptimeInt,
    Undefined,
    Null,
    AnyFrame,
    EnumLiteral,

    Int: Int,
    Float: usize, // bits

    Vector: Array,
    Optional: usize, // payload type index
    Pointer: Pointer,
    Array: Array,

    Struct, // TODO
    ErrorUnion, // TODO
    ErrorSet, // TODO
    Enum, // TODO
    Union, // TODO
    Fn, // TODO
    BoundFn, // TODO
    Opaque, // TODO
    Frame, // TODO

    const Int = struct {
        bits: usize,
        signed: bool,
    };

    const Pointer = struct {
        elem: usize,
        alignment: usize,
        is_const: bool,
        is_volatile: bool,
        allow_zero: bool,
        host_int_bytes: usize,
        bit_offset_in_host: usize,
    };

    const Array = struct {
        elem: usize,
        len: usize,
    };

    fn hash(t: Type) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, t);
        return hasher.final();
    }

    fn eql(a: Type, b: Type) bool {
        return std.meta.eql(a, b);
    }
};

const Dump = struct {
    zig_id: ?[]const u8 = null,
    zig_version: ?[]const u8 = null,
    root_name: ?[]const u8 = null,
    targets: std.ArrayList([]const u8),

    file_list: std.ArrayList([]const u8),
    file_map: FileMap,

    node_list: std.ArrayList(Node),
    node_map: NodeMap,

    error_list: std.ArrayList(Error),
    error_map: ErrorMap,

    type_list: std.ArrayList(Type),
    type_map: TypeMap,

    const FileMap = std.StringHashMap(usize);
    const NodeMap = std.HashMap(Node, usize, Node.hash, Node.eql, 80);
    const ErrorMap = std.HashMap(Error, usize, Error.hash, Error.eql, 80);
    const TypeMap = std.HashMap(Type, usize, Type.hash, Type.eql, 80);

    fn init(allocator: *mem.Allocator) Dump {
        return Dump{
            .targets = std.ArrayList([]const u8).init(allocator),
            .file_list = std.ArrayList([]const u8).init(allocator),
            .file_map = FileMap.init(allocator),
            .node_list = std.ArrayList(Node).init(allocator),
            .node_map = NodeMap.init(allocator),
            .error_list = std.ArrayList(Error).init(allocator),
            .error_map = ErrorMap.init(allocator),
            .type_list = std.ArrayList(Type).init(allocator),
            .type_map = TypeMap.init(allocator),
        };
    }

    fn mergeJson(self: *Dump, root: json.Value) !void {
        const params = &root.Object.get("params").?.value.Object;
        const zig_id = params.get("zigId").?.value.String;
        const zig_version = params.get("zigVersion").?.value.String;
        const root_name = params.get("rootName").?.value.String;
        try mergeSameStrings(&self.zig_id, zig_id);
        try mergeSameStrings(&self.zig_version, zig_version);
        try mergeSameStrings(&self.root_name, root_name);

        for (params.get("builds").?.value.Array.items) |json_build| {
            const target = json_build.Object.get("target").?.value.String;
            try self.targets.append(target);
        }

        // Merge files. If the string matches, it's the same file.
        const other_files = root.Object.get("files").?.value.Array.items;
        var other_file_to_mine = std.AutoHashMap(usize, usize).init(self.a());
        for (other_files) |other_file, i| {
            const gop = try self.file_map.getOrPut(other_file.String);
            if (!gop.found_existing) {
                gop.kv.value = self.file_list.items.len;
                try self.file_list.append(other_file.String);
            }
            try other_file_to_mine.putNoClobber(i, gop.kv.value);
        }

        // Merge AST nodes. If the file id, line, and column all match, it's the same AST node.
        const other_ast_nodes = root.Object.get("astNodes").?.value.Array.items;
        var other_ast_node_to_mine = std.AutoHashMap(usize, usize).init(self.a());
        for (other_ast_nodes) |other_ast_node_json, i| {
            const other_file_id = jsonObjInt(other_ast_node_json, "file");
            const other_node = Node{
                .line = jsonObjInt(other_ast_node_json, "line"),
                .col = jsonObjInt(other_ast_node_json, "col"),
                .file = other_file_to_mine.getValue(other_file_id).?,
                .fields = ([*]usize)(undefined)[0..0],
            };
            const gop = try self.node_map.getOrPut(other_node);
            if (!gop.found_existing) {
                gop.kv.value = self.node_list.items.len;
                try self.node_list.append(other_node);
            }
            try other_ast_node_to_mine.putNoClobber(i, gop.kv.value);
        }
        // convert fields lists
        for (other_ast_nodes) |other_ast_node_json, i| {
            const my_node_index = other_ast_node_to_mine.get(i).?.value;
            const my_node = &self.node_list.items[my_node_index];
            if (other_ast_node_json.Object.get("fields")) |fields_json_kv| {
                const other_fields = fields_json_kv.value.Array.items;
                my_node.fields = try self.a().alloc(usize, other_fields.len);
                for (other_fields) |other_field_index, field_i| {
                    const other_index = @intCast(usize, other_field_index.Integer);
                    my_node.fields[field_i] = other_ast_node_to_mine.get(other_index).?.value;
                }
            }
        }

        // Merge errors. If the AST Node matches, it's the same error value.
        const other_errors = root.Object.get("errors").?.value.Array.items;
        var other_error_to_mine = std.AutoHashMap(usize, usize).init(self.a());
        for (other_errors) |other_error_json, i| {
            const other_src_id = jsonObjInt(other_error_json, "src");
            const other_error = Error{
                .src = other_ast_node_to_mine.getValue(other_src_id).?,
                .name = other_error_json.Object.get("name").?.value.String,
            };
            const gop = try self.error_map.getOrPut(other_error);
            if (!gop.found_existing) {
                gop.kv.value = self.error_list.items.len;
                try self.error_list.append(other_error);
            }
            try other_error_to_mine.putNoClobber(i, gop.kv.value);
        }

        // Merge types. Now it starts to get advanced.
        // First we identify all the simple types and merge those.
        // Example: void, type, noreturn
        // We can also do integers and floats.
        const other_types = root.Object.get("types").?.value.Array.items;
        var other_types_to_mine = std.AutoHashMap(usize, usize).init(self.a());
        for (other_types) |other_type_json, i| {
            const type_kind = jsonObjInt(other_type_json, "kind");
            switch (type_kind) {
                fieldIndex(TypeId, "Int").? => {
                    var signed: bool = undefined;
                    var bits: usize = undefined;
                    if (other_type_json.Object.get("i")) |kv| {
                        signed = true;
                        bits = @intCast(usize, kv.value.Integer);
                    } else if (other_type_json.Object.get("u")) |kv| {
                        signed = false;
                        bits = @intCast(usize, kv.value.Integer);
                    } else {
                        unreachable;
                    }
                    const other_type = Type{
                        .Int = Type.Int{
                            .bits = bits,
                            .signed = signed,
                        },
                    };
                    try self.mergeOtherType(other_type, i, &other_types_to_mine);
                },
                fieldIndex(TypeId, "Float").? => {
                    const other_type = Type{
                        .Float = jsonObjInt(other_type_json, "bits"),
                    };
                    try self.mergeOtherType(other_type, i, &other_types_to_mine);
                },
                else => {},
            }

            inline for (simple_types) |simple_type_name| {
                if (type_kind == std.meta.fieldIndex(builtin.TypeId, simple_type_name).?) {
                    const other_type = @unionInit(Type, simple_type_name, {});
                    try self.mergeOtherType(other_type, i, &other_types_to_mine);
                }
            }
        }
    }

    fn mergeOtherType(
        self: *Dump,
        other_type: Type,
        other_type_index: usize,
        other_types_to_mine: *std.AutoHashMap(usize, usize),
    ) !void {
        const gop = try self.type_map.getOrPut(other_type);
        if (!gop.found_existing) {
            gop.kv.value = self.type_list.items.len;
            try self.type_list.append(other_type);
        }
        try other_types_to_mine.putNoClobber(other_type_index, gop.kv.value);
    }

    fn render(self: *Dump, stream: anytype) !void {
        var jw = json.WriteStream(@TypeOf(stream).Child, 10).init(stream);
        try jw.beginObject();

        try jw.objectField("typeKinds");
        try jw.beginArray();
        inline for (@typeInfo(builtin.TypeId).Enum.fields) |field| {
            try jw.arrayElem();
            try jw.emitString(field.name);
        }
        try jw.endArray();

        try jw.objectField("params");
        try jw.beginObject();

        try jw.objectField("zigId");
        try jw.emitString(self.zig_id.?);

        try jw.objectField("zigVersion");
        try jw.emitString(self.zig_version.?);

        try jw.objectField("rootName");
        try jw.emitString(self.root_name.?);

        try jw.objectField("builds");
        try jw.beginArray();
        for (self.targets.items) |target| {
            try jw.arrayElem();
            try jw.beginObject();
            try jw.objectField("target");
            try jw.emitString(target);
            try jw.endObject();
        }
        try jw.endArray();

        try jw.endObject();

        try jw.objectField("types");
        try jw.beginArray();
        for (self.type_list.items) |t| {
            try jw.arrayElem();
            try jw.beginObject();

            try jw.objectField("kind");
            try jw.emitNumber(@enumToInt(builtin.TypeId(t)));

            switch (t) {
                .Int => |int| {
                    if (int.signed) {
                        try jw.objectField("i");
                    } else {
                        try jw.objectField("u");
                    }
                    try jw.emitNumber(int.bits);
                },
                .Float => |bits| {
                    try jw.objectField("bits");
                    try jw.emitNumber(bits);
                },

                else => {},
            }

            try jw.endObject();
        }
        try jw.endArray();

        try jw.objectField("errors");
        try jw.beginArray();
        for (self.error_list.items) |zig_error| {
            try jw.arrayElem();
            try jw.beginObject();

            try jw.objectField("src");
            try jw.emitNumber(zig_error.src);

            try jw.objectField("name");
            try jw.emitString(zig_error.name);

            try jw.endObject();
        }
        try jw.endArray();

        try jw.objectField("astNodes");
        try jw.beginArray();
        for (self.node_list.items) |node| {
            try jw.arrayElem();
            try jw.beginObject();

            try jw.objectField("file");
            try jw.emitNumber(node.file);

            try jw.objectField("line");
            try jw.emitNumber(node.line);

            try jw.objectField("col");
            try jw.emitNumber(node.col);

            if (node.fields.len != 0) {
                try jw.objectField("fields");
                try jw.beginArray();

                for (node.fields) |field_node_index| {
                    try jw.arrayElem();
                    try jw.emitNumber(field_node_index);
                }
                try jw.endArray();
            }

            try jw.endObject();
        }
        try jw.endArray();

        try jw.objectField("files");
        try jw.beginArray();
        for (self.file_list.items) |file| {
            try jw.arrayElem();
            try jw.emitString(file);
        }
        try jw.endArray();

        try jw.endObject();
    }

    fn a(self: Dump) *mem.Allocator {
        return self.targets.allocator;
    }

    fn mergeSameStrings(opt_dest: *?[]const u8, src: []const u8) !void {
        if (opt_dest.*) |dest| {
            if (!mem.eql(u8, dest, src))
                return error.MismatchedDumps;
        } else {
            opt_dest.* = src;
        }
    }
};

fn jsonObjInt(json_val: json.Value, field: []const u8) usize {
    const uncasted = json_val.Object.get(field).?.value.Integer;
    return @intCast(usize, uncasted);
}
