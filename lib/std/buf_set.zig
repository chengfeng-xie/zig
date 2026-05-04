const std = @import("std.zig");
const StringHashMap = std.hash_map.String;
const mem = @import("mem.zig");
const Allocator = mem.Allocator;
const testing = std.testing;

/// A BufSet is a set of strings.  The BufSet duplicates
/// strings internally, and never takes ownership of strings
/// which are passed to it.
pub const BufSet = struct {
    hash_map: BufSetHashMap,

    const BufSetHashMap = StringHashMap(void);
    pub const Iterator = BufSetHashMap.KeyIterator;

    pub const init: BufSet = .{
        .hash_map = .empty,
    };

    /// Free a BufSet along with all stored keys.
    pub fn deinit(self: *BufSet, allocator: Allocator) void {
        var it = self.hash_map.keyIterator();
        while (it.next()) |key_ptr| {
            allocator.free(key_ptr.*);
        }
        self.hash_map.deinit(allocator);
        self.* = undefined;
    }

    /// Insert an item into the BufSet.  The item will be
    /// copied, so the caller may delete or reuse the
    /// passed string immediately.
    pub fn insert(self: *BufSet, allocator: Allocator, value: []const u8) !void {
        const gop = try self.hash_map.getOrPut(allocator, value);
        if (!gop.found_existing) {
            gop.key_ptr.* = copy(allocator, value) catch |err| {
                _ = self.hash_map.remove(value);
                return err;
            };
        }
    }

    /// Check if the set contains an item matching the passed string
    pub fn contains(self: BufSet, value: []const u8) bool {
        return self.hash_map.contains(value);
    }

    /// Remove an item from the set.
    pub fn remove(self: *BufSet, allocator: Allocator, value: []const u8) void {
        const kv = self.hash_map.fetchRemove(value) orelse return;
        allocator.free(kv.key);
    }

    /// Returns the number of items stored in the set
    pub fn count(self: *const BufSet) usize {
        return self.hash_map.count();
    }

    /// Returns an iterator over the items stored in the set.
    /// Iteration order is arbitrary.
    pub fn iterator(self: *const BufSet) Iterator {
        return self.hash_map.keyIterator();
    }

    /// Creates a copy of this BufSet, using a specified allocator.
    pub fn clone(
        self: *const BufSet,
        allocator: Allocator,
    ) Allocator.Error!BufSet {
        const cloned_hashmap = try self.hash_map.clone(allocator);
        const cloned = BufSet{ .hash_map = cloned_hashmap };
        var it = cloned.hash_map.keyIterator();
        while (it.next()) |key_ptr| {
            key_ptr.* = try copy(allocator, key_ptr.*);
        }

        return cloned;
    }

    test clone {
        var original: BufSet = .init;
        defer original.deinit(testing.allocator);

        try original.insert(testing.allocator, "x");

        var cloned = try original.clone(testing.allocator);
        defer cloned.deinit(testing.allocator);

        cloned.remove(testing.allocator, "x");
        try testing.expect(original.count() == 1);
        try testing.expect(cloned.count() == 0);

        try testing.expectError(
            error.OutOfMemory,
            original.clone(testing.failing_allocator),
        );
    }

    fn copy(allocator: Allocator, value: []const u8) ![]const u8 {
        const result = try allocator.alloc(u8, value.len);
        @memcpy(result, value);
        return result;
    }
};

test BufSet {
    const allocator = std.testing.allocator;

    var bufset: BufSet = .init;
    defer bufset.deinit(allocator);

    try bufset.insert(allocator, "x");
    try testing.expect(bufset.count() == 1);
    bufset.remove(allocator, "x");
    try testing.expect(bufset.count() == 0);

    try bufset.insert(allocator, "x");
    try bufset.insert(allocator, "y");
    try bufset.insert(allocator, "z");
}

test "clone with arena" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var buf: BufSet = .init;
    defer buf.deinit(allocator);

    try buf.insert(allocator, "member1");
    try buf.insert(allocator, "member2");

    _ = try buf.clone(arena.allocator());
}
