const std = @import("std");
const expect = std.testing.expect;

test "turn HashMap into a set with void" {
    const gpa = std.testing.allocator;

    var map: std.hash_map.Auto(i32, void) = .empty;
    defer map.deinit(gpa);

    try map.put(gpa, 1, {});
    try map.put(gpa, 2, {});

    try expect(map.contains(2));
    try expect(!map.contains(3));

    _ = map.remove(2);
    try expect(!map.contains(2));
}

// test
