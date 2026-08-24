//! Tracks metadata of file inputs associated with Zig compiler and build
//! system artifacts in order to determine whether those artifacts must be
//! produced again, or may be retrieved from the cache directory on the
//! filesystem.
const Cache = @This();
const builtin = @import("builtin");

const std = @import("std");
const Io = std.Io;
const crypto = std.crypto;
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const fmt = std.fmt;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.cache);

gpa: Allocator,
io: Io,
manifest_dir: Io.Dir,
hash: HashHelper = .{},
/// This value is accessed from multiple threads, protected by mutex.
recent_problematic_timestamp: Io.Timestamp = .zero,
mutex: Io.Mutex = .init,

/// A set of strings such as the zig library directory or project source root, which
/// are stripped from the file paths before putting into the cache. They
/// are replaced with single-character indicators. This is not to save
/// space but to eliminate absolute file paths. This improves portability
/// and usefulness of the cache for advanced use cases.
prefixes_buffer: [5]Directory = undefined,
prefixes_len: usize = 0,
/// Used to identify prefixes. References external memory.
cwd: []const u8,

pub const Path = @import("Cache/Path.zig");
pub const Directory = @import("Cache/Directory.zig");
pub const DepTokenizer = @import("Cache/DepTokenizer.zig");

pub fn addPrefix(cache: *Cache, directory: Directory) void {
    cache.prefixes_buffer[cache.prefixes_len] = directory;
    cache.prefixes_len += 1;
}

/// Be sure to call `Manifest.deinit` after successful initialization.
pub fn obtain(cache: *Cache) Manifest {
    return .{
        .cache = cache,
        .hash = cache.hash,
        .manifest_file = null,
        .manifest_dirty = false,
        .hex_digest = undefined,
    };
}

pub fn prefixes(cache: *const Cache) []const Directory {
    return cache.prefixes_buffer[0..cache.prefixes_len];
}

pub const PrefixedPath = struct {
    prefix: u8,
    sub_path: []const u8,

    fn eql(a: PrefixedPath, b: PrefixedPath) bool {
        return a.prefix == b.prefix and mem.eql(u8, a.sub_path, b.sub_path);
    }

    fn hash(pp: PrefixedPath) u32 {
        return @truncate(std.hash.Wyhash.hash(pp.prefix, pp.sub_path));
    }
};

fn findPrefixPath(cache: *const Cache, path: Path) !PrefixedPath {
    const gpa = cache.gpa;
    const resolved_path = try std.fs.path.resolve(gpa, &.{
        cache.cwd, path.root_dir.path orelse ".", path.subPathOrDot(),
    });
    errdefer gpa.free(resolved_path);
    return findPrefixResolved(cache, resolved_path);
}

fn findPrefix(cache: *const Cache, file_path: []const u8) !PrefixedPath {
    const gpa = cache.gpa;
    const resolved_path = try std.fs.path.resolve(gpa, &.{file_path});
    errdefer gpa.free(resolved_path);
    return findPrefixResolved(cache, resolved_path);
}

/// Takes ownership of `resolved_path` on success.
fn findPrefixResolved(cache: *const Cache, resolved_path: []u8) !PrefixedPath {
    const gpa = cache.gpa;
    const cwd = cache.cwd;
    for (cache.prefixes(), 0..) |prefix, i| {
        const p = prefix.path orelse continue;
        const sub_path = getPrefixSubpath(gpa, cwd, p, resolved_path) catch |err| switch (err) {
            error.NotASubPath => continue,
            else => |e| return e,
        };
        // Free the resolved path since we're not going to return it
        gpa.free(resolved_path);
        return .{
            .prefix = @intCast(i),
            .sub_path = sub_path,
        };
    }

    return .{
        .prefix = 0,
        .sub_path = resolved_path,
    };
}

fn getPrefixSubpath(gpa: Allocator, cwd: []const u8, prefix: []const u8, path: []u8) ![]u8 {
    const relative = try std.fs.path.relative(gpa, cwd, null, prefix, path);
    errdefer gpa.free(relative);
    var component_iterator: std.fs.path.NativeComponentIterator = .init(relative);
    if (component_iterator.root() != null) {
        return error.NotASubPath;
    }
    const first_component = component_iterator.first();
    if (first_component != null and mem.eql(u8, first_component.?.name, "..")) {
        return error.NotASubPath;
    }
    return relative;
}

/// This is 128 bits - Even with 2^54 cache entries, the probably of a collision would be under 10^-6
pub const bin_digest_len = 16;
pub const hex_digest_len = bin_digest_len * 2;
pub const BinDigest = [bin_digest_len]u8;
pub const HexDigest = [hex_digest_len]u8;

/// The type used for hashing file contents. Currently, this is SipHash128(1, 3), because it
/// provides enough collision resistance for the Manifest use cases, while being one of our
/// fastest options right now.
pub const Hasher = crypto.auth.siphash.SipHash128(1, 3);

/// Initial state with random bytes, that can be copied.
/// Refresh this with new random bytes when the manifest
/// format is modified in a non-backwards-compatible way.
pub const hasher_init: Hasher = Hasher.init(&.{
    0x33, 0x52, 0xa2, 0x84,
    0xcf, 0x17, 0x56, 0x57,
    0x01, 0xbb, 0xcd, 0xe4,
    0x77, 0xd6, 0xf0, 0x60,
});

pub const HashHelper = struct {
    hasher: Hasher = hasher_init,

    pub fn addBytes(hh: *HashHelper, bytes: []const u8) void {
        hh.hasher.update(mem.asBytes(&bytes.len));
        hh.hasher.update(bytes);
    }

    pub fn addBytesZ(hh: *HashHelper, bytes: [:0]const u8) void {
        hh.hasher.update(mem.absorbSentinel(bytes));
    }

    pub fn addOptionalBytes(hh: *HashHelper, optional_bytes: ?[]const u8) void {
        hh.add(optional_bytes != null);
        hh.addBytes(optional_bytes orelse return);
    }

    pub fn addListOfBytes(hh: *HashHelper, list_of_bytes: []const []const u8) void {
        hh.add(list_of_bytes.len);
        for (list_of_bytes) |bytes| hh.addBytes(bytes);
    }

    pub fn addOptionalListOfBytes(hh: *HashHelper, optional_list_of_bytes: ?[]const []const u8) void {
        hh.add(optional_list_of_bytes != null);
        hh.addListOfBytes(optional_list_of_bytes orelse return);
    }

    /// Convert the input value into bytes and record it as a dependency of the process being cached.
    pub fn add(hh: *HashHelper, x: anytype) void {
        switch (@TypeOf(x)) {
            std.SemanticVersion => {
                hh.add(x.major);
                hh.add(x.minor);
                hh.add(x.patch);
            },
            std.Target.Os.TaggedVersionRange => {
                switch (x) {
                    .hurd => |hurd| {
                        hh.add(hurd.range.min);
                        hh.add(hurd.range.max);
                        hh.add(hurd.glibc);
                    },
                    .linux => |linux| {
                        hh.add(linux.range.min);
                        hh.add(linux.range.max);
                        hh.add(linux.glibc);
                        hh.add(linux.android);
                    },
                    .windows => |windows| {
                        hh.add(windows.min);
                        hh.add(windows.max);
                    },
                    .semver => |semver| {
                        hh.add(semver.min);
                        hh.add(semver.max);
                    },
                    .none => {},
                }
            },
            std.zig.BuildId => switch (x) {
                .none, .fast, .uuid, .sha1, .md5 => hh.add(std.meta.activeTag(x)),
                .hexstring => |hex_string| hh.addBytes(hex_string.toSlice()),
            },
            else => switch (@typeInfo(@TypeOf(x))) {
                .bool, .int, .@"enum", .array => hh.addBytes(mem.asBytes(&x)),
                else => @compileError("unable to hash type " ++ @typeName(@TypeOf(x))),
            },
        }
    }

    pub fn addOptional(hh: *HashHelper, optional: anytype) void {
        hh.add(optional != null);
        hh.add(optional orelse return);
    }

    /// Returns a hex encoded hash of the inputs, without modifying state.
    pub fn peek(hh: HashHelper) [hex_digest_len]u8 {
        var copy = hh;
        return copy.final();
    }

    pub fn peekBin(hh: HashHelper) BinDigest {
        var copy = hh;
        var bin_digest: BinDigest = undefined;
        copy.hasher.final(&bin_digest);
        return bin_digest;
    }

    /// Returns a hex encoded hash of the inputs, mutating the state of the hasher.
    pub fn final(hh: *HashHelper) HexDigest {
        var bin_digest: BinDigest = undefined;
        hh.hasher.final(&bin_digest);
        return binToHex(bin_digest);
    }

    pub fn oneShot(bytes: []const u8) [hex_digest_len]u8 {
        var hasher: Hasher = hasher_init;
        hasher.update(bytes);
        var bin_digest: BinDigest = undefined;
        hasher.final(&bin_digest);
        return binToHex(bin_digest);
    }
};

pub fn binToHex(bin_digest: BinDigest) HexDigest {
    var out_digest: HexDigest = undefined;
    var w: std.Io.Writer = .fixed(&out_digest);
    w.printHex(&bin_digest, .lower) catch unreachable;
    return out_digest;
}

pub const Lock = struct {
    manifest_file: Io.File,

    pub fn release(lock: *Lock, io: Io) void {
        if (builtin.os.tag == .windows) {
            // Windows does not guarantee that locks are immediately unlocked when
            // the file handle is closed. See LockFileEx documentation.
            lock.manifest_file.unlock(io);
        }

        lock.manifest_file.close(io);
        lock.* = undefined;
    }
};

/// Format: a series of consecutive `Manifest.File`, followed by a final
/// terminating zero byte to distinguish empty manifest file from manifest with
/// zero files.
pub const Manifest = struct {
    cache: *Cache,
    /// Current state for incremental hashing.
    hash: HashHelper,
    hex_digest: HexDigest,
    /// When this is null, `Manifest` is in "pre-check" phase. Otherwise it is in "post-check" phase.
    manifest_file: ?Io.File,
    manifest_dirty: bool,
    /// Set this flag to true before calling hit() in order to indicate that
    /// upon a cache hit, the code using the cache will not modify the files
    /// within the cache directory. This allows multiple processes to utilize
    /// the same cache directory at the same time.
    want_shared_lock: bool = true,
    have_exclusive_lock: bool = false,
    // Indicate that we want isProblematicTimestamp to perform a filesystem write in
    // order to obtain a problematic timestamp for the next call. Calls after that
    // will then use the same timestamp, to avoid unnecessary filesystem writes.
    want_refresh_timestamp: bool = true,
    /// Uses `Cache.gpa`.
    files: Files = .empty,
    /// Indexes line up with `files`, but only up until `hit` is called. Uses
    /// `Cache.gpa`.
    input_files: std.ArrayList(InputFile) = .empty,
    diagnostic: Diagnostic = .none,
    /// Keeps track of the last time we performed a file system write to observe
    /// what time the file system thinks it is, according to its own granularity.
    recent_problematic_timestamp: Io.Timestamp = .zero,
    /// The entire manifest file contents, except for the final terminating
    /// zero byte. However maintains always at least 1 unused capacity so the
    /// final terminating byte can be added without allocation. Uses
    /// `Cache.gpa`.
    contents: std.ArrayList(u8) = .empty,
    /// All contents from all `input_files` whose contents were requested,
    /// concatenated. Total byte size will be less than `max_input_content_len`
    /// otherwise an error is returned.
    all_input_content: std.ArrayList(u8) = .empty,
    max_input_content_len: usize = std.math.maxInt(u32),

    pub const Files = std.array_hash_map.Custom(File.Offset, void, File.HashContext, false);

    /// Source files whose prefix and relative path are included when computing
    /// the cache manifest digest. It's the information needed to lazily hash
    /// the input files only when a cache miss occurs.
    ///
    /// `File.prefix`, `File.path`, and `File.mode` will be always populated,
    /// but the other fields of `File` will be populated depending on the
    /// fields of `InputFile`.
    pub const InputFile = struct {
        request_handle: bool,
        have_handle: bool,
        /// Determines whether `File.size`, `File.inode`, and `File.mtime` are populated.
        have_stat: bool,
        /// Determines whether `File.digest` is populated.
        have_digest: bool,
        contents: enum (usize) {
            requested = std.math.maxInt(u32) - 1,
            not_requested = std.math.maxInt(u32),
            /// Byte offset index into `Manifest.all_input_content`.
            _,
        },
        /// `have_handle` determines whether this is populated.
        handle: Io.File,

        /// Index into `Manifest.input_files`.
        pub const Index = enum(u32) {
            _,
        };
    };

    /// The data per tracked input file that is stored in the manifest file.
    pub const File = extern struct {
        size: u64,
        inode: u64,
        digest: BinDigest,
        /// Nanoseconds.
        mtime: i64,
        /// Starting with this field and continuing into the path, excluding the null byte,
        /// is the string that is hashed for the manifest digest.
        flags: Flags,
        /// Terminated by zero byte, then followed by padding until 8-byte aligned.
        path_start: [0]u8,

        pub const Flags = packed struct (u8) {
            is_directory: bool,
            metadata_only: bool,
            prefix: u6,
        };

        /// Byte index within `Manifest.contents` where the entry starts.
        pub const Offset = enum(u32) {
            _,

            pub fn get(offset: Offset, m: *const Manifest) *File {
                return @ptrCast(m.contents.items[@backingInt(offset)..][0..@sizeOf(File)]);
            }

            pub fn getFallible(offset: Offset, m: *const Manifest) error{EndOfStream}!*File {
                if (@backingInt(offset) + @sizeOf(File) >= m.contents.len) return error.EndOfStream;
                return get(offset, m);
            }
        };

        pub const HashContext = struct {
            manifest: *const Manifest,

            pub fn hash(this: @This(), off: Offset) u32 {
                const file = off.get(this.manifest);
                return @truncate(std.hash.Wyhash.hash(file.prefix, file.path()));
            }

            pub fn eql(this: @This(), a_off: Offset, b_off: Offset, b_index: usize) bool {
                _ = b_index;
                const a = a_off.get(this.manifest);
                const b = b_off.get(this.manifest);
                return a.prefix == b.prefix and mem.eql(u8, a.path(), b.path());
            }
        };


        pub fn path(file: *const File) [:0]const u8 {
            return pathFallible(file) catch unreachable;
        }

        pub fn pathFallible(file: *const File) error{EndOfStream}![:0]const u8 {
            const ptr: [*]u8 = &file.path_start;
            const len = mem.findScalar(u8, ptr, 0) orelse return error.EndOfStream;
            return ptr[0..len :0];
        }

        fn manifestDigestHash(file: *const File, hasher: *Hasher) void {
            const path_ptr: [*]u8 = &file.path_start;
            const path_len = mem.findScalar(u8, path_ptr, 0).?;
            comptime assert(@offsetOf(File, "path_start") - @offsetOf(File, "flags") == 1);
            // Includes flags and sentinel.
            const hash_string = (path_ptr - 1)[0..path_len + 2];
            hasher.update(hash_string);
        }

        fn setStat(file: *File, m: *Manifest, stat: Stat) Io.Cancelable!void {
            file.size = stat.size;
            file.inode = stat.inode;
            file.mtime = stat.mtime;

            if (try m.isProblematicTimestamp(stat.mtime)) {
                // The actual file has an unreliable timestamp; force it to be hashed.
                file.stat.mtime = 0;
                file.stat.inode = 0;
            }
        }

    };


    pub const Diagnostic = union(enum) {
        none,
        manifest_create: Io.File.OpenError,
        manifest_read: Io.File.Reader.Error,
        manifest_lock: Io.File.LockError,
        file_open: FileOp,
        file_stat: FileOp,
        file_read: FileOp,
        file_hash: FileOp,

        pub const FileOp = struct {
            file_index: usize,
            err: anyerror,
        };
    };

    pub const Stat = struct {
        size: u64,
        inode: Io.File.INode,
        mtime: Io.Timestamp,
    };

    pub const AddInputFileOptions = struct {
        handle: ?Io.File = null,
        stat: ?Stat = null,
        request_handle: bool = false,
        request_contents: bool = false,
        is_directory: bool = false,
        metadata_only: bool = false,

    };

    pub const AddInputFileError = error {
        /// The same file path has been added to the cache manifest both as a
        /// directory and as a normal file, making the intended caching
        /// behavior ambiguous.
        IsDirectoryAmbiguous,
    } || Allocator.Error;

    /// Add a file as a dependency of process being cached. When `hit` is
    /// called, the file's contents will be checked to ensure that it matches
    /// the contents from previous times.
    ///
    /// The contents of the input file may be requested and subsequently
    /// obtained via methods of the returned `InputFile.Index` after calling
    /// `hit`.
    pub fn addInputFile(m: *Manifest, path: Path, options: AddInputFileOptions) Allocator.Error!InputFile.Index {
        const gpa = m.cache.gpa;
        try m.files.ensureUnusedCapacity(gpa, 1);
        try m.input_files.ensureUnusedCapacity(gpa, 1);

        const prev_contents_len = m.contents.items.len;
        const header: *File = @ptrCast(try m.contents.addManyAsSlice(gpa, @sizeOf(File)));
        errdefer m.contents.shrinkRetainingCapacity(prev_contents_len);

        header.* = .{
            .flags = .{
                .prefix = try m.cache.findAppendPrefixedPath(&m.contents, path),
                .is_directory = options.is_directory,
                .metadata_only = options.metadata_only,
            },
            .size = undefined,
            .inode = undefined,
            .mtime = undefined,
            .digest = undefined,
        };
        assert(m.contents.items.len % @alignOf(File) == 0);

        const gop = try m.files.getOrPutAssumeCapacityContext(@fromBackingInt(prev_contents_len), .{
            .manifest = m,
        });
        if (gop.found_existing) {
            m.contents.shrinkRetainingCapacity(prev_contents_len);
            const existing_input_file = &m.input_files.items[gop.index];
            if (options.handle) |handle| {
                existing_input_file.handle = handle;
                existing_input_file.have_handle = true;
            }
            if (options.request_contents) switch (existing_input_file.contents) {
                .requested, .not_requested => existing_input_file.contents = .requested,
                _ => {},
            };
            const existing_header = &m.files.keys()[gop.index];
            if (options.stat) |stat| {
                existing_input_file.have_stat = true;
                existing_header.size = stat.size;
                existing_header.inode = stat.inode;
                existing_header.mtime = stat.mtime;
            }
            if (existing_header.flags.is_directory != options.is_directory)
                return error.IsDirectoryAmbiguous;
            if (!options.metadata_only)
                existing_header.flags.metadata_only = false;
        } else {
            m.input_files.appendAssumeCapacity(.{
                .request_handle = options.request_handle,
                .have_handle = options.handle != null,
                .handle = if (options.handle) |handle| handle else undefined,
                .contents = if (options.request_contents) .requested else .not_requested,
                .have_digest = false,
                .have_stat = options.stat != null,
            });
            assert(m.input_files.items.len - 1 == gop.index);
            if (options.stat) |stat| {
                header.size = stat.size;
                header.inode = stat.inode;
                header.mtime = stat.mtime;
            }
        }
        return @fromBackingInt(gop.index);
    }

    pub fn addInputFileOptional(m: *Manifest, opt_path: ?Path, options: AddInputFileOptions) Allocator.Error!void {
        m.hash.add(opt_path != null);
        _ = try addInputFile(m, opt_path orelse return, options);
    }

    pub const CheckError = error{
        /// Unable to check the cache for a reason that has been recorded into
        /// the `diagnostic` field.
        CacheCheckFailed,
        /// A cache manifest file exists however it could not be parsed.
        InvalidFormat,
    } || Allocator.Error || Io.Cancelable;

    pub const CheckStatus = enum { hit, miss };

    /// Check the cache to see if the input exists in it.
    /// A hex encoding of its hash is available by calling `final`.
    ///
    /// This function will also acquire an exclusive lock to the manifest file. This means
    /// that a process holding a Manifest will block any other process attempting to
    /// acquire the lock. If `want_shared_lock` is `true`, a cache hit guarantees the
    /// manifest file to be locked in shared mode, and a cache miss guarantees the manifest
    /// file to be locked in exclusive mode.
    ///
    /// The lock on the manifest file is released when `deinit` is called. As another
    /// option, one may call `toOwnedLock` to obtain a smaller object which can represent
    /// the lock. `deinit` is safe to call whether or not `toOwnedLock` has been called.
    pub fn check(man: *Manifest, parent_progress_node: std.Progress.Node) CheckError!CheckStatus {
        const node = parent_progress_node.start("Reusing Cache Artifacts", 0);
        defer node.end();
        return checkProgressless(man);
    }

    pub fn checkProgressless(man: *Manifest) CheckError!CheckStatus {
        assert(man.manifest_file == null);

        for (man.files.keys()[0..man.input_files.items.len]) |file_off| {
            file_off.get(man).manifestDigestHash(&man.hash.hasher);
        }

        man.diagnostic = .none;

        var bin_digest: BinDigest = undefined;
        man.hash.hasher.final(&bin_digest);
        man.hex_digest = binToHex(bin_digest);

        const manifest_file_path = &man.hex_digest;
        const io = man.cache.io;

        // We'll try to open the cache with an exclusive lock, but if that would block
        // and `want_shared_lock` is set, a shared lock might be sufficient, so we'll
        // open with a shared lock instead.
        while (true) {
            if (man.cache.manifest_dir.createFile(io, manifest_file_path, .{
                .read = true,
                .truncate = false,
                .lock = .exclusive,
                .lock_nonblocking = man.want_shared_lock,
            })) |manifest_file| {
                man.manifest_file = manifest_file;
                man.have_exclusive_lock = true;
                break;
            } else |err| switch (err) {
                error.WouldBlock => {
                    man.manifest_file = man.cache.manifest_dir.openFile(io, manifest_file_path, .{
                        .mode = .read_write,
                        .lock = .shared,
                    }) catch |e| {
                        man.diagnostic = .{ .manifest_create = e };
                        return error.CacheCheckFailed;
                    };
                    break;
                },
                error.FileNotFound => {
                    // There are no dir components, so the only possibility
                    // should be that the directory behind the handle has been
                    // deleted, however we have observed on macOS two processes
                    // racing to do openat() with O_CREAT manifest in ENOENT.
                    //
                    // As a workaround, we retry with exclusive=true which
                    // disambiguates by returning EEXIST, indicating original
                    // failure was a race, or ENOENT, indicating deletion of
                    // the directory of our open handle.
                    if (!builtin.os.tag.isDarwin()) {
                        man.diagnostic = .{ .manifest_create = error.FileNotFound };
                        return error.CacheCheckFailed;
                    }

                    if (man.cache.manifest_dir.createFile(io, manifest_file_path, .{
                        .read = true,
                        .truncate = false,
                        .lock = .exclusive,
                        .lock_nonblocking = man.want_shared_lock,
                        .exclusive = true,
                    })) |manifest_file| {
                        man.manifest_file = manifest_file;
                        man.have_exclusive_lock = true;
                        break;
                    } else |excl_err| switch (excl_err) {
                        error.WouldBlock, error.PathAlreadyExists => continue,
                        error.FileNotFound => {
                            man.diagnostic = .{ .manifest_create = error.FileNotFound };
                            return error.CacheCheckFailed;
                        },
                        error.Canceled => |e| return e,
                        else => |e| {
                            man.diagnostic = .{ .manifest_create = e };
                            return error.CacheCheckFailed;
                        },
                    }
                },
                error.Canceled => |e| return e,
                else => |e| {
                    man.diagnostic = .{ .manifest_create = e };
                    return error.CacheCheckFailed;
                },
            }
        }

        man.want_refresh_timestamp = true;

        // We're going to construct a second hash. Its input will begin with the digest we've
        // already computed (`bin_digest`), and then it'll have the digests of each input file,
        // including "post" files (see `addFilePost`). If this is a hit, we learn the set of "post"
        // files from the manifest on disk. If this is a miss, we'll learn those from future calls
        // to `addFilePost` etc. As such, the state of `man.hash.hasher` after this function
        // depends on whether this is a hit or a miss.
        //
        // If we return `CacheStatus.hit`, then `man.hash.hasher` must already include
        // the digests of the "post" files, so the caller can call `final`. Otherwise, on a cache
        // miss, `man.hash.hasher` will include the digests of all non-"post" files -- that is,
        // the ones we've already been told about. The rest will be discovered through calls to
        // `addFilePost` etc, which will update the hasher. After all files are added, the user can
        // use `final`, and will at some point `writeManifest` the file list to disk.

        man.hash.hasher = hasher_init;
        man.hash.hasher.update(&bin_digest);

        hit: {
            digests: {
                switch (try man.checkLocked()) {
                    .hit => break :hit,
                    .miss => if (!try man.upgradeToExclusiveLock()) break :digests,
                }
                // We've just had a miss with the shared lock, and upgraded to an exclusive lock. Someone
                // else might have modified the digest, so we need to check again before deciding to miss.
                // Before trying again, we must reset `man.hash.hasher` and `man.files`.
                // This is basically just the first half of `unhit`.
                man.hash.hasher = hasher_init;
                man.hash.hasher.update(&bin_digest);
                man.shrinkFilesToInput();
                switch (try man.checkLocked()) {
                    .hit => break :hit,
                    .miss => break :digests,
                }
            }

            // Cache miss. `checkLocked` guarantees that all input files have their digests populated
            // unless it returns an error.
            man.manifest_dirty = true;
            // All input file digests are already populated by `checkLocked`, so we can call `unhit` directly.
            unhit(man, &bin_digest);
            return .miss;
        }

        if (man.want_shared_lock) {
            man.downgradeToSharedLock() catch |err| {
                man.diagnostic = .{ .manifest_lock = err };
                return error.CacheCheckFailed;
            };
        }

        return .hit;
    }

    fn shrinkFilesToInput(m: *Manifest) void {
        if (m.files.count() <= m.input_files.items.len) return;
        const off = m.files.keys()[m.input_files.items.len];
        m.contents.shrinkRetainingCapacity(@backingInt(off));
        assert(m.contents.len % @alignOf(File) == 0);
        m.files.shrinkRetainingCapacity(m.input_files.items.len);
    }

    /// Assumes that `self.hash.hasher` has been updated only with the original digest and that
    /// `self.files` contains only the original input files.
    fn checkLocked(m: *Manifest) CheckError!CheckStatus {
        const gpa = m.cache.gpa;
        const io = m.cache.io;

        var manifest_reader = m.manifest_file.?.reader(io, &.{}); // Reads positionally from zero.
        m.contents.clearRetainingCapacity();
        manifest_reader.interface.appendRemainingUnlimited(gpa, &m.contents) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.ReadFailed => {
                m.diagnostic = .{ .manifest_read = manifest_reader.err.? };
                return error.CacheCheckFailed;
            },
        };

        // Guess number of files based on manifest contents len to reduce allocations.
        try m.files.ensureUnusedCapacity(gpa, m.contents.len / (@sizeOf(File) + 32));

        var file_index: usize = 0;
        var off: usize = 0;

        // This group we always want to compute the hash digests, even on a cache miss.
        var input_group: Io.Group = .init;
        defer input_group.cancel(io);

        // This group we would like to cancel as soon as a cache miss is discovered.
        const PostResult = union(enum) {
            checkFile: CheckFileResult,
        };
        var post_select_buffer: [10]PostResult = undefined;
        var post_select: Io.Select(PostResult) = .init(&post_select_buffer);
        var post_select_remaining: usize = 0;
        defer post_select.cancel(io);

        while (off + 1 < m.contents.len) {
            const file_off: File.Offset = @fromBackingInt(off);
            const file = try File.getFallible(file_off, m);
            if (file.flags.prefix >= m.cache.prefixes_len) return error.InvalidFormat;
            const path = try file.pathFallible();
            if (path.len == 0) return error.InvalidFormat;

            if (file_index < m.input_files.items.len) {
                if (m.files.keys()[file_index] != file_off) return error.InvalidFormat;

                input_group.async(io, checkFile, .{m.cache, file, path});
            } else {
                try m.files.put(gpa, file_off);

                post_select.async(.checkFile, checkFile, .{m.cache, file, path});
                post_select_remaining += 1;
            }

            file_index += 1;
            off += @sizeOf(File) + path.len + 1;
        }

        // Final terminating zero byte to distinguish empty manifest file from
        // manifest with zero files.
        const file_valid = off + 1 == m.contents.len and m.contents[off] == 0;
        if (!file_valid or file_index < m.input_files.items.len) {
            try input_group.await(io);
            return .miss;
        }

        // Don't track the trailing zero byte in contents.
        m.contents.len -= 1;

        var post_await_buffer: [10]PostResult = undefined;
        while (post_select_remaining > 0) {
            const n = try post_select.awaitMany(&post_await_buffer, 1);
            post_select_remaining -= n;
            for (post_await_buffer[0..n]) |u| switch (u) {
                .checkFile => |result| switch (result) {
                    .hit => continue,
                    .miss => {
                        post_select.cancelDiscard();
                        try input_group.await(io);
                        return .miss;
                    },
                    .fail => |diagnostic| {
                        m.diagnostic = diagnostic;
                        return error.CacheCheckFailed;
                    },
                },
            };
        }

        try input_group.await(io);

        for (m.files.keys()) |file_off| {
            m.hash.hasher.update(&file_off.get(m).digest);
        }

        return .hit;
    }

    const CheckFileResult = union(enum) {
        hit,
        miss,
        fail: Diagnostic,
    };

    /// Runs concurrently with other `checkFile`.
    fn checkFile(cache: *const Cache, file: *File, file_path: [:0]const u8) Io.Cancelable!CheckFileResult {
        const io = cache.io;
        const dir = cache.prefixes()[file.flags.prefix].handle;

        const this_file = dir.openFile(io, file_path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return .miss,
            error.Canceled => |e| return e,
            else => |e| return .{ .fail = .{ .file_open = .{
                .file_index = file_index,
                .err = e,
            } }},
        };
        defer this_file.close(io);

        const actual_stat = this_file.stat(io) catch |err| return .{ .fail = .{ .file_stat = .{
            .file_index = file_index,
            .err = err,
        } }};
        const size_match = actual_stat.size == file.size;
        const mtime_match = actual_stat.mtime.nanoseconds == file.mtime;
        const inode_match = actual_stat.inode == file.inode;

        if (!size_match or !mtime_match or !inode_match) {
            try file.setStat(actual_stat);

            var actual_digest: BinDigest = undefined;
            hashFile(io, this_file, &actual_digest) catch |err| return .{ .fail = .{ .file_read = .{
                .file_index = file_index,
                .err = err,
            } }};

            if (!mem.eql(u8, &file.digest, &actual_digest)) {
                file.digest = actual_digest;
                return .miss;
            }
        }

        return .hit;
    }

    /// Reset `man.hash.hasher` to the state it should be in after `hit` returns `CheckStatus.miss`.
    /// The hasher contains the original input digest, and all original input file digests (i.e.
    /// not including post files).
    ///
    /// Assumes that `bin_digest` is populated for all input files.
    pub fn unhit(man: *Manifest, bin_digest: BinDigest) void {
        // Reset the hash.
        man.hash.hasher = hasher_init;
        man.hash.hasher.update(&bin_digest);
        man.shrinkFilesToInput();
        for (man.files.keys()) |off| {
            const file = off.get(man);
            man.hash.hasher.update(&file.digest);
        }
    }

    fn isProblematicTimestamp(man: *Manifest, timestamp: Io.Timestamp) error{Canceled}!bool {
        const io = man.cache.io;

        // If the file_time is prior to the most recent problematic timestamp
        // then we don't need to access the filesystem.
        if (timestamp.nanoseconds < man.recent_problematic_timestamp.nanoseconds)
            return false;

        // Next we will check the globally shared Cache timestamp, which is accessed
        // from multiple threads.
        try man.cache.mutex.lock(io);
        defer man.cache.mutex.unlock(io);

        // Save the global one to our local one to avoid locking next time.
        man.recent_problematic_timestamp = man.cache.recent_problematic_timestamp;
        if (timestamp.nanoseconds < man.recent_problematic_timestamp.nanoseconds)
            return false;

        // This flag prevents multiple filesystem writes for the same hit() call.
        if (man.want_refresh_timestamp) {
            man.want_refresh_timestamp = false;

            var file = man.cache.manifest_dir.createFile(io, "timestamp", .{
                .read = true,
                .truncate = true,
            }) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => return true,
            };
            defer file.close(io);

            // Save locally and also save globally (we still hold the global lock).
            const stat = file.stat(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => return true,
            };
            man.recent_problematic_timestamp = stat.mtime;
            man.cache.recent_problematic_timestamp = man.recent_problematic_timestamp;
        }

        return timestamp.nanoseconds >= man.recent_problematic_timestamp.nanoseconds;
    }

    pub const AddFilePostOptions = struct {
        handle: union(enum) {
            file: ?Io.File,
            dir: ?Io.Dir,
        } = .{ .file = null },
        stat: ?Stat = null,
        contents: ?[]const u8 = null,
        metadata_only: bool = false,
    };

    pub const AddFilePostError = error {
        /// The same file path has been added to the cache manifest both as a
        /// directory and as a normal file, making the intended caching
        /// behavior ambiguous.
        IsDirectoryAmbiguous,
    } || Allocator.Error;

    /// Add a file as a dependency of process being cached, after cache miss
    /// occurs.
    pub fn addFilePost(m: *Manifest, path: Path, options: AddFilePostOptions) AddFilePostError!void {
        assert(m.manifest_file != null);
        const cache = m.cache;
        const gpa = cache.gpa;
        const io = cache.io;
        const is_directory = options.handle == .dir;

        try m.files.ensureUnusedCapacity(gpa, 1);

        const prev_contents_len = m.contents.items.len;
        const new_header: *File = @ptrCast(try m.contents.addManyAsSlice(gpa, @sizeOf(File)));
        errdefer m.contents.shrinkRetainingCapacity(prev_contents_len);

        new_header.* = .{
            .flags = .{
                .prefix = try cache.findAppendPrefixedPath(&m.contents, path),
                .is_directory = is_directory,
                .metadata_only = options.metadata_only,
            },
            .size = undefined,
            .inode = undefined,
            .mtime = undefined,
            .digest = @splat(0),
        };
        assert(m.contents.items.len % @alignOf(File) == 0);

        const gop = m.files.getOrPutAssumeCapacity(@fromBackingInt(prev_contents_len), .{
            .manifest = m,
        });
        m.files.lockPointers();
        defer m.files.unlockPointers();

        const header = if (gop.found_existing) h: {
            m.contents.shrinkRetainingCapacity(prev_contents_len);
            const existing_off = gop.key_ptr.*;
            const header = existing_off.get(m);
            if (header.flags.is_directory != is_directory)
                return error.IsDirectoryAmbiguous;
            if (!options.metadata_only)
                header.flags.metadata_only = false;
            break :h header;
        } else new_header;

        if (options.stat) |stat| {
            try header.setStat(m, stat);
            if (header.metadata_only) {
                return;
            } else if (options.contents) |contents| {
                var hasher = hasher_init;
                hasher.update(contents);
                hasher.final(&header.digest);
                return;
            }
        }

        const need_stat = options.stat == null;

        switch (options.handle) {
            .dir => |opt_handle| if (opt_handle) |handle| {
                try populateDirectory(m, header, need_stat, handle, options.contents, header.metadata_only);
            } else {
                const dir = cache.prefixes()[header.flags.prefix].handle;
                const handle = try dir.openDir(io, header.path(), .{ .access_sub_paths = false, .iterate = true, });
                defer handle.close(io);
                try populateDirectory(m, header, need_stat, handle, options.contents, header.metadata_only);
            },

            .file => |opt_handle| if (opt_handle) |handle| {
                try populateFile(m, header, need_stat, handle, options.contents, header.metadata_only);
            } else {
                const dir = cache.prefixes()[header.flags.prefix].handle;
                const handle = try dir.openFile(io, header.path(), .{ .mode = .read_only });
                defer handle.close(io);
                try populateFile(m, header, need_stat, handle, options.contents, header.metadata_only);
            },
        }
    }

    fn populateFile(m: *Manifest, file: *File, need_stat: bool, handle: Io.File, contents: ?[]const u8, metadata_only: bool,) !void {
        const io = m.cache.io;

        if (need_stat) {
            const stat = try handle.stat(io);
            try file.setStat(m, stat);
        }
        if (metadata_only) return;
        if (contents) |bytes| {
            var hasher = hasher_init;
            hasher.update(bytes);
            hasher.final(&file.digest);
        } else {
            try hashFile(io, handle, &file.digest);
        }
    }

    fn populateDirectory(m: *Manifest, file: *File, need_stat: bool, handle: Io.File, contents: ?[]const u8, metadata_only: bool,) !void {
        _ = m;
        _ = file;
        _ = need_stat;
        _ = handle;
        _ = contents;
        _ = metadata_only;
        @panic("TODO");
    }

    pub fn addDepFile(self: *Manifest, dir: Io.Dir, dep_file_sub_path: []const u8) !void {
        assert(self.manifest_file == null);
        return self.addDepFileMaybePost(dir, dep_file_sub_path);
    }

    pub fn addDepFilePost(self: *Manifest, dir: Io.Dir, dep_file_sub_path: []const u8) !void {
        assert(self.manifest_file != null);
        return self.addDepFileMaybePost(dir, dep_file_sub_path);
    }

    fn addDepFileMaybePost(self: *Manifest, dir: Io.Dir, dep_file_sub_path: []const u8) !void {
        const gpa = self.cache.gpa;
        const io = self.cache.io;
        const dep_file_contents = try dir.readFileAlloc(io, dep_file_sub_path, gpa, .limited(file_size_max));
        defer gpa.free(dep_file_contents);

        var error_buf: std.ArrayList(u8) = .empty;
        defer error_buf.deinit(gpa);

        var resolve_buf: std.ArrayList(u8) = .empty;
        defer resolve_buf.deinit(gpa);

        var it: DepTokenizer = .{ .bytes = dep_file_contents };
        while (it.next()) |token| {
            switch (token) {
                // We don't care about targets, we only want the prereqs
                // Clang is invoked in single-source mode but other programs may not
                .target, .target_must_resolve => {},
                .prereq => |file_path| if (self.manifest_file == null) {
                    _ = try self.addFilePath(.initCwd(file_path), null);
                } else try self.addFilePost(file_path),
                .prereq_must_resolve => {
                    resolve_buf.clearRetainingCapacity();
                    try token.resolve(gpa, &resolve_buf);
                    if (self.manifest_file == null) {
                        _ = try self.addFilePath(.initCwd(resolve_buf.items), null);
                    } else try self.addFilePost(resolve_buf.items);
                },
                else => |err| {
                    try err.printError(gpa, &error_buf);
                    log.err("failed parsing {s}: {s}", .{ dep_file_sub_path, error_buf.items });
                    return error.InvalidDepFile;
                },
            }
        }
    }

    /// Returns a binary hash of the inputs.
    pub fn finalBin(self: *Manifest) BinDigest {
        assert(self.manifest_file != null);

        // We don't close the manifest file yet, because we want to
        // keep it locked until the API user is done using it.
        // We also don't write out the manifest yet, because until
        // cache_release is called we still might be working on creating
        // the artifacts to cache.

        var bin_digest: BinDigest = undefined;
        self.hash.hasher.final(&bin_digest);
        return bin_digest;
    }

    /// Returns a hex encoded hash of the inputs.
    pub fn final(self: *Manifest) HexDigest {
        const bin_digest = self.finalBin();
        return binToHex(bin_digest);
    }

    /// If `want_shared_lock` is true, this function automatically downgrades the
    /// lock from exclusive to shared.
    pub fn writeManifest(m: *Manifest) !void {
        assert(m.have_exclusive_lock);
        const io = m.cache.io;
        const manifest_file = m.manifest_file.?;
        if (m.manifest_dirty) {

            m.contents.appendAssumeCapacity(0);
            defer _ = m.contents.pop().?;

            try manifest_file.setLength(io, m.contents.items.len);
            try manifest_file.writePositionalAll(io, m.contents.items, 0);

            m.manifest_dirty = false;
        }

        if (m.want_shared_lock) {
            try m.downgradeToSharedLock();
        }
    }

    fn downgradeToSharedLock(self: *Manifest) !void {
        if (!self.have_exclusive_lock) return;
        const io = self.cache.io;

        if (std.process.can_spawn or !builtin.single_threaded) {
            const manifest_file = self.manifest_file.?;
            try manifest_file.downgradeLock(io);
        }

        self.have_exclusive_lock = false;
    }

    fn upgradeToExclusiveLock(self: *Manifest) error{CacheCheckFailed}!bool {
        if (self.have_exclusive_lock) return false;
        assert(self.manifest_file != null);
        const io = self.cache.io;

        if (std.process.can_spawn or !builtin.single_threaded) {
            const manifest_file = self.manifest_file.?;
            // Here we intentionally have a period where the lock is released, in case there are
            // other processes holding a shared lock.
            manifest_file.unlock(io);
            manifest_file.lock(io, .exclusive) catch |err| {
                self.diagnostic = .{ .manifest_lock = err };
                return error.CacheCheckFailed;
            };
        }
        self.have_exclusive_lock = true;
        return true;
    }

    /// Obtain only the data needed to maintain a lock on the manifest file.
    /// The `Manifest` remains safe to deinit.
    ///
    /// Don't forget to call `writeManifest` before this!
    pub fn toOwnedLock(self: *Manifest) Lock {
        defer self.manifest_file = null;
        return .{ .manifest_file = self.manifest_file.? };
    }

    pub fn takeFiles(man: *Manifest) Files {
        defer man.files = .empty;
        return man.files;
    }

    pub fn freeFiles(gpa: Allocator, files: *Files) void {
        for (files.keys()) |*file| file.deinit(gpa);
        files.deinit(gpa);
    }

    /// Releases the manifest file and frees any memory the Manifest was using.
    /// `Manifest.hit` must be called first.
    ///
    /// Don't forget to call `writeManifest` before this!
    pub fn deinit(man: *Manifest) void {
        const io = man.cache.io;
        const gpa = man.cache.gpa;

        if (man.manifest_file) |file| {
            if (builtin.os.tag == .windows) {
                // See Lock.release for why this is required on Windows
                file.unlock(io);
            }

            file.close(io);
        }
        freeFiles(gpa, &man.files);
        man.* = undefined;
    }

    pub fn populateFileSystemInputs(man: *Manifest, buf: *std.ArrayList(u8)) Allocator.Error!void {
        assert(@typeInfo(std.zig.Server.Message.PathPrefix).@"enum".field_names.len == man.cache.prefixes_len);
        buf.clearRetainingCapacity();
        const gpa = man.cache.gpa;
        const files = man.files.keys();
        if (files.len > 0) {
            for (files) |file| {
                try buf.ensureUnusedCapacity(gpa, file.prefixed_path.sub_path.len + 2);
                buf.appendAssumeCapacity(file.prefixed_path.prefix + 1);
                buf.appendSliceAssumeCapacity(file.prefixed_path.sub_path);
                buf.appendAssumeCapacity(0);
            }
            // The null byte is a separator, not a terminator.
            buf.items.len -= 1;
        }
    }

    pub fn populateOtherManifest(man: *Manifest, other: *Manifest, prefix_map: [5]u8) Allocator.Error!void {
        const gpa = other.cache.gpa;
        assert(other.manifest_file != null);
        assert(@typeInfo(std.zig.Server.Message.PathPrefix).@"enum".field_names.len == man.cache.prefixes_len);
        assert(man.cache.prefixes_len == 5);

        const orig_files_len = other.files.count();
        const orig_contents_len = other.contents.items.len;
        errdefer {
            other.files.shrinkRetainingCapacity(orig_files_len);
            other.contents.shrinkRetainingCapacity(orig_contents_len);
        }

        for (man.files.keys(), 0..) |off, file_index| {
            try other.files.ensureUnusedCapacity(gpa, 1);

            const next_off = if (file_index < man.files.count())
                @backingInt(man.files.keys()[file_index + 1])
            else
                man.contents.items.len;

            const copy_bytes = man.contents.items[@backingInt(off)..next_off];
            const prev_contents_len = other.contents.items.len;
            try other.contents.appendSlice(gpa, copy_bytes);

            const gop = other.files.getOrPutAssumeCapacity(@fromBackingInt(prev_contents_len), .{
                .manifest = other,
            });

            if (gop.found_existing) {
                other.contents.shrinkRetainingCapacity(prev_contents_len);
                continue;
            }

            const other_file = File.get(@fromBackingInt(prev_contents_len));
            other_file.prefix = prefix_map[other_file.prefix];
        }
    }
};

fn hashFile(io: Io, file: Io.File, bin_digest: *[Hasher.mac_length]u8) Io.File.ReadPositionalError!void {
    var buffer: [2048]u8 = undefined;
    var hasher = hasher_init;
    var offset: u64 = 0;
    while (true) {
        const n = try file.readPositional(io, &.{&buffer}, offset);
        if (n == 0) break;
        hasher.update(buffer[0..n]);
        offset += n;
    }
    hasher.final(bin_digest);
}

// Create/Write a file, close it, then grab its stat.mtime timestamp.
fn testGetCurrentFileTimestamp(io: Io, dir: Io.Dir) !Io.Timestamp {
    const test_out_file = "test-filetimestamp.tmp";

    var file = try dir.createFile(io, test_out_file, .{
        .read = true,
        .truncate = true,
    });
    defer {
        file.close(io);
        dir.deleteFile(io, test_out_file) catch {};
    }

    return (try file.stat(io)).mtime;
}

test "cache file and then recall it" {
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cwd = try std.process.currentPathAlloc(io, testing.allocator);
    defer testing.allocator.free(cwd);

    const temp_file = "test.txt";
    const temp_manifest_dir = "temp_manifest_dir";

    try tmp.dir.writeFile(io, .{ .sub_path = temp_file, .data = "Hello, world!\n" });

    // Wait for file timestamps to tick
    const initial_time = try testGetCurrentFileTimestamp(io, tmp.dir);
    while ((try testGetCurrentFileTimestamp(io, tmp.dir)).nanoseconds == initial_time.nanoseconds) {
        try std.Io.Clock.Duration.sleep(.{ .clock = .boot, .raw = .fromNanoseconds(1) }, io);
    }

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;

    {
        var cache: Cache = .{
            .io = io,
            .gpa = testing.allocator,
            .manifest_dir = try tmp.dir.createDirPathOpen(io, temp_manifest_dir, .{}),
            .cwd = cwd,
        };
        cache.addPrefix(.{ .path = null, .handle = tmp.dir });
        defer cache.manifest_dir.close(io);

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.add(true);
            ch.hash.add(@as(u16, 1234));
            ch.hash.addBytes("1234");
            _ = try ch.addFilePath(.initCwd(temp_file), null);

            // There should be nothing in the cache
            try testing.expectEqual(false, try ch.hit(.none));

            digest1 = ch.final();
            try ch.writeManifest();
        }
        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.add(true);
            ch.hash.add(@as(u16, 1234));
            ch.hash.addBytes("1234");
            _ = try ch.addFilePath(.initCwd(temp_file), null);

            // Cache hit! We just "built" the same file
            try testing.expect(try ch.hit(.none));
            digest2 = ch.final();

            try testing.expectEqual(false, ch.have_exclusive_lock);
        }

        try testing.expectEqual(digest1, digest2);
    }
}

test "check that changing a file makes cache fail" {
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cwd = try std.process.currentPathAlloc(io, testing.allocator);
    defer testing.allocator.free(cwd);

    const temp_file = "cache_hash_change_file_test.txt";
    const temp_manifest_dir = "cache_hash_change_file_manifest_dir";
    const original_temp_file_contents = "Hello, world!\n";
    const updated_temp_file_contents = "Hello, world; but updated!\n";

    try tmp.dir.writeFile(io, .{ .sub_path = temp_file, .data = original_temp_file_contents });

    // Wait for file timestamps to tick
    const initial_time = try testGetCurrentFileTimestamp(io, tmp.dir);
    while ((try testGetCurrentFileTimestamp(io, tmp.dir)).nanoseconds == initial_time.nanoseconds) {
        try std.Io.Clock.Duration.sleep(.{ .clock = .boot, .raw = .fromNanoseconds(1) }, io);
    }

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;

    {
        var cache: Cache = .{
            .io = io,
            .gpa = testing.allocator,
            .manifest_dir = try tmp.dir.createDirPathOpen(io, temp_manifest_dir, .{}),
            .cwd = cwd,
        };
        cache.addPrefix(.{ .path = null, .handle = tmp.dir });
        defer cache.manifest_dir.close(io);

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            const temp_file_idx = try ch.addFilePath(.initCwd(temp_file), 100);

            // There should be nothing in the cache
            try testing.expectEqual(false, try ch.hit(.none));

            try testing.expect(mem.eql(u8, original_temp_file_contents, ch.files.keys()[temp_file_idx].contents.?));

            digest1 = ch.final();

            try ch.writeManifest();
        }

        try tmp.dir.writeFile(io, .{ .sub_path = temp_file, .data = updated_temp_file_contents });

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            const temp_file_idx = try ch.addFilePath(.initCwd(temp_file), 100);

            // A file that we depend on has been updated, so the cache should not contain an entry for it
            try testing.expectEqual(false, try ch.hit(.none));

            // The cache system does not keep the contents of re-hashed input files.
            try testing.expect(ch.files.keys()[temp_file_idx].contents == null);

            digest2 = ch.final();

            try ch.writeManifest();
        }

        try testing.expect(!mem.eql(u8, digest1[0..], digest2[0..]));
    }
}

test "no file inputs" {
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cwd = try std.process.currentPathAlloc(io, testing.allocator);
    defer testing.allocator.free(cwd);

    const temp_manifest_dir = "no_file_inputs_manifest_dir";

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;

    var cache: Cache = .{
        .io = io,
        .gpa = testing.allocator,
        .manifest_dir = try tmp.dir.createDirPathOpen(io, temp_manifest_dir, .{}),
        .cwd = cwd,
    };
    cache.addPrefix(.{ .path = null, .handle = tmp.dir });
    defer cache.manifest_dir.close(io);

    {
        var man = cache.obtain();
        defer man.deinit();

        man.hash.addBytes("1234");

        // There should be nothing in the cache
        try testing.expectEqual(false, try man.hit(.none));

        digest1 = man.final();

        try man.writeManifest();
    }
    {
        var man = cache.obtain();
        defer man.deinit();

        man.hash.addBytes("1234");

        try testing.expect(try man.hit(.none));
        digest2 = man.final();
        try testing.expectEqual(false, man.have_exclusive_lock);
    }

    try testing.expectEqual(digest1, digest2);
}

test "Manifest with files added after initial hash work" {
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cwd = try std.process.currentPathAlloc(io, testing.allocator);
    defer testing.allocator.free(cwd);

    const temp_file1 = "cache_hash_post_file_test1.txt";
    const temp_file2 = "cache_hash_post_file_test2.txt";
    const temp_manifest_dir = "cache_hash_post_file_manifest_dir";

    try tmp.dir.writeFile(io, .{ .sub_path = temp_file1, .data = "Hello, world!\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = temp_file2, .data = "Hello world the second!\n" });

    // Wait for file timestamps to tick
    const initial_time = try testGetCurrentFileTimestamp(io, tmp.dir);
    while ((try testGetCurrentFileTimestamp(io, tmp.dir)).nanoseconds == initial_time.nanoseconds) {
        try std.Io.Clock.Duration.sleep(.{ .clock = .boot, .raw = .fromNanoseconds(1) }, io);
    }

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;
    var digest3: HexDigest = undefined;

    {
        var cache: Cache = .{
            .io = io,
            .gpa = testing.allocator,
            .manifest_dir = try tmp.dir.createDirPathOpen(io, temp_manifest_dir, .{}),
            .cwd = cwd,
        };
        cache.addPrefix(.{ .path = null, .handle = tmp.dir });
        defer cache.manifest_dir.close(io);

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            _ = try ch.addFilePath(.initCwd(temp_file1), null);

            // There should be nothing in the cache
            try testing.expectEqual(false, try ch.hit(.none));

            _ = try ch.addFilePost(temp_file2);

            digest1 = ch.final();
            try ch.writeManifest();
        }
        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            _ = try ch.addFilePath(.initCwd(temp_file1), null);

            try testing.expect(try ch.hit(.none));
            digest2 = ch.final();

            try testing.expectEqual(false, ch.have_exclusive_lock);
        }
        try testing.expect(mem.eql(u8, &digest1, &digest2));

        // Modify the file added after initial hash
        try tmp.dir.writeFile(io, .{ .sub_path = temp_file2, .data = "Hello world the second, updated\n" });

        // Wait for file timestamps to tick
        const initial_time2 = try testGetCurrentFileTimestamp(io, tmp.dir);
        while ((try testGetCurrentFileTimestamp(io, tmp.dir)).nanoseconds == initial_time2.nanoseconds) {
            try std.Io.Clock.Duration.sleep(.{ .clock = .boot, .raw = .fromNanoseconds(1) }, io);
        }

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            _ = try ch.addFilePath(.initCwd(temp_file1), null);

            // A file that we depend on has been updated, so the cache should not contain an entry for it
            try testing.expectEqual(false, try ch.hit(.none));

            _ = try ch.addFilePost(temp_file2);

            digest3 = ch.final();

            try ch.writeManifest();
        }

        try testing.expect(!mem.eql(u8, &digest1, &digest3));
    }
}
