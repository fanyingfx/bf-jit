const std = @import("std");
const posix = std.posix;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();
    const args = try std.process.argsAlloc(arena_alloc);
    if (args.len <= 1) {
        std.debug.print("Usage: %s <input.bin>\n", .{});
        std.debug.print("No input is provided\n", .{});
        std.process.exit(1);
    }

    const file_path = args[1];
    const code = try std.fs.cwd().readFileAlloc(arena_alloc, file_path, 40960);
    const aligned_len = std.mem.alignForward(usize, code.len, std.mem.page_size);

    const mem = try std.posix.mmap(
        null,
        aligned_len,
        posix.PROT.READ | posix.PROT.WRITE,
         .{.TYPE = .PRIVATE,.ANONYMOUS = true},
        -1,
        0,
    );
    defer posix.munmap(mem);

    @memcpy(mem[0..code.len], code);

    try posix.mprotect(mem, posix.PROT.READ | posix.PROT.EXEC);
    const message = "urmom";

    const bf_main: *const fn (memory: [*]u8,msg_len:usize) void = @ptrCast(mem[0..code.len]);

    bf_main(@constCast(message),message.len);
}
