const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;

fn todo(comptime msg: []const u8) void {
    std.debug.panic("{s}\n", .{msg});
}
const OpKind = enum(u8) {
    Inc = '+',
    Dec = '-',
    Left = '<',
    Right = '>',
    Input = ',',
    Output = '.',
    Jump_If_Zero = '[',
    Jump_If_Nonzero = ']',
    pub fn to_char(self: OpKind) u8 {
        return @intFromEnum(self);
    }
};
const Op = struct {
    kind: OpKind,
    operand: usize,
};
fn is_bf_cmd(ch: u8) bool {
    const cmds = "+-<>,.[]";
    return std.mem.containsAtLeast(u8, cmds, 1, &[_]u8{ch});
}
const Lexer = struct {
    content: []const u8,
    pos: usize,

    pub fn next(self: *Lexer) u8 {
        while (self.pos < self.content.len and !is_bf_cmd(self.content[self.pos])) {
            self.pos += 1;
        }
        if (self.pos >= self.content.len) {
            return 0;
        }
        defer self.pos += 1;
        return self.content[self.pos];
    }
};

const Ops = std.ArrayList(Op);
const AddrStack = std.ArrayList(usize);
const Memory = std.ArrayList(isize);

fn interp(ops: []Op) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var memory = Memory.init(arena_alloc);
    try memory.append(0);
    var head: usize = 0;
    var ip: usize = 0;

    while (ip < ops.len) {
        const op = ops[ip];
        switch (op.kind) {
            .Inc => {
                memory.items[head] += @intCast(op.operand);
                ip += 1;
            },
            .Dec => {
                memory.items[head] -= @intCast(op.operand);
                ip += 1;
            },
            .Left => {
                if (ip < op.operand) {
                    std.debug.panic("RUNTIME ERROR: Memory underflow\n", .{});
                }
                head -= op.operand;
                ip += 1;
            },
            .Right => {
                head += op.operand;
                while (ip >= memory.items.len) {
                    try memory.append(0);
                }
                ip += 1;
            },
            .Input => {
                todo("TODO :input is not implemented");
            },
            .Output => {
                for (0..op.operand) |_| {
                    const c: u8 = @intCast(memory.items[head]);
                    std.debug.print("{c}", .{c});
                }
                ip += 1;
            },
            .Jump_If_Nonzero => {
                if (memory.items[head] != 0) {
                    ip = op.operand;
                } else {
                    ip += 1;
                }
            },
            .Jump_If_Zero => {
                if (memory.items[head] == 0) {
                    ip = op.operand;
                } else {
                    ip += 1;
                }
            },
        }
    }
}
const Backpatch = struct {
    operand_byte_addr: usize,
    src_byte_addr: usize,
    dst_op_index: usize,
};
const codef = *const fn (memory: [*]u8) void;
fn jit_compile(allocator: std.mem.Allocator, ops: []Op) !codef {
    var code_list = std.ArrayList(u8).init(allocator);
    var backpatches = std.ArrayList(Backpatch).init(allocator);
    var addrs = AddrStack.init(allocator);
    for (ops, 0..) |op, i| {
        try addrs.append(code_list.items.len);
        switch (op.kind) {
            .Inc => {
                assert(op.operand < 256);
                try code_list.appendSlice(&[_]u8{ 0x80, 0x07 }); // add byte [rdi],
                try code_list.append(@intCast(op.operand));
            },
            .Dec => {
                try code_list.appendSlice(&[_]u8{ 0x80, 0x2f }); // sub byte [rdi],
                try code_list.append(@intCast(op.operand));
            },
            .Left => {
                try code_list.appendSlice(&[_]u8{ 0x48, 0x81, 0xef }); //sub rdi,
                const operand: u32 = @intCast(op.operand);
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, operand, .little);
                try code_list.appendSlice(&buf);
            },
            .Right => {
                try code_list.appendSlice(&[_]u8{ 0x48, 0x81, 0xc7 }); //add rdi,
                const operand: u32 = @intCast(op.operand);
                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, operand, .little);
                try code_list.appendSlice(&buf);
            },
            .Input => {
                todo("Input is not implemented yet");
            },
            .Output => {
                for (0..op.operand) |_| {
                    try code_list.append(0x57); // add rdi
                    try code_list.appendSlice(&[_]u8{ 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00 }); // mov rax,1
                    try code_list.appendSlice(&[_]u8{ 0x48, 0x89, 0xfe }); // mov rax,rdi
                    try code_list.appendSlice(&[_]u8{ 0x48, 0xc7, 0xc7, 0x01, 0, 0, 0 }); // mov rdi,1
                    try code_list.appendSlice(&[_]u8{ 0x48, 0xc7, 0xc2, 0x01, 0, 0, 0 }); // mov rdx,1
                    try code_list.appendSlice(&[_]u8{ 0x0f, 0x05 }); // syscall
                    try code_list.append(0x5f);
                }
            },
            .Jump_If_Zero => {
                // 0f84 c800 0000 jz
                try code_list.appendSlice(&[_]u8{ 0x48, 0x31, 0xc0 }); // xor rax, rax
                try code_list.appendSlice(&[_]u8{ 0x8a, 0x07 }); // mov al , byte [rdi]
                try code_list.appendSlice(&[_]u8{ 0x48, 0x85, 0xc0 }); // test rax ,rax
                try code_list.appendSlice(&[_]u8{ 0x0f, 0x84 }); // jz

                const operand_addr = code_list.items.len;
                try code_list.appendSlice(&[_]u8{ 0, 0, 0, 0 }); // for backpatching

                const bp: Backpatch = .{
                    .operand_byte_addr = operand_addr,
                    .src_byte_addr = i,
                    .dst_op_index = op.operand,
                };
                try backpatches.append(bp);

                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(operand_addr), .little);
            },
            .Jump_If_Nonzero => {

                try code_list.appendSlice(&[_]u8{ 0x48, 0x31, 0xc0 }); // xor rax, rax
                try code_list.appendSlice(&[_]u8{ 0x8a, 0x07 }); // mov al , byte [rdi]
                try code_list.appendSlice(&[_]u8{ 0x48, 0x85, 0xc0 }); // test rax ,rax
                try code_list.appendSlice(&[_]u8{ 0x0f, 0x85 }); // jnz

                const operand_addr = code_list.items.len;
                try code_list.appendSlice(&[_]u8{ 0, 0, 0, 0 }); // for backpatching

                const bp: Backpatch = .{
                    .operand_byte_addr   = operand_addr,
                    .src_byte_addr  = i,
                    .dst_op_index = op.operand,
                };
                try backpatches.append(bp);

                var buf: [4]u8 = undefined;
                std.mem.writeInt(u32, &buf, @intCast(operand_addr), .little);
            },
        }
    }
    try addrs.append(code_list.items.len);
    for (backpatches.items) |bp| {
        const src_addr: i32 = @intCast(addrs.items[bp.src_byte_addr + 1]);
        const dst_addr: i32 = @intCast(addrs.items[bp.dst_op_index]);
        const operand = dst_addr - src_addr;
        var buf: [4]u8 = undefined;
        std.mem.writeInt(i32, &buf, @intCast(operand), .little);
        @memcpy(code_list.items[bp.operand_byte_addr .. bp.operand_byte_addr + 4], &buf);
        // std.debug.print("{any}\n", .{bp});
    }
    try code_list.append(0xc3);
    const code = code_list.items;

    const aligned_len = std.mem.alignForward(usize, code.len, std.mem.page_size);

    const mem = try std.posix.mmap(
        null,
        aligned_len,
        posix.PROT.READ | posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );

    @memcpy(mem[0..code.len], code);

    try posix.mprotect(mem, posix.PROT.READ | posix.PROT.EXEC);
    const bf_main: *const fn (memory: [*]u8) void = @ptrCast(mem[0..code.len]);
    return bf_main;
}
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();
    const args = try std.process.argsAlloc(arena_alloc);
    if (args.len <= 1) {
        std.debug.print("Usage: %s <input.bf>\n", .{});
        std.debug.print("No input is provided\n", .{});
        std.process.exit(1);
    }
    const file_path = args[1];
    const content = try std.fs.cwd().readFileAlloc(arena_alloc, file_path, 4096);
    var ops = Ops.init(arena_alloc);
    var stack = AddrStack.init(arena_alloc);
    var lexer: Lexer = .{ .content = content, .pos = 0 };
    var ch: u8 = lexer.next();
    while (ch > 0) {
        switch (ch) {
            '+', '-', '<', '>', '.', ',' => {
                var count: usize = 1;
                var s: u8 = lexer.next();
                while (s == ch) {
                    count += 1;
                    s = lexer.next();
                }
                const op: Op = .{ .kind = @enumFromInt(ch), .operand = count };
                try ops.append(op);
                ch = s;
            },
            '[' => {
                const addr: usize = ops.items.len;
                const op: Op = .{ .kind = @enumFromInt(ch), .operand = 0 };
                try ops.append(op);
                try stack.append(addr);
                ch = lexer.next();
            },
            ']' => {
                if (stack.items.len == 0) {
                    std.debug.print("{s} [{}]: ERROR Unbalanced loop\n", .{ file_path, lexer.pos });
                    std.process.exit(1);
                }
                const addr: usize = stack.pop();
                const op: Op = .{ .kind = @enumFromInt(ch), .operand = addr + 1 };
                try ops.append(op);
                ops.items[addr].operand = ops.items.len;

                ch = lexer.next();
            },
            else => std.debug.panic("wrong path!\n", .{}),
        }
    }
    const memory: []u8 = try arena_alloc.alloc(u8, 10 * 1000 * 1000);
    const bf_main = try jit_compile(arena_alloc, ops.items);
    @memset(memory, 0);
    bf_main(memory.ptr);
}
