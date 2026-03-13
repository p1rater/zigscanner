// zigscanner - A comprehensive network reconnaissance tool
// Written in Zig because we like pain and blazing fast performance
// Think of this as nmap's younger, more aggressive sibling

const std = @import("std");
const scanner = @import("scanner.zig");
const args = @import("args.zig");
const output = @import("output.zig");
const version = @import("version.zig");

pub fn main() !void {
    // GPA is our best friend here — we're doing a lot of allocations
    // and we need to track them all without leaking memory like a sieve
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    // Print the banner first because aesthetics matter, apparently
    try output.printBanner(stdout);

    // Parse CLI arguments — this is where users inevitably mess up
    const config = args.parseArgs(allocator) catch |err| {
        switch (err) {
            args.ArgError.NoTarget => {
                try stderr.print("[!] Error: No target specified. Use --help for usage.\n", .{});
                std.process.exit(1);
            },
            args.ArgError.InvalidPort => {
                try stderr.print("[!] Error: Invalid port range specified.\n", .{});
                std.process.exit(1);
            },
            args.ArgError.HelpRequested => {
                try args.printHelp(stdout);
                std.process.exit(0);
            },
            args.ArgError.VersionRequested => {
                try stdout.print("zigscanner v{s}\n", .{version.VERSION});
                std.process.exit(0);
            },
            else => return err,
        }
    };
    defer config.deinit(allocator);

    try stdout.print("[*] Target: {s}\n", .{config.target});
    try stdout.print("[*] Port range: {d}-{d}\n", .{ config.port_start, config.port_end });
    try stdout.print("[*] Threads: {d}\n", .{config.thread_count});
    try stdout.print("[*] Timeout: {d}ms\n\n", .{config.timeout_ms});

    // The actual heavy lifting happens here
    // All the cool stuff lives in scanner.zig
    var scan_result = try scanner.runScan(allocator, config);
    defer scan_result.deinit(allocator);

    // Display results — because what's the point if we can't read them?
    try output.printResults(stdout, scan_result, config);

    // If they asked for JSON output, write it to a file
    if (config.output_file) |file_path| {
        const file = std.fs.cwd().createFile(file_path, .{}) catch |err| {
            try stderr.print("[!] Failed to create output file: {}\n", .{err});
            std.process.exit(1);
        };
        defer file.close();
        try output.writeJson(file.writer(), scan_result);
        try stdout.print("\n[+] Results saved to: {s}\n", .{file_path});
    }
}
