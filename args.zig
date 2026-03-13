// args.zig — CLI argument parsing
// Nobody likes writing arg parsers. I don't like writing arg parsers.
// But here we are, and at least this one is somewhat readable.

const std = @import("std");

pub const ArgError = error{
    NoTarget,
    InvalidPort,
    InvalidTimeout,
    InvalidThreadCount,
    HelpRequested,
    VersionRequested,
    UnknownFlag,
};

pub const ScanType = enum {
    tcp_connect, // The safe, reliable, polite option
    tcp_syn,     // Stealth scan — requires root, naturally
    udp,         // UDP is chaos, but someone has to scan it
    ping,        // Just checking if the host is alive
    service,     // Full service/version detection
};

pub const Config = struct {
    target: []const u8,
    port_start: u16,
    port_end: u16,
    thread_count: u32,
    timeout_ms: u64,
    scan_type: ScanType,
    os_detection: bool,
    service_detection: bool,
    verbose: bool,
    output_file: ?[]const u8,

    // Clean up anything we allocated for this config
    pub fn deinit(self: Config, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        if (self.output_file) |f| allocator.free(f);
    }
};

pub fn parseArgs(allocator: std.mem.Allocator) !Config {
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    // Defaults that make sense for most use cases
    // (1000ms timeout is generous but not insane)
    var config = Config{
        .target = "",
        .port_start = 1,
        .port_end = 1024,
        .thread_count = 100,
        .timeout_ms = 1000,
        .scan_type = .tcp_connect,
        .os_detection = false,
        .service_detection = false,
        .verbose = false,
        .output_file = null,
    };

    var target_set = false;
    var i: usize = 1; // skip argv[0] which is the program name, obviously

    while (i < argv.len) : (i += 1) {
        const arg = argv[i];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return ArgError.HelpRequested;
        }

        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-V")) {
            return ArgError.VersionRequested;
        }

        // Port range: -p 80 or -p 1-65535 or -p 22,80,443
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--ports")) {
            i += 1;
            if (i >= argv.len) return ArgError.InvalidPort;
            try parsePortRange(argv[i], &config.port_start, &config.port_end);
            continue;
        }

        // Thread count — more isn't always better, but it often is
        if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--threads")) {
            i += 1;
            if (i >= argv.len) return ArgError.InvalidThreadCount;
            config.thread_count = std.fmt.parseInt(u32, argv[i], 10) catch return ArgError.InvalidThreadCount;
            // Sanity check — 5000 threads on one machine is just asking for trouble
            if (config.thread_count == 0 or config.thread_count > 5000) return ArgError.InvalidThreadCount;
            continue;
        }

        // Timeout in milliseconds
        if (std.mem.eql(u8, arg, "--timeout")) {
            i += 1;
            if (i >= argv.len) return ArgError.InvalidTimeout;
            config.timeout_ms = std.fmt.parseInt(u64, argv[i], 10) catch return ArgError.InvalidTimeout;
            continue;
        }

        // Scan type flags — mutually exclusive, last one wins
        if (std.mem.eql(u8, arg, "--syn") or std.mem.eql(u8, arg, "-sS")) {
            config.scan_type = .tcp_syn;
            continue;
        }
        if (std.mem.eql(u8, arg, "--udp") or std.mem.eql(u8, arg, "-sU")) {
            config.scan_type = .udp;
            continue;
        }
        if (std.mem.eql(u8, arg, "--ping") or std.mem.eql(u8, arg, "-sn")) {
            config.scan_type = .ping;
            continue;
        }

        // Extra detection features — slow but informative
        if (std.mem.eql(u8, arg, "-O") or std.mem.eql(u8, arg, "--os-detect")) {
            config.os_detection = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-sV") or std.mem.eql(u8, arg, "--service-detect")) {
            config.service_detection = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
            continue;
        }

        // Output file for JSON results
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= argv.len) return ArgError.NoTarget;
            config.output_file = try allocator.dupe(u8, argv[i]);
            continue;
        }

        // If it starts with '-', it's an unknown flag — tell the user
        if (arg[0] == '-') {
            std.debug.print("[!] Unknown flag: {s}\n", .{arg});
            return ArgError.UnknownFlag;
        }

        // Otherwise it must be the target (IP or hostname)
        // We only support one target for now — CIDR ranges are a future problem
        if (!target_set) {
            config.target = try allocator.dupe(u8, arg);
            target_set = true;
        }
    }

    if (!target_set) return ArgError.NoTarget;

    return config;
}

// Parse port ranges like "80", "1-1024", "22,80,443,8080-8090"
// This is a bit ugly but handles the common cases well enough
fn parsePortRange(input: []const u8, start: *u16, end: *u16) !void {
    // Simple single port
    if (std.mem.indexOfScalar(u8, input, '-') == null and
        std.mem.indexOfScalar(u8, input, ',') == null)
    {
        const port = std.fmt.parseInt(u16, input, 10) catch return ArgError.InvalidPort;
        start.* = port;
        end.* = port;
        return;
    }

    // Range like 1-1024
    if (std.mem.indexOfScalar(u8, input, '-')) |dash_pos| {
        const lo = std.fmt.parseInt(u16, input[0..dash_pos], 10) catch return ArgError.InvalidPort;
        const hi = std.fmt.parseInt(u16, input[dash_pos + 1 ..], 10) catch return ArgError.InvalidPort;
        if (lo > hi) return ArgError.InvalidPort;
        start.* = lo;
        end.* = hi;
        return;
    }

    // Common ports shorthand — "top" means top 1000 well-known ports
    if (std.mem.eql(u8, input, "top") or std.mem.eql(u8, input, "common")) {
        start.* = 1;
        end.* = 1024;
        return;
    }

    // Full range
    if (std.mem.eql(u8, input, "all") or std.mem.eql(u8, input, "full")) {
        start.* = 1;
        end.* = 65535;
        return;
    }

    return ArgError.InvalidPort;
}

pub fn printHelp(writer: anytype) !void {
    try writer.print(
        \\zigscanner - Fast network reconnaissance tool
        \\
        \\USAGE:
        \\  zigscanner [OPTIONS] <target>
        \\
        \\TARGET:
        \\  IP address (e.g. 192.168.1.1)
        \\  Hostname   (e.g. example.com)
        \\
        \\OPTIONS:
        \\  -p, --ports <range>      Port range to scan (default: 1-1024)
        \\                           Examples: 80, 1-65535, top, all
        \\  -t, --threads <n>        Number of concurrent threads (default: 100)
        \\      --timeout <ms>       Connection timeout in ms (default: 1000)
        \\  -sS, --syn               TCP SYN (stealth) scan [requires root]
        \\  -sU, --udp               UDP scan
        \\  -sn, --ping              Ping scan only (no port scan)
        \\  -O,  --os-detect         Enable OS fingerprinting
        \\  -sV, --service-detect    Enable service/version detection
        \\  -v,  --verbose           Verbose output
        \\  -o,  --output <file>     Save results as JSON
        \\  -h,  --help              Show this help
        \\  -V,  --version           Show version
        \\
        \\EXAMPLES:
        \\  zigscanner 192.168.1.1
        \\  zigscanner -p 1-65535 -t 500 192.168.1.1
        \\  zigscanner -p top -sV -O 10.0.0.1
        \\  zigscanner --timeout 500 -o results.json 192.168.1.100
        \\
        \\NOTE: SYN scan requires root/administrator privileges.
        \\      Use TCP connect scan if you're not root.
        \\
    , .{});
}
