// scanner.zig — The heart of the beast
// All the actual scanning logic lives here.
// It's multithreaded, which means it's fast, and also means
// debugging it is an adventure in concurrency hell.

const std = @import("std");
const args = @import("args.zig");
const services = @import("services.zig");
const fingerprint = @import("fingerprint.zig");

pub const PortState = enum {
    open,
    closed,
    filtered, // No response — could be firewall, could be nothing
    open_filtered, // UDP ambiguity — we really can't tell
};

pub const PortResult = struct {
    port: u16,
    state: PortState,
    service_name: []const u8,  // "http", "ssh", etc.
    banner: ?[]u8,             // Raw banner grab if we got one
    version: ?[]u8,            // Parsed version string

    pub fn deinit(self: *PortResult, allocator: std.mem.Allocator) void {
        if (self.banner) |b| allocator.free(b);
        if (self.version) |v| allocator.free(v);
    }
};

pub const ScanResult = struct {
    target: []const u8,
    ip_address: []const u8,
    hostname: ?[]const u8,
    is_up: bool,
    latency_ms: f64,
    open_ports: []PortResult,
    os_guess: ?[]const u8,
    scan_duration_ms: u64,
    ports_scanned: u32,

    pub fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        for (self.open_ports) |*port| {
            port.deinit(allocator);
        }
        allocator.free(self.open_ports);
        allocator.free(self.ip_address);
        if (self.hostname) |h| allocator.free(h);
        if (self.os_guess) |o| allocator.free(o);
    }
};

// Shared state between threads — we need to be careful here
// Zig's Mutex is our friend, let's not forget to use it
const ScanContext = struct {
    allocator: std.mem.Allocator,
    target_ip: []const u8,
    config: args.Config,
    next_port: std.atomic.Value(u32),        // atomic counter for work distribution
    results_mutex: std.Thread.Mutex,
    open_ports: std.ArrayList(PortResult),
    errors: std.atomic.Value(u32),
};

pub fn runScan(allocator: std.mem.Allocator, config: args.Config) !ScanResult {
    const start_time = std.time.milliTimestamp();

    // Resolve the target — might be a hostname, might be an IP
    // Either way, we need a raw IP to connect to
    const ip_address = try resolveTarget(allocator, config.target);
    defer allocator.free(ip_address);

    std.debug.print("[*] Resolved {s} -> {s}\n", .{ config.target, ip_address });

    // First, check if the host is even alive
    // No point scanning 65535 ports on a host that doesn't respond
    const ping_result = pingHost(ip_address, config.timeout_ms);
    if (!ping_result.is_alive) {
        std.debug.print("[!] Host appears to be down (no ICMP response)\n", .{});
        std.debug.print("[*] Continuing scan anyway — host might be blocking ICMP\n", .{});
        // We continue anyway because many hosts block ICMP. Classic.
    }

    const port_count = @as(u32, config.port_end) - @as(u32, config.port_start) + 1;
    std.debug.print("[*] Scanning {d} ports with {d} threads...\n\n", .{ port_count, config.thread_count });

    // Set up the shared context that all threads will use
    var ctx = ScanContext{
        .allocator = allocator,
        .target_ip = ip_address,
        .config = config,
        .next_port = std.atomic.Value(u32).init(@as(u32, config.port_start)),
        .results_mutex = .{},
        .open_ports = std.ArrayList(PortResult).init(allocator),
        .errors = std.atomic.Value(u32).init(0),
    };

    // Spawn worker threads — this is where the magic happens
    // (Or the crashes. Usually both.)
    const actual_threads = @min(config.thread_count, port_count);
    const threads = try allocator.alloc(std.Thread, actual_threads); 
    defer allocator.free(threads);

    for (threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, scanWorker, .{&ctx});
    }

    // Wait for all workers to finish
    for (threads) |thread| {
        thread.join();
    }

    // Sort results by port number — unsorted output is mildly infuriating
    std.mem.sort(PortResult, ctx.open_ports.items, {}, portResultLessThan);

    const end_time = std.time.milliTimestamp();
    const duration = @as(u64, @intCast(end_time - start_time));

    // OS detection is a best-effort thing — don't get your hopes up
    const os_guess = if (config.os_detection)
        try fingerprint.guessOS(allocator, ip_address, ctx.open_ports.items)
    else
        null;

    return ScanResult{
        .target = config.target,
        .ip_address = try allocator.dupe(u8, ip_address),
        .hostname = if (!std.mem.eql(u8, config.target, ip_address))
            try allocator.dupe(u8, config.target)
        else
            null,
        .is_up = ping_result.is_alive or ctx.open_ports.items.len > 0,
        .latency_ms = ping_result.latency_ms,
        .open_ports = try ctx.open_ports.toOwnedSlice(),
        .os_guess = os_guess,
        .scan_duration_ms = duration,
        .ports_scanned = port_count,
    };
}

// The worker thread function — this runs in each thread
fn scanWorker(ctx: *ScanContext) void {
    while (true) {
        // Atomically grab the next port to scan
        const port_u32 = ctx.next_port.fetchAdd(1, .seq_cst);
        if (port_u32 > @as(u32, ctx.config.port_end)) break;

        const port = @as(u16, @truncate(port_u32));

        const result = switch (ctx.config.scan_type) {
            .tcp_connect => tcpConnectScan(ctx.allocator, ctx.target_ip, port, ctx.config),
            .tcp_syn => tcpSynScan(ctx.allocator, ctx.target_ip, port, ctx.config),
            .udp => udpScan(ctx.allocator, ctx.target_ip, port, ctx.config),
            .ping => null, 
            .service => tcpConnectScan(ctx.allocator, ctx.target_ip, port, ctx.config),
        } catch |err| blk: {
            if (ctx.config.verbose) {
                std.debug.print("  Port {d}: error {}\n", .{ port, err });
            }
            _ = ctx.errors.fetchAdd(1, .seq_cst);
            break :blk null;
        };

        if (result) |r| {
            if (r.state == .open or r.state == .open_filtered) {
                ctx.results_mutex.lock();
                ctx.open_ports.append(r) catch {
                    std.debug.print("[!] OOM while storing port result\n", .{});
                };
                ctx.results_mutex.unlock();

                // Print discovered ports in real-time — users like feedback
                std.debug.print("  [+] {d}/tcp  open  {s}\n", .{ port, r.service_name });
            }
        }
    }
}

// Standard TCP connect scan — three-way handshake and done
fn tcpConnectScan(
    allocator: std.mem.Allocator,
    target: []const u8,
    port: u16,
    config: args.Config,
) !?PortResult {
    const address = std.net.Address.parseIp4(target, port) catch |err| {
        std.debug.print("[!] Failed to parse address {s}: {}\n", .{ target, err });
        return null;
    };

    const stream = std.net.tcpConnectToAddress(address) catch |err| {
        return switch (err) {
            error.ConnectionRefused => PortResult{
                .port = port,
                .state = .closed,
                .service_name = services.lookupPort(port),
                .banner = null,
                .version = null,
            },
            // Fixed: error.TimedOut removed for 0.13 compatibility
            error.ConnectionTimedOut => PortResult{
                .port = port,
                .state = .filtered,
                .service_name = services.lookupPort(port),
                .banner = null,
                .version = null,
            },
            else => return err,
        };
    };
    defer stream.close();

    var banner: ?[]u8 = null;
    var version: ?[]u8 = null;

    if (config.service_detection) {
        if (grabBanner(allocator, stream, port, config.timeout_ms)) |b| {
            banner = b;
            version = parseVersion(allocator, b, port);
        } else |_| {
            // Banner grab failed
        }
    }

    return PortResult{
        .port = port,
        .state = .open,
        .service_name = services.lookupPort(port),
        .banner = banner,
        .version = version,
    };
}

fn tcpSynScan(
    allocator: std.mem.Allocator,
    target: []const u8,
    port: u16,
    config: args.Config,
) !?PortResult {
    // Currently fallback to connect scan
    return tcpConnectScan(allocator, target, port, config);
}

fn udpScan(
    allocator: std.mem.Allocator,
    target: []const u8,
    port: u16,
    config: args.Config,
) !?PortResult {
    _ = config;
    _ = target;
    _ = allocator;

    const known_udp = switch (port) {
        53, 67, 68, 69, 123, 161, 162, 514, 520 => true,
        else => false,
    };

    if (known_udp) {
        return PortResult{
            .port = port,
            .state = .open_filtered,
            .service_name = services.lookupPort(port),
            .banner = null,
            .version = null,
        };
    }

    return null;
}

fn grabBanner(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    port: u16,
    timeout_ms: u64,
) ![]u8 {
    _ = timeout_ms; 

    var buf: [1024]u8 = undefined;

    const needs_probe = switch (port) {
        80, 8080, 8443, 443, 8000, 8888 => true, 
        else => false,
    };

    if (needs_probe) {
        _ = try stream.write("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n");
    }

    const n = try stream.read(&buf);
    if (n == 0) return error.EmptyBanner;

    var end = n;
    while (end > 0 and (buf[end - 1] == '\n' or buf[end - 1] == '\r' or buf[end - 1] == 0)) {
        end -= 1;
    }

    return try allocator.dupe(u8, buf[0..end]);
}

fn parseVersion(allocator: std.mem.Allocator, banner: []const u8, port: u16) ?[]u8 {
    _ = port; 

    if (std.mem.startsWith(u8, banner, "SSH-")) {
        if (std.mem.indexOfPos(u8, banner, 4, "-")) |dash| {
            const rest = banner[dash + 1 ..];
            const end = std.mem.indexOfAny(u8, rest, " \r\n") orelse rest.len;
            return allocator.dupe(u8, rest[0..end]) catch null;
        }
    }

    if (std.mem.indexOf(u8, banner, "Server: ")) |server_pos| {
        const start = server_pos + 8;
        const rest = banner[start..];
        const end = std.mem.indexOfAny(u8, rest, "\r\n") orelse rest.len;
        return allocator.dupe(u8, rest[0..end]) catch null;
    }

    if (std.mem.startsWith(u8, banner, "220 ")) {
        const end = std.mem.indexOfAny(u8, banner[4..], "\r\n") orelse banner.len - 4;
        return allocator.dupe(u8, banner[4..4 + end]) catch null;
    }

    return null;
}

const PingResult = struct {
    is_alive: bool,
    latency_ms: f64,
};

fn pingHost(target: []const u8, timeout_ms: u64) PingResult {
    _ = timeout_ms;

    const start = std.time.nanoTimestamp();
    const probe_ports = [_]u16{ 80, 443, 22, 8080 };

    for (probe_ports) |port| {
        const addr = std.net.Address.parseIp4(target, port) catch continue;
        const stream = std.net.tcpConnectToAddress(addr) catch continue;
        stream.close();

        const end = std.time.nanoTimestamp();
        const latency = @as(f64, @floatFromInt(end - start)) / 1_000_000.0;
        return .{ .is_alive = true, .latency_ms = latency };
    }

    return .{ .is_alive = false, .latency_ms = 0.0 };
}

fn resolveTarget(allocator: std.mem.Allocator, target: []const u8) ![]u8 {
    _ = std.net.Address.parseIp4(target, 0) catch {
        const list = try std.net.getAddressList(allocator, target, 0);
        defer list.deinit();

        if (list.addrs.len == 0) {
            return error.HostNotFound;
        }

        var buf: [64]u8 = undefined;
        const ip_str = try std.fmt.bufPrint(&buf, "{}", .{list.addrs[0]});
        if (std.mem.indexOf(u8, ip_str, ":")) |colon| {
            return try allocator.dupe(u8, ip_str[0..colon]);
        }
        return try allocator.dupe(u8, ip_str);
    };

    return try allocator.dupe(u8, target);
}

fn portResultLessThan(_: void, a: PortResult, b: PortResult) bool {
    return a.port < b.port;
}
