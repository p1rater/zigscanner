// fingerprint.zig — OS and service fingerprinting
// This is the dark art of guessing what OS a machine is running
// based on which ports are open and what they say.
// It's more reliable than astrology. Slightly.

const std = @import("std");
const scanner = @import("scanner.zig");

// Attempt to guess the OS from open port patterns and banner strings
// Returns a heap-allocated string or null if we have no idea
// (which is often — OS detection is genuinely hard)
pub fn guessOS(
    allocator: std.mem.Allocator,
    target_ip: []const u8,
    open_ports: []scanner.PortResult,
) !?[]u8 {
    _ = target_ip; // We'd use this for TCP/IP stack fingerprinting in a full impl

    // Build a quick set of open port numbers for easy lookup
    var port_set = std.AutoHashMap(u16, void).init(allocator);
    defer port_set.deinit();

    for (open_ports) |port| {
        try port_set.put(port.port, {});
    }

    // Check banners for OS hints — this is surprisingly effective
    for (open_ports) |port| {
        if (port.banner) |banner| {
            if (os: {
                // SSH banners often contain the OS name — thank you, OpenSSH defaults
                if (std.mem.indexOf(u8, banner, "Ubuntu")) |_| break :os "Linux (Ubuntu)";
                if (std.mem.indexOf(u8, banner, "Debian")) |_| break :os "Linux (Debian)";
                if (std.mem.indexOf(u8, banner, "CentOS")) |_| break :os "Linux (CentOS)";
                if (std.mem.indexOf(u8, banner, "Red Hat")) |_| break :os "Linux (RHEL)";
                if (std.mem.indexOf(u8, banner, "Fedora")) |_| break :os "Linux (Fedora)";
                if (std.mem.indexOf(u8, banner, "Alpine")) |_| break :os "Linux (Alpine)";
                if (std.mem.indexOf(u8, banner, "FreeBSD")) |_| break :os "FreeBSD";
                if (std.mem.indexOf(u8, banner, "OpenBSD")) |_| break :os "OpenBSD";
                if (std.mem.indexOf(u8, banner, "NetBSD")) |_| break :os "NetBSD";

                // Windows usually doesn't give OS info in banners (it's shy)
                // But SMB fingerprinting can tell us a lot
                if (std.mem.indexOf(u8, banner, "Windows")) |_| break :os "Windows";
                if (std.mem.indexOf(u8, banner, "IIS")) |_| break :os "Windows (IIS)";

                // macOS runs pretty standard services, harder to fingerprint
                if (std.mem.indexOf(u8, banner, "Darwin")) |_| break :os "macOS/Darwin";

                // Embedded/IoT devices often have telltale banners
                if (std.mem.indexOf(u8, banner, "RouterOS")) |_| break :os "MikroTik RouterOS";
                if (std.mem.indexOf(u8, banner, "Cisco")) |_| break :os "Cisco IOS";
                if (std.mem.indexOf(u8, banner, "Juniper")) |_| break :os "Juniper JunOS";

                break :os null;
            }) |os_name| {
                return try allocator.dupe(u8, os_name);
            }
        }
    }

    // No banner hints — fall back to port pattern heuristics
    // These are rough generalizations, not gospel
    return heuristicOSGuess(allocator, port_set);
}

// Guess OS from port combination patterns
// This is educated guessing, but it's better than nothing
fn heuristicOSGuess(
    allocator: std.mem.Allocator,
    port_set: std.AutoHashMap(u16, void),
) !?[]u8 {
    const has = struct {
        fn port(set: std.AutoHashMap(u16, void), p: u16) bool {
            return set.contains(p);
        }
    };

    // Windows has a very distinctive fingerprint —
    // it almost always runs SMB, RPC, and sometimes RDP
    const smb = has.port(port_set, 445);
    const rpc = has.port(port_set, 135);
    const rdp = has.port(port_set, 3389);
    const winrm = has.port(port_set, 5985) or has.port(port_set, 5986);

    if (smb and rpc) {
        if (rdp) {
            return try allocator.dupe(u8, "Windows (likely Server, RDP enabled)");
        }
        if (winrm) {
            return try allocator.dupe(u8, "Windows (WinRM enabled)");
        }
        return try allocator.dupe(u8, "Windows");
    }

    // Linux servers often have SSH + some combination of web/db ports
    const ssh = has.port(port_set, 22);
    const http = has.port(port_set, 80) or has.port(port_set, 443);
    const mysql = has.port(port_set, 3306);
    const postgres = has.port(port_set, 5432);

    if (ssh and !smb and !rpc) {
        if (http and (mysql or postgres)) {
            return try allocator.dupe(u8, "Linux (web server stack)");
        }
        if (http) {
            return try allocator.dupe(u8, "Linux (likely)");
        }
        return try allocator.dupe(u8, "Unix-like (SSH only)");
    }

    // Network equipment tends to only expose specific ports
    const telnet = has.port(port_set, 23);
    const snmp = has.port(port_set, 161);

    if (snmp and telnet and !ssh) {
        return try allocator.dupe(u8, "Network device (router/switch)");
    }

    // Not enough info to make a reasonable guess
    return null;
}

// Parse TTL from ping response to get a rough OS clue
// Windows: 128, Linux: 64, Cisco: 255, etc.
// This is super unreliable across hops but works on local networks
pub fn ttlOsHint(ttl: u8) []const u8 {
    // TTL values decrease by 1 per hop, so we check ranges
    // not exact values — a TTL of 63 probably started as 64 (Linux)
    return if (ttl >= 240)
        "Cisco/Network Device (TTL ~255)"
    else if (ttl >= 120)
        "Windows (TTL ~128)"
    else if (ttl >= 56)
        "Linux/Unix (TTL ~64)"
    else
        "Unknown (unusual TTL)";
}

// Check if an HTTP response looks like a specific framework
// This helps identify web applications, not just web servers
pub fn detectWebFramework(banner: []const u8) ?[]const u8 {
    // Server header tells us a lot
    if (std.mem.indexOf(u8, banner, "Apache")) |_| return "Apache httpd";
    if (std.mem.indexOf(u8, banner, "nginx")) |_| return "nginx";
    if (std.mem.indexOf(u8, banner, "Microsoft-IIS")) |_| return "Microsoft IIS";
    if (std.mem.indexOf(u8, banner, "lighttpd")) |_| return "lighttpd";
    if (std.mem.indexOf(u8, banner, "Caddy")) |_| return "Caddy";
    if (std.mem.indexOf(u8, banner, "openresty")) |_| return "OpenResty";

    // Application frameworks sometimes expose themselves too
    if (std.mem.indexOf(u8, banner, "Express")) |_| return "Node.js/Express";
    if (std.mem.indexOf(u8, banner, "Werkzeug")) |_| return "Python/Flask";
    if (std.mem.indexOf(u8, banner, "gunicorn")) |_| return "Python/Gunicorn";
    if (std.mem.indexOf(u8, banner, "Jetty")) |_| return "Java/Jetty";
    if (std.mem.indexOf(u8, banner, "Tomcat")) |_| return "Apache Tomcat";

    return null;
}
