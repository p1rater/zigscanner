// output.zig — Presenting results in a way humans can actually read
// Good output formatting is 50% of what makes a tool feel professional.
// The other 50% is not crashing. We try to do both.

const std = @import("std");
const scanner = @import("scanner.zig");
const args = @import("args.zig");
const services = @import("services.zig");
const version = @import("version.zig");

// The banner — every self-respecting security tool has one
pub fn printBanner(writer: anytype) !void {
    const red = "\x1b[31m";
    const reset = "\x1b[0m";

    try writer.print(
        \\
        \\  {s}▒███████▒  ██████ {s}
        \\  {s}▒ ▒ ▒ ▄▀░▒██    ▒ {s}
        \\  {s}░ ▒ ▄▀▒░ ░ ▓██▄   {s}
        \\  {s}  ▄▀▒    ░ ▒   ██▒{s}
        \\  {s}▒███████▒▒██████▒▒{s}
        \\  {s}░▒▒ ▓░▒░▒▒ ▒▓▒ ▒ ░{s}
        \\  {s}░░▒ ▒ ░ ▒░ ░▒  ░ ░{s}
        \\  {s}░ ░ ░ ░ ░░  ░  ░ {s}
        \\  {s}  ░ ░           ░ {s}
        \\  {s}░                 {s}
        \\
        \\  {s}zigscanner v{s}{s}
        \\  {s}by @p1rater{s}
        \\
    , .{ 
        red, reset, 
        red, reset, 
        red, reset, 
        red, reset, 
        red, reset, 
        red, reset, 
        red, reset, 
        red, reset, 
        red, reset, 
        red, reset, 
        red, version.VERSION, reset,
        red, reset 
    });
}

pub fn printResults(writer: anytype, result: scanner.ScanResult, config: args.Config) !void {
    const divider = "─" ** 60;

    try writer.print("\n{s}\n", .{divider});
    try writer.print("  Scan Results for: {s}", .{result.target});

    if (result.hostname) |_| {
        try writer.print(" ({s})", .{result.ip_address});
    }
    try writer.print("\n{s}\n\n", .{divider});

    if (result.is_up) {
        try writer.print("  Host Status : UP", .{});
        if (result.latency_ms > 0) {
            try writer.print(" ({d:.2}ms latency)\n", .{result.latency_ms});
        } else {
            try writer.print("\n", .{});
        }
    } else {
        try writer.print("  Host Status : DOWN (or blocking ICMP)\n", .{});
    }

    if (result.os_guess) |os| {
        try writer.print("  OS Guess    : {s} (confidence: low-medium)\n", .{os});
    }

    try writer.print("  Ports Scanned: {d}\n", .{result.ports_scanned});
    try writer.print("  Open Ports   : {d}\n", .{result.open_ports.len});
    try writer.print("  Scan Time    : {d}ms\n\n", .{result.scan_duration_ms});

    if (result.open_ports.len == 0) {
        try writer.print("  No open ports found.\n", .{});
        return;
    }

    try writer.print("  {s:<8} {s:<12} {s:<20} {s}\n", .{ "PORT", "STATE", "SERVICE", "VERSION/INFO" });
    try writer.print("  {s}\n", .{ "─" ** 56 });

    for (result.open_ports) |port| {
        const state_str = switch (port.state) {
            .open => "open",
            .closed => "closed",
            .filtered => "filtered",
            .open_filtered => "open|filtered",
        };

// Sensitive marker'ı belirle
        const sensitive_marker = if (services.isSensitivePort(port.port)) " ⚠" else "";

        // FORMATI DÜZELTTİK: 
        // {d}/tcp -> Port numarası
        // {s:<12} -> State (open/closed)
        // {s:<20} -> Service name
        // {s}     -> Sensitive marker
        try writer.print("  {d}/tcp  {s:<12} {s:<20}{s}", .{
            port.port,
            state_str,
            port.service_name,
            sensitive_marker,
        });

        if (port.version) |ver| {
            try writer.print(" | {s}", .{ver});
        }

        try writer.print("\n", .{});

        if (config.verbose) {
            if (port.banner) |banner| {
                const max_banner_len = 80;
                const display_len = @min(banner.len, max_banner_len);
                try writer.print("            Banner: {s}{s}\n", .{
                    banner[0..display_len],
                    if (display_len < banner.len) "..." else "",
                });
            }
        }
    }

    try printSensitiveWarnings(writer, result.open_ports);
    try writer.print("\n{s}\n", .{divider});
}

fn printSensitiveWarnings(writer: anytype, open_ports: []scanner.PortResult) !void {
    var any_warnings = false;

    for (open_ports) |port| {
        if (services.isSensitivePort(port.port)) {
            if (!any_warnings) {
                try writer.print("\n  ⚠  SECURITY NOTES:\n", .{});
                any_warnings = true;
            }
            const warning = sensitivePortWarning(port.port);
            try writer.print("  •  Port {d} ({s}): {s}\n", .{
                port.port,
                port.service_name,
                warning,
            });
        }
    }
}

fn sensitivePortWarning(port: u16) []const u8 {
    return switch (port) {
        23    => "Telnet is unencrypted. Please use SSH instead.",
        21    => "FTP transmits credentials in plaintext. Consider SFTP/FTPS.",
        2375  => "Docker API without TLS! Unauthenticated access = full host compromise.",
        6379  => "Redis exposed. If no auth configured, this is a critical vulnerability.",
        9200  => "Elasticsearch API exposed. Data may be publicly readable.",
        27017 => "MongoDB exposed. Check if authentication is enabled.",
        3389  => "RDP exposed to network. Ensure strong credentials and consider VPN.",
        5900  => "VNC exposed. Ensure password authentication is enabled.",
        else  => "Verify this service requires network exposure.",
    };
}

pub fn writeJson(writer: anytype, result: scanner.ScanResult) !void {
    try writer.print("{{\n", .{});
    try writer.print("  \"target\": \"{s}\",\n", .{result.target});
    try writer.print("  \"ip_address\": \"{s}\",\n", .{result.ip_address});
    try writer.print("  \"is_up\": {s},\n", .{if (result.is_up) "true" else "false"});
    try writer.print("  \"latency_ms\": {d:.2},\n", .{result.latency_ms});
    try writer.print("  \"ports_scanned\": {d},\n", .{result.ports_scanned});
    try writer.print("  \"scan_duration_ms\": {d},\n", .{result.scan_duration_ms});

    if (result.os_guess) |os| {
        try writer.print("  \"os_guess\": \"{s}\",\n", .{os});
    } else {
        try writer.print("  \"os_guess\": null,\n", .{});
    }

    try writer.print("  \"open_ports\": [\n", .{});
    for (result.open_ports, 0..) |port, i| {
        const is_last = i == result.open_ports.len - 1;
        try writer.print("    {{\n", .{});
        try writer.print("      \"port\": {d},\n", .{port.port});
        try writer.print("      \"protocol\": \"tcp\",\n", .{});
        try writer.print("      \"state\": \"{s}\",\n", .{@tagName(port.state)});
        try writer.print("      \"service\": \"{s}\",\n", .{port.service_name});
        try writer.print("      \"sensitive\": {s}", .{
            if (services.isSensitivePort(port.port)) "true" else "false",
        });

        if (port.version) |v| {
            try writer.print(",\n      \"version\": \"{s}\"", .{v});
        }

        if (port.banner) |b| {
            try writer.print(",\n      \"banner\": \"", .{});
            try writeJsonEscapedString(writer, b);
            try writer.print("\"", .{});
        }

        try writer.print("\n    }}{s}\n", .{if (is_last) "" else ","});
    }
    try writer.print("  ]\n}}\n", .{});
}

fn writeJsonEscapedString(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"'  => try writer.print("\\\"", .{}),
            '\\' => try writer.print("\\\\", .{}),
            '\n' => try writer.print("\\n",  .{}),
            '\r' => try writer.print("\\r",  .{}),
            '\t' => try writer.print("\\t",  .{}),
            // Fixed: Split range to avoid duplicates with named escapes
            0...8, 11...12, 14...0x1f => try writer.print("\\u{x:0>4}", .{c}), 
            else => try writer.writeByte(c),
        }
    }
}
