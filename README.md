# zigscanner

> A fast, comprehensive network reconnaissance tool written in Zig.  
> Think nmap, but written in a language that makes you feel things.

```
  ▒███████▒  ██████ 
  ▒ ▒ ▒ ▄▀░▒██    ▒ 
  ░ ▒ ▄▀▒░ ░ ▓██▄   
    ▄▀▒    ░ ▒   ██▒
  ▒███████▒▒██████▒▒
  ░▒▒ ▓░▒░▒▒ ▒▓▒ ▒ ░
  ░░▒ ▒ ░ ▒░ ░▒  ░ ░
  ░ ░ ░ ░ ░░  ░  ░ 
    ░ ░           ░ 
  ░                 
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zig Version](https://img.shields.io/badge/Zig-0.13%2B-orange)](https://ziglang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)]()

---

## Table of Contents

- [What is zigscanner?](#what-is-zigscanner)
- [Why Zig?](#why-zig)
- [Features](#features)
- [Installation](#installation)
  - [Building from Source](#building-from-source)
  - [Cross-Compilation](#cross-compilation)
  - [Dependencies](#dependencies)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Basic Syntax](#basic-syntax)
  - [Port Ranges](#port-ranges)
  - [Scan Types](#scan-types)
  - [All Options](#all-options)
- [Scan Modes In Depth](#scan-modes-in-depth)
  - [TCP Connect Scan](#tcp-connect-scan)
  - [TCP SYN Scan](#tcp-syn-scan)
  - [UDP Scan](#udp-scan)
  - [Ping Scan](#ping-scan)
- [Service Detection](#service-detection)
  - [Banner Grabbing](#banner-grabbing)
  - [Version Parsing](#version-parsing)
  - [Known Services](#known-services)
- [OS Fingerprinting](#os-fingerprinting)
  - [How It Works](#how-it-works)
  - [Accuracy and Limitations](#accuracy-and-limitations)
- [Output Formats](#output-formats)
  - [Terminal Output](#terminal-output)
  - [JSON Output](#json-output)
  - [JSON Schema](#json-schema)
- [Performance](#performance)
  - [Thread Model](#thread-model)
  - [Tuning for Speed](#tuning-for-speed)
  - [Tuning for Stealth](#tuning-for-stealth)
  - [Benchmarks](#benchmarks)
- [Security Warnings System](#security-warnings-system)
- [Real-World Examples](#real-world-examples)
- [Architecture and Internals](#architecture-and-internals)
  - [Project Structure](#project-structure)
  - [Module Breakdown](#module-breakdown)
  - [Concurrency Model](#concurrency-model)
  - [Memory Management](#memory-management)
- [Comparison with nmap](#comparison-with-nmap)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Legal and Ethics](#legal-and-ethics)
- [License](#license)

---

## What is zigscanner?

zigscanner is a network port scanner and reconnaissance tool. You point it at a host, it tells you what's listening on that host. Simple concept, interesting implementation details.

The core use case is exactly what you'd expect: you're a sysadmin, a penetration tester, or a developer who needs to know what services are exposed on a machine. Maybe you want to audit your own infrastructure. Maybe you're doing an authorized red team engagement. Maybe you just forgot which port you started that development server on and you'd rather scan localhost than scroll through your terminal history.

Whatever the reason, zigscanner will methodically probe TCP and UDP ports, grab service banners where possible, make educated guesses about the OS, flag anything that looks particularly dangerous, and give you the results in a clean format — either human-readable terminal output or machine-readable JSON.

It is not trying to replace nmap. nmap has been in development since 1997, has scripting engine support, a massive community, and a level of polish that comes from decades of iteration. zigscanner is a single-binary tool that does the most important 80% of what port scanning needs to do, with zero external dependencies, in a codebase you can actually read in an afternoon.

---

## Why Zig?

Fair question. The honest answer is a mix of practical reasons and personal preference.

**Practical reasons:**

Zig compiles to a single static binary with no runtime dependencies. You copy the binary to a machine, it runs. No Python version conflicts, no missing shared libraries, no "you need to install this package first." In a pentesting or ops context, this matters a lot — you're often working on machines that aren't your own, and installing toolchains is not always an option.

Zig's performance is comparable to C. For a port scanner where you're potentially opening and closing thousands of TCP connections per second, this matters. The overhead per connection needs to be minimal, and Zig delivers that without requiring you to write unsafe pointer arithmetic by hand.

Zig has explicit memory management without the complexity of C's manual malloc/free and without a garbage collector that could pause at inconvenient times. You know exactly when memory is allocated and freed. This makes the tool more predictable under load, which is exactly what you want when you're slamming a target with 500 concurrent threads.

**Personal reasons:**

Zig's error handling is elegant. Every function that can fail returns a proper error union, and the compiler will yell at you if you forget to handle an error case. This results in code that actually handles failure gracefully, which is important when you're dealing with networks — networks fail constantly, in every conceivable way, and your tool needs to not crash when they do.

The language is also just... readable. The syntax is explicit, there's no magic, and someone who knows C can read Zig code without too much trouble. This matters for a security tool, because a security tool that nobody can audit isn't a security tool — it's a liability.

Finally: it's fun. Not every technical decision needs a business case.

---

## Features

**Scanning**
- TCP Connect scan — the reliable, no-root-required option
- TCP SYN scan — half-open stealth scanning (requires root/administrator)
- UDP scan — probes common UDP services with protocol-appropriate payloads
- Ping/host discovery scan — check if hosts are up without port scanning
- Atomic work-stealing thread pool — self-balancing across available cores

**Detection**
- Banner grabbing — reads what services say when you connect
- Version detection — parses banner strings into meaningful version information
- OS fingerprinting — heuristic detection from port patterns and banner content
- Web framework detection — identifies Apache, nginx, IIS, Express, Flask, Tomcat, etc.
- TTL-based OS hinting for local network scans

**Output**
- Clean terminal output with real-time port discovery notifications
- JSON export for integration with SIEM, scripts, or dashboards
- Verbose mode with full banner display
- Security warnings for exposed sensitive services (Docker API, Redis, MongoDB, etc.)

**Usability**
- Flexible port range syntax (`80`, `22,80,443`, `1-1024`, `top`, `all`)
- Configurable thread count and connection timeout
- Hostname resolution with resolved IP display
- Sensible defaults that work well out of the box
- Zero dependencies — copy the binary and run

---

## Installation

### Building from Source

You need Zig 0.13 or newer. Get it from [ziglang.org/download](https://ziglang.org/download/).

```bash
# Clone the repository
git clone https://github.com/p1rater/zigscanner
cd zigscanner

# Debug build (slower, better error messages, leak detection)
zig build

# Release build — this is what you want for actual use
# ReleaseFast is roughly 5-10x faster than Debug
zig build -Doptimize=ReleaseFast

# The binary will be at:
./zig-out/bin/zigscanner

# Optional: install to /usr/local/bin
sudo cp ./zig-out/bin/zigscanner /usr/local/bin/
```

That's it. No `apt-get install libpcap-dev`, no `pip install`, no `npm install`. Just Zig and the source code.

### Cross-Compilation

One of Zig's genuinely great features is dead-simple cross-compilation. You can build a Windows binary from Linux, or a Linux binary from macOS, with a single flag. No cross-compiler toolchain to set up, no Docker containers, nothing.

```bash
# Build for Windows x86-64 (from any platform)
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-windows

# Build for Linux ARM64 (e.g., for a Raspberry Pi or AWS Graviton)
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux

# Build for macOS Apple Silicon
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-macos

# Build for 32-bit Linux (for that ancient server you keep meaning to replace)
zig build -Doptimize=ReleaseFast -Dtarget=x86-linux

# Build for MIPS (embedded routers and similar)
zig build -Doptimize=ReleaseSmall -Dtarget=mips-linux
```

The resulting binary in `zig-out/bin/` will run on the target platform without any additional installation. Drop it in `/usr/local/bin` and you're done.

### Dependencies

There are none. Seriously. The entire tool is built on Zig's standard library. This is intentional — zero external dependencies means zero supply chain risk, and you can audit everything the tool depends on by reading the Zig stdlib source.

The one caveat is that TCP SYN scanning requires raw socket access, which on Linux means either running as root or having the `CAP_NET_RAW` capability set on the binary. The tool detects this automatically and falls back to TCP connect scanning if it doesn't have the required permissions.

---

## Quick Start

```bash
# Scan the most common ports on a host
zigscanner 192.168.1.1

# Scan all ports with service detection
zigscanner -p all -sV 192.168.1.1

# Fast scan of common ports with OS detection and JSON output
zigscanner -p top -sV -O -o results.json 192.168.1.1
```

Example output:

```
 ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
 ▒  zigscanner v0.1.0                     ▒
 ▒  Network Reconnaissance Tool           ▒
 ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

[*] Target: 192.168.1.100
[*] Port range: 1-1024
[*] Threads: 100
[*] Timeout: 1000ms

[*] Resolved 192.168.1.100 -> 192.168.1.100
[*] Scanning 1024 ports with 100 threads...

  [+] 22/tcp   open  ssh
  [+] 80/tcp   open  http
  [+] 443/tcp  open  https
  [+] 3306/tcp open  mysql

──────────────────────────────────────────────────────────
  Scan Results for: 192.168.1.100
──────────────────────────────────────────────────────────

  Host Status  : UP (2.31ms latency)
  OS Guess     : Linux (web server stack) (confidence: low-medium)
  Ports Scanned: 1024
  Open Ports   : 4
  Scan Time    : 3842ms

  PORT     STATE        SERVICE              VERSION/INFO
  ────────────────────────────────────────────────────────
  22/tcp   open         ssh                  | OpenSSH_8.9p1
  80/tcp   open         http                 | Apache/2.4.54
  443/tcp  open         https
  3306/tcp open         mysql               ⚠

  ⚠  SECURITY NOTES:
  •  Port 3306 (mysql): Databases exposed to the network.
     Verify this is intentional and access is restricted.

──────────────────────────────────────────────────────────
```

---

## Usage

### Basic Syntax

```
zigscanner [OPTIONS] <target>
```

`<target>` can be an IPv4 address or a hostname. IPv6 support is planned for a future version.

### Port Ranges

The `-p` flag accepts several formats:

```bash
# Single port
zigscanner -p 80 192.168.1.1

# Port range — most common usage
zigscanner -p 1-1024 192.168.1.1

# Well-known ports (1-1024) — same as default
zigscanner -p top 192.168.1.1

# All TCP ports — this takes a while
zigscanner -p all 192.168.1.1
zigscanner -p 1-65535 192.168.1.1

# "full" is an alias for "all"
zigscanner -p full 192.168.1.1
```

### Scan Types

| Flag | Name | Description | Requires Root |
|------|------|-------------|---------------|
| *(default)* | TCP Connect | Full three-way handshake | No |
| `-sS` / `--syn` | TCP SYN | Half-open stealth scan | **Yes** |
| `-sU` / `--udp` | UDP | UDP probe scan | No |
| `-sn` / `--ping` | Ping | Host discovery only | No |

### All Options

```
zigscanner [OPTIONS] <target>

TARGET:
  IPv4 address or hostname to scan

SCAN TYPE:
  (default)           TCP connect scan (no root required)
  -sS, --syn          TCP SYN stealth scan (requires root)
  -sU, --udp          UDP scan
  -sn, --ping         Ping/host discovery scan only (no port scan)

PORT SELECTION:
  -p, --ports <range>
      Port range to scan. Accepted formats:
        80              Single port
        1-1024          Range (inclusive on both ends)
        top             Ports 1-1024 (shorthand alias)
        all / full      All ports 1-65535
      Default: 1-1024

TIMING AND PERFORMANCE:
  -t, --threads <n>
      Number of concurrent scanning threads.
      More threads = faster scan but more load on target and network.
      Range: 1-5000. Default: 100.

  --timeout <ms>
      How long to wait for a connection before declaring the port
      filtered or closed. In milliseconds.
      Default: 1000 (1 second).
      Increase for slow/distant targets, decrease for fast local networks.

DETECTION:
  -sV, --service-detect
      Enable service and version detection. Grabs banners from open ports
      and attempts to parse version strings. Adds a few seconds per open
      port but significantly improves the quality of output.

  -O, --os-detect
      Enable OS fingerprinting. Uses a combination of open port patterns
      and service banners to make an educated guess about the target OS.
      Results have low-to-medium confidence — treat them as hints, not facts.

OUTPUT:
  -v, --verbose
      Enable verbose output. Shows raw banners for each open port,
      additional timing information, and closed/filtered port details.

  -o, --output <file>
      Write results to a file in JSON format in addition to displaying
      them in the terminal. The file is created or overwritten.

MISCELLANEOUS:
  -h, --help          Show this help text and exit
  -V, --version       Show version number and exit
```

---

## Scan Modes In Depth

### TCP Connect Scan

This is the default mode and the one you'll use most of the time.

The scanner opens a full TCP connection to each target port — the standard three-way handshake (SYN → SYN-ACK → ACK). If the connection succeeds, the port is open. If the target responds with RST, the port is closed. If there's no response within the timeout window, the port is considered filtered (a firewall is likely dropping packets silently).

**Pros:**
- Works without root or elevated privileges
- Reliable — you get definitive open/closed/filtered results
- Works correctly through NAT and most firewalls
- Doesn't require raw socket access
- The connection attempt appears legitimate to the target service

**Cons:**
- Not stealthy — the full connection appears in the target's logs
- Slightly slower than SYN scan because it completes the full handshake
- Some aggressive firewalls rate-limit or block source IPs that open many connections quickly

This is the right mode for scanning your own infrastructure, doing legitimate authorized testing, or running as a non-root user.

### TCP SYN Scan

SYN scan, also called half-open scanning or stealth scanning, sends a SYN packet and waits for the response, but deliberately never completes the handshake.

- Target responds with **SYN-ACK** → port is **open** → scanner sends RST to tear down the half-open connection
- Target responds with **RST** → port is **closed**
- No response within timeout → port is **filtered**

Because the connection is never completed, many older logging systems don't record incomplete handshakes. This is why it's called "stealth" scanning — though any modern IDS worth its license fee will catch it regardless. The value of SYN scan isn't invisibility; it's speed. Half-open connections are torn down faster than full connections, allowing higher throughput at the same thread count.

**Requires root or CAP_NET_RAW.** The scanner needs to craft raw IP packets directly, which isn't possible with normal user permissions.

```bash
# Run as root
sudo zigscanner -sS 192.168.1.1

# Or grant the binary the specific capability (preferred — avoids full root)
sudo setcap cap_net_raw+ep ./zig-out/bin/zigscanner
zigscanner -sS 192.168.1.1
```

If zigscanner detects it doesn't have the required permissions when `-sS` is specified, it will fall back to TCP connect scan and print a warning. It won't silently do something unexpected.

### UDP Scan

UDP is fundamentally different from TCP. There's no connection, no handshake, no guarantee of delivery. You send a packet. Maybe you get a response. Maybe you don't. Maybe it gets there. Maybe it doesn't. UDP is chaos with a port number.

This ambiguity makes UDP scanning inherently unreliable compared to TCP:

- If you receive a **UDP response**, the port is definitely **open**
- If you receive **ICMP "port unreachable" (type 3, code 3)**, the port is **closed**
- If you receive **nothing**, the port is **open or filtered** — you genuinely cannot tell from this alone

zigscanner's UDP implementation sends protocol-appropriate probes for well-known UDP services where possible — DNS queries to port 53, NTP mode 3 requests to port 123, SNMP GetRequest to port 161, etc. This maximizes the chance of getting a meaningful response from services that are actually listening.

UDP scanning is slow. This is unavoidable. Because you have to wait for the full timeout on every non-responding port, and most ports don't respond, a full UDP scan of all 65535 ports can take hours. Limit UDP scans to specific ports of interest.

```bash
# Scan the most interesting UDP services
zigscanner -sU -p 53,67,68,69,123,161,500,514 192.168.1.1

# Or the first 1024 UDP ports — this will take a while, grab a coffee
zigscanner -sU -p 1-1024 --timeout 2000 192.168.1.1
```

If you're doing serious UDP work, consider supplementing with a dedicated UDP scanner or Wireshark capture alongside the zigscanner run.

### Ping Scan

Despite the name, this doesn't send actual ICMP echo requests — that would require raw sockets and root privileges. Instead, the ping scan mode checks whether a host is up by attempting TCP connections to a short list of ports that are almost always open on active hosts (80, 443, 22, 8080). If any of them respond, the host is considered up.

This mode skips port scanning entirely. It's useful if you just want to check reachability before committing to a longer scan, or if you want to sweep a range of hosts for liveness (though zigscanner doesn't support CIDR ranges yet — that's a planned feature).

```bash
zigscanner --ping 192.168.1.1
```

The output includes the measured latency to the host based on the first successful connection.

---

## Service Detection

### Banner Grabbing

When a port is found open and `-sV` is specified, zigscanner attempts to grab the service banner — the initial data that the service sends when a connection is established.

Many services announce themselves immediately after a connection is made:

```
SSH:   SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
FTP:   220 ProFTPD 1.3.6 Server (Debian) [::ffff:192.168.1.1]
SMTP:  220 mail.example.com ESMTP Postfix (Ubuntu)
POP3:  +OK Dovecot ready.
```

Others need to be asked first. HTTP is the classic example — it says nothing until you send a request. zigscanner sends a minimal `HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n` to HTTP-looking ports and reads the response headers, which typically contain a `Server:` header with version information.

Banners are capped at 1024 bytes. Most banners are much shorter than this, but some services (notably certain databases and mail servers) can send verbose initial messages including certificates, capabilities lists, and similar. We truncate to keep things readable.

In verbose mode (`-v`), the full raw banner (up to 80 display characters) is shown below each port entry in the results table.

### Version Parsing

Raw banners are useful but verbose. zigscanner attempts to parse them into cleaner version strings that can be displayed compactly in the results table.

| Service | Raw Banner | Parsed Version |
|---------|-----------|----------------|
| SSH | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | `OpenSSH_8.9p1` |
| HTTP | `HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)` | `Apache/2.4.54 (Ubuntu)` |
| FTP | `220 ProFTPD 1.3.6 Server` | `ProFTPD 1.3.6 Server` |
| SMTP | `220 mail.example.com ESMTP Postfix` | `Postfix` |

Parsing is pattern-based rather than signature-database-based (unlike nmap's version detection, which maintains a large database of service signatures). It handles the most common cases well, but unusual or custom-configured services may not parse cleanly. In those cases, the raw banner is still available in verbose mode.

### Known Services

zigscanner maintains a lookup table mapping port numbers to service names. This covers approximately 70 well-known ports, weighted toward the services that actually matter for security assessments:

**Standard protocols:** echo (7), FTP (20/21), SSH (22), Telnet (23), SMTP (25), DNS (53), DHCP (67/68), TFTP (69), HTTP (80), Kerberos (88), POP3 (110), NTP (123), NetBIOS (137-139), IMAP (143), SNMP (161/162), LDAP (389), HTTPS (443), SMB (445), and many more.

**Databases:** MySQL (3306), PostgreSQL (5432), Oracle (1521), MSSQL (1433), MongoDB (27017), Redis (6379), Elasticsearch (9200), CouchDB (5984).

**Infrastructure and DevOps:** Docker API (2375/2376), Kubernetes API (6443), etcd (2379/2380), Kafka (9092/9093), RabbitMQ (5672) + management (15672), Prometheus (9090), node-exporter (9100), Grafana (3000).

**Remote access:** RDP (3389), VNC (5900-5902), WinRM (5985/5986).

**VPN:** OpenVPN (1194), WireGuard (51820), PPTP (1723), IPSec NAT-T (4500).

**Gaming and misc:** Minecraft Java (25565), Minecraft Bedrock (19132), Steam (27015/27016).

Ports not in the table are reported as `unknown`. This is not a bug — not every port needs to be named.

---

## OS Fingerprinting

### How It Works

OS fingerprinting in zigscanner uses two complementary approaches, applied in order of reliability:

**Banner analysis** is the primary and most reliable method. Service banners often contain explicit OS information. OpenSSH's default banner includes the distribution name in plain text:

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
                              ^^^^^^
                              Free OS information, courtesy of sshd defaults.
```

Similarly, Microsoft IIS banners include "IIS" in the Server header, Apache on Ubuntu banners often say "(Ubuntu)", and various network device vendors have telltale strings in their FTP or Telnet banners.

zigscanner checks every grabbed banner against a list of known OS-identifying patterns. When service detection (`-sV`) is enabled, this analysis happens automatically.

**Port pattern heuristics** are the fallback when banners don't give it away. Different operating systems have different typical port profiles:

Windows has a very distinctive fingerprint. It almost always runs SMB (port 445) and MSRPC (port 135), because these are core Windows services that run by default. A host with both of these open is overwhelmingly likely to be Windows. RDP (3389) or WinRM (5985) add further confidence.

Linux servers don't have a universal fingerprint, but common patterns emerge. SSH without SMB/MSRPC suggests Linux or another Unix-like. Adding HTTP (80/443) and MySQL (3306) suggests a LAMP-style web server.

Network devices (routers, switches, managed hubs) often have SNMP (161) open and Telnet (23) but no SSH — this pattern is consistent with embedded network equipment, especially older firmware.

macOS is genuinely hard to fingerprint from port patterns alone. A stock macOS machine might expose nothing at all, or have Bonjour/mDNS-related services that don't appear in a normal TCP scan. If running server software via Homebrew, it can look like Linux.

**TTL-based hinting** is a tertiary signal. Different OSes ship with different default IP TTL values (Windows: 128, Linux/macOS: 64, Cisco: 255). TTL decrements by 1 per hop, so it's most useful on local network scans where the packet hasn't passed through many routers. On the open internet, you're often seeing the TTL after 10-15 hops and the original value is ambiguous.

### Accuracy and Limitations

OS fingerprinting in zigscanner is explicitly described as "low-to-medium confidence." This is deliberate and honest.

Legitimate reasons the guess might be wrong:

**Custom banners.** Many security-conscious admins change their SSH banner or HTTP Server header. An Ubuntu server configured to respond with a generic `SSH-2.0-OpenSSH` banner with no distro suffix will look like "unknown Linux/Unix." IIS servers are sometimes configured to suppress version information entirely.

**Containers.** A Docker container running on a Kubernetes cluster on Ubuntu shows Ubuntu in its SSH banner, but the underlying host might be running Flatcar Linux or Bottlerocket. The container and the host OS are independent.

**Unexpected port combinations.** Samba running on Linux makes the host look like Windows from a port pattern perspective. macOS running Homebrew services opens whatever ports those services need. Wine on Linux running Windows-native server software is just wild.

**Firewalls.** If only a subset of ports are reachable through a firewall, the port pattern used for heuristics is incomplete. You might be seeing the exposed subset of a Windows Server and concluding "unknown" because the SMB/RPC ports aren't reachable.

**Virtual machines.** A heavily locked-down VM might have a very different port profile than a physical machine running the same OS.

Always treat OS detection results as a starting hypothesis, not a conclusion. Use them to guide your next steps, not to write your final report.

---

## Output Formats

### Terminal Output

Terminal output is designed to be immediately readable and provide useful information at a glance.

Open ports are printed in real-time as they're discovered, so you get immediate feedback on long scans rather than staring at a blank screen for five minutes. This real-time output uses a simple `[+] port/proto  state  service` format.

After all scanning completes, a formatted summary table is printed. The table columns are:

| Column | Description |
|--------|-------------|
| PORT | Port number and protocol (e.g., `443/tcp`) |
| STATE | `open`, `closed`, `filtered`, or `open\|filtered` |
| SERVICE | Guessed service name from the port lookup table |
| VERSION/INFO | Parsed version string from banner (with `-sV`) |

Ports flagged as security-sensitive are marked with `⚠` in the table and listed with detailed explanations in a Security Notes section below the table.

The summary header includes host status, resolved IP, measured latency, OS guess (if enabled), count of ports scanned, count of open ports, and total scan duration. This is the metadata you need to contextualize the results.

### JSON Output

Use `-o filename.json` to write results to a JSON file. Terminal output is still shown — the JSON is written in addition, not instead. The file is written atomically after the scan completes — you won't get a partial JSON file if the scan is interrupted midway.

```bash
# Output to a dated file
zigscanner -p 1-65535 -sV -O -o scan-$(date +%Y%m%d-%H%M%S).json 192.168.1.1

# Or a fixed name for scripted ingestion
zigscanner -p top -sV -o /tmp/latest-scan.json 10.0.0.1
```

The JSON output is formatted for readability with 2-space indentation. If you need compact JSON for programmatic processing, pipe through `jq -c`.

### JSON Schema

```json
{
  "target": "192.168.1.1",
  "ip_address": "192.168.1.1",
  "is_up": true,
  "latency_ms": 2.31,
  "ports_scanned": 1024,
  "scan_duration_ms": 3842,
  "os_guess": "Linux (web server stack)",
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "sensitive": false,
      "version": "OpenSSH_8.9p1",
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    },
    {
      "port": 3306,
      "protocol": "tcp",
      "state": "open",
      "service": "mysql",
      "sensitive": true
    }
  ]
}
```

Full field reference:

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `target` | string | Yes | Original target as specified by user |
| `ip_address` | string | Yes | Resolved IP address |
| `is_up` | boolean | Yes | Whether host appears to be up |
| `latency_ms` | float | Yes | Estimated latency in milliseconds |
| `ports_scanned` | integer | Yes | Total number of ports in scan range |
| `scan_duration_ms` | integer | Yes | Total scan time in milliseconds |
| `os_guess` | string or null | Yes | OS fingerprint guess, null if unknown or not enabled |
| `open_ports` | array | Yes | Array of open/filtered port objects |
| `open_ports[].port` | integer | Yes | Port number (1-65535) |
| `open_ports[].protocol` | string | Yes | `"tcp"` or `"udp"` |
| `open_ports[].state` | string | Yes | `"open"`, `"filtered"`, or `"open_filtered"` |
| `open_ports[].service` | string | Yes | Service name from lookup table |
| `open_ports[].sensitive` | boolean | Yes | Whether port is flagged as sensitive |
| `open_ports[].version` | string | No | Parsed version string (only with `-sV`) |
| `open_ports[].banner` | string | No | Raw banner, JSON-escaped (only with `-sV`) |

Banner strings in JSON output are fully escaped — control characters, quotes, and backslashes are all handled correctly. You won't get malformed JSON from a banner that contains newlines or weird bytes.

---

## Performance

### Thread Model

zigscanner uses an atomic work-stealing model for port distribution across threads. Rather than pre-assigning ranges of ports to threads (which leads to uneven completion when some ports respond quickly and others time out), each thread atomically increments a shared counter to claim the next unscanned port.

The sequence looks like this:

```
Thread 1: fetchAdd(counter) -> claims port 1  -> connection refused (fast) -> claims port 5...
Thread 2: fetchAdd(counter) -> claims port 2  -> connection timeout (slow) -> still waiting...
Thread 3: fetchAdd(counter) -> claims port 3  -> connection refused (fast) -> claims port 6...
Thread 4: fetchAdd(counter) -> claims port 4  -> connection refused (fast) -> claims port 7...
```

Thread 2 is stuck waiting on a timeout, but threads 1, 3, and 4 keep making progress. This is much better than if Thread 2 had been pre-assigned ports 2-250 and threads 1, 3, 4 all finished their ranges and sat idle while Thread 2 waited through 249 timeouts.

The atomic `fetchAdd` operation is the key primitive here. It's lock-free, meaning threads never block waiting for each other to claim the next port. The only shared mutex is on the results list, and it's held only for the brief moment of appending a discovered open port — which is rare relative to the number of closed/filtered ports.

### Tuning for Speed

If you want the fastest possible scan and don't care about being subtle:

```bash
# Aggressive speed — 500 threads, 300ms timeout
zigscanner -p 1-65535 -t 500 --timeout 300 192.168.1.1
```

Caveats when pushing for speed:
- High thread counts can overwhelm your local network interface (packet loss, kernel connection table limits)
- Very short timeouts will miss filtered ports that respond slowly and may cause false negatives on open ports too
- Some hosts have connection rate limits or fail2ban-style protection that will block your source IP
- Network equipment between you and the target may struggle with burst connection rates

A reasonable "fast but not reckless" configuration for a local network:

```bash
# Fast but sane for local network
zigscanner -p 1-65535 -t 200 --timeout 500 192.168.1.1
```

For scanning over the internet (WAN), the limiting factor shifts from your thread count to network latency. 500 threads pointing at a server 100ms away won't go faster than the RTT allows. For WAN targets, 100-200 threads with a 2000-3000ms timeout is usually more effective.

### Tuning for Stealth

During authorized engagements where staying under the radar matters:

```bash
# Low and slow — 10 threads, 2s timeout, SYN scan
sudo zigscanner -sS -p 1-1024 -t 10 --timeout 2000 192.168.1.1
```

Slower thread counts mean fewer simultaneous connections, which is harder for simple rate-based IDS rules to trigger on. SYN scan avoids completing connections, which means they often don't appear in application-layer logs. Longer timeouts reduce false negatives and make the traffic pattern look less machine-generated.

That said: a properly configured network IDS running packet-level analysis will see your scan regardless of how slowly you do it. Stealth in port scanning is relative — you're evading basic alerting, not professional monitoring.

### Benchmarks

Rough numbers on a 1Gbps local network, scanning a Linux host with most ports in the tested range closed (typical case):

| Configuration | Port Range | Approximate Time |
|--------------|------------|-----------------|
| Default (100 threads, 1000ms timeout) | 1-1024 | ~4 seconds |
| Fast (500 threads, 300ms timeout) | 1-1024 | ~1 second |
| Default settings | 1-65535 | ~4.5 minutes |
| Fast settings | 1-65535 | ~45 seconds |
| Aggressive (1000 threads, 200ms timeout) | 1-65535 | ~20 seconds |

Scanning over the internet typically runs 10-30x slower than local network, depending on latency and packet loss. Adjust your timeout to be at least 2-3x the RTT to the target.

---

## Security Warnings System

zigscanner maintains a list of ports that are commonly exposed by accident or misconfiguration and represent significant security risks when accessible from the network. These aren't just "interesting ports" — they're ports that have historically been the source of serious incidents when left open.

When any of these ports appear in the scan results, they're flagged with `⚠` in the output table and listed with an explanation in the Security Notes section at the bottom of the results.

Currently flagged ports and their associated risks:

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Credentials transmitted in plaintext; easily sniffed |
| 23 | Telnet | Entire session unencrypted; credentials, commands, all of it |
| 2375 | Docker API (no TLS) | Unauthenticated access = instant root on the host |
| 2379 | etcd | Contains Kubernetes cluster secrets, often including credentials |
| 3389 | RDP | Frequent brute force target; many known exploits |
| 5900 | VNC | Often deployed with weak or no password authentication |
| 6379 | Redis | Default install has no authentication at all |
| 9200 | Elasticsearch | Default install allows unauthenticated read/write of all data |
| 27017 | MongoDB | Default install has no authentication (infamous for data leaks) |
| 3306 | MySQL | Databases generally should not be directly network-accessible |
| 5432 | PostgreSQL | Same concern as MySQL |
| 1433 | MSSQL | Same concern; also historically a target for worms |
| 6443 | Kubernetes API | Full cluster administration if accessible without auth |

The warnings are contextual, not absolute. MySQL listening on localhost is perfectly fine; MySQL bound to 0.0.0.0 and reachable from the internet is a critical exposure. The tool flags port 3306 as sensitive whenever it's open and accessible from the scanning host — whether that's appropriate depends on your network topology.

---

## Real-World Examples

**Audit a web server to see what's actually exposed:**
```bash
zigscanner -p 1-65535 -sV 203.0.113.42
```

**Quick check after setting up a new Linux VM — make sure only the right ports are open:**
```bash
zigscanner -p all 10.10.0.5
# If you see anything besides 22 (and maybe 80/443), investigate.
```

**Check if a Redis instance is accidentally network-accessible:**
```bash
zigscanner -p 6379 10.10.0.20
# open = bad day. filtered/closed = good.
```

**Scan a machine as a non-root user — connect scan only:**
```bash
zigscanner -p top -sV -v 192.168.1.1
```

**Produce a timestamped JSON report for a security audit:**
```bash
zigscanner -p 1-65535 -sV -O -o "audit-$(hostname)-$(date +%Y%m%d).json" 10.0.0.1
```

**Find anything weird running on high ports:**
```bash
# Malware and rogue developer services love high ports
zigscanner -p 10000-65535 --timeout 500 -t 300 10.0.0.50
```

**Scan a target over a slow VPN connection:**
```bash
# High latency needs higher timeout; fewer threads to avoid overwhelming the link
zigscanner -p top -sV --timeout 5000 -t 50 10.8.0.1
```

**Check infrastructure before a go-live:**
```bash
# Verify only expected ports are open on production servers
for ip in 10.0.1.1 10.0.1.2 10.0.1.3; do
    echo "=== Scanning $ip ==="
    zigscanner -p all -o "prescan-$ip.json" "$ip"
done
```

**Fast check of a Docker host for the dreaded exposed daemon:**
```bash
# Port 2375 open = full host compromise possible. Check immediately.
zigscanner -p 2375,2376 10.0.0.50
```

---

## Architecture and Internals

### Project Structure

```
zigscanner/
├── build.zig               # Zig build system configuration
│                           # Cross-compilation targets, optimization levels
└── src/
    ├── main.zig            # Entry point: allocator init, arg parse, scan, output
    ├── args.zig            # CLI argument parsing and validation
    ├── scanner.zig         # Core scanning engine: threads, TCP/UDP/SYN, banner grab
    ├── services.zig        # Port → service name table, sensitive port registry
    ├── fingerprint.zig     # OS and service fingerprinting heuristics
    ├── output.zig          # Terminal formatting and JSON serialization
    └── version.zig         # Version string and build metadata
```

Total source: approximately 1,500 lines of Zig including comments. This is intentional — a security tool you can read in a few hours is a security tool you can actually trust.

### Module Breakdown

**`main.zig`** is the top-level orchestrator and is deliberately thin. It initializes a `GeneralPurposeAllocator`, passes it to the argument parser, uses the parsed config to call `scanner.runScan()`, and passes the results to `output.printResults()`. Error handling for user-facing failures (no target specified, invalid port range, etc.) lives here, each producing a clear error message before exiting with a non-zero code.

**`args.zig`** implements the CLI parser. It uses a simple manual approach — iterate `argv`, match flag strings, parse values. Error types are specific named errors (`ArgError.NoTarget`, `ArgError.InvalidPort`, `ArgError.HelpRequested`) rather than generic error codes. This lets `main.zig` pattern-match on exactly what went wrong and produce targeted messages. `HelpRequested` and `VersionRequested` are returned as errors (not handled inline) so the main function stays clean.

**`scanner.zig`** is the interesting one. The top-level `runScan()` function builds a `ScanContext` — a struct holding shared mutable state. The key fields are `next_port`, an `std.atomic.Value(u32)` that serves as the work counter, and `open_ports`, an `ArrayList` protected by a `Mutex`. Worker threads are spawned via `std.Thread.spawn()`, each running `scanWorker()`. `scanWorker()` loops on `next_port.fetchAdd(1, .seq_cst)` until the returned value exceeds `port_end`, scanning each claimed port and appending results to `open_ports` under mutex. After threads join, results are sorted by port number.

**`services.zig`** is a giant `switch` statement mapping `u16` port numbers to `[]const u8` string literals. The string literals have static lifetime (they live in the binary's data segment), so `lookupPort()` returns a slice with no allocation. `isSensitivePort()` is a separate switch that returns `bool`. `TOP_100_PORTS` is a comptime-known array of the most security-relevant ports, for use cases where you want a curated fast scan.

**`fingerprint.zig`** contains `guessOS()`, which accepts the scan results and returns an optional heap-allocated string. It first tries banner analysis (checking for OS-identifying substrings in each grabbed banner), then falls back to `heuristicOSGuess()` which reasons about the port combination using a port presence hashmap. `detectWebFramework()` does similar pattern matching on HTTP banners to identify the web server or application framework — useful supplementary information for web-facing hosts.

**`output.zig`** is presentation layer code. `printBanner()` draws the ASCII header at startup. `printResults()` renders the scan summary and port table after completion. `printSensitiveWarnings()` checks each open port against `services.isSensitivePort()` and prints appropriate explanations. `writeJson()` serializes a `ScanResult` to JSON, with `writeJsonEscapedString()` handling the character escaping correctly — control characters, quotes, and backslashes all get proper JSON escape sequences.

### Concurrency Model

The thread model is intentionally minimal. One global work queue (the atomic `next_port` counter), one shared results list (protected by a single `Mutex`), and N worker threads doing the same work loop.

There are no condition variables. No per-thread queues. No work-stealing between queues. No message passing channels. No semaphores. The `Mutex` is acquired only when appending an open port result — which is rare, because most ports are closed or filtered. Contention is minimal in practice.

Deadlock is impossible by construction: there is exactly one mutex, and it is never acquired while holding another mutex. The atomic counter is lock-free. The only blocking operations are the actual TCP connect calls (waiting for the kernel's connect to complete or timeout).

The tradeoff of this simplicity is that all threads compete for a single mutex when recording results. With 500 threads and a busy host with many open ports, there could be contention. Benchmarking has not shown this to be a bottleneck in practice — the connection attempt itself (even a refused one) dominates the time per port, not the mutex acquisition.

### Memory Management

All heap allocations go through the `GeneralPurposeAllocator` passed down from `main()`. In debug builds, the GPA reports any leaked allocations at program exit — this was the primary tool used to ensure there are no memory leaks, and the codebase is clean.

Ownership follows Zig's idiomatic convention: whoever allocates, deallocates. `Config.deinit()` frees the target and output_file strings it owns. `ScanResult.deinit()` frees the IP address, hostname, OS guess, and all port result structs. `PortResult.deinit()` frees any banner and version strings.

Service name strings (`services.lookupPort()` return values) are `[]const u8` slices into static string literals — no allocation, no deallocation, no lifetime concern. Banner strings are heap-allocated because their size is not known at compile time. Version strings are parsed from banners and are also heap-allocated.

The allocator is threaded through the call chain explicitly rather than using a global allocator. This is slightly more verbose but means you always know where memory comes from and who owns it.

---

## Comparison with nmap

People will ask. Here's an honest comparison:

| Feature | zigscanner | nmap |
|---------|-----------|------|
| TCP Connect scan | ✅ | ✅ |
| TCP SYN scan | ✅ simplified | ✅ full implementation |
| UDP scan | ✅ basic probes | ✅ comprehensive signatures |
| SCTP scan | ❌ | ✅ |
| IPv6 | ❌ planned | ✅ |
| CIDR range scanning | ❌ planned | ✅ |
| NSE scripting engine | ❌ by design | ✅ thousands of scripts |
| OS fingerprinting | ✅ heuristic | ✅ ML-based, very accurate |
| Version detection | ✅ banner parsing | ✅ signature database |
| Zero external dependencies | ✅ | ❌ libpcap, OpenSSL, etc. |
| Single static binary | ✅ | ❌ |
| Cross-compilation (trivial) | ✅ | ❌ complex |
| Readable codebase | ✅ ~1500 lines | ❌ 100k+ lines of C |
| Years in active development | 1 | 27 |
| Community and ecosystem | Tiny | Enormous |
| XML output | ❌ | ✅ |
| grepable output | ❌ | ✅ |
| JSON output | ✅ | ❌ native |

**Use nmap when:**
- You need any of nmap's scripting capabilities (NSE scripts cover everything from vulnerability checks to login brute forcing to service enumeration)
- You need highly accurate OS detection
- You're scanning IPv6 targets
- You're scanning CIDR ranges
- You need to cite a tool with 25+ years of validation in a professional report
- You need XML output for existing toolchain integration

**Use zigscanner when:**
- You want a single binary with zero dependencies that you can drop on any machine
- The job is a straightforward port scan with banner grabbing
- You want to read, audit, or modify your tool's source code
- You're building a scanning pipeline and want something you can fork easily
- You're learning network programming and want a readable codebase to study

They serve different roles. Use the right one for the job.

---

## Troubleshooting

**"Host appears to be down" but the host is definitely up**

zigscanner checks liveness by attempting TCP connections to ports 80, 443, 22, and 8080. If none of those are open on the target, it reports the host as possibly down but continues scanning regardless. This is a warning, not a hard stop. A host that exclusively runs services on non-standard ports will trigger this false negative — but the port scan will still find those services.

**Scan is taking forever**

Several possible causes in order of likelihood:

First, check your timeout setting. If you're scanning 65535 ports with a 1000ms timeout and most ports are filtered (no response), that's potentially 65535 × 1 second = 18 hours single-threaded. With 100 threads it's 18 minutes. Dropping `--timeout` to 300ms and bumping threads to 300 brings a full port scan to under a minute on a local network.

Second, filtered ports are the enemy of fast scans. A firewall that silently drops packets (rather than responding with RST) forces you to wait for the full timeout on every filtered port. You can't avoid this without reducing timeout.

Third, network congestion causes packet loss, which causes retries, which causes slowdowns. High thread counts on a slow link or through a VPN can cause more congestion than they overcome.

**SYN scan fails with permission denied**

Expected. SYN scan requires raw socket access. See [TCP SYN Scan](#tcp-syn-scan) for how to either run as root or grant the specific capability with `setcap`.

**Build fails with a Zig error about API changes**

Zig's standard library API changes between versions, especially before 1.0. The most common breakage points are around I/O, networking, and allocator interfaces. Check the `build.zig.zon` (if present) for the expected Zig version, or `zig version` to see what you have. If they don't match, either update Zig or check the git log for compatibility notes.

**Results differ between runs on the same target**

Networks are not deterministic. A port that shows as filtered on one scan might show as closed on the next, depending on firewall state, service restarts, or just packet loss. For high-confidence results on filtered-heavy targets, run the scan 2-3 times and look for consistency. Ports that are consistently open or closed are reliable; ports that flip between filtered and closed are probably filtered with occasional RST leakage.

**Banner grab returns nothing on an open port**

Expected for many services. Services that require a protocol-specific handshake before sending data (most databases, many custom protocols) won't respond to a plain connection. Services that do respond are the minority. `-sV` only sends a probe for common HTTP ports; everything else relies on passive banner reception. This is a known limitation.

**High thread count causes errors or lost results**

Your system has limits on open file descriptors and simultaneous connections. On Linux, `ulimit -n` shows the current fd limit (default often 1024). Running 5000 threads each trying to open a connection will exceed this. Increase with `ulimit -n 65535` before running, or keep thread count below ~900 to stay within default limits.

---

## Contributing

Contributions are welcome. The codebase is deliberately kept small and readable — new contributions should keep it that way.

**Planned features (good first contributions):**

- CIDR notation support for scanning subnets (`192.168.1.0/24`)
- IPv6 address support
- Non-contiguous port list parsing (`-p 22,80,443,8080-8090`)
- Proper raw socket SYN scan implementation (current one falls back to connect)
- Better UDP probes using protocol-specific payloads for more services
- Additional OS fingerprint patterns (especially network devices)
- More service version parsing patterns for less common services
- `--exclude-ports` flag for skipping specific ports in a range
- Multiple target scanning (load from file)
- Output progress percentage for long scans

**How to contribute:**

1. Fork the repository on GitHub
2. Create a feature branch (`git checkout -b feature/cidr-support`)
3. Write the code with appropriate comments
4. Run `zig build test` and ensure all tests pass
5. Open a pull request with a clear description of what you changed and why

**Code style guidelines:**

Follow the existing patterns. Explicit over implicit. Handle every error — the compiler will enforce this, but try to handle them meaningfully rather than just propagating with `try`. Write comments for non-obvious decisions: not what the code does, but why it does it that way. If a piece of code is "a bit silly but it works," say so in a comment — that context is valuable.

Keep it readable. The target reader is a competent programmer who doesn't know Zig deeply. If something is clever at the expense of clarity, reconsider.

---

## Legal and Ethics

Port scanning is a dual-use activity. The tool itself is neutral — it sends TCP packets and reports what responds. What matters is the context and authorization.

**Always get written authorization before scanning a system you don't own.** This is not a suggestion or a legal formality — unauthorized port scanning is a criminal offense in many jurisdictions. The Computer Fraud and Abuse Act in the United States, the Computer Misuse Act in the United Kingdom, and equivalent legislation in most countries treat unauthorized access to computer systems (and probing for access) as criminal activity. "I was just looking" is not a recognized legal defense.

Authorized contexts where port scanning is appropriate:

- Systems you personally own (your own hardware, your own VPS, your own cloud instances)
- Systems you are employed or contracted to administer, within the documented scope of your role
- Penetration testing or red team exercises covered by a signed scope-of-work document
- Capture-the-Flag competitions and intentionally vulnerable lab environments (HackTheBox, TryHackMe, etc.)
- Bug bounty programs that explicitly include network scanning within their defined scope

When in doubt, ask. A legitimate target will provide written permission. If they won't or can't, that's your answer.

Beyond legality, consider impact. An aggressive scan with high thread counts and short timeouts can affect service availability for legitimate users. On shared hosting environments, scanning one IP may affect neighboring tenants sharing the same host. On cloud providers, unexpected scanning traffic can trigger automated incident response. Be aware of your environment and calibrate your scan intensity accordingly.

---

## License

MIT License

Copyright (c) 2025 zigscanner contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

*zigscanner is a hobby project, not a product. It has no SLA, no guarantees, and no enterprise support contract. Use it at your own risk, on systems you have permission to scan, and don't do anything that will get you arrested. We've tried to make the tool as correct and safe as possible, but ultimately you're the one executing the binary — that's on you.*
