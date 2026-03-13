# zigscanner

A fast, comprehensive network reconnaissance tool written in Zig.  
Think nmap, but written in a language that makes you feel things.

```
 ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
 ▒  zigscanner v0.1.0                     ▒
 ▒  Network Reconnaissance Tool           ▒
 ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
```

## Features

- **TCP Connect Scan** — Reliable three-way handshake scanning (no root required)
- **TCP SYN Scan** — Stealth scan mode (requires root)
- **UDP Scan** — Scans common UDP services
- **Service Detection** — Banner grabbing and version parsing
- **OS Fingerprinting** — Heuristic OS detection from port patterns and banners
- **JSON Output** — Machine-readable results for SIEM/pipeline integration
- **Multithreaded** — Up to 5000 concurrent threads for fast scans
- **Security Warnings** — Highlights sensitive exposed services (Docker API, Redis, etc.)

## Building

Requires **Zig 0.13+**

```bash
# Clone and build
git clone https://github.com/you/zigscanner
cd zigscanner
zig build -Doptimize=ReleaseFast

# The binary ends up at:
./zig-out/bin/zigscanner
```

## Usage

```bash
# Basic scan (ports 1-1024)
zigscanner 192.168.1.1

# Full port scan with service detection
zigscanner -p 1-65535 -sV 192.168.1.1

# Fast scan with more threads and short timeout
zigscanner -p 1-65535 -t 500 --timeout 300 192.168.1.1

# With OS detection and JSON output
zigscanner -p top -sV -O -o results.json 192.168.1.100

# UDP scan of common ports
zigscanner --udp -p 1-1024 192.168.1.1

# Verbose output (shows banners, closed ports)
zigscanner -v -sV 10.0.0.1
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --ports` | Port range (`80`, `1-1024`, `top`, `all`) | `1-1024` |
| `-t, --threads` | Concurrent threads | `100` |
| `--timeout` | Connection timeout (ms) | `1000` |
| `-sS, --syn` | TCP SYN scan (root required) | — |
| `-sU, --udp` | UDP scan | — |
| `-sn, --ping` | Ping scan only | — |
| `-O, --os-detect` | OS fingerprinting | — |
| `-sV, --service-detect` | Service/version detection | — |
| `-v, --verbose` | Verbose output | — |
| `-o, --output` | Save results as JSON | — |

## Project Structure

```
zigscanner/
├── build.zig           # Build configuration
└── src/
    ├── main.zig        # Entry point, argument handling, top-level flow
    ├── args.zig        # CLI argument parsing
    ├── scanner.zig     # Core scanning logic (TCP/UDP/SYN)
    ├── services.zig    # Port-to-service name mapping (~70 entries)
    ├── fingerprint.zig # OS detection heuristics
    ├── output.zig      # Terminal and JSON output formatting
    └── version.zig     # Version constants
```

## Notes

- **Only scan systems you own or have permission to scan.** Port scanning unauthorized hosts is illegal in many jurisdictions.
- SYN scan requires root/administrator privileges for raw socket access.
- OS fingerprinting is heuristic — take results with a grain of salt.
- UDP scanning is inherently unreliable and slow. That's UDP's fault, not ours.

## License

MIT — do whatever you want, just don't blame us.
