# gtrace

[![CI](https://github.com/hervehildenbrand/gtrace/actions/workflows/ci.yml/badge.svg)](https://github.com/hervehildenbrand/gtrace/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/hervehildenbrand/gtrace)](https://goreportcard.com/report/github.com/hervehildenbrand/gtrace)
[![Release](https://img.shields.io/github/v/release/hervehildenbrand/gtrace?include_prereleases)](https://github.com/hervehildenbrand/gtrace/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/hervehildenbrand/gtrace/releases)

Advanced network path analysis tool combining local traceroute with GlobalPing's distributed probe network.

![gtrace demo](demo/gtrace-demo.gif)

## Why gtrace?

| Feature | gtrace | mtr | traceroute |
|---------|--------|-----|------------|
| MPLS label detection | Yes | No | No |
| ECMP/load balancing detection | Yes | No | No |
| GlobalPing integration | Yes | No | No |
| ASN + geolocation enrichment | Yes | Partial | No |
| IPv4/IPv6 dual-stack | Yes | Yes | Yes |
| MTR-style continuous mode | Yes | Yes | No |
| JSON/CSV export | Yes | Yes | No |

## Features

- **Multi-Protocol Traceroute**: ICMP, UDP, and TCP probing
- **IPv4/IPv6 Support**: Dual-stack with `-4` and `-6` flags
- **MPLS Detection**: Extract and display MPLS label stacks from ICMP extensions
- **ECMP Detection**: Identify load-balanced paths with multiple IPs per hop
- **Rich Enrichment**: ASN lookup, reverse DNS, geolocation, IX detection
- **MTR Mode**: Continuous monitoring with real-time statistics
- **GlobalPing Integration**: Run traces from 500+ global probe locations
- **Export Formats**: JSON, CSV, and text output

## Installation

### From Source

```bash
go install github.com/hervehildenbrand/gtrace/cmd/gtrace@latest
```

### Build Locally

```bash
git clone https://github.com/hervehildenbrand/gtrace.git
cd gtrace
go build -o gtrace ./cmd/gtrace
```

## Quick Start

```bash
# Basic ICMP traceroute
sudo gtrace 8.8.8.8 --simple

# UDP traceroute with ECMP detection
sudo gtrace cloudflare.com --simple --protocol udp --packets 6

# TCP traceroute to specific port
sudo gtrace example.com --simple --protocol tcp --port 443

# MTR-style continuous monitoring
sudo gtrace 8.8.8.8

# Compare local and remote traces
sudo gtrace 8.8.8.8 --compare --from "New York,London"

# IPv6 traceroute
sudo gtrace -6 google.com --simple

# Compare IPv6 local vs remote
sudo gtrace -6 google.com --compare --from Paris
```

## Usage

### Basic Options

| Flag | Description | Default |
|------|-------------|---------|
| `-4, --ipv4` | Force IPv4 only | false |
| `-6, --ipv6` | Force IPv6 only | false |
| `--protocol` | Protocol: icmp, udp, tcp | icmp |
| `--port` | Target port (TCP/UDP) | 33434 |
| `--max-hops` | Maximum TTL | 30 |
| `--packets` | Probes per hop | 3 |
| `--timeout` | Per-hop timeout | 500ms |
| `--simple` | Simple output (no TUI) | false |

### MTR Mode

| Flag | Description | Default |
|------|-------------|---------|
| `--interval` | Time between cycles | 1s |
| `--cycles` | Number of cycles (0=infinite) | 0 |

**Keyboard shortcuts in MTR mode:**
- `p` - Pause/Resume
- `r` - Reset statistics
- `n` - Toggle DNS/IP display
- `q` - Quit

### GlobalPing Integration

| Flag | Description |
|------|-------------|
| `--from` | Probe locations (city, country, ASN, or cloud region) |
| `--compare` | Compare local trace with remote probes |
| `--api-key` | GlobalPing API key for higher rate limits |

### Export

| Flag | Description |
|------|-------------|
| `-o, --output` | Export to file (format auto-detected from extension) |
| `--format` | Explicit format: json, csv, txt |

### Enrichment

| Flag | Description |
|------|-------------|
| `--offline` | Use only local GeoIP databases |
| `--db-status` | Show GeoIP database status |
| `--download-db` | Instructions to download GeoIP databases |

## Examples

### Detect MPLS Labels

```bash
sudo gtrace www.internet2.edu --simple
```

Output shows MPLS labels on backbone hops:
```
 8  129.250.2.106  [AS2914]  202ms  [MPLS: L=309833 E=0 S=1 TTL=1]
 9  129.250.6.6    [AS2914]  79ms   [MPLS: L=36001 E=0 S=1 TTL=1]
```

### Detect Load Balancing (ECMP)

```bash
sudo gtrace cloudflare.com --simple --protocol udp --packets 8
```

Multiple IPs at the same hop indicate ECMP:
```
 8  141.101.67.83  141.101.67.95  141.101.67.115  [AS13335]  3.44ms
```

### IPv6 Traceroute

```bash
# Force IPv6
sudo gtrace -6 google.com --simple

# Compare IPv6 paths from different locations
sudo gtrace -6 cloudflare.com --compare --from "Frankfurt,Singapore"
```

### Export to JSON

```bash
sudo gtrace 8.8.8.8 --simple -o trace.json
```

JSON includes full hop data with ASN, geolocation, and timing:
```json
{
  "target": "8.8.8.8",
  "hops": [
    {
      "ttl": 1,
      "ip": "192.168.1.1",
      "avgRtt": 0.5,
      "lossPercent": 0
    }
  ]
}
```

### Compare Local vs Remote

```bash
sudo gtrace 8.8.8.8 --compare --from "Paris,Tokyo"
```

Shows side-by-side comparison of paths from different locations.

## Architecture

```
gtrace/
├── cmd/gtrace/          # CLI entry point
├── internal/
│   ├── trace/           # Traceroute engines (ICMP, UDP, TCP)
│   ├── display/         # TUI and simple output renderers
│   ├── enrich/          # ASN, geo, rDNS enrichment
│   ├── export/          # JSON, CSV, text exporters
│   ├── globalping/      # GlobalPing API client
│   └── monitor/         # Route change detection
└── pkg/hop/             # Hop data structures
```

## Requirements

- Go 1.24+
- Root/sudo privileges for raw socket access
- Optional: MaxMind GeoIP databases for offline geolocation

## License

MIT
