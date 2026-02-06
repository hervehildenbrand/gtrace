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
| Active ECMP probing (Paris-style) | Yes | No | No |
| NAT detection | Yes | No | No |
| Path MTU discovery | Yes | No | No |
| GlobalPing integration | Yes | No | No |
| ASN + geolocation enrichment | Yes | Partial | No |
| IPv4/IPv6 dual-stack | Yes | Yes | Yes |
| MTR-style continuous mode | Yes | Yes | No |
| Latency jitter (StdDev) | Yes | Yes | No |
| JSON/CSV export | Yes | Yes | No |

## Features

- **Multi-Protocol Traceroute**: ICMP, UDP, and TCP probing
- **IPv4/IPv6 Support**: Dual-stack with `-4` and `-6` flags
- **MPLS Detection**: Extract and display MPLS label stacks from ICMP extensions
- **ECMP Detection**: Passive detection of load-balanced paths with multiple IPs per hop
- **Active ECMP Probing**: Paris traceroute-style flow variation to actively discover ECMP paths
- **NAT Detection**: Identify NAT devices along the path via response TTL analysis
- **Path MTU Discovery**: Discover per-hop MTU using Don't Fragment bit and ICMP feedback
- **Rich Enrichment**: ASN lookup, reverse DNS, geolocation, IX detection
- **MTR Mode**: Continuous monitoring with real-time statistics including latency jitter (StdDev)
- **GlobalPing Integration**: Run traces from 500+ global probe locations
- **Export Formats**: JSON, CSV, and text output

## Installation

### Precompiled Binaries

Download the latest release for your platform from the [Releases page](https://github.com/hervehildenbrand/gtrace/releases).

Available for Linux, macOS, and Windows (amd64 and arm64).

```bash
# Example: Linux amd64 (replace VERSION with the desired release, e.g. 0.3.3)
curl -LO https://github.com/hervehildenbrand/gtrace/releases/download/vVERSION/gtrace_VERSION_linux_amd64.tar.gz
tar xzf gtrace_VERSION_linux_amd64.tar.gz
sudo mv gtrace /usr/local/bin/
```

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

# Active ECMP probing (Paris traceroute-style)
sudo gtrace cloudflare.com --simple --protocol udp --ecmp-flows 8

# TCP traceroute to specific port
sudo gtrace example.com --simple --protocol tcp --port 443

# NAT detection
sudo gtrace 8.8.8.8 --simple --detect-nat

# Path MTU discovery
sudo gtrace 8.8.8.8 --simple --discover-mtu --probe-size 1500

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

### Detection & Discovery

| Flag | Description | Default |
|------|-------------|---------|
| `--detect-nat` | Enable NAT detection via TTL analysis | false |
| `--ecmp-flows` | ECMP flow variations per hop (0=disabled) | 0 |
| `--discover-mtu` | Enable Path MTU Discovery | false |
| `--probe-size` | Probe packet size in bytes | 64 |

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
| `--from` | Probe locations, comma-separated (max 5) |
| `--compare` | Compare local trace with remote probes |
| `--api-key` | GlobalPing API key for higher rate limits |

### Export

| Flag | Description |
|------|-------------|
| `-o, --output` | Export to file (format auto-detected from extension) |
| `--format` | Explicit format: json, csv, text (or txt) |

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
# Passive detection: send multiple probes and observe path divergence
sudo gtrace cloudflare.com --simple --protocol udp --packets 8

# Active probing: Paris traceroute-style flow variation
sudo gtrace google.com --simple --protocol udp --ecmp-flows 8
```

Multiple IPs at the same hop indicate ECMP:
```
 6  72.14.202.232  72.14.205.190  193.251.255.104  72.14.204.184  [AS15169]  3.44ms
```

### Detect NAT Devices

```bash
sudo gtrace 8.8.8.8 --simple --detect-nat
```

NAT devices are identified by TTL anomalies in ICMP responses:
```
 3  10.0.0.1  [AS3215]  5.42ms 4.89ms 5.01ms  [NAT]
 7  72.14.236.73  [AS15169]  8.21ms 7.98ms 8.44ms  [NAT]
```

### Path MTU Discovery

```bash
sudo gtrace 8.8.8.8 --simple --discover-mtu --probe-size 1500 --protocol udp
```

Discovers the MTU along the path using the Don't Fragment bit:
```
 1  192.168.1.1  0.87ms 0.76ms 0.60ms
 2  80.10.255.25  [AS3215]  1.57ms 1.05ms 1.81ms  [MTU:1500]
```

When the probe size exceeds the path MTU, EMSGSIZE is reported locally:
```
 1  * * *  [MTU:1500]
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

JSON includes full hop data with ASN, geolocation, timing, and detection results:
```json
{
  "target": "8.8.8.8",
  "hops": [
    {
      "ttl": 1,
      "ip": "192.168.1.1",
      "avgRtt": 0.5,
      "lossPercent": 0,
      "nat": true,
      "mtu": 1500
    }
  ]
}
```

### Compare Local vs Remote

```bash
# Compare against a single remote location
sudo gtrace 8.8.8.8 --compare --from Paris

# Compare against multiple remote locations (up to 5)
sudo gtrace 8.8.8.8 --compare --from "Paris,Tokyo"
```

Each remote location produces its own side-by-side comparison against the local trace, separated by `===`. Column headers show the actual probe location (e.g. "Paris, FR, OVH SAS").

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
