# gtr - GlobalPing Traceroute CLI

## Overview

A unified CLI tool that combines local traceroute with GlobalPing's global probe network, featuring advanced diagnostics (MPLS, ECMP, MTU, NAT detection), rich hop enrichment, and real-time TUI.

**Language:** Go (single binary, raw socket support, excellent networking libraries)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          gtr CLI                                │
├─────────────────────────────────────────────────────────────────┤
│  Commands:                                                      │
│    gtr <target>              - Local trace only                 │
│    gtr <target> --from <loc> - Remote trace via GlobalPing      │
│    gtr <target> --compare    - Local + remote side-by-side      │
│    gtr <target> --monitor    - Continuous monitoring mode       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │  Local Engine   │    │ GlobalPing API  │                    │
│  │  (raw sockets)  │    │    Client       │                    │
│  └────────┬────────┘    └────────┬────────┘                    │
│           └──────────┬───────────┘                              │
│                      ▼                                          │
│           ┌─────────────────┐                                   │
│           │  Hop Processor  │  ← Enrichment (ASN, Geo, rDNS)   │
│           └────────┬────────┘                                   │
│                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │            Display Layer                                    ││
│  │  • TUI (default)  • Simple (--simple)  • Export (-o)       ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Local Traceroute Engine

**Protocol Support:**
- ICMP (default) - most compatible
- UDP (--protocol=udp) - classic traceroute ports 33434+
- TCP (--protocol=tcp --port=443) - for filtered networks

**MPLS Label Discovery:**
- Parse ICMP Time Exceeded extensions (RFC 4950)
- Display: `MPLS: L=24015 E=0 S=1 TTL=1`
- Support label stacks (multiple labels)
- Track label changes in monitoring mode

**ECMP Path Detection (Paris/Dublin):**
- Vary flow IDs (UDP src port, ICMP checksum) to discover paths
- Display all paths with frequency
- Visual indicator: `[ECMP:2]` when load balancing detected

**MTU Discovery:**
- Binary search with DF bit
- Per-hop MTU from ICMP "Fragmentation Needed"
- Flag MTU < 1500 in unusual places

**NAT Detection:**
- Track IP ID field changes
- Detect source port rewriting
- Mark hops: `[NAT]`

### GlobalPing Integration

**Location Specification:**
```bash
gtr google.com --from "London"              # City
gtr google.com --from "DE"                  # Country code
gtr google.com --from "AS13335"             # By ASN
gtr google.com --from "AWS+us-east-1"       # Cloud region
gtr google.com --from "London,Tokyo,NYC"    # Multiple
```

**Comparison Views:**
- `--view=side` (default) - Columns side-by-side
- `--view=tabs` - Tabbed, switch with Tab key
- `--view=unified` - Merged path showing convergence

**API Handling:**
- Poll every 500ms for real-time updates
- Response caching for repeat queries
- Rate limit handling (250/hour free)
- Auth: `--api-key` flag or `GLOBALPING_API_KEY` env

### Display Modes

**TUI (default):**
```
┌─ gtr → google.com ─────────────────────────────────────────────────────┐
│ Hop │ IP Address      │ ASN/Org         │ Geo    │ Loss │ Avg │ Graph │
├─────┼─────────────────┼─────────────────┼────────┼──────┼─────┼───────┤
│  1  │ 192.168.1.1     │ Private         │ Local  │  0%  │ 1ms │ ▁▁▁▂▁ │
│  2  │ 10.0.0.1        │ AS1234 Comcast  │ SF, US │  0%  │ 5ms │ ▁▂▁▁▃ │
├─────┴─────────────────┴─────────────────┴────────┴──────┴─────┴───────┤
│ MPLS: Hop 2 L=24015 │ ECMP: Hop 3 (2 paths) │ MTU: 1500 │ NAT: -     │
└───────────────────────────────────────────────────────────────────────┘
```

**Key bindings:** q=quit, e=export, p=pause, r=reset, Tab=switch view, ?=help

**Simple mode (--simple):**
- Traditional line-by-line output
- Pipe-friendly, no ANSI codes with --no-color

### Monitoring Mode

```bash
gtr google.com --monitor --alert-latency=100ms --alert-loss=5%
```

**Alert Triggers:**
- Route change: New IP at hop
- Latency threshold: Exceeds configured ms
- Packet loss: Exceeds configured %
- MPLS change: Label stack changes
- AS path change: Traffic shifts AS

### Enrichment

**Per-hop data:**
- ASN + Organization (Team Cymru or local MaxMind)
- GeoIP city/country (MaxMind GeoLite2)
- Reverse DNS (PTR lookup)
- IX detection (PeeringDB)

**Offline support:**
```bash
gtr --download-db    # Download MaxMind DBs
gtr --offline        # Use local DBs only
```

### Export Formats

- JSON (`-o results.json`)
- CSV (`-o results.csv`)
- Text (`-o results.txt`)

Auto-detect format from extension, or explicit `--format=json`

## CLI Reference

```
gtr <target> [flags]

Flags:
  --from <location>      Run from GlobalPing location(s)
  --compare              Compare local + remote traces
  --view <mode>          Display mode: side|tabs|unified (default: side)
  --protocol <proto>     Protocol: icmp|udp|tcp (default: icmp)
  --port <port>          Port for TCP/UDP (default: 33434 UDP, 80 TCP)
  --packets <n>          Packets per hop (default: 3)
  --max-hops <n>         Maximum hops (default: 30)
  --timeout <duration>   Per-hop timeout (default: 3s)

  --monitor              Continuous monitoring mode
  --alert-latency <ms>   Alert on latency threshold
  --alert-loss <pct>     Alert on packet loss threshold

  --simple               Simple output (no TUI)
  --no-color             Disable colors
  -o, --output <file>    Export to file (json/csv/txt)
  --format <fmt>         Explicit export format

  --api-key <key>        GlobalPing API key
  --offline              Use only local enrichment DBs
  --download-db          Download MaxMind databases

  -v, --verbose          Verbose output
  --version              Show version
  -h, --help             Show help
```

## Project Structure

```
gtr/
├── cmd/
│   └── gtr/
│       └── main.go           # Entry point, CLI parsing
├── internal/
│   ├── trace/
│   │   ├── local.go          # Local traceroute engine
│   │   ├── icmp.go           # ICMP protocol handler
│   │   ├── udp.go            # UDP protocol handler
│   │   ├── tcp.go            # TCP protocol handler
│   │   ├── mpls.go           # MPLS label parsing
│   │   ├── ecmp.go           # ECMP path detection
│   │   ├── mtu.go            # MTU discovery
│   │   └── nat.go            # NAT detection
│   ├── globalping/
│   │   ├── client.go         # API client
│   │   ├── types.go          # API types
│   │   └── poller.go         # Result polling
│   ├── enrich/
│   │   ├── asn.go            # ASN lookup
│   │   ├── geo.go            # GeoIP lookup
│   │   ├── rdns.go           # Reverse DNS
│   │   ├── ix.go             # IX detection
│   │   └── cache.go          # Enrichment cache
│   ├── display/
│   │   ├── tui.go            # TUI renderer
│   │   ├── simple.go         # Simple text output
│   │   └── compare.go        # Comparison views
│   ├── monitor/
│   │   ├── monitor.go        # Monitoring loop
│   │   └── alerts.go         # Alert triggers
│   └── export/
│       ├── json.go           # JSON export
│       ├── csv.go            # CSV export
│       └── text.go           # Text export
├── pkg/
│   └── hop/
│       └── hop.go            # Shared hop data model
├── go.mod
├── go.sum
└── README.md
```

## Dependencies

**Core:**
- `golang.org/x/net/icmp` - ICMP packet handling
- `golang.org/x/net/ipv4` - IPv4 raw sockets
- `github.com/spf13/cobra` - CLI framework

**TUI:**
- `github.com/charmbracelet/bubbletea` - TUI framework
- `github.com/charmbracelet/lipgloss` - Styling
- `github.com/charmbracelet/bubbles` - TUI components

**Enrichment:**
- `github.com/oschwald/maxminddb-golang` - MaxMind DB reader

## Implementation Phases

### Phase 1: Core Infrastructure
1. Project setup (go mod, directory structure)
2. CLI parsing with cobra
3. Hop data model
4. Simple text output

### Phase 2: Local Traceroute Engine
1. ICMP traceroute (basic)
2. UDP traceroute
3. TCP traceroute
4. MPLS label parsing
5. ECMP detection
6. MTU discovery
7. NAT detection

### Phase 3: GlobalPing Integration
1. API client (create measurement, poll results)
2. Location parsing
3. Result mapping to hop model
4. Rate limiting/caching

### Phase 4: Enrichment
1. ASN lookup (Team Cymru)
2. GeoIP (MaxMind)
3. Reverse DNS
4. IX detection (PeeringDB)
5. Offline DB download

### Phase 5: TUI
1. Basic TUI with bubbletea
2. Real-time updates
3. Sparkline graphs
4. Key bindings
5. Comparison views

### Phase 6: Monitoring
1. Continuous trace loop
2. Change detection
3. Alert triggers
4. Alert output

### Phase 7: Export & Polish
1. JSON export
2. CSV export
3. Text export
4. Error handling
5. Testing
6. Documentation

## Verification

1. **Unit tests:** Each package has _test.go files
2. **Integration test:** Full trace to known target (google.com)
3. **Manual testing:**
   - `gtr google.com` - Basic local trace
   - `gtr google.com --from London` - GlobalPing trace
   - `gtr google.com --compare --from London,Tokyo` - Comparison
   - `gtr google.com --monitor` - Monitoring mode
   - `gtr google.com -o test.json` - Export
