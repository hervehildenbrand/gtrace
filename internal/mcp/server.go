package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// NewServer creates a new MCP server with all gtrace tools registered.
func NewServer(version, apiKey string) *server.MCPServer {
	s := server.NewMCPServer(
		"gtrace",
		version,
		server.WithToolCapabilities(false),
	)

	h := &handlers{apiKey: apiKey}

	s.AddTool(listProbesTool(), h.handleListProbes)
	s.AddTool(tracerouteTool(), h.handleTraceroute)
	s.AddTool(mtrTool(), h.handleMTR)
	s.AddTool(globalPingTool(), h.handleGlobalPing)
	s.AddTool(asnLookupTool(), h.handleASNLookup)
	s.AddTool(geoLookupTool(), h.handleGeoLookup)
	s.AddTool(reverseDNSTool(), h.handleReverseDNS)

	return s
}

func tracerouteTool() mcp.Tool {
	return mcp.NewTool("traceroute",
		mcp.WithDescription("Run a traceroute to a target host. Shows the network path with IP addresses, hostnames, ASN info, latency, and geolocation for each hop. Requires root/sudo on macOS; root or CAP_NET_RAW on Linux."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Target hostname or IP address to trace"),
		),
		mcp.WithString("protocol",
			mcp.Description("Protocol to use: icmp, udp, or tcp"),
			mcp.Enum("icmp", "udp", "tcp"),
		),
		mcp.WithNumber("port",
			mcp.Description("Destination port for TCP/UDP probes (default: 33434 for UDP, 80 for TCP)"),
		),
		mcp.WithNumber("max_hops",
			mcp.Description("Maximum number of hops (default: 30)"),
		),
		mcp.WithString("timeout",
			mcp.Description("Per-hop timeout as a duration string (default: 500ms)"),
		),
		mcp.WithNumber("packets",
			mcp.Description("Number of probes per hop (default: 3)"),
		),
		mcp.WithBoolean("ipv4",
			mcp.Description("Force IPv4 only"),
		),
		mcp.WithBoolean("ipv6",
			mcp.Description("Force IPv6 only"),
		),
		mcp.WithBoolean("detect_nat",
			mcp.Description("Enable NAT detection via TTL analysis"),
		),
		mcp.WithNumber("ecmp_flows",
			mcp.Description("ECMP flow variations per hop (0=disabled, 8=recommended)"),
		),
		mcp.WithBoolean("discover_mtu",
			mcp.Description("Enable Path MTU Discovery"),
		),
		mcp.WithNumber("probe_size",
			mcp.Description("Probe packet size in bytes (default: 64)"),
		),
		mcp.WithBoolean("decode",
			mcp.Description("Decode transport headers from ICMP error bodies (shows DSCP, DF, TCP flags, port translation)"),
		),
	)
}

func mtrTool() mcp.Tool {
	return mcp.NewTool("mtr",
		mcp.WithDescription("Run an MTR (My Traceroute) report to a target host. Combines traceroute and ping to show packet loss and latency statistics over multiple cycles. Requires root/sudo on macOS; root or CAP_NET_RAW on Linux."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Target hostname or IP address"),
		),
		mcp.WithString("protocol",
			mcp.Description("Protocol to use: icmp, udp, or tcp"),
			mcp.Enum("icmp", "udp", "tcp"),
		),
		mcp.WithNumber("port",
			mcp.Description("Destination port for TCP/UDP probes"),
		),
		mcp.WithNumber("max_hops",
			mcp.Description("Maximum number of hops (default: 30)"),
		),
		mcp.WithString("timeout",
			mcp.Description("Per-hop timeout as a duration string (default: 500ms)"),
		),
		mcp.WithNumber("cycles",
			mcp.Description("Number of trace cycles to run (default: 10)"),
		),
		mcp.WithString("interval",
			mcp.Description("Interval between cycles as a duration string (default: 1s)"),
		),
		mcp.WithNumber("ecmp_flows",
			mcp.Description("ECMP flow variations per hop (0=disabled)"),
		),
		mcp.WithBoolean("decode",
			mcp.Description("Decode transport headers from ICMP error bodies (shows DSCP, DF, TCP flags, port translation)"),
		),
	)
}

func listProbesTool() mcp.Tool {
	return mcp.NewTool("list_probes",
		mcp.WithDescription(`Discover available GlobalPing probe locations worldwide. Use this BEFORE the globalping tool to find precise probe locations.

Workflow: call list_probes to find probes, then use the globalping tool with structured 'from' syntax for precise selection.

Filter by country (ISO code), city, ASN number, network name, or tag. Returns probe locations with city, country, ASN, and network info.

Examples:
- Find probes in Japan: {"country": "JP"}
- Find probes in Cloudflare's network: {"asn": 13335}
- Find probes at a specific IXP or network: {"network": "LINX"} or {"tag": "datacenter"}`),
		mcp.WithString("country",
			mcp.Description("ISO country code filter (e.g., JP, US, DE, GB)"),
		),
		mcp.WithString("city",
			mcp.Description("City name filter (case-insensitive substring match)"),
		),
		mcp.WithNumber("asn",
			mcp.Description("ASN number filter (e.g., 13335 for Cloudflare, 2497 for IIJ)"),
		),
		mcp.WithString("network",
			mcp.Description("Network name filter (case-insensitive substring match)"),
		),
		mcp.WithString("tag",
			mcp.Description("Probe tag filter (e.g., datacenter, eyeball)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of probes to return (default: 20)"),
		),
	)
}

func globalPingTool() mcp.Tool {
	return mcp.NewTool("globalping",
		mcp.WithDescription(`Run a traceroute from remote GlobalPing probe locations worldwide. Supports ICMP (default), TCP, and UDP protocols — use TCP/UDP when ICMP is filtered.

Does not require root privileges. Works without an API key (rate-limited); provide one via --api-key for higher limits.

Use the list_probes tool first to discover available probe locations, then specify them here.

Location syntax for 'from' parameter:
- Simple: "Paris", "Tokyo", "DE", "AS13335" (flexible matching)
- Structured: "country:JP", "city:London,asn:5089" (precise AND-filtering)
- Multiple: "Paris; Tokyo" or semicolon-separated for multiple structured locations

Protocol examples:
- TCP traceroute to port 443: protocol="tcp", port=443
- UDP traceroute: protocol="udp", port=33434
- ICMP (default): omit protocol parameter

Tip: When ICMP is filtered, try protocol="tcp" with port=80 or port=443 for better path visibility.`),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Target hostname or IP address to trace"),
		),
		mcp.WithString("from",
			mcp.Required(),
			mcp.Description("Probe locations (max 5). Simple: 'Paris; Tokyo; DE'. Structured for precision: 'city:Tokyo,asn:2497' or 'country:GB,network:BT'. Use semicolons to separate multiple locations. Use list_probes tool to discover available locations."),
		),
		mcp.WithString("protocol",
			mcp.Description("Protocol to use: icmp, udp, or tcp"),
			mcp.Enum("icmp", "udp", "tcp"),
		),
		mcp.WithNumber("port",
			mcp.Description("Destination port for TCP/UDP probes"),
		),
		mcp.WithNumber("max_hops",
			mcp.Description("Maximum number of hops"),
		),
		mcp.WithBoolean("ipv4",
			mcp.Description("Force IPv4 only"),
		),
		mcp.WithBoolean("ipv6",
			mcp.Description("Force IPv6 only"),
		),
	)
}

func asnLookupTool() mcp.Tool {
	return mcp.NewTool("asn_lookup",
		mcp.WithDescription("Look up ASN (Autonomous System Number) information for an IP address. Returns ASN, organization name, country, prefix, and registry. No special privileges required."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IP address to look up (IPv4 or IPv6)"),
		),
	)
}

func geoLookupTool() mcp.Tool {
	return mcp.NewTool("geo_lookup",
		mcp.WithDescription("Look up geolocation information for an IP address. Returns city, country, region, coordinates, and timezone. No special privileges required."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IP address to look up (IPv4 or IPv6)"),
		),
	)
}

func reverseDNSTool() mcp.Tool {
	return mcp.NewTool("reverse_dns",
		mcp.WithDescription("Perform a reverse DNS lookup for an IP address. Returns the hostname associated with the IP. No special privileges required."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IP address to look up (IPv4 or IPv6)"),
		),
	)
}
