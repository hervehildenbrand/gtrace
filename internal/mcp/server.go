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
		mcp.WithDescription("Run a traceroute to a target host. Shows the network path with IP addresses, hostnames, ASN info, latency, and geolocation for each hop. Requires root/sudo privileges."),
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
	)
}

func mtrTool() mcp.Tool {
	return mcp.NewTool("mtr",
		mcp.WithDescription("Run an MTR (My Traceroute) report to a target host. Combines traceroute and ping to show packet loss and latency statistics over multiple cycles. Requires root/sudo privileges."),
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
	)
}

func globalPingTool() mcp.Tool {
	return mcp.NewTool("globalping",
		mcp.WithDescription("Run a traceroute from remote GlobalPing probe locations worldwide. Does not require root privileges. Requires a GlobalPing API key for authenticated access."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Target hostname or IP address to trace"),
		),
		mcp.WithString("from",
			mcp.Required(),
			mcp.Description("Comma-separated probe locations (e.g., 'Paris, London, Tokyo'). Max 5 locations."),
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
		mcp.WithDescription("Look up ASN (Autonomous System Number) information for an IP address. Returns ASN, organization name, country, prefix, and registry."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IP address to look up (IPv4 or IPv6)"),
		),
	)
}

func geoLookupTool() mcp.Tool {
	return mcp.NewTool("geo_lookup",
		mcp.WithDescription("Look up geolocation information for an IP address. Returns city, country, region, coordinates, and timezone."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IP address to look up (IPv4 or IPv6)"),
		),
	)
}

func reverseDNSTool() mcp.Tool {
	return mcp.NewTool("reverse_dns",
		mcp.WithDescription("Perform a reverse DNS lookup for an IP address. Returns the hostname associated with the IP."),
		mcp.WithString("ip",
			mcp.Required(),
			mcp.Description("IP address to look up (IPv4 or IPv6)"),
		),
	)
}
