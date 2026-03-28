package mcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/internal/globalping"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// formatProbeList formats a list of probes for MCP output.
func formatProbeList(probes []globalping.Probe) string {
	var sb strings.Builder

	if len(probes) == 0 {
		sb.WriteString("No probes found matching the criteria.\n")
		return sb.String()
	}

	fmt.Fprintf(&sb, "Found %d probes:\n\n", len(probes))
	fmt.Fprintf(&sb, "%-20s  %-4s  %8s  %-25s  %s\n",
		"City", "CC", "ASN", "Network", "Tags")
	sb.WriteString(strings.Repeat("-", 85))
	sb.WriteByte('\n')

	for _, p := range probes {
		tags := ""
		if len(p.Tags) > 0 {
			tags = strings.Join(p.Tags, ", ")
		}
		cityStr := p.Location.City
		if len(cityStr) > 20 {
			cityStr = cityStr[:17] + "..."
		}
		networkStr := p.Location.Network
		if len(networkStr) > 25 {
			networkStr = networkStr[:22] + "..."
		}
		fmt.Fprintf(&sb, "%-20s  %-4s  %8d  %-25s  %s\n",
			cityStr,
			p.Location.Country,
			p.Location.ASN,
			networkStr,
			tags)
	}

	sb.WriteString("\nUse these with the globalping tool's 'from' parameter.\n")
	sb.WriteString("Example: from='city:Tokyo,asn:2497' or from='country:GB,network:BT'\n")

	return sb.String()
}

// formatTraceResult formats a TraceResult as a human-readable text table.
func formatTraceResult(tr *hop.TraceResult) string {
	var sb strings.Builder

	// Header
	fmt.Fprintf(&sb, "Traceroute to %s (%s)\n", tr.Target, tr.TargetIP)
	fmt.Fprintf(&sb, "Protocol: %s\n", tr.Protocol)
	if tr.Source != "" {
		fmt.Fprintf(&sb, "Source: %s\n", tr.Source)
	}
	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteByte('\n')

	for _, h := range tr.Hops {
		formatHop(&sb, h)
	}

	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteByte('\n')
	if tr.ReachedTarget {
		fmt.Fprintf(&sb, "Target reached in %d hops\n", tr.TotalHops())
	} else {
		fmt.Fprintf(&sb, "Target not reached (%d hops)\n", tr.TotalHops())
	}
	if !tr.StartTime.IsZero() && !tr.EndTime.IsZero() {
		fmt.Fprintf(&sb, "Duration: %v\n", tr.EndTime.Sub(tr.StartTime).Round(time.Millisecond))
	}

	return sb.String()
}

func formatHop(sb *strings.Builder, h *hop.Hop) {
	ip := h.PrimaryIP()
	if ip == nil {
		fmt.Fprintf(sb, "%2d  * * * (no response)\n", h.TTL)
		return
	}

	line := fmt.Sprintf("%2d  %s", h.TTL, ip.String())
	if h.Enrichment.Hostname != "" {
		line += fmt.Sprintf(" (%s)", h.Enrichment.Hostname)
	}
	if h.Enrichment.ASN > 0 {
		line += fmt.Sprintf(" [AS%d %s]", h.Enrichment.ASN, h.Enrichment.ASOrg)
	}
	sb.WriteString(line)
	sb.WriteByte('\n')

	// RTTs
	var timings []string
	for _, p := range h.Probes {
		if p.Timeout {
			timings = append(timings, "*")
		} else {
			ms := float64(p.RTT) / float64(time.Millisecond)
			timings = append(timings, fmt.Sprintf("%.2fms", ms))
		}
	}
	fmt.Fprintf(sb, "    RTT: %s (avg: %.2fms, loss: %.1f%%)\n",
		strings.Join(timings, " "),
		float64(h.AvgRTT())/float64(time.Millisecond),
		h.LossPercent())

	// MPLS
	for _, m := range h.MPLS {
		fmt.Fprintf(sb, "    MPLS: %s\n", m.String())
	}

	// Interface Info (RFC 5837)
	if h.InterfaceInfo != nil {
		if h.InterfaceInfo.Name != "" {
			fmt.Fprintf(sb, "    Interface: %s", h.InterfaceInfo.Name)
			if h.InterfaceInfo.IP != nil {
				fmt.Fprintf(sb, " (%s)", h.InterfaceInfo.IP)
			}
			if h.InterfaceInfo.Role != "" {
				fmt.Fprintf(sb, " [%s]", h.InterfaceInfo.Role)
			}
			sb.WriteByte('\n')
		} else if h.InterfaceInfo.IP != nil {
			fmt.Fprintf(sb, "    Interface IP: %s", h.InterfaceInfo.IP)
			if h.InterfaceInfo.Role != "" {
				fmt.Fprintf(sb, " [%s]", h.InterfaceInfo.Role)
			}
			sb.WriteByte('\n')
		}
	}

	// ICMP code (check first non-timeout probe)
	for _, p := range h.Probes {
		if !p.Timeout && p.ICMPType == 3 {
			codeText := icmpCodeText(p.ICMPCode)
			if codeText != "" {
				fmt.Fprintf(sb, "    [ICMP: %s (code %d)]\n", codeText, p.ICMPCode)
			}
			break
		}
	}

	// TransportInfo (decoded header info)
	for _, p := range h.Probes {
		if p.TransportInfo != nil {
			formatTransportInfo(sb, p.TransportInfo)
			break
		}
	}

	// NAT
	if h.NAT {
		sb.WriteString("    [NAT detected]\n")
	}

	// MTU
	if h.MTU > 0 {
		fmt.Fprintf(sb, "    [MTU: %d]\n", h.MTU)
	}

	// Geo
	if h.Enrichment.City != "" || h.Enrichment.Country != "" {
		var geo []string
		if h.Enrichment.City != "" {
			geo = append(geo, h.Enrichment.City)
		}
		if h.Enrichment.Country != "" {
			geo = append(geo, h.Enrichment.Country)
		}
		fmt.Fprintf(sb, "    Geo: %s\n", strings.Join(geo, ", "))
	}

	// IX
	if h.Enrichment.IX != "" {
		fmt.Fprintf(sb, "    IX: %s\n", h.Enrichment.IX)
	}
}

// formatMTRStats formats MTR statistics as a text table.
func formatMTRStats(stats map[int]*display.HopStats, cycles int, target string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "MTR report to %s (%d cycles)\n", target, cycles)
	sb.WriteString(strings.Repeat("-", 90))
	sb.WriteByte('\n')

	// Header
	fmt.Fprintf(&sb, "%-4s %-40s %6s %5s %5s %8s %8s %8s %8s\n",
		"Hop", "Host", "Loss%", "Snt", "Rcv", "Best", "Avg", "Wrst", "StDev")
	sb.WriteString(strings.Repeat("-", 90))
	sb.WriteByte('\n')

	// Find the last TTL that had any successful response.
	// Trim trailing all-timeout hops (past the target).
	maxTTL := 0
	for ttl, s := range stats {
		if s.Recv > 0 && ttl > maxTTL {
			maxTTL = ttl
		}
	}

	for ttl := 1; ttl <= maxTTL; ttl++ {
		s, ok := stats[ttl]
		if !ok {
			continue
		}

		host := "???"
		ip := s.PrimaryIP()
		if ip != nil {
			host = ip.String()
			e := s.PrimaryEnrichment()
			if e.Hostname != "" {
				host = fmt.Sprintf("%s (%s)", e.Hostname, ip.String())
			}
			if e.ASN > 0 {
				host += fmt.Sprintf(" [AS%d]", e.ASN)
			}
		}

		// Truncate host to 40 chars
		if len(host) > 40 {
			host = host[:37] + "..."
		}

		fmt.Fprintf(&sb, "%-4d %-40s %5.1f%% %5d %5d %7.1f %7.1f %7.1f %7.1f\n",
			ttl,
			host,
			s.LossPercent(),
			s.Sent,
			s.Recv,
			float64(s.BestRTT)/float64(time.Millisecond),
			float64(s.AvgRTT())/float64(time.Millisecond),
			float64(s.WorstRTT)/float64(time.Millisecond),
			float64(s.StdDev())/float64(time.Millisecond),
		)

		// TTL manipulation indicator
		if s.TTLManipulated {
			sb.WriteString("    [ttl_manipulated: middlebox modified original datagram TTL]\n")
		}

		// ICMP code indicator
		if s.LastICMPType == 3 {
			codeText := icmpCodeText(s.LastICMPCode)
			if codeText != "" {
				fmt.Fprintf(&sb, "    [icmp_code: %d, icmp_code_text: %s]\n", s.LastICMPCode, codeText)
			}
		}

		// Route flap indicator
		if s.HasRouteFlap() {
			sb.WriteString("    [route_flap: route instability detected]\n")
		}

		// Rate-limit indicator
		if s.RateLimited {
			sb.WriteString("    [rate_limited: likely ICMP rate limiting, not real loss]\n")
		}

		// ECMP classification
		if s.ECMPClassified != "" {
			fmt.Fprintf(&sb, "    [ecmp_type: %s]\n", s.ECMPClassified)
		}

		// TransportInfo (decoded header info)
		if s.LastTransportInfo != nil {
			formatTransportInfo(&sb, s.LastTransportInfo)
		}

		// ECMP sub-rows
		if s.HasECMP() {
			for _, ipInfo := range s.SortedIPs() {
				subHost := ipInfo.IP.String()
				if ipInfo.Enrichment.Hostname != "" {
					subHost = fmt.Sprintf("%s (%s)", ipInfo.Enrichment.Hostname, ipInfo.IP.String())
				}
				if len(subHost) > 38 {
					subHost = subHost[:35] + "..."
				}
				fmt.Fprintf(&sb, "       ├─ %-38s (seen %dx)\n", subHost, ipInfo.Count)
			}
		}
	}

	return sb.String()
}

// formatGlobalPingResults formats results from multiple GlobalPing probe locations.
func formatGlobalPingResults(results []*globalPingProbeResult) string {
	var sb strings.Builder

	for i, pr := range results {
		if i > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "=== Probe: %s, %s (AS%d %s) ===\n",
			pr.probe.City, pr.probe.Country, pr.probe.ASN, pr.probe.Network)
		sb.WriteString(formatTraceResult(pr.trace))
	}

	return sb.String()
}

// globalPingProbeResult pairs a probe location with its trace result.
type globalPingProbeResult struct {
	probe probeInfo
	trace *hop.TraceResult
}

// probeInfo holds probe location metadata.
type probeInfo struct {
	City    string
	Country string
	ASN     int
	Network string
}

// formatPingResults formats ping results from multiple probes.
func formatPingResults(results []globalping.PingProbeResult, target string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Ping results for %s\n", target)
	sb.WriteString(strings.Repeat("-", 60))
	sb.WriteByte('\n')

	for i, pr := range results {
		if i > 0 {
			sb.WriteByte('\n')
		}

		fmt.Fprintf(&sb, "=== Probe: %s, %s (AS%d %s) ===\n",
			pr.Probe.City, pr.Probe.Country, pr.Probe.ASN, pr.Probe.Network)

		r := pr.Result
		if r.ResolvedHostname != "" && r.ResolvedHostname != r.ResolvedAddress {
			fmt.Fprintf(&sb, "Target: %s (%s)\n", r.ResolvedAddress, r.ResolvedHostname)
		} else if r.ResolvedAddress != "" {
			fmt.Fprintf(&sb, "Target: %s\n", r.ResolvedAddress)
		}

		fmt.Fprintf(&sb, "Packets: %d sent, %d received, %.1f%% loss\n",
			r.Stats.Total, r.Stats.Rcv, r.Stats.Loss)

		if r.Stats.Min != nil && r.Stats.Avg != nil && r.Stats.Max != nil {
			fmt.Fprintf(&sb, "RTT: min=%.2f avg=%.2f max=%.2f ms\n",
				*r.Stats.Min, *r.Stats.Avg, *r.Stats.Max)
		}

		if len(r.Timings) > 0 {
			var parts []string
			for _, t := range r.Timings {
				parts = append(parts, fmt.Sprintf("%.2fms", t.RTT))
			}
			fmt.Fprintf(&sb, "Timings: %s\n", strings.Join(parts, " "))
		}
	}

	return sb.String()
}

// formatDNSResults formats DNS results from multiple probes.
func formatDNSResults(results []globalping.DNSProbeResult, target string, trace bool) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "DNS lookup for %s\n", target)
	sb.WriteString(strings.Repeat("-", 60))
	sb.WriteByte('\n')

	for i, pr := range results {
		if i > 0 {
			sb.WriteByte('\n')
		}

		fmt.Fprintf(&sb, "=== Probe: %s, %s (AS%d %s) ===\n",
			pr.Probe.City, pr.Probe.Country, pr.Probe.ASN, pr.Probe.Network)

		r := pr.Result

		if trace && r.RawOutput != "" {
			sb.WriteString(r.RawOutput)
			sb.WriteByte('\n')
			continue
		}

		if r.Resolver != "" {
			fmt.Fprintf(&sb, "Resolver: %s\n", r.Resolver)
		}
		fmt.Fprintf(&sb, "Status: %s (%d)\n", r.StatusCodeName, r.StatusCode)
		if r.Timings.Total > 0 {
			fmt.Fprintf(&sb, "Query time: %.1f ms\n", r.Timings.Total)
		}

		if len(r.Answers) > 0 {
			sb.WriteString("\nANSWER SECTION:\n")
			for _, a := range r.Answers {
				fmt.Fprintf(&sb, "  %-30s %5d  %s  %-5s %s\n",
					a.Name, a.TTL, a.Class, a.Type, a.Value)
			}
		}
	}

	return sb.String()
}

// formatASNResult formats an ASN lookup result.
func formatASNResult(result *enrich.ASNResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ASN:      AS%d\n", result.ASN)
	fmt.Fprintf(&sb, "Name:     %s\n", result.Name)
	fmt.Fprintf(&sb, "Prefix:   %s\n", result.Prefix)
	fmt.Fprintf(&sb, "Country:  %s\n", result.Country)
	fmt.Fprintf(&sb, "Registry: %s\n", result.Registry)
	if result.Date != "" {
		fmt.Fprintf(&sb, "Allocated: %s\n", result.Date)
	}
	return sb.String()
}

// formatGeoResult formats a geo lookup result.
func formatGeoResult(result *enrich.GeoResult) string {
	var sb strings.Builder
	if result.City != "" {
		fmt.Fprintf(&sb, "City:    %s\n", result.City)
	}
	if result.Region != "" {
		fmt.Fprintf(&sb, "Region:  %s\n", result.Region)
	}
	fmt.Fprintf(&sb, "Country: %s (%s)\n", result.CountryName, result.Country)
	fmt.Fprintf(&sb, "Coords:  %.4f, %.4f\n", result.Latitude, result.Longitude)
	if result.Timezone != "" {
		fmt.Fprintf(&sb, "TZ:      %s\n", result.Timezone)
	}
	return sb.String()
}

// formatRDNSResult formats a reverse DNS lookup result.
func formatRDNSResult(ip, hostname string) string {
	return fmt.Sprintf("IP:       %s\nHostname: %s\n", ip, hostname)
}

// formatTransportInfo formats decoded transport header info.
func formatTransportInfo(sb *strings.Builder, ti *hop.TransportInfo) {
	var parts []string

	if ti.DSCP != 0 {
		parts = append(parts, fmt.Sprintf("DSCP:%d", ti.DSCP))
	}
	if ti.DF {
		parts = append(parts, "DF")
	}
	if ti.TCPFlagsStr != "" {
		parts = append(parts, fmt.Sprintf("TCP:%s", ti.TCPFlagsStr))
	}
	if ti.TCPSrcPort != 0 {
		parts = append(parts, fmt.Sprintf("port:%d→%d", ti.TCPSrcPort, ti.TCPDstPort))
	} else if ti.UDPSrcPort != 0 {
		parts = append(parts, fmt.Sprintf("port:%d→%d", ti.UDPSrcPort, ti.UDPDstPort))
	}

	if len(parts) > 0 {
		fmt.Fprintf(sb, "    [%s]\n", strings.Join(parts, " "))
	}
}

// icmpCodeText returns a human-readable description of an ICMP Dest Unreachable code.
func icmpCodeText(code int) string {
	switch code {
	case 0:
		return "network unreachable"
	case 1:
		return "host unreachable"
	case 2:
		return "protocol unreachable"
	case 3:
		return "port unreachable"
	case 4:
		return "fragmentation needed"
	case 9, 10, 13:
		return "admin prohibited"
	default:
		return ""
	}
}
