package mcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

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

	// Find max TTL
	maxTTL := 0
	for ttl := range stats {
		if ttl > maxTTL {
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
