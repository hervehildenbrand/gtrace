package mcp

import (
	"bytes"
	"fmt"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/internal/export"
	"github.com/hervehildenbrand/gtrace/internal/globalping"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
	"github.com/mark3labs/mcp-go/mcp"
)

// tracerouteResult renders a completed trace as a CallToolResult.
// format "json" returns structured content; view "graph" renders the
// path graph instead of the classic table (text format only).
func tracerouteResult(tr *hop.TraceResult, format, view string) *mcp.CallToolResult {
	if format == "json" {
		return mcp.NewToolResultStructured(export.ConvertTrace(tr), traceSummary(tr))
	}
	if view == "graph" {
		return graphResult([]*hop.TraceResult{tr})
	}
	return mcp.NewToolResultText(formatTraceResult(tr))
}

// graphResult renders one or more traces as the ANSI-free path graph.
func graphResult(results []*hop.TraceResult) *mcp.CallToolResult {
	for _, tr := range results {
		if tr.Source == "" {
			tr.Source = "Local"
		}
	}
	var buf bytes.Buffer
	if err := display.NewGraphRenderer(&buf, true).Render(results); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("graph rendering failed: %v", err))
	}
	return mcp.NewToolResultText(buf.String())
}

// globalPingResult renders multi-probe GlobalPing traces as a CallToolResult.
func globalPingResult(results []*globalPingProbeResult, format, view string) *mcp.CallToolResult {
	if format == "json" {
		traces := make([]*export.ExportedTrace, 0, len(results))
		for _, pr := range results {
			traces = append(traces, export.ConvertTrace(pr.trace))
		}
		summary := fmt.Sprintf("GlobalPing traceroute from %d probes", len(results))
		return mcp.NewToolResultStructured(traces, summary)
	}
	if view == "graph" {
		traces := make([]*hop.TraceResult, 0, len(results))
		for _, pr := range results {
			traces = append(traces, pr.trace)
		}
		return graphResult(traces)
	}
	return mcp.NewToolResultText(formatGlobalPingResults(results))
}

// traceSummary is the short text fallback accompanying structured trace output.
func traceSummary(tr *hop.TraceResult) string {
	reached := "target not reached"
	if tr.ReachedTarget {
		reached = "target reached"
	}
	return fmt.Sprintf("Traceroute to %s (%s): %d hops, %s", tr.Target, tr.TargetIP, tr.TotalHops(), reached)
}

// mtrReport is the structured JSON shape of an MTR run.
type mtrReport struct {
	Target string      `json:"target"`
	Cycles int         `json:"cycles"`
	Hops   []mtrHopRow `json:"hops"`
}

// mtrHopRow mirrors the columns of formatMTRStats for one hop.
type mtrHopRow struct {
	TTL      int     `json:"ttl"`
	IP       string  `json:"ip,omitempty"`
	Hostname string  `json:"hostname,omitempty"`
	ASN      uint32  `json:"asn,omitempty"`
	Loss     float64 `json:"lossPercent"`
	Sent     int     `json:"sent"`
	Recv     int     `json:"recv"`
	BestMs   float64 `json:"bestMs"`
	AvgMs    float64 `json:"avgMs"`
	WorstMs  float64 `json:"worstMs"`
}

// mtrResult renders MTR statistics as a CallToolResult.
func mtrResult(stats map[int]*display.HopStats, cycles int, target, format string) *mcp.CallToolResult {
	if format != "json" {
		return mcp.NewToolResultText(formatMTRStats(stats, cycles, target))
	}

	// Trim trailing all-timeout hops exactly like the text formatter.
	maxTTL := 0
	for ttl, s := range stats {
		if s.Recv > 0 && ttl > maxTTL {
			maxTTL = ttl
		}
	}

	report := &mtrReport{Target: target, Cycles: cycles, Hops: make([]mtrHopRow, 0, maxTTL)}
	for ttl := 1; ttl <= maxTTL; ttl++ {
		s, ok := stats[ttl]
		if !ok {
			continue
		}
		row := mtrHopRow{
			TTL:     ttl,
			Loss:    s.LossPercent(),
			Sent:    s.Sent,
			Recv:    s.Recv,
			BestMs:  float64(s.BestRTT) / float64(time.Millisecond),
			AvgMs:   float64(s.AvgRTT()) / float64(time.Millisecond),
			WorstMs: float64(s.WorstRTT) / float64(time.Millisecond),
		}
		if ip := s.PrimaryIP(); ip != nil {
			row.IP = ip.String()
			e := s.PrimaryEnrichment()
			row.Hostname = e.Hostname
			row.ASN = e.ASN
		}
		report.Hops = append(report.Hops, row)
	}

	summary := fmt.Sprintf("MTR report to %s (%d cycles, %d hops)", target, cycles, len(report.Hops))
	return mcp.NewToolResultStructured(report, summary)
}

// pingResult renders distributed ping results as a CallToolResult.
func pingResult(results []globalping.PingProbeResult, target, format string) *mcp.CallToolResult {
	if format == "json" {
		summary := fmt.Sprintf("Ping results for %s from %d probes", target, len(results))
		return mcp.NewToolResultStructured(results, summary)
	}
	return mcp.NewToolResultText(formatPingResults(results, target))
}

// dnsResult renders distributed DNS results as a CallToolResult.
func dnsResult(results []globalping.DNSProbeResult, target string, trace bool, format string) *mcp.CallToolResult {
	if format == "json" {
		summary := fmt.Sprintf("DNS results for %s from %d probes", target, len(results))
		return mcp.NewToolResultStructured(results, summary)
	}
	return mcp.NewToolResultText(formatDNSResults(results, target, trace))
}

// probeListResult renders discovered probes as a CallToolResult.
func probeListResult(probes []globalping.Probe, format string) *mcp.CallToolResult {
	if format == "json" {
		return mcp.NewToolResultStructured(probes, fmt.Sprintf("%d probes found", len(probes)))
	}
	return mcp.NewToolResultText(formatProbeList(probes))
}

// asnResult renders an ASN lookup as a CallToolResult.
func asnResult(result *enrich.ASNResult, format string) *mcp.CallToolResult {
	if format == "json" {
		return mcp.NewToolResultStructured(result, fmt.Sprintf("AS%d %s", result.ASN, result.Name))
	}
	return mcp.NewToolResultText(formatASNResult(result))
}

// geoResult renders a geolocation lookup as a CallToolResult.
func geoResult(result *enrich.GeoResult, format string) *mcp.CallToolResult {
	if format == "json" {
		return mcp.NewToolResultStructured(result, result.String())
	}
	return mcp.NewToolResultText(formatGeoResult(result))
}

// rdnsRecord is the structured JSON shape of a reverse DNS lookup.
type rdnsRecord struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// rdnsResult renders a reverse DNS lookup as a CallToolResult.
func rdnsResult(ip, hostname, format string) *mcp.CallToolResult {
	if format == "json" {
		return mcp.NewToolResultStructured(&rdnsRecord{IP: ip, Hostname: hostname}, fmt.Sprintf("%s -> %s", ip, hostname))
	}
	return mcp.NewToolResultText(formatRDNSResult(ip, hostname))
}
