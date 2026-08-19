package mcp

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/internal/export"
	"github.com/hervehildenbrand/gtrace/internal/globalping"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// resultTestTrace fabricates a small enriched trace for seam tests.
func resultTestTrace() *hop.TraceResult {
	tr := hop.NewTraceResult("example.com", "93.184.216.34")
	tr.Protocol = "icmp"
	tr.ReachedTarget = true

	h1 := hop.NewHop(1)
	h1.AddProbe(net.ParseIP("192.168.1.1"), 1*time.Millisecond)
	h1.SetEnrichment(hop.Enrichment{Hostname: "gw.local", ASN: 64496, ASOrg: "Example ISP"})
	tr.AddHop(h1)

	h2 := hop.NewHop(2)
	h2.AddTimeout()
	tr.AddHop(h2)

	h3 := hop.NewHop(3)
	h3.AddProbe(net.ParseIP("93.184.216.34"), 10*time.Millisecond)
	tr.AddHop(h3)

	return tr
}

func resultText(t *testing.T, res *mcplib.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := res.Content[0].(mcplib.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want TextContent", res.Content[0])
	}
	return tc.Text
}

func TestTracerouteResult_TextDefault_MatchesFormatTraceResult(t *testing.T) {
	tr := resultTestTrace()

	res := tracerouteResult(tr, "text", "table")

	if got, want := resultText(t, res), formatTraceResult(tr); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if res.StructuredContent != nil {
		t.Error("text format must not set structuredContent")
	}
}

func TestTracerouteResult_JSON_MatchesExportedTrace(t *testing.T) {
	tr := resultTestTrace()

	res := tracerouteResult(tr, "json", "table")

	exported, ok := res.StructuredContent.(*export.ExportedTrace)
	if !ok {
		t.Fatalf("structuredContent is %T, want *export.ExportedTrace", res.StructuredContent)
	}
	if exported.Target != "example.com" {
		t.Errorf("target = %q, want example.com", exported.Target)
	}
	if len(exported.Hops) != 3 {
		t.Errorf("hops = %d, want 3", len(exported.Hops))
	}
	if exported.Hops[0].ASN != 64496 {
		t.Errorf("hop1 ASN = %d, want 64496", exported.Hops[0].ASN)
	}
	if resultText(t, res) == "" {
		t.Error("json format must keep a text fallback")
	}
}

func TestTracerouteResult_GraphView_ContainsLaneGlyphs(t *testing.T) {
	tr := resultTestTrace()

	res := tracerouteResult(tr, "text", "graph")

	text := resultText(t, res)
	if !strings.Contains(text, "●") {
		t.Errorf("graph view missing hop glyph ●:\n%s", text)
	}
	if !strings.Contains(text, "○") {
		t.Errorf("graph view missing timeout glyph ○:\n%s", text)
	}
	if strings.Contains(text, "\x1b[") {
		t.Error("graph view must not contain ANSI escapes")
	}
}

func TestTracerouteResult_JSONIgnoresView(t *testing.T) {
	res := tracerouteResult(resultTestTrace(), "json", "graph")

	if res.StructuredContent == nil {
		t.Error("format=json must win over view=graph")
	}
}

// resultTestGlobalPing fabricates two probe results with distinct sources.
func resultTestGlobalPing() []*globalPingProbeResult {
	mk := func(source, hopIP string) *hop.TraceResult {
		tr := hop.NewTraceResult("example.com", "93.184.216.34")
		tr.Protocol = "ICMP"
		tr.Source = source
		tr.ReachedTarget = true
		h := hop.NewHop(1)
		h.AddProbe(net.ParseIP(hopIP), 5*time.Millisecond)
		tr.AddHop(h)
		return tr
	}
	return []*globalPingProbeResult{
		{probe: probeInfo{City: "Paris", Country: "FR", ASN: 12322, Network: "Free SAS"}, trace: mk("Paris, FR", "10.0.0.1")},
		{probe: probeInfo{City: "Tokyo", Country: "JP", ASN: 2497, Network: "IIJ"}, trace: mk("Tokyo, JP", "10.0.1.1")},
	}
}

func TestGlobalPingResult_TextDefault_MatchesFormat(t *testing.T) {
	results := resultTestGlobalPing()

	res := globalPingResult(results, "text", "table")

	if got, want := resultText(t, res), formatGlobalPingResults(results); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if res.StructuredContent != nil {
		t.Error("text format must not set structuredContent")
	}
}

func TestGlobalPingResult_JSON_ExportedTracePerProbe(t *testing.T) {
	results := resultTestGlobalPing()

	res := globalPingResult(results, "json", "table")

	traces, ok := res.StructuredContent.([]*export.ExportedTrace)
	if !ok {
		t.Fatalf("structuredContent is %T, want []*export.ExportedTrace", res.StructuredContent)
	}
	if len(traces) != 2 {
		t.Fatalf("traces = %d, want 2", len(traces))
	}
	if traces[0].Source != "Paris, FR" || traces[1].Source != "Tokyo, JP" {
		t.Errorf("sources = %q, %q; want probe locations", traces[0].Source, traces[1].Source)
	}
}

func TestGlobalPingResult_GraphView_ContainsLaneGlyphs(t *testing.T) {
	res := globalPingResult(resultTestGlobalPing(), "text", "graph")

	text := resultText(t, res)
	if !strings.Contains(text, "●") {
		t.Errorf("graph view missing hop glyph ●:\n%s", text)
	}
	if strings.Contains(text, "\x1b[") {
		t.Error("graph view must not contain ANSI escapes")
	}
}

func resultTestMTRStats() map[int]*display.HopStats {
	stats := make(map[int]*display.HopStats)
	s1 := display.NewHopStats(1)
	for i := 0; i < 4; i++ {
		s1.AddProbe(net.ParseIP("192.168.1.1"), time.Duration(i+1)*time.Millisecond)
	}
	s1.SetEnrichment(hop.Enrichment{Hostname: "gw.local", ASN: 64496})
	stats[1] = s1

	s2 := display.NewHopStats(2)
	s2.AddProbe(net.ParseIP("8.8.8.8"), 10*time.Millisecond)
	s2.AddTimeout()
	stats[2] = s2

	// Trailing all-timeout hop must be trimmed like the text formatter does.
	s3 := display.NewHopStats(3)
	s3.AddTimeout()
	stats[3] = s3
	return stats
}

func TestMTRResult_TextDefault_MatchesFormatMTRStats(t *testing.T) {
	stats := resultTestMTRStats()

	res := mtrResult(stats, 4, "example.com", "text")

	if got, want := resultText(t, res), formatMTRStats(stats, 4, "example.com"); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestMTRResult_JSON_HopStatsFields(t *testing.T) {
	stats := resultTestMTRStats()

	res := mtrResult(stats, 4, "example.com", "json")

	report, ok := res.StructuredContent.(*mtrReport)
	if !ok {
		t.Fatalf("structuredContent is %T, want *mtrReport", res.StructuredContent)
	}
	if report.Target != "example.com" || report.Cycles != 4 {
		t.Errorf("target/cycles = %q/%d", report.Target, report.Cycles)
	}
	if len(report.Hops) != 2 {
		t.Fatalf("hops = %d, want 2 (trailing timeout hop trimmed)", len(report.Hops))
	}
	h1 := report.Hops[0]
	if h1.TTL != 1 || h1.IP != "192.168.1.1" || h1.Hostname != "gw.local" || h1.ASN != 64496 {
		t.Errorf("hop1 = %+v", h1)
	}
	if h1.Sent != 4 || h1.Recv != 4 || h1.Loss != 0 {
		t.Errorf("hop1 counters = %+v", h1)
	}
	h2 := report.Hops[1]
	if h2.Sent != 2 || h2.Recv != 1 || h2.Loss != 50 {
		t.Errorf("hop2 counters = %+v", h2)
	}
	if h2.BestMs != 10 || h2.AvgMs != 10 || h2.WorstMs != 10 {
		t.Errorf("hop2 RTTs = %+v", h2)
	}
}

func TestPingResult_JSON_RawProbeResults(t *testing.T) {
	avg := 12.5
	results := []globalping.PingProbeResult{
		{
			Probe:  globalping.ProbeInfo{City: "Paris", Country: "FR", ASN: 12322, Network: "Free SAS"},
			Result: globalping.PingResult{Stats: globalping.PingStats{Total: 3, Rcv: 3, Avg: &avg}},
		},
	}

	res := pingResult(results, "example.com", "json")

	got, ok := res.StructuredContent.([]globalping.PingProbeResult)
	if !ok {
		t.Fatalf("structuredContent is %T, want []globalping.PingProbeResult", res.StructuredContent)
	}
	if len(got) != 1 || got[0].Probe.City != "Paris" || *got[0].Result.Stats.Avg != 12.5 {
		t.Errorf("payload = %+v", got)
	}
}

func TestPingResult_TextDefault_MatchesFormat(t *testing.T) {
	results := []globalping.PingProbeResult{{Probe: globalping.ProbeInfo{City: "Paris"}}}

	res := pingResult(results, "example.com", "text")

	if got, want := resultText(t, res), formatPingResults(results, "example.com"); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestDNSResult_JSON_RawProbeResults(t *testing.T) {
	results := []globalping.DNSProbeResult{
		{
			Probe: globalping.ProbeInfo{City: "Tokyo", Country: "JP"},
			Result: globalping.DNSResult{
				StatusCode: 0,
				Answers:    []globalping.DNSAnswer{{Name: "example.com.", Type: "A", Value: "93.184.216.34"}},
			},
		},
	}

	res := dnsResult(results, "example.com", false, "json")

	got, ok := res.StructuredContent.([]globalping.DNSProbeResult)
	if !ok {
		t.Fatalf("structuredContent is %T, want []globalping.DNSProbeResult", res.StructuredContent)
	}
	if len(got) != 1 || got[0].Result.Answers[0].Value != "93.184.216.34" {
		t.Errorf("payload = %+v", got)
	}
}

func TestDNSResult_TextDefault_MatchesFormat(t *testing.T) {
	results := []globalping.DNSProbeResult{{Probe: globalping.ProbeInfo{City: "Tokyo"}}}

	res := dnsResult(results, "example.com", true, "text")

	if got, want := resultText(t, res), formatDNSResults(results, "example.com", true); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestProbeListResult_JSON_RawProbes(t *testing.T) {
	probes := []globalping.Probe{
		{Version: "1.0", Location: globalping.ProbeLocation{City: "Paris", Country: "FR", ASN: 12322}},
	}

	res := probeListResult(probes, "json")

	got, ok := res.StructuredContent.([]globalping.Probe)
	if !ok {
		t.Fatalf("structuredContent is %T, want []globalping.Probe", res.StructuredContent)
	}
	if len(got) != 1 || got[0].Location.City != "Paris" {
		t.Errorf("payload = %+v", got)
	}
}

func TestProbeListResult_TextDefault_MatchesFormat(t *testing.T) {
	probes := []globalping.Probe{{Location: globalping.ProbeLocation{City: "Paris"}}}

	res := probeListResult(probes, "text")

	if got, want := resultText(t, res), formatProbeList(probes); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestASNResult_JSON_RawStruct(t *testing.T) {
	r := &enrich.ASNResult{ASN: 15169, Name: "GOOGLE"}

	res := asnResult(r, "json")

	got, ok := res.StructuredContent.(*enrich.ASNResult)
	if !ok {
		t.Fatalf("structuredContent is %T, want *enrich.ASNResult", res.StructuredContent)
	}
	if got.ASN != 15169 {
		t.Errorf("payload = %+v", got)
	}
}

func TestASNResult_TextDefault_MatchesFormat(t *testing.T) {
	r := &enrich.ASNResult{ASN: 15169, Name: "GOOGLE"}

	res := asnResult(r, "text")

	if got, want := resultText(t, res), formatASNResult(r); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestGeoResult_JSON_RawStruct(t *testing.T) {
	r := &enrich.GeoResult{City: "Mountain View", Country: "US"}

	res := geoResult(r, "json")

	got, ok := res.StructuredContent.(*enrich.GeoResult)
	if !ok {
		t.Fatalf("structuredContent is %T, want *enrich.GeoResult", res.StructuredContent)
	}
	if got.City != "Mountain View" {
		t.Errorf("payload = %+v", got)
	}
}

func TestGeoResult_TextDefault_MatchesFormat(t *testing.T) {
	r := &enrich.GeoResult{City: "Mountain View", Country: "US", CountryName: "United States"}

	res := geoResult(r, "text")

	if got, want := resultText(t, res), formatGeoResult(r); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestRDNSResult_JSON_IPAndHostname(t *testing.T) {
	res := rdnsResult("8.8.8.8", "dns.google", "json")

	got, ok := res.StructuredContent.(*rdnsRecord)
	if !ok {
		t.Fatalf("structuredContent is %T, want *rdnsRecord", res.StructuredContent)
	}
	if got.IP != "8.8.8.8" || got.Hostname != "dns.google" {
		t.Errorf("payload = %+v", got)
	}
}

func TestRDNSResult_TextDefault_MatchesFormat(t *testing.T) {
	res := rdnsResult("8.8.8.8", "dns.google", "text")

	if got, want := resultText(t, res), formatRDNSResult("8.8.8.8", "dns.google"); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func allTools() map[string]mcplib.Tool {
	return map[string]mcplib.Tool{
		"list_probes": listProbesTool(),
		"traceroute":  tracerouteTool(),
		"mtr":         mtrTool(),
		"globalping":  globalPingTool(),
		"ping":        pingTool(),
		"dns":         dnsTool(),
		"asn_lookup":  asnLookupTool(),
		"geo_lookup":  geoLookupTool(),
		"reverse_dns": reverseDNSTool(),
	}
}

func paramEnum(t *testing.T, tool mcplib.Tool, param string) []string {
	t.Helper()
	prop, ok := tool.InputSchema.Properties[param]
	if !ok {
		return nil
	}
	m, ok := prop.(map[string]any)
	if !ok {
		t.Fatalf("%s property is %T, want map", param, prop)
	}
	raw, _ := m["enum"].([]string)
	return raw
}

func TestListTools_HaveFormatParam(t *testing.T) {
	for name, tool := range allTools() {
		enum := paramEnum(t, tool, "format")
		if enum == nil {
			t.Errorf("tool %s missing 'format' parameter", name)
			continue
		}
		if len(enum) != 2 || enum[0] != "text" || enum[1] != "json" {
			t.Errorf("tool %s format enum = %v, want [text json]", name, enum)
		}
	}
}

func TestListTools_ViewParamOnlyOnTraceTools(t *testing.T) {
	withView := map[string]bool{"traceroute": true, "globalping": true}
	for name, tool := range allTools() {
		enum := paramEnum(t, tool, "view")
		if withView[name] {
			if enum == nil {
				t.Errorf("tool %s missing 'view' parameter", name)
				continue
			}
			if len(enum) != 2 || enum[0] != "table" || enum[1] != "graph" {
				t.Errorf("tool %s view enum = %v, want [table graph]", name, enum)
			}
		} else if enum != nil {
			t.Errorf("tool %s must not have a 'view' parameter", name)
		}
	}
}
