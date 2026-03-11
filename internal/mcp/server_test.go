package mcp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/enrich"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestNewServer_RegistersAllTools(t *testing.T) {
	s := NewServer("1.0.0-test", "")

	tools := s.ListTools()

	expected := map[string]bool{
		"list_probes": false,
		"traceroute":  false,
		"mtr":         false,
		"globalping":  false,
		"asn_lookup":  false,
		"geo_lookup":  false,
		"reverse_dns": false,
	}

	for name := range tools {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("tool %q not registered", name)
		}
	}

	if len(tools) != 7 {
		t.Errorf("expected 7 tools, got %d", len(tools))
	}
}

func TestTracerouteTool_HasRequiredParams(t *testing.T) {
	tool := tracerouteTool()

	if tool.Name != "traceroute" {
		t.Errorf("expected name 'traceroute', got %q", tool.Name)
	}

	found := false
	for _, r := range tool.InputSchema.Required {
		if r == "target" {
			found = true
			break
		}
	}
	if !found {
		t.Error("'target' should be required")
	}
}

func TestMTRTool_HasRequiredParams(t *testing.T) {
	tool := mtrTool()

	if tool.Name != "mtr" {
		t.Errorf("expected name 'mtr', got %q", tool.Name)
	}

	found := false
	for _, r := range tool.InputSchema.Required {
		if r == "target" {
			found = true
			break
		}
	}
	if !found {
		t.Error("'target' should be required")
	}
}

func TestGlobalPingTool_HasRequiredParams(t *testing.T) {
	tool := globalPingTool()

	requiredMap := make(map[string]bool)
	for _, r := range tool.InputSchema.Required {
		requiredMap[r] = true
	}

	if !requiredMap["target"] {
		t.Error("'target' should be required")
	}
	if !requiredMap["from"] {
		t.Error("'from' should be required")
	}
}

func TestHandleASNLookup_InvalidIP(t *testing.T) {
	h := &handlers{}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"ip": "not-an-ip",
	}

	result, err := h.handleASNLookup(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error result for invalid IP")
	}
}

func TestHandleASNLookup_MissingIP(t *testing.T) {
	h := &handlers{}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := h.handleASNLookup(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error result for missing IP")
	}
}

func TestHandleGeoLookup_InvalidIP(t *testing.T) {
	h := &handlers{}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"ip": "invalid",
	}

	result, err := h.handleGeoLookup(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error result for invalid IP")
	}
}

func TestHandleReverseDNS_InvalidIP(t *testing.T) {
	h := &handlers{}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"ip": "invalid",
	}

	result, err := h.handleReverseDNS(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error result for invalid IP")
	}
}

func TestHandleGlobalPing_MissingFrom(t *testing.T) {
	h := &handlers{}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"target": "example.com",
	}

	result, err := h.handleGlobalPing(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error when 'from' is missing")
	}
}

func TestHandleTraceroute_MissingTarget(t *testing.T) {
	h := &handlers{}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := h.handleTraceroute(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error for missing target")
	}
}

func TestHandleMTR_MissingTarget(t *testing.T) {
	h := &handlers{}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := h.handleMTR(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error for missing target")
	}
}

func TestGetAddressFamily(t *testing.T) {
	tests := []struct {
		name     string
		args     map[string]any
		expected string
	}{
		{"default", map[string]any{}, "auto"},
		{"ipv4", map[string]any{"ipv4": true}, "ipv4"},
		{"ipv6", map[string]any{"ipv6": true}, "ipv6"},
		{"both_ipv4_wins", map[string]any{"ipv4": true, "ipv6": true}, "ipv4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := mcplib.CallToolRequest{}
			req.Params.Arguments = tt.args

			af := getAddressFamily(req)
			var got string
			switch af {
			case 0:
				got = "auto"
			case 1:
				got = "ipv4"
			case 2:
				got = "ipv6"
			}
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

// --- Formatting Tests ---

func TestFormatTraceResult(t *testing.T) {
	tr := hop.NewTraceResult("example.com", "93.184.216.34")
	tr.Protocol = "icmp"
	tr.ReachedTarget = true

	h1 := hop.NewHop(1)
	h1.AddProbe(net.ParseIP("192.168.1.1"), 1*time.Millisecond)
	h1.SetEnrichment(hop.Enrichment{
		Hostname: "gateway.local",
		ASN:      64496,
		ASOrg:    "Example ISP",
	})
	tr.AddHop(h1)

	h2 := hop.NewHop(2)
	h2.AddTimeout()
	tr.AddHop(h2)

	h3 := hop.NewHop(3)
	h3.AddProbe(net.ParseIP("93.184.216.34"), 10*time.Millisecond)
	tr.AddHop(h3)

	result := formatTraceResult(tr)

	checks := []string{
		"example.com",
		"93.184.216.34",
		"icmp",
		"192.168.1.1",
		"gateway.local",
		"AS64496",
		"* * *",
		"Target reached in 3 hops",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("result missing %q:\n%s", check, result)
		}
	}
}

func TestFormatMTRStats(t *testing.T) {
	stats := make(map[int]*display.HopStats)

	s1 := display.NewHopStats(1)
	for i := 0; i < 10; i++ {
		s1.AddProbe(net.ParseIP("192.168.1.1"), time.Duration(i+1)*time.Millisecond)
	}
	s1.SetEnrichment(hop.Enrichment{Hostname: "gw.local"})
	stats[1] = s1

	s2 := display.NewHopStats(2)
	for i := 0; i < 10; i++ {
		s2.AddTimeout()
	}
	stats[2] = s2

	// Hop 3: target with responses (makes hop 2 an intermediate timeout hop)
	s3 := display.NewHopStats(3)
	for i := 0; i < 10; i++ {
		s3.AddProbe(net.ParseIP("8.8.8.8"), time.Duration(i+5)*time.Millisecond)
	}
	stats[3] = s3

	result := formatMTRStats(stats, 10, "example.com")

	checks := []string{
		"MTR report to example.com",
		"10 cycles",
		"gw.local",
		"192.168.1.1",
		"100.0%", // hop 2 intermediate timeout
		"8.8.8.8",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("result missing %q:\n%s", check, result)
		}
	}
}

func TestFormatASNResult(t *testing.T) {
	result := formatASNResult(&enrich.ASNResult{
		ASN:      15169,
		Name:     "GOOGLE",
		Prefix:   "8.8.8.0/24",
		Country:  "US",
		Registry: "arin",
		Date:     "2014-03-14",
	})

	checks := []string{"AS15169", "GOOGLE", "8.8.8.0/24", "US", "arin", "2014-03-14"}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("result missing %q:\n%s", check, result)
		}
	}
}

func TestFormatGeoResult(t *testing.T) {
	result := formatGeoResult(&enrich.GeoResult{
		City:        "Mountain View",
		Country:     "US",
		CountryName: "United States",
		Region:      "California",
		Latitude:    37.386,
		Longitude:   -122.0838,
		Timezone:    "America/Los_Angeles",
	})

	checks := []string{"Mountain View", "California", "United States", "US", "37.3860", "America/Los_Angeles"}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("result missing %q:\n%s", check, result)
		}
	}
}

func TestFormatRDNSResult(t *testing.T) {
	result := formatRDNSResult("8.8.8.8", "dns.google")

	if !strings.Contains(result, "8.8.8.8") {
		t.Errorf("result missing IP: %s", result)
	}
	if !strings.Contains(result, "dns.google") {
		t.Errorf("result missing hostname: %s", result)
	}
}

func TestFormatGlobalPingResults(t *testing.T) {
	tr := hop.NewTraceResult("example.com", "93.184.216.34")
	tr.Protocol = "icmp"
	tr.ReachedTarget = true

	h1 := hop.NewHop(1)
	h1.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	tr.AddHop(h1)

	results := []*globalPingProbeResult{
		{
			probe: probeInfo{
				City:    "Paris",
				Country: "FR",
				ASN:     12322,
				Network: "Free SAS",
			},
			trace: tr,
		},
	}

	output := formatGlobalPingResults(results)

	checks := []string{"Paris", "FR", "AS12322", "Free SAS", "example.com"}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("result missing %q:\n%s", check, output)
		}
	}
}

func TestFormatMTRStats_TrimsAfterTarget(t *testing.T) {
	stats := make(map[int]*display.HopStats)

	// Hop 1: gateway with responses
	s1 := display.NewHopStats(1)
	for i := 0; i < 5; i++ {
		s1.AddProbe(net.ParseIP("192.168.1.1"), 2*time.Millisecond)
	}
	stats[1] = s1

	// Hop 2: intermediate with responses
	s2 := display.NewHopStats(2)
	for i := 0; i < 5; i++ {
		s2.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	}
	stats[2] = s2

	// Hop 3: target reached
	s3 := display.NewHopStats(3)
	for i := 0; i < 5; i++ {
		s3.AddProbe(net.ParseIP("8.8.8.8"), 10*time.Millisecond)
	}
	stats[3] = s3

	// Hops 4-6: beyond target, all timeouts (should be trimmed)
	for ttl := 4; ttl <= 6; ttl++ {
		s := display.NewHopStats(ttl)
		for i := 0; i < 5; i++ {
			s.AddTimeout()
		}
		stats[ttl] = s
	}

	result := formatMTRStats(stats, 5, "8.8.8.8")

	// Should show hops 1-3
	if !strings.Contains(result, "192.168.1.1") {
		t.Error("expected hop 1 (192.168.1.1) in output")
	}
	if !strings.Contains(result, "8.8.8.8") {
		t.Error("expected hop 3 (8.8.8.8) in output")
	}

	// Should NOT show hops 4-6 (all timeouts after target)
	if strings.Contains(result, "???") {
		t.Errorf("expected trailing timeout hops to be trimmed, got:\n%s", result)
	}
}

func TestFormatHop_NoResponse(t *testing.T) {
	var sb strings.Builder
	h := hop.NewHop(5)
	h.AddTimeout()
	h.AddTimeout()
	h.AddTimeout()

	formatHop(&sb, h)
	result := sb.String()

	if !strings.Contains(result, "* * *") {
		t.Errorf("expected timeout markers in result: %s", result)
	}
	if !strings.Contains(result, "5") {
		t.Errorf("expected hop number 5 in result: %s", result)
	}
}

func TestFormatHop_WithNATAndMTU(t *testing.T) {
	var sb strings.Builder
	h := hop.NewHop(3)
	h.AddProbe(net.ParseIP("10.0.0.1"), 2*time.Millisecond)
	h.NAT = true
	h.MTU = 1400

	formatHop(&sb, h)
	result := sb.String()

	if !strings.Contains(result, "NAT detected") {
		t.Errorf("expected NAT marker in result: %s", result)
	}
	if !strings.Contains(result, "MTU: 1400") {
		t.Errorf("expected MTU in result: %s", result)
	}
}

func TestUpdateMCPRateLimitFlags(t *testing.T) {
	stats := map[int]*display.HopStats{
		1: display.NewHopStats(1),
		2: display.NewHopStats(2),
		3: display.NewHopStats(3),
	}

	// Hop 1: 0% loss
	for i := 0; i < 10; i++ {
		stats[1].AddProbe(net.ParseIP("10.0.0.1"), time.Millisecond)
	}
	// Hop 2: 50% loss (rate limited — downstream is fine)
	for i := 0; i < 5; i++ {
		stats[2].AddProbe(net.ParseIP("10.0.0.2"), time.Millisecond)
		stats[2].AddTimeout()
	}
	// Hop 3: 0% loss
	for i := 0; i < 10; i++ {
		stats[3].AddProbe(net.ParseIP("10.0.0.3"), time.Millisecond)
	}

	updateMCPRateLimitFlags(stats)

	if stats[1].RateLimited {
		t.Error("hop 1 should NOT be rate limited")
	}
	if !stats[2].RateLimited {
		t.Error("hop 2 SHOULD be rate limited (50% loss but downstream is 0%)")
	}
	if stats[3].RateLimited {
		t.Error("hop 3 should NOT be rate limited")
	}
}

func TestUpdateMCPRateLimitFlags_RealLoss(t *testing.T) {
	stats := map[int]*display.HopStats{
		1: display.NewHopStats(1),
		2: display.NewHopStats(2),
		3: display.NewHopStats(3),
	}

	// All hops have ~50% loss — this is real loss, not rate limiting
	for i := 0; i < 5; i++ {
		stats[1].AddProbe(net.ParseIP("10.0.0.1"), time.Millisecond)
		stats[1].AddTimeout()
		stats[2].AddProbe(net.ParseIP("10.0.0.2"), time.Millisecond)
		stats[2].AddTimeout()
		stats[3].AddProbe(net.ParseIP("10.0.0.3"), time.Millisecond)
		stats[3].AddTimeout()
	}

	updateMCPRateLimitFlags(stats)

	if stats[2].RateLimited {
		t.Error("hop 2 should NOT be rate limited when downstream also has loss")
	}
}

func TestUpdateMCPECMPClassification_PerFlow(t *testing.T) {
	stats := map[int]*display.HopStats{
		1: display.NewHopStats(1),
	}
	stats[1].AddProbe(net.ParseIP("10.0.0.1"), time.Millisecond)
	stats[1].AddProbe(net.ParseIP("10.0.0.2"), time.Millisecond)

	// Each flow consistently goes to one IP
	stats[1].FlowPaths[1] = map[string]int{"10.0.0.1": 3}
	stats[1].FlowPaths[2] = map[string]int{"10.0.0.2": 3}

	updateMCPECMPClassification(stats)

	if stats[1].ECMPClassified != "per_flow" {
		t.Errorf("expected per_flow, got %q", stats[1].ECMPClassified)
	}
}

func TestUpdateMCPECMPClassification_PerPacket(t *testing.T) {
	stats := map[int]*display.HopStats{
		1: display.NewHopStats(1),
	}
	stats[1].AddProbe(net.ParseIP("10.0.0.1"), time.Millisecond)
	stats[1].AddProbe(net.ParseIP("10.0.0.2"), time.Millisecond)

	// A single flow hits multiple IPs — per-packet load balancing
	stats[1].FlowPaths[1] = map[string]int{"10.0.0.1": 2, "10.0.0.2": 1}

	updateMCPECMPClassification(stats)

	if stats[1].ECMPClassified != "per_packet" {
		t.Errorf("expected per_packet, got %q", stats[1].ECMPClassified)
	}
}

func TestUpdateMCPECMPClassification_NoECMP(t *testing.T) {
	stats := map[int]*display.HopStats{
		1: display.NewHopStats(1),
	}
	stats[1].AddProbe(net.ParseIP("10.0.0.1"), time.Millisecond)

	updateMCPECMPClassification(stats)

	if stats[1].ECMPClassified != "" {
		t.Errorf("expected empty, got %q", stats[1].ECMPClassified)
	}
}
