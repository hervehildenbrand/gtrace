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

	if len(tools) != 6 {
		t.Errorf("expected 6 tools, got %d", len(tools))
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

func TestHandleGlobalPing_MissingAPIKey(t *testing.T) {
	h := &handlers{apiKey: ""}
	ctx := context.Background()

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"target": "example.com",
		"from":   "Paris",
	}

	result, err := h.handleGlobalPing(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("expected error when API key is missing")
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

	result := formatMTRStats(stats, 10, "example.com")

	checks := []string{
		"MTR report to example.com",
		"10 cycles",
		"gw.local",
		"192.168.1.1",
		"100.0%",
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
