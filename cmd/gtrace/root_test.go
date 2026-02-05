package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hervehildenbrand/gtrace/internal/globalping"
)

func TestRootCommand_RequiresTarget(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()

	if err == nil {
		t.Error("expected error when no target provided")
	}
}

func TestRootCommand_AcceptsTarget(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	// Use --dry-run to avoid actual traceroute
	cmd.SetArgs([]string{"google.com", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRootCommand_ParsesFromFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--from", "London", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	from, _ := cmd.Flags().GetString("from")
	if from != "London" {
		t.Errorf("expected from 'London', got %q", from)
	}
}

func TestRootCommand_ParsesProtocolFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--protocol", "tcp", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	protocol, _ := cmd.Flags().GetString("protocol")
	if protocol != "tcp" {
		t.Errorf("expected protocol 'tcp', got %q", protocol)
	}
}

func TestRootCommand_ParsesPortFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--port", "443", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	port, _ := cmd.Flags().GetInt("port")
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestRootCommand_ParsesMaxHopsFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--max-hops", "20", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	maxHops, _ := cmd.Flags().GetInt("max-hops")
	if maxHops != 20 {
		t.Errorf("expected max-hops 20, got %d", maxHops)
	}
}

func TestRootCommand_ParsesCompareFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--compare", "--from", "London", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	compare, _ := cmd.Flags().GetBool("compare")
	if !compare {
		t.Error("expected compare to be true")
	}
}

func TestRootCommand_ParsesMonitorFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--monitor", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	monitor, _ := cmd.Flags().GetBool("monitor")
	if !monitor {
		t.Error("expected monitor to be true")
	}
}

func TestRootCommand_ParsesOutputFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "-o", "results.json", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output, _ := cmd.Flags().GetString("output")
	if output != "results.json" {
		t.Errorf("expected output 'results.json', got %q", output)
	}
}

func TestRootCommand_ParsesSimpleFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--simple", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	simple, _ := cmd.Flags().GetBool("simple")
	if !simple {
		t.Error("expected simple to be true")
	}
}

func TestRootCommand_ValidatesProtocol(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--protocol", "invalid", "--dry-run"})

	err := cmd.Execute()

	if err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestRootCommand_DefaultValues(t *testing.T) {
	cmd := NewRootCmd()

	protocol, _ := cmd.Flags().GetString("protocol")
	if protocol != "icmp" {
		t.Errorf("expected default protocol 'icmp', got %q", protocol)
	}

	maxHops, _ := cmd.Flags().GetInt("max-hops")
	if maxHops != 30 {
		t.Errorf("expected default max-hops 30, got %d", maxHops)
	}

	packets, _ := cmd.Flags().GetInt("packets")
	if packets != 3 {
		t.Errorf("expected default packets 3, got %d", packets)
	}
}

func TestRootCommand_EnrichmentEnabledByDefault(t *testing.T) {
	cmd := NewRootCmd()

	// Enrichment should be enabled by default (offline=false)
	offline, _ := cmd.Flags().GetBool("offline")
	if offline {
		t.Error("expected offline to be false by default (enrichment enabled)")
	}
}

func TestRootCommand_ParsesAlertLatencyFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--monitor", "--alert-latency", "100ms", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	alertLatency, _ := cmd.Flags().GetString("alert-latency")
	if alertLatency != "100ms" {
		t.Errorf("expected alert-latency '100ms', got %q", alertLatency)
	}
}

func TestRootCommand_ParsesAlertLossFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--monitor", "--alert-loss", "5%", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	alertLoss, _ := cmd.Flags().GetString("alert-loss")
	if alertLoss != "5%" {
		t.Errorf("expected alert-loss '5%%', got %q", alertLoss)
	}
}

func TestRootCommand_SimpleDefaultsFalse(t *testing.T) {
	cmd := NewRootCmd()

	// TUI should be default, so --simple should default to false
	simple, _ := cmd.Flags().GetBool("simple")
	if simple {
		t.Error("expected simple to be false by default (TUI mode)")
	}
}

func TestParseLatencyThreshold_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected int64 // milliseconds
	}{
		{"100ms", 100},
		{"1s", 1000},
		{"50ms", 50},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := parseLatencyThreshold(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Milliseconds() != tt.expected {
				t.Errorf("expected %dms, got %dms", tt.expected, d.Milliseconds())
			}
		})
	}
}

func TestParseLossThreshold_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"5%", 5.0},
		{"10%", 10.0},
		{"0.5%", 0.5},
		{"5", 5.0}, // Allow without percent sign
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pct, err := parseLossThreshold(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pct != tt.expected {
				t.Errorf("expected %.1f%%, got %.1f%%", tt.expected, pct)
			}
		})
	}
}

func TestRootCommand_DBStatus(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--db-status"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "GeoIP Database Status") {
		t.Errorf("expected output to contain 'GeoIP Database Status', got: %s", output)
	}
}

func TestRootCommand_DownloadDB(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--download-db"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "MaxMind") {
		t.Errorf("expected output to contain 'MaxMind', got: %s", output)
	}
}

func TestRootCommand_MTRModeDefaultValues(t *testing.T) {
	cmd := NewRootCmd()

	// Check MTR mode default interval
	interval, _ := cmd.Flags().GetString("interval")
	if interval != "1s" {
		t.Errorf("expected default interval '1s', got %q", interval)
	}

	// Check MTR mode default cycles (0 = infinite)
	cycles, _ := cmd.Flags().GetInt("cycles")
	if cycles != 0 {
		t.Errorf("expected default cycles 0, got %d", cycles)
	}

	// Check MTR mode default timeout
	timeout, _ := cmd.Flags().GetString("timeout")
	if timeout != "500ms" {
		t.Errorf("expected default timeout '500ms' (MTR-style), got %q", timeout)
	}
}

func TestRootCommand_ParsesIntervalFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--interval", "500ms", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	interval, _ := cmd.Flags().GetString("interval")
	if interval != "500ms" {
		t.Errorf("expected interval '500ms', got %q", interval)
	}
}

func TestRootCommand_ParsesCyclesFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--cycles", "10", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	cycles, _ := cmd.Flags().GetInt("cycles")
	if cycles != 10 {
		t.Errorf("expected cycles 10, got %d", cycles)
	}
}

func TestRootCommand_CompareRequiresFrom(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	// --compare without --from should error
	cmd.SetArgs([]string{"google.com", "--compare", "--dry-run"})

	err := cmd.Execute()

	if err == nil {
		t.Fatal("expected error when --compare is used without --from")
	}
	if !strings.Contains(err.Error(), "--from") {
		t.Errorf("error should mention --from, got: %v", err)
	}
}

func TestRootCommand_ParsesIPv4Flag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "-4", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ipv4, _ := cmd.Flags().GetBool("ipv4")
	if !ipv4 {
		t.Error("expected ipv4 to be true")
	}
}

func TestRootCommand_ParsesIPv6Flag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "-6", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ipv6, _ := cmd.Flags().GetBool("ipv6")
	if !ipv6 {
		t.Error("expected ipv6 to be true")
	}
}

func TestRootCommand_IPv4AndIPv6AreMutuallyExclusive(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "-4", "-6", "--dry-run"})

	err := cmd.Execute()

	if err == nil {
		t.Fatal("expected error when both -4 and -6 are specified")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusivity, got: %v", err)
	}
}

func TestRootCommand_IPv4DefaultsFalse(t *testing.T) {
	cmd := NewRootCmd()

	ipv4, _ := cmd.Flags().GetBool("ipv4")
	if ipv4 {
		t.Error("expected ipv4 to be false by default")
	}
}

func TestRootCommand_IPv6DefaultsFalse(t *testing.T) {
	cmd := NewRootCmd()

	ipv6, _ := cmd.Flags().GetBool("ipv6")
	if ipv6 {
		t.Error("expected ipv6 to be false by default")
	}
}

func TestGetIPVersion_Default(t *testing.T) {
	cfg := &Config{}
	if v := getIPVersion(cfg); v != 0 {
		t.Errorf("expected 0 (auto) for default config, got %d", v)
	}
}

func TestGetIPVersion_IPv4Only(t *testing.T) {
	cfg := &Config{IPv4Only: true}
	if v := getIPVersion(cfg); v != 4 {
		t.Errorf("expected 4 for IPv4Only, got %d", v)
	}
}

func TestGetIPVersion_IPv6Only(t *testing.T) {
	cfg := &Config{IPv6Only: true}
	if v := getIPVersion(cfg); v != 6 {
		t.Errorf("expected 6 for IPv6Only, got %d", v)
	}
}

func TestDisplayMTRHop_ShowsASN(t *testing.T) {
	buf := new(bytes.Buffer)
	mh := &globalping.MTRHop{
		ResolvedAddress:  "80.10.255.25",
		ResolvedHostname: "host.example.net",
		ASN:              []uint32{3215},
		Stats: globalping.MTRStats{
			Loss:  0.0,
			Total: 3,
			Rcv:   3,
			Min:   0.5,
			Avg:   0.7,
			Max:   1.1,
		},
	}

	displayMTRHop(buf, 2, mh)

	output := buf.String()
	if !strings.Contains(output, "[AS3215]") {
		t.Errorf("expected output to contain '[AS3215]', got: %q", output)
	}
}

func TestDisplayMTRHop_NoASN(t *testing.T) {
	buf := new(bytes.Buffer)
	mh := &globalping.MTRHop{
		ResolvedAddress: "192.168.1.1",
		ASN:             []uint32{},
		Stats: globalping.MTRStats{
			Loss:  0.0,
			Total: 3,
			Rcv:   3,
			Min:   0.5,
			Avg:   0.7,
			Max:   1.1,
		},
	}

	displayMTRHop(buf, 1, mh)

	output := buf.String()
	if strings.Contains(output, "[AS") {
		t.Errorf("expected no ASN in output, got: %q", output)
	}
}

func TestDisplayMTRHop_MultipleASNs_ShowsFirst(t *testing.T) {
	buf := new(bytes.Buffer)
	mh := &globalping.MTRHop{
		ResolvedAddress: "1.1.1.1",
		ASN:             []uint32{13335, 15169},
		Stats: globalping.MTRStats{
			Loss:  0.0,
			Total: 3,
			Rcv:   3,
			Min:   0.5,
			Avg:   0.7,
			Max:   1.1,
		},
	}

	displayMTRHop(buf, 1, mh)

	output := buf.String()
	if !strings.Contains(output, "[AS13335]") {
		t.Errorf("expected output to contain '[AS13335]', got: %q", output)
	}
}

func TestDisplayMTRHop_ColumnsAligned(t *testing.T) {
	// Hop with ASN and hop without ASN should have stats at the same column position
	withASN := new(bytes.Buffer)
	mhWith := &globalping.MTRHop{
		ResolvedAddress: "80.10.255.25",
		ASN:             []uint32{3215},
		Stats: globalping.MTRStats{
			Loss: 0.0, Total: 3, Rcv: 3, Min: 0.5, Avg: 0.7, Max: 1.1,
		},
	}
	displayMTRHop(withASN, 2, mhWith)

	withoutASN := new(bytes.Buffer)
	mhWithout := &globalping.MTRHop{
		ResolvedAddress: "192.168.1.1",
		ASN:             []uint32{},
		Stats: globalping.MTRStats{
			Loss: 0.0, Total: 3, Rcv: 3, Min: 0.5, Avg: 0.7, Max: 1.1,
		},
	}
	displayMTRHop(withoutASN, 1, mhWithout)

	// Find the position of "0.0%" (the Loss column) in each output
	outWith := withASN.String()
	outWithout := withoutASN.String()
	posWith := strings.Index(outWith, "0.0%")
	posWithout := strings.Index(outWithout, "0.0%")

	if posWith != posWithout {
		t.Errorf("columns misaligned: with ASN Loss%% at position %d, without ASN at %d\nwith:    %q\nwithout: %q",
			posWith, posWithout, outWith, outWithout)
	}
}
