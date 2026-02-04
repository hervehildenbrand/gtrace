package export

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtr/pkg/hop"
)

func TestJSONExporter_Export_ProducesValidJSON(t *testing.T) {
	tr := createTestTrace()
	exporter := NewJSONExporter()

	var buf bytes.Buffer
	err := exporter.Export(&buf, tr)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestJSONExporter_Export_IncludesTarget(t *testing.T) {
	tr := createTestTrace()
	exporter := NewJSONExporter()

	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	var result ExportedTrace
	json.Unmarshal(buf.Bytes(), &result)

	if result.Target != "google.com" {
		t.Errorf("expected target 'google.com', got %q", result.Target)
	}
	if result.TargetIP != "8.8.8.8" {
		t.Errorf("expected target IP '8.8.8.8', got %q", result.TargetIP)
	}
}

func TestJSONExporter_Export_IncludesHops(t *testing.T) {
	tr := createTestTrace()
	exporter := NewJSONExporter()

	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	var result ExportedTrace
	json.Unmarshal(buf.Bytes(), &result)

	if len(result.Hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(result.Hops))
	}

	if result.Hops[0].TTL != 1 {
		t.Errorf("expected first hop TTL 1, got %d", result.Hops[0].TTL)
	}
	if result.Hops[0].IP != "192.168.1.1" {
		t.Errorf("expected first hop IP '192.168.1.1', got %q", result.Hops[0].IP)
	}
}

func TestJSONExporter_Export_IncludesTimings(t *testing.T) {
	tr := createTestTrace()
	exporter := NewJSONExporter()

	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	var result ExportedTrace
	json.Unmarshal(buf.Bytes(), &result)

	if len(result.Hops[0].Probes) != 3 {
		t.Fatalf("expected 3 probes, got %d", len(result.Hops[0].Probes))
	}

	if result.Hops[0].Probes[0].RTT != 1.0 {
		t.Errorf("expected RTT 1.0, got %v", result.Hops[0].Probes[0].RTT)
	}
}

func TestJSONExporter_Export_PrettyPrints(t *testing.T) {
	tr := createTestTrace()
	exporter := NewJSONExporter()
	exporter.Pretty = true

	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	// Pretty printed JSON should have newlines
	if !bytes.Contains(buf.Bytes(), []byte("\n")) {
		t.Error("expected pretty-printed JSON to have newlines")
	}
}

func createTestTrace() *hop.TraceResult {
	tr := hop.NewTraceResult("google.com", "8.8.8.8")
	tr.Protocol = "icmp"
	tr.StartTime = time.Now()

	h1 := hop.NewHop(1)
	h1.AddProbe(net.ParseIP("192.168.1.1"), 1*time.Millisecond)
	h1.AddProbe(net.ParseIP("192.168.1.1"), 2*time.Millisecond)
	h1.AddProbe(net.ParseIP("192.168.1.1"), 1*time.Millisecond)
	tr.AddHop(h1)

	h2 := hop.NewHop(2)
	h2.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	h2.AddTimeout()
	h2.AddProbe(net.ParseIP("10.0.0.1"), 6*time.Millisecond)
	h2.SetEnrichment(hop.Enrichment{
		ASN:      12345,
		ASOrg:    "Test ISP",
		Hostname: "router.test.com",
	})
	tr.AddHop(h2)

	tr.ReachedTarget = true
	tr.EndTime = time.Now()

	return tr
}
