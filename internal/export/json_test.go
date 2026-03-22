package export

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
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

func TestJSONExporter_Export_IncludesICMPCode(t *testing.T) {
	tr := hop.NewTraceResult("example.com", "1.2.3.4")
	tr.Protocol = "udp"

	h := hop.NewHop(1)
	h.Probes = append(h.Probes, hop.Probe{
		IP:       net.ParseIP("1.2.3.4"),
		RTT:      5 * time.Millisecond,
		ICMPType: 3,
		ICMPCode: 3,
	})
	tr.AddHop(h)

	exporter := NewJSONExporter()
	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	var result ExportedTrace
	json.Unmarshal(buf.Bytes(), &result)

	if result.Hops[0].ICMPCode != "port_unreachable" {
		t.Errorf("expected icmpCode 'port_unreachable', got %q", result.Hops[0].ICMPCode)
	}
}

func TestJSONExporter_Export_OmitsICMPCodeForEchoReply(t *testing.T) {
	tr := hop.NewTraceResult("example.com", "1.2.3.4")
	tr.Protocol = "icmp"

	h := hop.NewHop(1)
	h.Probes = append(h.Probes, hop.Probe{
		IP:       net.ParseIP("1.2.3.4"),
		RTT:      5 * time.Millisecond,
		ICMPType: 0, // Echo Reply
		ICMPCode: 0,
	})
	tr.AddHop(h)

	exporter := NewJSONExporter()
	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	var result ExportedTrace
	json.Unmarshal(buf.Bytes(), &result)

	if result.Hops[0].ICMPCode != "" {
		t.Errorf("expected empty icmpCode for echo reply, got %q", result.Hops[0].ICMPCode)
	}

	// Also verify it's omitted from JSON output entirely
	if bytes.Contains(buf.Bytes(), []byte("icmpCode")) {
		t.Error("expected icmpCode to be omitted from JSON output")
	}
}

func TestJSONExporter_Export_AllICMPCodes(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "network_unreachable"},
		{1, "host_unreachable"},
		{3, "port_unreachable"},
		{4, "fragmentation_needed"},
		{9, "admin_prohibited"},
		{10, "admin_prohibited"},
		{13, "admin_prohibited"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			tr := hop.NewTraceResult("x", "1.2.3.4")
			h := hop.NewHop(1)
			h.Probes = append(h.Probes, hop.Probe{
				IP: net.ParseIP("1.2.3.4"), RTT: time.Millisecond,
				ICMPType: 3, ICMPCode: tt.code,
			})
			tr.AddHop(h)

			exporter := NewJSONExporter()
			var buf bytes.Buffer
			_ = exporter.Export(&buf, tr)

			var result ExportedTrace
			json.Unmarshal(buf.Bytes(), &result)

			if result.Hops[0].ICMPCode != tt.expected {
				t.Errorf("code %d: expected %q, got %q", tt.code, tt.expected, result.Hops[0].ICMPCode)
			}
		})
	}
}

func TestJSONExport_DecodeField(t *testing.T) {
	tr := &hop.TraceResult{
		Hops: []*hop.Hop{{
			TTL: 1,
			Probes: []hop.Probe{{
				IP:  net.ParseIP("1.2.3.4"),
				RTT: time.Millisecond,
				TransportInfo: &hop.TransportInfo{
					DSCP:        46,
					DF:          true,
					TCPSrcPort:  12345,
					TCPDstPort:  80,
					TCPFlagsStr: "SYN",
				},
			}},
		}},
	}
	var buf bytes.Buffer
	e := NewJSONExporter()
	e.Pretty = true
	err := e.Export(&buf, tr)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, `"dscp": 46`) {
		t.Error("expected DSCP in JSON output")
	}
	if !strings.Contains(output, `"tcpFlags": "SYN"`) {
		t.Error("expected TCP flags in JSON output")
	}
	if !strings.Contains(output, `"df": true`) {
		t.Error("expected DF in JSON output")
	}
}

func TestJSONExport_NoDecodeWhenNil(t *testing.T) {
	tr := &hop.TraceResult{
		Hops: []*hop.Hop{{
			TTL: 1,
			Probes: []hop.Probe{{
				IP:  net.ParseIP("1.2.3.4"),
				RTT: time.Millisecond,
			}},
		}},
	}
	var buf bytes.Buffer
	e := NewJSONExporter()
	err := e.Export(&buf, tr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "decode") {
		t.Error("decode field should not appear when TransportInfo is nil")
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
