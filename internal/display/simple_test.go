package display

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestSimpleRenderer_RenderHop_FormatsBasicHop(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 5*time.Millisecond)
	h.AddProbe(net.ParseIP("192.168.1.1"), 6*time.Millisecond)
	h.AddProbe(net.ParseIP("192.168.1.1"), 4*time.Millisecond)

	result := r.RenderHop(h)

	if !strings.Contains(result, "1") {
		t.Error("expected hop number in output")
	}
	if !strings.Contains(result, "192.168.1.1") {
		t.Error("expected IP address in output")
	}
	if !strings.Contains(result, "5.00ms") || !strings.Contains(result, "6.00ms") || !strings.Contains(result, "4.00ms") {
		t.Errorf("expected RTT values in output, got %q", result)
	}
}

func TestSimpleRenderer_RenderHop_ShowsTimeoutAsAsterisk(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 5*time.Millisecond)
	h.AddTimeout()
	h.AddProbe(net.ParseIP("192.168.1.1"), 6*time.Millisecond)

	result := r.RenderHop(h)

	if !strings.Contains(result, "*") {
		t.Error("expected asterisk for timeout")
	}
}

func TestSimpleRenderer_RenderHop_ShowsAllTimeouts(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddTimeout()
	h.AddTimeout()
	h.AddTimeout()

	result := r.RenderHop(h)

	if !strings.Contains(result, "* * *") {
		t.Errorf("expected '* * *' for all timeouts, got %q", result)
	}
}

func TestSimpleRenderer_RenderHop_ShowsHostname(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("1.1.1.1"), 5*time.Millisecond)
	h.SetEnrichment(hop.Enrichment{
		Hostname: "one.one.one.one",
	})

	result := r.RenderHop(h)

	if !strings.Contains(result, "one.one.one.one") {
		t.Error("expected hostname in output")
	}
}

func TestSimpleRenderer_RenderHop_ShowsASN(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("1.1.1.1"), 5*time.Millisecond)
	h.SetEnrichment(hop.Enrichment{
		ASN:   13335,
		ASOrg: "Cloudflare",
	})

	result := r.RenderHop(h)

	if !strings.Contains(result, "AS13335") {
		t.Error("expected ASN in output")
	}
}

func TestSimpleRenderer_RenderHop_ShowsMPLS(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	h.SetMPLS([]hop.MPLSLabel{
		{Label: 24015, Exp: 0, S: true, TTL: 1},
	})

	result := r.RenderHop(h)

	if !strings.Contains(result, "MPLS") && !strings.Contains(result, "24015") {
		t.Error("expected MPLS label info in output")
	}
}

func TestSimpleRenderer_RenderHop_ShowsECMP(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	h.AddProbe(net.ParseIP("10.0.0.2"), 6*time.Millisecond)

	result := r.RenderHop(h)

	if !strings.Contains(result, "10.0.0.1") || !strings.Contains(result, "10.0.0.2") {
		t.Error("expected both IPs shown for ECMP")
	}
}

func TestSimpleRenderer_RenderTrace_OutputsAllHops(t *testing.T) {
	r := NewSimpleRenderer()
	tr := hop.NewTraceResult("google.com", "8.8.8.8")

	h1 := hop.NewHop(1)
	h1.AddProbe(net.ParseIP("192.168.1.1"), 1*time.Millisecond)
	tr.AddHop(h1)

	h2 := hop.NewHop(2)
	h2.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	tr.AddHop(h2)

	var buf bytes.Buffer
	r.RenderTrace(&buf, tr)
	result := buf.String()

	if !strings.Contains(result, "google.com") {
		t.Error("expected target in output")
	}
	if !strings.Contains(result, "192.168.1.1") {
		t.Error("expected hop 1 IP in output")
	}
	if !strings.Contains(result, "10.0.0.1") {
		t.Error("expected hop 2 IP in output")
	}
}

func TestSimpleRenderer_RenderTrace_ShowsHeader(t *testing.T) {
	r := NewSimpleRenderer()
	tr := hop.NewTraceResult("google.com", "8.8.8.8")

	var buf bytes.Buffer
	r.RenderTrace(&buf, tr)
	result := buf.String()

	if !strings.Contains(result, "traceroute to google.com") {
		t.Errorf("expected traceroute header, got %q", result)
	}
}

func TestSimpleRenderer_RenderHop_ShowsNAT(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	h.NAT = true

	result := r.RenderHop(h)

	if !strings.Contains(result, "[NAT]") {
		t.Errorf("expected [NAT] in output, got %q", result)
	}
}

func TestSimpleRenderer_RenderHop_ShowsMTU(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("10.0.0.1"), 5*time.Millisecond)
	h.MTU = 1400

	result := r.RenderHop(h)

	if !strings.Contains(result, "[MTU:1400]") {
		t.Errorf("expected [MTU:1400] in output, got %q", result)
	}
}

func TestSimpleRenderer_RenderHop_ShowsMTU_AllTimeouts(t *testing.T) {
	r := NewSimpleRenderer()
	h := hop.NewHop(1)
	h.AddTimeout()
	h.AddTimeout()
	h.AddTimeout()
	h.MTU = 1500

	result := r.RenderHop(h)

	if !strings.Contains(result, "[MTU:1500]") {
		t.Errorf("expected [MTU:1500] on all-timeout hop, got %q", result)
	}
}

func TestSimpleRenderer_FormatRTT_FormatsMilliseconds(t *testing.T) {
	r := NewSimpleRenderer()

	result := r.FormatRTT(5 * time.Millisecond)
	if result != "5.00ms" {
		t.Errorf("expected '5.00ms', got %q", result)
	}

	result = r.FormatRTT(500 * time.Microsecond)
	if result != "0.50ms" {
		t.Errorf("expected '0.50ms', got %q", result)
	}
}
