package hop

import (
	"net"
	"testing"
	"time"
)

func TestNewHop_CreatesHopWithTTL(t *testing.T) {
	h := NewHop(1)

	if h.TTL != 1 {
		t.Errorf("expected TTL 1, got %d", h.TTL)
	}
}

func TestHop_AddProbe_RecordsRTT(t *testing.T) {
	h := NewHop(1)
	ip := net.ParseIP("192.168.1.1")
	rtt := 5 * time.Millisecond

	h.AddProbe(ip, rtt)

	if len(h.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(h.Probes))
	}
	if h.Probes[0].RTT != rtt {
		t.Errorf("expected RTT %v, got %v", rtt, h.Probes[0].RTT)
	}
	if !h.Probes[0].IP.Equal(ip) {
		t.Errorf("expected IP %v, got %v", ip, h.Probes[0].IP)
	}
}

func TestHop_AddTimeout_RecordsTimeoutProbe(t *testing.T) {
	h := NewHop(1)

	h.AddTimeout()

	if len(h.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(h.Probes))
	}
	if !h.Probes[0].Timeout {
		t.Error("expected probe to be marked as timeout")
	}
}

func TestHop_AvgRTT_CalculatesCorrectly(t *testing.T) {
	h := NewHop(1)
	ip := net.ParseIP("192.168.1.1")

	h.AddProbe(ip, 10*time.Millisecond)
	h.AddProbe(ip, 20*time.Millisecond)
	h.AddProbe(ip, 30*time.Millisecond)

	avg := h.AvgRTT()
	expected := 20 * time.Millisecond

	if avg != expected {
		t.Errorf("expected avg RTT %v, got %v", expected, avg)
	}
}

func TestHop_AvgRTT_ExcludesTimeouts(t *testing.T) {
	h := NewHop(1)
	ip := net.ParseIP("192.168.1.1")

	h.AddProbe(ip, 10*time.Millisecond)
	h.AddTimeout()
	h.AddProbe(ip, 20*time.Millisecond)

	avg := h.AvgRTT()
	expected := 15 * time.Millisecond

	if avg != expected {
		t.Errorf("expected avg RTT %v, got %v", expected, avg)
	}
}

func TestHop_AvgRTT_ReturnsZeroForAllTimeouts(t *testing.T) {
	h := NewHop(1)

	h.AddTimeout()
	h.AddTimeout()

	avg := h.AvgRTT()

	if avg != 0 {
		t.Errorf("expected avg RTT 0, got %v", avg)
	}
}

func TestHop_LossPercent_CalculatesCorrectly(t *testing.T) {
	h := NewHop(1)
	ip := net.ParseIP("192.168.1.1")

	h.AddProbe(ip, 10*time.Millisecond)
	h.AddTimeout()
	h.AddProbe(ip, 20*time.Millisecond)
	h.AddTimeout()

	loss := h.LossPercent()
	expected := 50.0

	if loss != expected {
		t.Errorf("expected loss %v%%, got %v%%", expected, loss)
	}
}

func TestHop_LossPercent_ReturnsZeroForNoProbes(t *testing.T) {
	h := NewHop(1)

	loss := h.LossPercent()

	if loss != 0 {
		t.Errorf("expected loss 0, got %v", loss)
	}
}

func TestHop_PrimaryIP_ReturnsFirstNonNilIP(t *testing.T) {
	h := NewHop(1)
	h.AddTimeout()
	ip := net.ParseIP("192.168.1.1")
	h.AddProbe(ip, 10*time.Millisecond)

	primary := h.PrimaryIP()

	if !primary.Equal(ip) {
		t.Errorf("expected primary IP %v, got %v", ip, primary)
	}
}

func TestHop_PrimaryIP_ReturnsNilForAllTimeouts(t *testing.T) {
	h := NewHop(1)
	h.AddTimeout()
	h.AddTimeout()

	primary := h.PrimaryIP()

	if primary != nil {
		t.Errorf("expected nil primary IP, got %v", primary)
	}
}

func TestHop_HasMultipleIPs_DetectsECMP(t *testing.T) {
	h := NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 10*time.Millisecond)
	h.AddProbe(net.ParseIP("192.168.1.2"), 10*time.Millisecond)

	if !h.HasMultipleIPs() {
		t.Error("expected HasMultipleIPs to return true")
	}
}

func TestHop_HasMultipleIPs_FalseForSingleIP(t *testing.T) {
	h := NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 10*time.Millisecond)
	h.AddProbe(net.ParseIP("192.168.1.1"), 20*time.Millisecond)

	if h.HasMultipleIPs() {
		t.Error("expected HasMultipleIPs to return false")
	}
}

func TestMPLSLabel_String_FormatsCorrectly(t *testing.T) {
	label := MPLSLabel{
		Label: 24015,
		Exp:   0,
		S:     true,
		TTL:   1,
	}

	expected := "L=24015 E=0 S=1 TTL=1"
	result := label.String()

	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestHop_SetMPLS_StoresLabels(t *testing.T) {
	h := NewHop(1)
	labels := []MPLSLabel{
		{Label: 24015, Exp: 0, S: true, TTL: 1},
	}

	h.SetMPLS(labels)

	if len(h.MPLS) != 1 {
		t.Fatalf("expected 1 MPLS label, got %d", len(h.MPLS))
	}
	if h.MPLS[0].Label != 24015 {
		t.Errorf("expected label 24015, got %d", h.MPLS[0].Label)
	}
}

func TestHop_SetEnrichment_StoresASNAndGeo(t *testing.T) {
	h := NewHop(1)

	h.SetEnrichment(Enrichment{
		ASN:      13335,
		ASOrg:    "Cloudflare, Inc.",
		Country:  "US",
		City:     "San Francisco",
		Hostname: "one.one.one.one",
	})

	if h.Enrichment.ASN != 13335 {
		t.Errorf("expected ASN 13335, got %d", h.Enrichment.ASN)
	}
	if h.Enrichment.ASOrg != "Cloudflare, Inc." {
		t.Errorf("expected ASOrg 'Cloudflare, Inc.', got %q", h.Enrichment.ASOrg)
	}
	if h.Enrichment.Country != "US" {
		t.Errorf("expected Country 'US', got %q", h.Enrichment.Country)
	}
}

func TestNewTraceResult_CreatesWithTarget(t *testing.T) {
	tr := NewTraceResult("google.com", "8.8.8.8")

	if tr.Target != "google.com" {
		t.Errorf("expected target google.com, got %q", tr.Target)
	}
	if tr.TargetIP != "8.8.8.8" {
		t.Errorf("expected target IP 8.8.8.8, got %q", tr.TargetIP)
	}
}

func TestTraceResult_AddHop_AppendsHop(t *testing.T) {
	tr := NewTraceResult("google.com", "8.8.8.8")
	h := NewHop(1)

	tr.AddHop(h)

	if len(tr.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(tr.Hops))
	}
}

func TestTraceResult_GetHop_ReturnsCorrectHop(t *testing.T) {
	tr := NewTraceResult("google.com", "8.8.8.8")
	h1 := NewHop(1)
	h2 := NewHop(2)
	tr.AddHop(h1)
	tr.AddHop(h2)

	result := tr.GetHop(2)

	if result.TTL != 2 {
		t.Errorf("expected TTL 2, got %d", result.TTL)
	}
}

func TestTraceResult_GetHop_ReturnsNilForMissing(t *testing.T) {
	tr := NewTraceResult("google.com", "8.8.8.8")

	result := tr.GetHop(5)

	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestTraceResult_IsComplete_TrueWhenReachedTarget(t *testing.T) {
	tr := NewTraceResult("google.com", "8.8.8.8")
	tr.ReachedTarget = true

	if !tr.IsComplete() {
		t.Error("expected IsComplete to return true")
	}
}

func TestHop_AddProbeWithTTL_StoresResponseTTL(t *testing.T) {
	h := NewHop(5)
	ip := net.ParseIP("10.0.0.1")

	h.AddProbeWithTTL(ip, 10*time.Millisecond, 128)

	if len(h.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(h.Probes))
	}
	if h.Probes[0].ResponseTTL != 128 {
		t.Errorf("expected ResponseTTL 128, got %d", h.Probes[0].ResponseTTL)
	}
	if h.Probes[0].RTT != 10*time.Millisecond {
		t.Errorf("expected RTT 10ms, got %v", h.Probes[0].RTT)
	}
}

func TestTraceResult_TotalHops_ReturnsCount(t *testing.T) {
	tr := NewTraceResult("google.com", "8.8.8.8")
	tr.AddHop(NewHop(1))
	tr.AddHop(NewHop(2))
	tr.AddHop(NewHop(3))

	if tr.TotalHops() != 3 {
		t.Errorf("expected 3 hops, got %d", tr.TotalHops())
	}
}
