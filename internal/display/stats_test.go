package display

import (
	"net"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestNewHopStats(t *testing.T) {
	stats := NewHopStats(5)

	if stats.TTL != 5 {
		t.Errorf("expected TTL 5, got %d", stats.TTL)
	}
	if stats.Sent != 0 {
		t.Errorf("expected Sent 0, got %d", stats.Sent)
	}
	if stats.Recv != 0 {
		t.Errorf("expected Recv 0, got %d", stats.Recv)
	}
}

func TestHopStats_AddProbe(t *testing.T) {
	stats := NewHopStats(1)
	ip := net.ParseIP("192.168.1.1")

	stats.AddProbe(ip, 10*time.Millisecond)

	if stats.Sent != 1 {
		t.Errorf("expected Sent 1, got %d", stats.Sent)
	}
	if stats.Recv != 1 {
		t.Errorf("expected Recv 1, got %d", stats.Recv)
	}
	if !stats.LastIP.Equal(ip) {
		t.Errorf("expected LastIP %v, got %v", ip, stats.LastIP)
	}
	if stats.LastRTT != 10*time.Millisecond {
		t.Errorf("expected LastRTT 10ms, got %v", stats.LastRTT)
	}
	if stats.BestRTT != 10*time.Millisecond {
		t.Errorf("expected BestRTT 10ms, got %v", stats.BestRTT)
	}
	if stats.WorstRTT != 10*time.Millisecond {
		t.Errorf("expected WorstRTT 10ms, got %v", stats.WorstRTT)
	}
}

func TestHopStats_AddProbe_UpdatesBestWorst(t *testing.T) {
	stats := NewHopStats(1)
	ip := net.ParseIP("192.168.1.1")

	stats.AddProbe(ip, 10*time.Millisecond)
	stats.AddProbe(ip, 5*time.Millisecond)  // Better
	stats.AddProbe(ip, 20*time.Millisecond) // Worse

	if stats.BestRTT != 5*time.Millisecond {
		t.Errorf("expected BestRTT 5ms, got %v", stats.BestRTT)
	}
	if stats.WorstRTT != 20*time.Millisecond {
		t.Errorf("expected WorstRTT 20ms, got %v", stats.WorstRTT)
	}
	if stats.LastRTT != 20*time.Millisecond {
		t.Errorf("expected LastRTT 20ms, got %v", stats.LastRTT)
	}
}

func TestHopStats_AddTimeout(t *testing.T) {
	stats := NewHopStats(1)

	stats.AddTimeout()

	if stats.Sent != 1 {
		t.Errorf("expected Sent 1, got %d", stats.Sent)
	}
	if stats.Recv != 0 {
		t.Errorf("expected Recv 0, got %d", stats.Recv)
	}
}

func TestHopStats_LossPercent(t *testing.T) {
	tests := []struct {
		name     string
		sent     int
		recv     int
		expected float64
	}{
		{"no probes", 0, 0, 0},
		{"no loss", 10, 10, 0},
		{"50% loss", 10, 5, 50},
		{"100% loss", 10, 0, 100},
		{"20% loss", 5, 4, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := NewHopStats(1)
			ip := net.ParseIP("192.168.1.1")

			for i := 0; i < tt.recv; i++ {
				stats.AddProbe(ip, 10*time.Millisecond)
			}
			for i := 0; i < tt.sent-tt.recv; i++ {
				stats.AddTimeout()
			}

			loss := stats.LossPercent()
			if loss != tt.expected {
				t.Errorf("expected loss %.1f%%, got %.1f%%", tt.expected, loss)
			}
		})
	}
}

func TestHopStats_AvgRTT(t *testing.T) {
	tests := []struct {
		name     string
		rtts     []time.Duration
		expected time.Duration
	}{
		{"no probes", nil, 0},
		{"single probe", []time.Duration{10 * time.Millisecond}, 10 * time.Millisecond},
		{"multiple probes", []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}, 20 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := NewHopStats(1)
			ip := net.ParseIP("192.168.1.1")

			for _, rtt := range tt.rtts {
				stats.AddProbe(ip, rtt)
			}

			avg := stats.AvgRTT()
			if avg != tt.expected {
				t.Errorf("expected avg %v, got %v", tt.expected, avg)
			}
		})
	}
}

func TestHopStats_Reset(t *testing.T) {
	stats := NewHopStats(1)
	ip := net.ParseIP("192.168.1.1")

	stats.AddProbe(ip, 10*time.Millisecond)
	stats.AddProbe(ip, 20*time.Millisecond)
	stats.AddTimeout()

	stats.Reset()

	if stats.Sent != 0 {
		t.Errorf("expected Sent 0 after reset, got %d", stats.Sent)
	}
	if stats.Recv != 0 {
		t.Errorf("expected Recv 0 after reset, got %d", stats.Recv)
	}
	if stats.BestRTT != 0 {
		t.Errorf("expected BestRTT 0 after reset, got %v", stats.BestRTT)
	}
	if stats.WorstRTT != 0 {
		t.Errorf("expected WorstRTT 0 after reset, got %v", stats.WorstRTT)
	}
	if stats.SumRTT != 0 {
		t.Errorf("expected SumRTT 0 after reset, got %v", stats.SumRTT)
	}
	if len(stats.RTTHistory) != 0 {
		t.Errorf("expected empty RTTHistory after reset, got %d", len(stats.RTTHistory))
	}
	// TTL should be preserved
	if stats.TTL != 1 {
		t.Errorf("expected TTL 1 preserved after reset, got %d", stats.TTL)
	}
}

func TestHopStats_RTTHistory_RingBuffer(t *testing.T) {
	stats := NewHopStats(1)
	ip := net.ParseIP("192.168.1.1")

	// Add more than RTTHistorySize probes
	for i := 1; i <= 15; i++ {
		stats.AddProbe(ip, time.Duration(i)*time.Millisecond)
	}

	// Should only keep last RTTHistorySize entries
	if len(stats.RTTHistory) != RTTHistorySize {
		t.Errorf("expected RTTHistory length %d, got %d", RTTHistorySize, len(stats.RTTHistory))
	}

	// First entry should be 6ms (15 - 10 + 1 = 6)
	expected := 6 * time.Millisecond
	if stats.RTTHistory[0] != expected {
		t.Errorf("expected first RTTHistory entry %v, got %v", expected, stats.RTTHistory[0])
	}

	// Last entry should be 15ms
	lastIdx := len(stats.RTTHistory) - 1
	expectedLast := 15 * time.Millisecond
	if stats.RTTHistory[lastIdx] != expectedLast {
		t.Errorf("expected last RTTHistory entry %v, got %v", expectedLast, stats.RTTHistory[lastIdx])
	}
}

func TestHopStats_StdDev(t *testing.T) {
	tests := []struct {
		name string
		rtts []time.Duration
		want time.Duration // approximate
	}{
		{"no samples", nil, 0},
		{"single", []time.Duration{10 * time.Millisecond}, 0},
		{"identical", []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}, 0},
		{"varied", []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}, 8165 * time.Microsecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewHopStats(1)
			ip := net.ParseIP("1.1.1.1")
			for _, rtt := range tt.rtts {
				s.AddProbe(ip, rtt)
			}
			got := s.StdDev()
			// 10% tolerance
			diff := got - tt.want
			if diff < 0 {
				diff = -diff
			}
			if tt.want > 0 && float64(diff) > float64(tt.want)*0.1 {
				t.Errorf("StdDev() = %v, want ~%v", got, tt.want)
			}
			if tt.want == 0 && got != 0 {
				t.Errorf("StdDev() = %v, want 0", got)
			}
		})
	}
}

func TestHopStats_SetEnrichment(t *testing.T) {
	stats := NewHopStats(1)
	enrichment := hop.Enrichment{
		ASN:      12345,
		ASOrg:    "Test Org",
		Hostname: "test.example.com",
	}

	stats.SetEnrichment(enrichment)

	if stats.Enrichment.ASN != 12345 {
		t.Errorf("expected ASN 12345, got %d", stats.Enrichment.ASN)
	}
	if stats.Enrichment.ASOrg != "Test Org" {
		t.Errorf("expected ASOrg 'Test Org', got %s", stats.Enrichment.ASOrg)
	}
}

func TestHopStats_SetMPLS(t *testing.T) {
	stats := NewHopStats(1)
	labels := []hop.MPLSLabel{
		{Label: 100, Exp: 0, S: true, TTL: 64},
	}

	stats.SetMPLS(labels)

	if len(stats.MPLS) != 1 {
		t.Errorf("expected 1 MPLS label, got %d", len(stats.MPLS))
	}
	if stats.MPLS[0].Label != 100 {
		t.Errorf("expected MPLS label 100, got %d", stats.MPLS[0].Label)
	}
}

func TestHopStats_HasECMP_SingleIP(t *testing.T) {
	stats := NewHopStats(1)
	ip := net.ParseIP("192.168.1.1")

	stats.AddProbe(ip, 10*time.Millisecond)
	stats.AddProbe(ip, 15*time.Millisecond)

	if stats.HasECMP() {
		t.Error("expected HasECMP false for single IP")
	}
	if stats.UniqueIPCount() != 1 {
		t.Errorf("expected UniqueIPCount 1, got %d", stats.UniqueIPCount())
	}
}

func TestHopStats_HasECMP_MultipleIPs(t *testing.T) {
	stats := NewHopStats(1)
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	stats.AddProbe(ip1, 10*time.Millisecond)
	stats.AddProbe(ip2, 15*time.Millisecond)

	if !stats.HasECMP() {
		t.Error("expected HasECMP true for two IPs")
	}
	if stats.UniqueIPCount() != 2 {
		t.Errorf("expected UniqueIPCount 2, got %d", stats.UniqueIPCount())
	}
}

func TestHopStats_PrimaryIP_MostSeen(t *testing.T) {
	stats := NewHopStats(1)
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	// ip1 seen 3 times, ip2 seen 1 time
	stats.AddProbe(ip1, 10*time.Millisecond)
	stats.AddProbe(ip1, 12*time.Millisecond)
	stats.AddProbe(ip2, 15*time.Millisecond)
	stats.AddProbe(ip1, 11*time.Millisecond)

	primary := stats.PrimaryIP()
	if !primary.Equal(ip1) {
		t.Errorf("expected PrimaryIP %v, got %v", ip1, primary)
	}
}

func TestHopStats_PrimaryIP_FallsBackToLastIP(t *testing.T) {
	stats := NewHopStats(1)
	// Manually set LastIP without using AddProbe (empty IPCounts)
	stats.LastIP = net.ParseIP("10.0.0.1")

	primary := stats.PrimaryIP()
	if !primary.Equal(stats.LastIP) {
		t.Errorf("expected PrimaryIP to fall back to LastIP %v, got %v", stats.LastIP, primary)
	}
}

func TestHopStats_IPEnrichments(t *testing.T) {
	stats := NewHopStats(1)
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	e1 := hop.Enrichment{ASN: 100, Hostname: "router1.example.com"}
	e2 := hop.Enrichment{ASN: 200, Hostname: "router2.example.com"}

	stats.AddProbe(ip1, 10*time.Millisecond)
	stats.SetIPEnrichment(ip1, e1)
	stats.AddProbe(ip2, 15*time.Millisecond)
	stats.SetIPEnrichment(ip2, e2)

	// Per-IP enrichments should be stored
	if got, ok := stats.IPEnrichments[ip1.String()]; !ok || got.ASN != 100 {
		t.Errorf("expected IP1 enrichment ASN 100, got %v", got)
	}
	if got, ok := stats.IPEnrichments[ip2.String()]; !ok || got.ASN != 200 {
		t.Errorf("expected IP2 enrichment ASN 200, got %v", got)
	}

	// Legacy field should hold last-set enrichment
	if stats.Enrichment.ASN != 200 {
		t.Errorf("expected legacy Enrichment ASN 200, got %d", stats.Enrichment.ASN)
	}

	// PrimaryEnrichment should return enrichment for the most-seen IP
	// ip1 and ip2 each seen once — order is nondeterministic, but both are valid
	pe := stats.PrimaryEnrichment()
	if pe.ASN != 100 && pe.ASN != 200 {
		t.Errorf("expected PrimaryEnrichment ASN 100 or 200, got %d", pe.ASN)
	}
}

func TestHopStats_SortedIPs_OrderByCount(t *testing.T) {
	stats := NewHopStats(1)
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	ip3 := net.ParseIP("10.0.0.3")

	// ip1 ×5, ip2 ×1, ip3 ×3
	for i := 0; i < 5; i++ {
		stats.AddProbe(ip1, 10*time.Millisecond)
	}
	stats.AddProbe(ip2, 12*time.Millisecond)
	for i := 0; i < 3; i++ {
		stats.AddProbe(ip3, 14*time.Millisecond)
	}

	sorted := stats.SortedIPs()
	if len(sorted) != 3 {
		t.Fatalf("expected 3 IPs, got %d", len(sorted))
	}

	// Descending by count: ip1(5), ip3(3), ip2(1)
	if !sorted[0].IP.Equal(ip1) || sorted[0].Count != 5 {
		t.Errorf("expected first IP %v ×5, got %v ×%d", ip1, sorted[0].IP, sorted[0].Count)
	}
	if !sorted[1].IP.Equal(ip3) || sorted[1].Count != 3 {
		t.Errorf("expected second IP %v ×3, got %v ×%d", ip3, sorted[1].IP, sorted[1].Count)
	}
	if !sorted[2].IP.Equal(ip2) || sorted[2].Count != 1 {
		t.Errorf("expected third IP %v ×1, got %v ×%d", ip2, sorted[2].IP, sorted[2].Count)
	}
}

func TestHopStats_SortedIPs_IncludesEnrichment(t *testing.T) {
	stats := NewHopStats(1)
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	e1 := hop.Enrichment{ASN: 100, Hostname: "router1.example.com"}
	e2 := hop.Enrichment{ASN: 200, Hostname: "router2.example.com"}

	stats.AddProbe(ip1, 10*time.Millisecond)
	stats.SetIPEnrichment(ip1, e1)
	stats.AddProbe(ip2, 12*time.Millisecond)
	stats.SetIPEnrichment(ip2, e2)

	sorted := stats.SortedIPs()
	if len(sorted) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(sorted))
	}

	// Both have count 1, so order is by IP string (10.0.0.1 < 10.0.0.2)
	if sorted[0].Enrichment.ASN != 100 {
		t.Errorf("expected first IP enrichment ASN 100, got %d", sorted[0].Enrichment.ASN)
	}
	if sorted[1].Enrichment.ASN != 200 {
		t.Errorf("expected second IP enrichment ASN 200, got %d", sorted[1].Enrichment.ASN)
	}
}

func TestHopStats_SortedIPs_Empty(t *testing.T) {
	stats := NewHopStats(1)

	sorted := stats.SortedIPs()
	if len(sorted) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(sorted))
	}
}

func TestHopStats_PrimaryEnrichment_FallsBackToLegacy(t *testing.T) {
	stats := NewHopStats(1)
	stats.Enrichment = hop.Enrichment{ASN: 999, Hostname: "legacy.example.com"}

	pe := stats.PrimaryEnrichment()
	if pe.ASN != 999 {
		t.Errorf("expected PrimaryEnrichment to fall back to legacy ASN 999, got %d", pe.ASN)
	}
}

func TestHopStats_Reset_ClearsECMP(t *testing.T) {
	stats := NewHopStats(1)
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	stats.AddProbe(ip1, 10*time.Millisecond)
	stats.AddProbe(ip2, 15*time.Millisecond)
	stats.SetIPEnrichment(ip1, hop.Enrichment{ASN: 100})

	if !stats.HasECMP() {
		t.Fatal("precondition: expected HasECMP true before reset")
	}

	stats.Reset()

	if stats.HasECMP() {
		t.Error("expected HasECMP false after reset")
	}
	if len(stats.IPCounts) != 0 {
		t.Errorf("expected empty IPCounts after reset, got %d", len(stats.IPCounts))
	}
	if len(stats.IPEnrichments) != 0 {
		t.Errorf("expected empty IPEnrichments after reset, got %d", len(stats.IPEnrichments))
	}
	if stats.TTL != 1 {
		t.Errorf("expected TTL 1 preserved after reset, got %d", stats.TTL)
	}
}
