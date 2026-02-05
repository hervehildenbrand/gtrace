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
