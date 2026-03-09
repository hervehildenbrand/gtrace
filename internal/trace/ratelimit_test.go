package trace

import (
	"testing"

	"github.com/hervehildenbrand/gtrace/internal/display"
)

func TestDetectRateLimiting_HopWithHighLossLowDownstream(t *testing.T) {
	// Hop 3 has 50% loss, but hops 4-6 have ~0% loss → rate-limited
	stats := makeStats(map[int]lossSetup{
		1: {sent: 20, recv: 20},
		2: {sent: 20, recv: 20},
		3: {sent: 20, recv: 10}, // 50% loss
		4: {sent: 20, recv: 20},
		5: {sent: 20, recv: 20},
		6: {sent: 20, recv: 20},
	})

	result := DetectRateLimiting(stats)

	if !result[3] {
		t.Errorf("expected hop 3 to be marked as rate-limited")
	}
	if result[1] || result[2] || result[4] || result[5] || result[6] {
		t.Errorf("expected only hop 3 to be rate-limited, got %v", result)
	}
}

func TestDetectRateLimiting_RealLoss(t *testing.T) {
	// Hop 3 has 50% loss AND downstream hops also have high loss → real loss
	stats := makeStats(map[int]lossSetup{
		1: {sent: 20, recv: 20},
		2: {sent: 20, recv: 20},
		3: {sent: 20, recv: 10}, // 50% loss
		4: {sent: 20, recv: 12}, // 40% loss
		5: {sent: 20, recv: 11}, // 45% loss
		6: {sent: 20, recv: 10}, // 50% loss
	})

	result := DetectRateLimiting(stats)

	if result[3] {
		t.Errorf("hop 3 should NOT be rate-limited when downstream also has high loss")
	}
}

func TestDetectRateLimiting_LowLossNotFlagged(t *testing.T) {
	// All hops below 10% loss → nothing should be flagged
	stats := makeStats(map[int]lossSetup{
		1: {sent: 20, recv: 19},
		2: {sent: 20, recv: 20},
		3: {sent: 20, recv: 19},
	})

	result := DetectRateLimiting(stats)

	for ttl, rl := range result {
		if rl {
			t.Errorf("hop %d should not be rate-limited with low loss", ttl)
		}
	}
}

func TestDetectRateLimiting_LastHopHighLoss(t *testing.T) {
	// Last hop has high loss — no downstream to compare, should NOT flag
	stats := makeStats(map[int]lossSetup{
		1: {sent: 20, recv: 20},
		2: {sent: 20, recv: 20},
		3: {sent: 20, recv: 10}, // 50% loss, but it's the last hop
	})

	result := DetectRateLimiting(stats)

	if result[3] {
		t.Errorf("last hop should not be flagged as rate-limited (no downstream data)")
	}
}

func TestDetectRateLimiting_AllTimeout(t *testing.T) {
	// All hops timeout → nothing to flag
	stats := makeStats(map[int]lossSetup{
		1: {sent: 20, recv: 0},
		2: {sent: 20, recv: 0},
		3: {sent: 20, recv: 0},
	})

	result := DetectRateLimiting(stats)

	if len(result) != 0 {
		t.Errorf("all-timeout should produce empty result, got %v", result)
	}
}

func TestDetectRateLimiting_SingleHop(t *testing.T) {
	stats := makeStats(map[int]lossSetup{
		1: {sent: 20, recv: 10},
	})

	result := DetectRateLimiting(stats)

	if result[1] {
		t.Errorf("single hop should not be rate-limited")
	}
}

func TestDetectRateLimiting_MultipleRateLimitedHops(t *testing.T) {
	// Hops 2 and 4 both rate-limit, downstream is clean
	stats := makeStats(map[int]lossSetup{
		1: {sent: 20, recv: 20},
		2: {sent: 20, recv: 10}, // 50% loss
		3: {sent: 20, recv: 20},
		4: {sent: 20, recv: 8},  // 60% loss
		5: {sent: 20, recv: 20},
		6: {sent: 20, recv: 20},
	})

	result := DetectRateLimiting(stats)

	if !result[2] {
		t.Errorf("hop 2 should be rate-limited")
	}
	if !result[4] {
		t.Errorf("hop 4 should be rate-limited")
	}
}

// --- helpers ---

type lossSetup struct {
	sent int
	recv int
}

func makeStats(setup map[int]lossSetup) map[int]*display.HopStats {
	stats := make(map[int]*display.HopStats)
	for ttl, ls := range setup {
		s := display.NewHopStats(ttl)
		s.Sent = ls.sent
		s.Recv = ls.recv
		stats[ttl] = s
	}
	return stats
}
