package trace

import (
	"github.com/hervehildenbrand/gtrace/internal/display"
)

// DetectRateLimiting identifies hops that are likely rate-limiting ICMP responses
// rather than experiencing real packet loss. If hop N has high loss but hops
// N+1..max have significantly lower loss, hop N is rate-limiting.
func DetectRateLimiting(stats map[int]*display.HopStats) map[int]bool {
	result := make(map[int]bool)

	// Find the max TTL with responses
	maxTTL := 0
	for ttl, s := range stats {
		if s.Recv > 0 && ttl > maxTTL {
			maxTTL = ttl
		}
	}

	for ttl, s := range stats {
		loss := s.LossPercent()
		if loss <= 10 {
			continue
		}

		// Need downstream hops to compare against
		downstreamLoss, downstreamCount := avgDownstreamLoss(stats, ttl, maxTTL)
		if downstreamCount == 0 {
			continue
		}

		if loss-downstreamLoss > 15 {
			result[ttl] = true
		}
	}

	return result
}

// avgDownstreamLoss calculates the average loss% of responding hops after the given TTL.
func avgDownstreamLoss(stats map[int]*display.HopStats, ttl, maxTTL int) (float64, int) {
	var totalLoss float64
	var count int

	for t := ttl + 1; t <= maxTTL; t++ {
		s, ok := stats[t]
		if !ok || s.Recv == 0 {
			continue
		}
		totalLoss += s.LossPercent()
		count++
	}

	if count == 0 {
		return 0, 0
	}
	return totalLoss / float64(count), count
}
