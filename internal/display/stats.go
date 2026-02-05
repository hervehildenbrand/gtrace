package display

import (
	"net"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// RTTHistorySize is the number of RTT samples to keep for sparkline display.
const RTTHistorySize = 10

// HopStats aggregates statistics for a single TTL across multiple trace cycles.
// This is used by the MTR-style continuous tracing mode.
type HopStats struct {
	TTL        int
	Sent       int
	Recv       int
	LastIP     net.IP
	BestRTT    time.Duration
	WorstRTT   time.Duration
	SumRTT     time.Duration // For calculating avg
	LastRTT    time.Duration
	RTTHistory []time.Duration // Ring buffer for sparkline
	Enrichment hop.Enrichment
	MPLS       []hop.MPLSLabel
}

// NewHopStats creates a new HopStats for the given TTL.
func NewHopStats(ttl int) *HopStats {
	return &HopStats{
		TTL:        ttl,
		RTTHistory: make([]time.Duration, 0, RTTHistorySize),
	}
}

// AddProbe records a successful probe response.
func (s *HopStats) AddProbe(ip net.IP, rtt time.Duration) {
	s.Sent++
	s.Recv++
	s.LastIP = ip
	s.LastRTT = rtt
	s.SumRTT += rtt

	// Update best/worst
	if s.BestRTT == 0 || rtt < s.BestRTT {
		s.BestRTT = rtt
	}
	if rtt > s.WorstRTT {
		s.WorstRTT = rtt
	}

	// Add to history (ring buffer)
	if len(s.RTTHistory) >= RTTHistorySize {
		// Shift left, drop oldest
		copy(s.RTTHistory, s.RTTHistory[1:])
		s.RTTHistory[RTTHistorySize-1] = rtt
	} else {
		s.RTTHistory = append(s.RTTHistory, rtt)
	}
}

// AddTimeout records a probe that timed out.
func (s *HopStats) AddTimeout() {
	s.Sent++
}

// LossPercent calculates the packet loss percentage.
func (s *HopStats) LossPercent() float64 {
	if s.Sent == 0 {
		return 0
	}
	return float64(s.Sent-s.Recv) / float64(s.Sent) * 100
}

// AvgRTT calculates the average RTT.
func (s *HopStats) AvgRTT() time.Duration {
	if s.Recv == 0 {
		return 0
	}
	return s.SumRTT / time.Duration(s.Recv)
}

// Reset clears all statistics while preserving the TTL.
func (s *HopStats) Reset() {
	ttl := s.TTL
	*s = HopStats{
		TTL:        ttl,
		RTTHistory: make([]time.Duration, 0, RTTHistorySize),
	}
}

// SetEnrichment sets the enrichment data for this hop.
func (s *HopStats) SetEnrichment(e hop.Enrichment) {
	s.Enrichment = e
}

// SetMPLS sets the MPLS labels for this hop.
func (s *HopStats) SetMPLS(labels []hop.MPLSLabel) {
	s.MPLS = labels
}
