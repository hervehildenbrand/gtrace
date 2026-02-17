package display

import (
	"math"
	"net"
	"sort"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// IPInfo holds a single IP's probe count and enrichment data for ECMP display.
type IPInfo struct {
	IP         net.IP
	Count      int
	Enrichment hop.Enrichment
}

// RTTHistorySize is the number of RTT samples to keep for sparkline display.
const RTTHistorySize = 10

// HopStats aggregates statistics for a single TTL across multiple trace cycles.
// This is used by the MTR-style continuous tracing mode.
type HopStats struct {
	TTL           int
	Sent          int
	Recv          int
	LastIP        net.IP
	BestRTT       time.Duration
	WorstRTT      time.Duration
	SumRTT        time.Duration // For calculating avg
	LastRTT       time.Duration
	RTTHistory    []time.Duration // Ring buffer for sparkline
	Enrichment    hop.Enrichment
	MPLS          []hop.MPLSLabel
	IPCounts      map[string]int           // IP string -> probe count
	IPEnrichments map[string]hop.Enrichment // IP string -> enrichment
}

// NewHopStats creates a new HopStats for the given TTL.
func NewHopStats(ttl int) *HopStats {
	return &HopStats{
		TTL:           ttl,
		RTTHistory:    make([]time.Duration, 0, RTTHistorySize),
		IPCounts:      make(map[string]int),
		IPEnrichments: make(map[string]hop.Enrichment),
	}
}

// AddProbe records a successful probe response.
func (s *HopStats) AddProbe(ip net.IP, rtt time.Duration) {
	s.Sent++
	s.Recv++
	s.LastIP = ip
	s.LastRTT = rtt
	s.SumRTT += rtt

	if ip != nil {
		s.IPCounts[ip.String()]++
	}

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

// StdDev calculates the standard deviation of RTT values.
func (s *HopStats) StdDev() time.Duration {
	if len(s.RTTHistory) < 2 {
		return 0
	}
	var sum float64
	for _, rtt := range s.RTTHistory {
		sum += float64(rtt)
	}
	mean := sum / float64(len(s.RTTHistory))
	var variance float64
	for _, rtt := range s.RTTHistory {
		d := float64(rtt) - mean
		variance += d * d
	}
	variance /= float64(len(s.RTTHistory))
	return time.Duration(math.Sqrt(variance))
}

// Reset clears all statistics while preserving the TTL.
func (s *HopStats) Reset() {
	ttl := s.TTL
	*s = HopStats{
		TTL:           ttl,
		RTTHistory:    make([]time.Duration, 0, RTTHistorySize),
		IPCounts:      make(map[string]int),
		IPEnrichments: make(map[string]hop.Enrichment),
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

// HasECMP returns true if multiple IPs have responded at this TTL.
func (s *HopStats) HasECMP() bool {
	return len(s.IPCounts) > 1
}

// UniqueIPCount returns the number of distinct IPs seen at this TTL.
func (s *HopStats) UniqueIPCount() int {
	return len(s.IPCounts)
}

// PrimaryIP returns the most-frequently-seen IP for stable display.
// Falls back to LastIP if IPCounts is empty.
func (s *HopStats) PrimaryIP() net.IP {
	if len(s.IPCounts) == 0 {
		return s.LastIP
	}
	var bestIP string
	var bestCount int
	for ip, count := range s.IPCounts {
		if count > bestCount {
			bestCount = count
			bestIP = ip
		}
	}
	return net.ParseIP(bestIP)
}

// PrimaryEnrichment returns the enrichment for the primary (most-seen) IP.
// Falls back to the legacy Enrichment field if no per-IP enrichment exists.
func (s *HopStats) PrimaryEnrichment() hop.Enrichment {
	primary := s.PrimaryIP()
	if primary != nil {
		if e, ok := s.IPEnrichments[primary.String()]; ok {
			return e
		}
	}
	return s.Enrichment
}

// SetIPEnrichment stores enrichment data for a specific IP and updates the
// legacy Enrichment field for backward compatibility.
func (s *HopStats) SetIPEnrichment(ip net.IP, e hop.Enrichment) {
	if ip != nil {
		s.IPEnrichments[ip.String()] = e
	}
	s.Enrichment = e
}

// SortedIPs returns all IPs seen at this TTL, sorted by probe count descending,
// then by IP string for stability. Includes enrichment data for each IP.
func (s *HopStats) SortedIPs() []IPInfo {
	if len(s.IPCounts) == 0 {
		return nil
	}

	result := make([]IPInfo, 0, len(s.IPCounts))
	for ipStr, count := range s.IPCounts {
		info := IPInfo{
			IP:    net.ParseIP(ipStr),
			Count: count,
		}
		if e, ok := s.IPEnrichments[ipStr]; ok {
			info.Enrichment = e
		}
		result = append(result, info)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].IP.String() < result[j].IP.String()
	})

	return result
}
