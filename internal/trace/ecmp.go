// Package trace implements traceroute functionality using various protocols.
package trace

import (
	"fmt"
	"net"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// ECMPInfo contains information about ECMP (Equal-Cost Multi-Path) routing detected at a hop.
type ECMPInfo struct {
	Detected  bool     // Whether ECMP was detected
	PathCount int      // Number of distinct paths/IPs observed
	IPs       []net.IP // List of unique IPs seen at this hop
}

// String returns a formatted string for ECMP indication.
func (e ECMPInfo) String() string {
	if !e.Detected {
		return ""
	}
	return fmt.Sprintf("[ECMP:%d]", e.PathCount)
}

// DetectECMP analyzes a hop's probes to detect ECMP routing.
// ECMP is detected when multiple distinct IP addresses respond at the same TTL.
func DetectECMP(h *hop.Hop) ECMPInfo {
	if h == nil {
		return ECMPInfo{}
	}

	// Collect unique IPs from probes
	seen := make(map[string]bool)
	var uniqueIPs []net.IP

	for _, p := range h.Probes {
		if p.IP != nil {
			ipStr := p.IP.String()
			if !seen[ipStr] {
				seen[ipStr] = true
				uniqueIPs = append(uniqueIPs, p.IP)
			}
		}
	}

	pathCount := len(uniqueIPs)

	return ECMPInfo{
		Detected:  pathCount > 1,
		PathCount: pathCount,
		IPs:       uniqueIPs,
	}
}

// GenerateFlowID generates a unique flow identifier for Paris traceroute style probing.
// Different flow IDs will take different paths through ECMP load balancers.
// For ICMP: this affects the checksum calculation
// For UDP: this is used as the source port offset
func GenerateFlowID(probeNum int) uint16 {
	// Use probe number with some variation to create distinct flow IDs
	// Base port for UDP is typically 33434, so we offset from there
	// For ICMP, this value will be incorporated into the payload to affect checksum
	return uint16(33434 + probeNum*7) // Prime multiplier for better distribution
}

// ECMPType classifies the type of ECMP load balancing observed.
type ECMPType int

const (
	ECMPTypeUnknown   ECMPType = iota // Cannot determine or no ECMP
	ECMPTypePerFlow                   // Per-flow: same 5-tuple → same path
	ECMPTypePerPacket                 // Per-packet: same flow hits different paths
)

// String returns the string representation of the ECMP type.
func (e ECMPType) String() string {
	switch e {
	case ECMPTypePerFlow:
		return "per_flow"
	case ECMPTypePerPacket:
		return "per_packet"
	default:
		return "unknown"
	}
}

// ClassifyECMP determines whether ECMP load balancing is per-flow or per-packet.
// flowPaths maps flowID → (IP string → hit count).
// If any single flow hits multiple IPs, it's per-packet.
// If different flows each hit a single (but different) IP, it's per-flow.
func ClassifyECMP(flowPaths map[int]map[string]int) ECMPType {
	if len(flowPaths) == 0 {
		return ECMPTypeUnknown
	}

	// Check if any flow hit multiple IPs
	for _, ipCounts := range flowPaths {
		if len(ipCounts) > 1 {
			return ECMPTypePerPacket
		}
	}

	// All flows are consistent (each hits one IP).
	// Check if different flows hit different IPs → per-flow ECMP
	allIPs := make(map[string]bool)
	for _, ipCounts := range flowPaths {
		for ip := range ipCounts {
			allIPs[ip] = true
		}
	}

	if len(allIPs) > 1 && len(flowPaths) > 1 {
		return ECMPTypePerFlow
	}

	return ECMPTypeUnknown
}

// ECMPProbeConfig holds configuration for ECMP-aware probing.
type ECMPProbeConfig struct {
	// FlowsPerHop is the number of different flow IDs to try per hop
	// Higher values increase chance of detecting all ECMP paths but take longer
	FlowsPerHop int

	// PacketsPerFlow is the number of packets to send per flow ID
	PacketsPerFlow int
}

// DefaultECMPConfig returns sensible defaults for ECMP detection.
func DefaultECMPConfig() *ECMPProbeConfig {
	return &ECMPProbeConfig{
		FlowsPerHop:    8,  // Try 8 different flow IDs
		PacketsPerFlow: 1,  // 1 packet per flow (total 8 probes per hop)
	}
}

// AnalyzeTraceForECMP analyzes a complete trace result for ECMP at each hop.
// Returns a slice of ECMPInfo, one per hop.
func AnalyzeTraceForECMP(tr *hop.TraceResult) []ECMPInfo {
	if tr == nil {
		return nil
	}

	infos := make([]ECMPInfo, len(tr.Hops))
	for i, h := range tr.Hops {
		infos[i] = DetectECMP(h)
	}

	return infos
}

// HasECMP returns true if any hop in the trace exhibits ECMP routing.
func HasECMP(tr *hop.TraceResult) bool {
	for _, h := range tr.Hops {
		if DetectECMP(h).Detected {
			return true
		}
	}
	return false
}
