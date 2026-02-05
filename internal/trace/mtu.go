// Package trace implements traceroute functionality using various protocols.
package trace

import (
	"fmt"
)

// MTU constants
const (
	// StandardMTU is the typical Ethernet MTU
	StandardMTU = 1500

	// MinMTU is the minimum MTU for IPv4 (RFC 791)
	MinMTU = 68

	// JumboMTU threshold - MTUs above this are considered jumbo frames
	JumboMTU = 1500
)

// MTUInfo contains MTU discovery results for a hop.
type MTUInfo struct {
	// Discovered indicates whether MTU was successfully discovered
	Discovered bool

	// MTU is the discovered Maximum Transmission Unit in bytes
	MTU int

	// FragmentationNeeded indicates if we received ICMP Fragmentation Needed
	FragmentationNeeded bool
}

// String returns a formatted string for MTU display.
func (m MTUInfo) String() string {
	if !m.Discovered || m.MTU == 0 {
		return ""
	}
	return fmt.Sprintf("MTU:%d", m.MTU)
}

// IsReduced returns true if the MTU is below the standard 1500 bytes.
func (m MTUInfo) IsReduced() bool {
	return m.Discovered && m.MTU > 0 && m.MTU < StandardMTU
}

// IsJumbo returns true if the MTU is above the standard 1500 bytes (jumbo frames).
func (m MTUInfo) IsJumbo() bool {
	return m.Discovered && m.MTU > JumboMTU
}

// ParseMTUFromICMP extracts the MTU value from an ICMP Destination Unreachable
// (Fragmentation Needed) message.
//
// ICMP message structure for Type 3, Code 4:
// - Type (1 byte): 3 (Destination Unreachable)
// - Code (1 byte): 4 (Fragmentation Needed and DF set)
// - Checksum (2 bytes)
// - unused (2 bytes)
// - Next-Hop MTU (2 bytes) - big-endian
// - Original IP header + first 8 bytes of original datagram
//
// Returns the MTU value and true if successfully parsed, or 0 and false otherwise.
func ParseMTUFromICMP(data []byte) (int, bool) {
	// Need at least 8 bytes for ICMP header
	if len(data) < 8 {
		return 0, false
	}

	// Check Type = 3 (Destination Unreachable)
	if data[0] != 3 {
		return 0, false
	}

	// Check Code = 4 (Fragmentation Needed and DF set)
	if data[1] != 4 {
		return 0, false
	}

	// Extract Next-Hop MTU from bytes 6-7 (big-endian)
	mtu := int(data[6])<<8 | int(data[7])

	// Validate MTU is reasonable
	if mtu < MinMTU || mtu > 65535 {
		// RFC 1191 says if MTU is 0, fall back to table-based PMTUD
		// We return the value anyway for informational purposes
		if mtu == 0 {
			return 0, false
		}
	}

	return mtu, true
}

// MTUSearchMidpoint calculates the midpoint for binary search MTU discovery.
func MTUSearchMidpoint(low, high int) int {
	return (low + high) / 2
}

// MTUDiscoveryConfig holds configuration for Path MTU discovery.
type MTUDiscoveryConfig struct {
	// StartMTU is the initial MTU to test (default: 1500)
	StartMTU int

	// MinMTU is the minimum MTU to test (default: 68)
	MinMTU int

	// MaxIterations limits the binary search iterations
	MaxIterations int
}

// DefaultMTUDiscoveryConfig returns sensible defaults for PMTUD.
func DefaultMTUDiscoveryConfig() *MTUDiscoveryConfig {
	return &MTUDiscoveryConfig{
		StartMTU:      StandardMTU,
		MinMTU:        576, // Common minimum for Internet paths
		MaxIterations: 10,  // Enough for binary search in typical range
	}
}

// MTUProbeResult represents the result of an MTU probe.
type MTUProbeResult struct {
	// Size is the packet size that was sent
	Size int

	// Success indicates if the packet got through
	Success bool

	// ReportedMTU is the MTU reported in ICMP Fragmentation Needed (if any)
	ReportedMTU int
}

// CalculatePathMTU determines the path MTU given a series of probe results.
// Uses binary search to narrow down the maximum working MTU.
func CalculatePathMTU(results []MTUProbeResult) int {
	if len(results) == 0 {
		return StandardMTU
	}

	// Find the largest successful probe
	maxSuccess := 0
	for _, r := range results {
		if r.Success && r.Size > maxSuccess {
			maxSuccess = r.Size
		}
	}

	// If we have a reported MTU from ICMP, prefer that
	for _, r := range results {
		if r.ReportedMTU > 0 && r.ReportedMTU < StandardMTU {
			return r.ReportedMTU
		}
	}

	if maxSuccess > 0 {
		return maxSuccess
	}

	return StandardMTU
}
