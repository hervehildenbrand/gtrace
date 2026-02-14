// Package trace implements traceroute functionality using various protocols.
package trace

import "net"

// NATType indicates the type of NAT behavior detected.
type NATType int

const (
	// NATTypeUnknown indicates NAT detection could not determine type
	NATTypeUnknown NATType = iota

	// NATTypeIPRewrite indicates IP ID field rewriting was detected
	NATTypeIPRewrite

	// NATTypePortRewrite indicates source port rewriting was detected
	NATTypePortRewrite

	// NATTypeTTLAnomaly indicates TTL inconsistency suggesting NAT
	NATTypeTTLAnomaly
)

// NATInfo contains NAT detection results for a hop.
type NATInfo struct {
	// Detected indicates whether NAT was detected at this hop
	Detected bool

	// Type indicates the type of NAT behavior observed
	Type NATType

	// Confidence is a 0-100 score indicating detection confidence
	Confidence int
}

// String returns a formatted string for NAT display.
func (n NATInfo) String() string {
	if !n.Detected {
		return ""
	}
	return "[NAT]"
}

// IPIDMaxSequentialGap is the maximum gap between IP IDs that's still considered sequential.
// Some packet loss or reordering can cause small gaps.
const IPIDMaxSequentialGap = 100

// DetectNATFromIPID analyzes IP ID values to detect NAT.
// NAT devices often rewrite IP ID fields, causing non-sequential IDs.
// Returns true if NAT is likely based on IP ID pattern analysis.
func DetectNATFromIPID(ipIDs []uint16) bool {
	if len(ipIDs) < 2 {
		return false
	}

	// Check for all-zeros pattern (common in firewalls/NAT)
	allZeros := true
	for _, id := range ipIDs {
		if id != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return true
	}

	// Check if IDs are sequential (normal behavior without NAT)
	sequentialCount := 0
	for i := 1; i < len(ipIDs); i++ {
		if IPIDIsSequential(ipIDs[i-1], ipIDs[i]) {
			sequentialCount++
		}
	}

	// If most IDs are not sequential, likely NAT
	totalPairs := len(ipIDs) - 1
	sequentialRatio := float64(sequentialCount) / float64(totalPairs)

	// If less than 50% are sequential, consider it NAT
	return sequentialRatio < 0.5
}

// IPIDIsSequential checks if two IP IDs appear to be sequential.
// Handles uint16 wraparound and allows small gaps.
func IPIDIsSequential(id1, id2 uint16) bool {
	// Calculate forward distance (handling wraparound)
	var diff uint16
	if id2 >= id1 {
		diff = id2 - id1
	} else {
		// Wraparound case: id2 < id1
		diff = (65535 - id1) + id2 + 1
	}

	return diff <= IPIDMaxSequentialGap
}

// DetectNATFromTTL checks if TTL values suggest NAT by comparing the forward
// hop number with the inferred return path length. Uses the nmap/p0f method:
// infer the initial TTL by rounding the observed response TTL up to the nearest
// OS default, then compare return hops vs forward hops.
// Flags only if the mismatch exceeds 5 hops (asymmetric routing tolerance).
func DetectNATFromTTL(hopNumber, responseTTL int) bool {
	if hopNumber <= 0 || responseTTL <= 0 {
		return false
	}

	inferredInitial := InferInitialTTL(responseTTL)
	if inferredInitial == 0 {
		return false
	}

	returnHops := inferredInitial - responseTTL
	diff := returnHops - hopNumber
	if diff < 0 {
		diff = -diff
	}

	return diff > 5
}

// CommonTTLDefaults returns common OS default TTL values.
func CommonTTLDefaults() []int {
	return []int{
		64,  // Linux, macOS, FreeBSD, iOS, Android
		128, // Windows
		255, // Cisco IOS, Solaris, some network equipment
		32,  // Some embedded devices (legacy)
	}
}

// InferInitialTTL rounds an observed response TTL up to the nearest standard
// OS default (32, 64, 128, 255). This is the nmap/p0f method for determining
// the original TTL a router sent its response with.
func InferInitialTTL(observedTTL int) int {
	if observedTTL <= 0 {
		return 0
	}
	defaults := []int{32, 64, 128, 255}
	for _, d := range defaults {
		if observedTTL <= d {
			return d
		}
	}
	return 255
}

// IsCGNATAddress checks if an IP is in the RFC 6598 CGNAT shared address
// space (100.64.0.0/10). These addresses always indicate carrier-grade NAT.
func IsCGNATAddress(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 100 && ip4[1]&0xC0 == 64
}

// IsPrivateAddress checks if an IP is in RFC 1918 private address space
// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
func IsPrivateAddress(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 10.0.0.0/8
	if ip4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return false
}

// DetectNATFromIP uses IP address classification to detect NAT.
// CGNAT addresses (100.64.0.0/10) are flagged at any hop.
// RFC 1918 private addresses are flagged at hop > 1 (hop 1 is the user's gateway).
func DetectNATFromIP(ip net.IP, hopNumber int) bool {
	if IsCGNATAddress(ip) {
		return true
	}
	if hopNumber > 1 && IsPrivateAddress(ip) {
		return true
	}
	return false
}

// GuessOSFromTTL attempts to guess the operating system based on TTL.
func GuessOSFromTTL(ttl int) string {
	switch {
	case ttl <= 32:
		return "embedded/legacy"
	case ttl <= 64:
		return "Linux/macOS/BSD"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Cisco/Solaris"
	default:
		return "unknown"
	}
}

// NATDetectionConfig holds configuration for NAT detection.
type NATDetectionConfig struct {
	// EnableIPIDTracking enables IP ID field analysis
	EnableIPIDTracking bool

	// EnableTTLAnalysis enables TTL-based NAT detection
	EnableTTLAnalysis bool

	// MinSamplesForDetection is the minimum number of samples needed
	MinSamplesForDetection int
}

// DefaultNATDetectionConfig returns sensible defaults.
func DefaultNATDetectionConfig() *NATDetectionConfig {
	return &NATDetectionConfig{
		EnableIPIDTracking:     true,
		EnableTTLAnalysis:      true,
		MinSamplesForDetection: 3,
	}
}
