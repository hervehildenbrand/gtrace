// Package trace implements traceroute functionality using various protocols.
package trace

// MTU constants
const (
	// StandardMTU is the typical Ethernet MTU
	StandardMTU = 1500

	// MinMTU is the minimum MTU for IPv4 (RFC 791)
	MinMTU = 68

	// MinMTUv6 is the minimum MTU for IPv6 (RFC 8200)
	MinMTUv6 = 1280
)

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

// ParseMTUFromICMPv6PacketTooBig extracts the MTU from an ICMPv6 Packet Too
// Big message (RFC 4443 section 3.2).
//
// Message structure:
// - Type (1 byte): 2 (Packet Too Big)
// - Code (1 byte): 0
// - Checksum (2 bytes)
// - MTU (4 bytes) - big-endian
// - As much of the invoking packet as fits
//
// Returns the MTU and true if successfully parsed, or 0 and false otherwise.
func ParseMTUFromICMPv6PacketTooBig(data []byte) (int, bool) {
	if len(data) < 8 {
		return 0, false
	}
	if data[0] != 2 {
		return 0, false
	}
	mtu := int(data[4])<<24 | int(data[5])<<16 | int(data[6])<<8 | int(data[7])
	if mtu < MinMTUv6 || mtu > 65535 {
		return 0, false
	}
	return mtu, true
}
