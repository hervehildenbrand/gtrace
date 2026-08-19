package trace

import (
	"net"
	"testing"
)

func TestParseMTUFromICMP(t *testing.T) {
	// ICMP Destination Unreachable (Fragmentation Needed) message structure:
	// Type (1) | Code (1) | Checksum (2) | unused (2) | Next-Hop MTU (2) | Original IP header + 8 bytes
	tests := []struct {
		name     string
		data     []byte
		expected int
		ok       bool
	}{
		{
			name: "valid MTU 1400",
			// Type=3, Code=4, Checksum=0, unused=0, MTU=1400 (0x0578)
			data:     []byte{3, 4, 0, 0, 0, 0, 0x05, 0x78},
			expected: 1400,
			ok:       true,
		},
		{
			name: "valid MTU 1500",
			// MTU=1500 (0x05DC)
			data:     []byte{3, 4, 0, 0, 0, 0, 0x05, 0xDC},
			expected: 1500,
			ok:       true,
		},
		{
			name:     "too short",
			data:     []byte{3, 4, 0, 0},
			expected: 0,
			ok:       false,
		},
		{
			name:     "wrong type",
			data:     []byte{11, 0, 0, 0, 0, 0, 0x05, 0x78}, // Time Exceeded
			expected: 0,
			ok:       false,
		},
		{
			name:     "wrong code",
			data:     []byte{3, 0, 0, 0, 0, 0, 0x05, 0x78}, // Code 0 = Network Unreachable
			expected: 0,
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mtu, ok := ParseMTUFromICMP(tt.data)
			if ok != tt.ok {
				t.Errorf("ParseMTUFromICMP() ok = %v, want %v", ok, tt.ok)
			}
			if mtu != tt.expected {
				t.Errorf("ParseMTUFromICMP() mtu = %d, want %d", mtu, tt.expected)
			}
		})
	}
}

func TestMTUBinarySearch(t *testing.T) {
	// Test the binary search bounds calculation
	tests := []struct {
		name     string
		low      int
		high     int
		expected int // midpoint
	}{
		{
			name:     "standard range",
			low:      1400,
			high:     1500,
			expected: 1450,
		},
		{
			name:     "narrow range",
			low:      1498,
			high:     1500,
			expected: 1499,
		},
		{
			name:     "equal bounds",
			low:      1500,
			high:     1500,
			expected: 1500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mid := MTUSearchMidpoint(tt.low, tt.high)
			if mid != tt.expected {
				t.Errorf("MTUSearchMidpoint(%d, %d) = %d, want %d", tt.low, tt.high, mid, tt.expected)
			}
		})
	}
}

func TestCommonMTUValues(t *testing.T) {
	// Verify common MTU constants are defined correctly
	if StandardMTU != 1500 {
		t.Errorf("StandardMTU = %d, want 1500", StandardMTU)
	}
	if MinMTU != 68 {
		t.Errorf("MinMTU = %d, want 68 (IPv4 minimum)", MinMTU)
	}
}

func TestParseMTUFromICMPv6PacketTooBig(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantMTU int
		wantOK  bool
	}{
		{
			name: "valid packet too big with MTU 1400",
			// Type 2, Code 0, checksum, MTU (32-bit big-endian)
			data:    []byte{2, 0, 0x12, 0x34, 0x00, 0x00, 0x05, 0x78},
			wantMTU: 1400,
			wantOK:  true,
		},
		{
			name:    "valid packet too big with MTU 1280",
			data:    []byte{2, 0, 0, 0, 0x00, 0x00, 0x05, 0x00},
			wantMTU: 1280,
			wantOK:  true,
		},
		{
			name:    "wrong type",
			data:    []byte{3, 0, 0, 0, 0x00, 0x00, 0x05, 0x78},
			wantMTU: 0,
			wantOK:  false,
		},
		{
			name:    "MTU below IPv6 minimum",
			data:    []byte{2, 0, 0, 0, 0x00, 0x00, 0x04, 0x00}, // 1024
			wantMTU: 0,
			wantOK:  false,
		},
		{
			name:    "truncated message",
			data:    []byte{2, 0, 0, 0, 0x00},
			wantMTU: 0,
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mtu, ok := ParseMTUFromICMPv6PacketTooBig(tt.data)
			if mtu != tt.wantMTU || ok != tt.wantOK {
				t.Errorf("ParseMTUFromICMPv6PacketTooBig() = (%d, %v), want (%d, %v)", mtu, ok, tt.wantMTU, tt.wantOK)
			}
		})
	}
}

func TestMinMTUv6_IsRFC8200Minimum(t *testing.T) {
	if MinMTUv6 != 1280 {
		t.Errorf("MinMTUv6 = %d, want 1280", MinMTUv6)
	}
}

func TestGetEgressMTU_LoopbackReturnsPositiveMTU(t *testing.T) {
	mtu := GetEgressMTU(net.ParseIP("127.0.0.1"))
	if mtu < MinMTU {
		t.Errorf("GetEgressMTU(127.0.0.1) = %d, want >= %d", mtu, MinMTU)
	}
}

func TestGetEgressMTU_UnroutableFallsBackToStandard(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1; dialing usually still succeeds (no packets
	// are sent for UDP dial), so this mainly guards the fallback path: the
	// result must always be a sane MTU.
	mtu := GetEgressMTU(net.ParseIP("192.0.2.1"))
	if mtu < MinMTU {
		t.Errorf("GetEgressMTU(192.0.2.1) = %d, want >= %d", mtu, MinMTU)
	}
}
