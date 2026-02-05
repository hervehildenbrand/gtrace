package trace

import (
	"testing"
)

func TestMTUInfo_String(t *testing.T) {
	tests := []struct {
		name     string
		info     MTUInfo
		expected string
	}{
		{
			name:     "standard MTU",
			info:     MTUInfo{MTU: 1500, Discovered: true},
			expected: "MTU:1500",
		},
		{
			name:     "reduced MTU",
			info:     MTUInfo{MTU: 1400, Discovered: true},
			expected: "MTU:1400",
		},
		{
			name:     "not discovered",
			info:     MTUInfo{MTU: 0, Discovered: false},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.String(); got != tt.expected {
				t.Errorf("MTUInfo.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestMTUInfo_IsReduced(t *testing.T) {
	tests := []struct {
		name     string
		info     MTUInfo
		expected bool
	}{
		{
			name:     "standard MTU",
			info:     MTUInfo{MTU: 1500, Discovered: true},
			expected: false,
		},
		{
			name:     "reduced MTU",
			info:     MTUInfo{MTU: 1400, Discovered: true},
			expected: true,
		},
		{
			name:     "jumbo MTU",
			info:     MTUInfo{MTU: 9000, Discovered: true},
			expected: false,
		},
		{
			name:     "not discovered",
			info:     MTUInfo{MTU: 0, Discovered: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.IsReduced(); got != tt.expected {
				t.Errorf("MTUInfo.IsReduced() = %v, want %v", got, tt.expected)
			}
		})
	}
}

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
