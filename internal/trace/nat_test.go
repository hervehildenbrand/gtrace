package trace

import (
	"testing"
)

func TestNATInfo_String(t *testing.T) {
	tests := []struct {
		name     string
		info     NATInfo
		expected string
	}{
		{
			name:     "NAT detected",
			info:     NATInfo{Detected: true, Type: NATTypeIPRewrite},
			expected: "[NAT]",
		},
		{
			name:     "NAT with port rewrite",
			info:     NATInfo{Detected: true, Type: NATTypePortRewrite},
			expected: "[NAT]",
		},
		{
			name:     "no NAT",
			info:     NATInfo{Detected: false},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.String(); got != tt.expected {
				t.Errorf("NATInfo.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDetectNATFromIPID(t *testing.T) {
	tests := []struct {
		name     string
		ipIDs    []uint16
		expected bool
	}{
		{
			name:     "sequential IDs - no NAT",
			ipIDs:    []uint16{1000, 1001, 1002, 1003},
			expected: false,
		},
		{
			name:     "random IDs - possible NAT",
			ipIDs:    []uint16{1000, 5432, 2345, 9876},
			expected: true,
		},
		{
			name:     "all zeros - possible NAT/firewall",
			ipIDs:    []uint16{0, 0, 0, 0},
			expected: true,
		},
		{
			name:     "nearly sequential - no NAT",
			ipIDs:    []uint16{1000, 1002, 1003, 1005}, // gaps of 1-2 are normal
			expected: false,
		},
		{
			name:     "single ID - cannot determine",
			ipIDs:    []uint16{1000},
			expected: false,
		},
		{
			name:     "empty - cannot determine",
			ipIDs:    []uint16{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectNATFromIPID(tt.ipIDs); got != tt.expected {
				t.Errorf("DetectNATFromIPID(%v) = %v, want %v", tt.ipIDs, got, tt.expected)
			}
		})
	}
}

func TestDetectNATFromTTL(t *testing.T) {
	tests := []struct {
		name        string
		expectedTTL int
		actualTTL   int
		expected    bool
	}{
		{
			name:        "TTL matches - no NAT",
			expectedTTL: 64,
			actualTTL:   64,
			expected:    false,
		},
		{
			name:        "TTL 1 less - normal decrement",
			expectedTTL: 64,
			actualTTL:   63,
			expected:    false,
		},
		{
			name:        "TTL significantly different - possible NAT",
			expectedTTL: 64,
			actualTTL:   128,
			expected:    true,
		},
		{
			name:        "TTL from different OS default",
			expectedTTL: 64,
			actualTTL:   255,
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectNATFromTTL(tt.expectedTTL, tt.actualTTL); got != tt.expected {
				t.Errorf("DetectNATFromTTL(%d, %d) = %v, want %v",
					tt.expectedTTL, tt.actualTTL, got, tt.expected)
			}
		})
	}
}

func TestIPIDIsSequential(t *testing.T) {
	tests := []struct {
		name     string
		id1      uint16
		id2      uint16
		expected bool
	}{
		{
			name:     "sequential",
			id1:      100,
			id2:      101,
			expected: true,
		},
		{
			name:     "gap of 2",
			id1:      100,
			id2:      102,
			expected: true,
		},
		{
			name:     "gap of 10 - still acceptable",
			id1:      100,
			id2:      110,
			expected: true,
		},
		{
			name:     "large gap - not sequential",
			id1:      100,
			id2:      500,
			expected: false,
		},
		{
			name:     "wraparound",
			id1:      65530,
			id2:      5,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPIDIsSequential(tt.id1, tt.id2); got != tt.expected {
				t.Errorf("IPIDIsSequential(%d, %d) = %v, want %v",
					tt.id1, tt.id2, got, tt.expected)
			}
		})
	}
}

func TestCommonTTLDefaults(t *testing.T) {
	// Verify common OS TTL defaults are defined
	defaults := CommonTTLDefaults()

	// Should include common values
	found64 := false
	found128 := false
	found255 := false

	for _, ttl := range defaults {
		switch ttl {
		case 64:
			found64 = true
		case 128:
			found128 = true
		case 255:
			found255 = true
		}
	}

	if !found64 {
		t.Error("missing TTL 64 (Linux/macOS default)")
	}
	if !found128 {
		t.Error("missing TTL 128 (Windows default)")
	}
	if !found255 {
		t.Error("missing TTL 255 (Cisco/Solaris default)")
	}
}
