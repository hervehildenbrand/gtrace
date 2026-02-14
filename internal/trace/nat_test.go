package trace

import (
	"net"
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
		hopNumber   int
		responseTTL int
		expected    bool
	}{
		{
			name:        "Cisco router at hop 3 (TTL 252) - no NAT",
			hopNumber:   3,
			responseTTL: 252,
			expected:    false,
		},
		{
			name:        "Linux router at hop 7 (TTL 57) - no NAT",
			hopNumber:   7,
			responseTTL: 57,
			expected:    false,
		},
		{
			name:        "Windows router at hop 5 (TTL 123) - no NAT",
			hopNumber:   5,
			responseTTL: 123,
			expected:    false,
		},
		{
			name:        "Google router at hop 10 (TTL 245) - no NAT",
			hopNumber:   10,
			responseTTL: 245,
			expected:    false,
		},
		{
			name:        "significant mismatch - possible NAT",
			hopNumber:   3,
			responseTTL: 117,
			expected:    true,
		},
		{
			name:        "zero response TTL - no NAT",
			hopNumber:   5,
			responseTTL: 0,
			expected:    false,
		},
		{
			name:        "zero hop number - no NAT",
			hopNumber:   0,
			responseTTL: 64,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectNATFromTTL(tt.hopNumber, tt.responseTTL); got != tt.expected {
				t.Errorf("DetectNATFromTTL(%d, %d) = %v, want %v",
					tt.hopNumber, tt.responseTTL, got, tt.expected)
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

func TestInferInitialTTL(t *testing.T) {
	tests := []struct {
		name        string
		observedTTL int
		expected    int
	}{
		{"zero", 0, 0},
		{"1 rounds to 32", 1, 32},
		{"32 stays 32", 32, 32},
		{"33 rounds to 64", 33, 64},
		{"64 stays 64", 64, 64},
		{"65 rounds to 128", 65, 128},
		{"128 stays 128", 128, 128},
		{"129 rounds to 255", 129, 255},
		{"255 stays 255", 255, 255},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InferInitialTTL(tt.observedTTL); got != tt.expected {
				t.Errorf("InferInitialTTL(%d) = %d, want %d", tt.observedTTL, got, tt.expected)
			}
		})
	}
}

func TestIsCGNATAddress(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"CGNAT address", "100.64.0.1", true},
		{"CGNAT upper bound", "100.127.255.255", true},
		{"above CGNAT range", "100.128.0.0", false},
		{"private 10.x not CGNAT", "10.0.0.1", false},
		{"public IP", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsCGNATAddress(ip); got != tt.expected {
				t.Errorf("IsCGNATAddress(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestIsPrivateAddress(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"10.0.0.1 is private", "10.0.0.1", true},
		{"10.255.255.255 is private", "10.255.255.255", true},
		{"172.16.0.1 is private", "172.16.0.1", true},
		{"172.31.255.255 is private", "172.31.255.255", true},
		{"172.32.0.0 not private", "172.32.0.0", false},
		{"192.168.0.1 is private", "192.168.0.1", true},
		{"192.168.255.255 is private", "192.168.255.255", true},
		{"8.8.8.8 not private", "8.8.8.8", false},
		{"11.0.0.1 not private", "11.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsPrivateAddress(ip); got != tt.expected {
				t.Errorf("IsPrivateAddress(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestDetectNATFromIP(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		hopNumber int
		expected  bool
	}{
		{"CGNAT at any hop", "100.64.0.1", 1, true},
		{"CGNAT at hop 5", "100.64.0.1", 5, true},
		{"private at hop 1 - gateway, no flag", "192.168.1.1", 1, false},
		{"private at hop 2 - NAT detected", "10.0.0.1", 2, true},
		{"private at hop 3 - NAT detected", "172.16.0.1", 3, true},
		{"public IP - no NAT", "8.8.8.8", 5, false},
		{"public IP at hop 1 - no NAT", "1.1.1.1", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := DetectNATFromIP(ip, tt.hopNumber); got != tt.expected {
				t.Errorf("DetectNATFromIP(%s, %d) = %v, want %v", tt.ip, tt.hopNumber, got, tt.expected)
			}
		})
	}
}
