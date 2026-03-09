package trace

import (
	"testing"
)

func TestExtractOriginalTTL(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected int
	}{
		{
			name: "TTL=1 at byte 8",
			// IPv4 header: byte 8 is TTL
			data:     []byte{0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8},
			expected: 1,
		},
		{
			name:     "TTL=64",
			data:     []byte{0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8},
			expected: 64,
		},
		{
			name:     "TTL=0 (decremented to zero)",
			data:     []byte{0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8},
			expected: 0,
		},
		{
			name:     "data too short",
			data:     []byte{0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00},
			expected: -1,
		},
		{
			name:     "nil data",
			data:     nil,
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractOriginalTTL(tt.data)
			if got != tt.expected {
				t.Errorf("ExtractOriginalTTL() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestIsTTLManipulated(t *testing.T) {
	tests := []struct {
		name        string
		sentTTL     int
		originalTTL int
		expected    bool
	}{
		{"TTL=1 matches sent TTL=1 (normal Time Exceeded)", 1, 1, false},
		{"TTL=0 matches sent TTL=1 (normal, router decremented)", 1, 0, false},
		{"TTL=5 for sent TTL=1 (manipulated)", 1, 5, true},
		{"TTL=64 for sent TTL=3 (middlebox reset)", 3, 64, true},
		{"negative original TTL", 1, -1, false},
		{"sent TTL=0", 0, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTTLManipulated(tt.sentTTL, tt.originalTTL)
			if got != tt.expected {
				t.Errorf("IsTTLManipulated(%d, %d) = %v, want %v", tt.sentTTL, tt.originalTTL, got, tt.expected)
			}
		})
	}
}
