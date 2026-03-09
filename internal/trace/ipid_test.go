package trace

import (
	"testing"
)

func TestExtractIPID(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint16
	}{
		{
			name: "normal IP header with ID 0x1234",
			// Minimal IPv4 header: bytes 4-5 are IP ID
			data:     []byte{0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8},
			expected: 0x1234,
		},
		{
			name:     "IP ID zero",
			data:     []byte{0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8},
			expected: 0x0000,
		},
		{
			name:     "IP ID 0xFFFF",
			data:     []byte{0x45, 0x00, 0x00, 0x3c, 0xFF, 0xFF, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8},
			expected: 0xFFFF,
		},
		{
			name:     "data too short",
			data:     []byte{0x45, 0x00, 0x00},
			expected: 0,
		},
		{
			name:     "nil data",
			data:     nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractIPID(tt.data)
			if got != tt.expected {
				t.Errorf("ExtractIPID() = 0x%04x, want 0x%04x", got, tt.expected)
			}
		})
	}
}
