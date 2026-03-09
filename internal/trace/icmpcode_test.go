package trace

import (
	"testing"
)

func TestICMPCodeIndicator(t *testing.T) {
	tests := []struct {
		name     string
		icmpType int
		code     int
		expected string
	}{
		{"network unreachable", 3, 0, "[!N]"},
		{"host unreachable", 3, 1, "[!H]"},
		{"port unreachable (normal UDP)", 3, 3, "[!P]"},
		{"fragmentation needed", 3, 4, "[!F]"},
		{"admin prohibited code 9", 3, 9, "[!X]"},
		{"admin prohibited code 10", 3, 10, "[!X]"},
		{"admin prohibited code 13", 3, 13, "[!X]"},
		{"protocol unreachable", 3, 2, ""},
		{"time exceeded (not dest unreach)", 11, 0, ""},
		{"echo reply (not dest unreach)", 0, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ICMPCodeIndicator(tt.icmpType, tt.code)
			if got != tt.expected {
				t.Errorf("ICMPCodeIndicator(%d, %d) = %q, want %q", tt.icmpType, tt.code, got, tt.expected)
			}
		})
	}
}

func TestICMPCodeText(t *testing.T) {
	tests := []struct {
		icmpType int
		code     int
		expected string
	}{
		{3, 0, "network unreachable"},
		{3, 1, "host unreachable"},
		{3, 3, "port unreachable"},
		{3, 4, "fragmentation needed"},
		{3, 9, "admin prohibited"},
		{3, 10, "admin prohibited"},
		{3, 13, "admin prohibited"},
		{3, 2, "protocol unreachable"},
		{11, 0, ""},
		{3, 99, ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := ICMPCodeText(tt.icmpType, tt.code)
			if got != tt.expected {
				t.Errorf("ICMPCodeText(%d, %d) = %q, want %q", tt.icmpType, tt.code, got, tt.expected)
			}
		})
	}
}
