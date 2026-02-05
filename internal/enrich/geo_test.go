package enrich

import (
	"net"
	"testing"
)

func TestGeoResult_String(t *testing.T) {
	tests := []struct {
		name     string
		result   GeoResult
		expected string
	}{
		{
			name: "full location",
			result: GeoResult{
				City:    "San Francisco",
				Country: "US",
			},
			expected: "San Francisco, US",
		},
		{
			name: "country only",
			result: GeoResult{
				Country: "DE",
			},
			expected: "DE",
		},
		{
			name: "city only",
			result: GeoResult{
				City: "London",
			},
			expected: "London",
		},
		{
			name:     "empty",
			result:   GeoResult{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.String(); got != tt.expected {
				t.Errorf("GeoResult.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGeoResult_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		result   GeoResult
		expected bool
	}{
		{
			name:     "empty",
			result:   GeoResult{},
			expected: true,
		},
		{
			name:     "has city",
			result:   GeoResult{City: "NYC"},
			expected: false,
		},
		{
			name:     "has country",
			result:   GeoResult{Country: "US"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsEmpty(); got != tt.expected {
				t.Errorf("GeoResult.IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"10.x.x.x", "10.0.0.1", true},
		{"172.16.x.x", "172.16.0.1", true},
		{"172.31.x.x", "172.31.255.255", true},
		{"192.168.x.x", "192.168.1.1", true},
		{"127.x.x.x", "127.0.0.1", true},
		{"public IP", "8.8.8.8", false},
		{"public IP 2", "1.1.1.1", false},
		{"169.254 link-local", "169.254.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsPrivateIP(ip); got != tt.expected {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestNewGeoLookup(t *testing.T) {
	lookup := NewGeoLookup()
	if lookup == nil {
		t.Fatal("NewGeoLookup() returned nil")
	}
}

func TestGeoLookup_LookupPrivateIP(t *testing.T) {
	lookup := NewGeoLookup()

	// Private IPs should return empty result without error
	ip := net.ParseIP("192.168.1.1")
	result, err := lookup.Lookup(nil, ip)

	if err != nil {
		t.Errorf("unexpected error for private IP: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if !result.IsEmpty() {
		t.Error("private IP should return empty geo result")
	}
}

func TestGeoLookup_LookupNilIP(t *testing.T) {
	lookup := NewGeoLookup()

	_, err := lookup.Lookup(nil, nil)
	if err == nil {
		t.Error("expected error for nil IP")
	}
}

func TestGeoDBPath(t *testing.T) {
	path := DefaultGeoDBPath()
	if path == "" {
		t.Error("DefaultGeoDBPath() returned empty string")
	}
}
