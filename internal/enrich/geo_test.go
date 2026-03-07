package enrich

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestIsPrivateIP_IPv6(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IPv6 loopback", "::1", true},
		{"IPv6 ULA fc00::", "fc00::1", true},
		{"IPv6 ULA fd00::", "fd00::1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 public Google DNS", "2001:4860:4860::8888", false},
		{"IPv6 public Cloudflare", "2606:4700:4700::1111", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
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

func TestGeoLookup_APIFallback(t *testing.T) {
	// Mock ip-api.com server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "success",
			"city":        "Ashburn",
			"country":     "United States",
			"countryCode": "US",
			"regionName":  "Virginia",
			"lat":         39.03,
			"lon":         -77.5,
			"timezone":    "America/New_York",
		})
	}))
	defer srv.Close()

	lookup := NewGeoLookupWithDB("") // No database
	lookup.apiBaseURL = srv.URL

	result, err := lookup.Lookup(context.Background(), net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.City != "Ashburn" {
		t.Errorf("City = %q, want %q", result.City, "Ashburn")
	}
	if result.Country != "US" {
		t.Errorf("Country = %q, want %q", result.Country, "US")
	}
	if result.CountryName != "United States" {
		t.Errorf("CountryName = %q, want %q", result.CountryName, "United States")
	}
	if result.Region != "Virginia" {
		t.Errorf("Region = %q, want %q", result.Region, "Virginia")
	}
	if result.Latitude != 39.03 {
		t.Errorf("Latitude = %v, want %v", result.Latitude, 39.03)
	}
	if result.Longitude != -77.5 {
		t.Errorf("Longitude = %v, want %v", result.Longitude, -77.5)
	}
	if result.Timezone != "America/New_York" {
		t.Errorf("Timezone = %q, want %q", result.Timezone, "America/New_York")
	}
}

func TestGeoLookup_APIFallback_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "fail",
			"message": "reserved range",
		})
	}))
	defer srv.Close()

	lookup := NewGeoLookupWithDB("")
	lookup.apiBaseURL = srv.URL

	result, err := lookup.Lookup(context.Background(), net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return empty result on API failure, not error
	if !result.IsEmpty() {
		t.Errorf("expected empty result on API failure, got %+v", result)
	}
}
