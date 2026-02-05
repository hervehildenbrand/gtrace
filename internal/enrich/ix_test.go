package enrich

import (
	"net"
	"testing"
)

func TestIXResult_String(t *testing.T) {
	tests := []struct {
		name     string
		result   IXResult
		expected string
	}{
		{
			name: "with IX name",
			result: IXResult{
				Name:    "DE-CIX Frankfurt",
				Matched: true,
			},
			expected: "IX:DE-CIX Frankfurt",
		},
		{
			name: "not matched",
			result: IXResult{
				Matched: false,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.String(); got != tt.expected {
				t.Errorf("IXResult.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestIXResult_IsIX(t *testing.T) {
	tests := []struct {
		name     string
		result   IXResult
		expected bool
	}{
		{
			name:     "matched IX",
			result:   IXResult{Matched: true, Name: "AMS-IX"},
			expected: true,
		},
		{
			name:     "not matched",
			result:   IXResult{Matched: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsIX(); got != tt.expected {
				t.Errorf("IXResult.IsIX() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewIXLookup(t *testing.T) {
	lookup := NewIXLookup()
	if lookup == nil {
		t.Fatal("NewIXLookup() returned nil")
	}
}

func TestIXLookup_LookupPrivateIP(t *testing.T) {
	lookup := NewIXLookup()

	// Private IPs should not be IX
	ip := net.ParseIP("192.168.1.1")
	result, err := lookup.Lookup(nil, ip)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.IsIX() {
		t.Error("private IP should not be an IX")
	}
}

func TestIXLookup_LookupNilIP(t *testing.T) {
	lookup := NewIXLookup()

	_, err := lookup.Lookup(nil, nil)
	if err == nil {
		t.Error("expected error for nil IP")
	}
}

func TestIsKnownIXPrefix(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Known IX prefixes
		{"DE-CIX", "80.81.192.1", true},
		{"AMS-IX", "80.249.208.1", true},
		{"LINX", "195.66.224.1", true},

		// Not IX
		{"Google DNS", "8.8.8.8", false},
		{"Cloudflare", "1.1.1.1", false},
		{"Private", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsKnownIXPrefix(ip); got != tt.expected {
				t.Errorf("IsKnownIXPrefix(%s) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestGetIXNameFromPrefix(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"DE-CIX", "80.81.192.1", "DE-CIX"},
		{"AMS-IX", "80.249.208.1", "AMS-IX"},
		{"LINX", "195.66.224.1", "LINX"},
		{"Unknown", "8.8.8.8", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := GetIXNameFromPrefix(ip); got != tt.expected {
				t.Errorf("GetIXNameFromPrefix(%s) = %q, want %q", tt.ip, got, tt.expected)
			}
		})
	}
}
