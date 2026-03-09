package trace

import (
	"testing"
)

func TestClassifyECMP_PerFlow(t *testing.T) {
	// Each flow consistently hits the same IP, but different flows hit different IPs
	flowPaths := map[int]map[string]int{
		1: {"1.1.1.1": 3},
		2: {"2.2.2.2": 3},
		3: {"3.3.3.3": 3},
	}

	got := ClassifyECMP(flowPaths)
	if got != ECMPTypePerFlow {
		t.Errorf("expected ECMPTypePerFlow, got %v", got)
	}
}

func TestClassifyECMP_PerPacket(t *testing.T) {
	// Same flow hits multiple IPs → per-packet load balancing
	flowPaths := map[int]map[string]int{
		1: {"1.1.1.1": 2, "2.2.2.2": 1},
		2: {"2.2.2.2": 3},
	}

	got := ClassifyECMP(flowPaths)
	if got != ECMPTypePerPacket {
		t.Errorf("expected ECMPTypePerPacket, got %v", got)
	}
}

func TestClassifyECMP_SingleFlow(t *testing.T) {
	// Only one flow, one IP → unknown
	flowPaths := map[int]map[string]int{
		1: {"1.1.1.1": 3},
	}

	got := ClassifyECMP(flowPaths)
	if got != ECMPTypeUnknown {
		t.Errorf("expected ECMPTypeUnknown, got %v", got)
	}
}

func TestClassifyECMP_Empty(t *testing.T) {
	got := ClassifyECMP(nil)
	if got != ECMPTypeUnknown {
		t.Errorf("expected ECMPTypeUnknown, got %v", got)
	}
}

func TestClassifyECMP_AllSameIP(t *testing.T) {
	// Multiple flows all hit same IP → no ECMP
	flowPaths := map[int]map[string]int{
		1: {"1.1.1.1": 3},
		2: {"1.1.1.1": 3},
		3: {"1.1.1.1": 3},
	}

	got := ClassifyECMP(flowPaths)
	if got != ECMPTypeUnknown {
		t.Errorf("expected ECMPTypeUnknown (no ECMP), got %v", got)
	}
}

func TestECMPType_String(t *testing.T) {
	tests := []struct {
		t        ECMPType
		expected string
	}{
		{ECMPTypePerFlow, "per_flow"},
		{ECMPTypePerPacket, "per_packet"},
		{ECMPTypeUnknown, "unknown"},
	}

	for _, tt := range tests {
		if got := tt.t.String(); got != tt.expected {
			t.Errorf("ECMPType(%d).String() = %q, want %q", tt.t, got, tt.expected)
		}
	}
}
