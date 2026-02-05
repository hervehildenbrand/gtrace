package trace

import (
	"net"
	"testing"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestECMPDetector_NoECMP(t *testing.T) {
	// Hop with single IP - no ECMP
	h := hop.NewHop(5)
	h.AddProbe(net.ParseIP("192.168.1.1"), 10)
	h.AddProbe(net.ParseIP("192.168.1.1"), 11)
	h.AddProbe(net.ParseIP("192.168.1.1"), 12)

	info := DetectECMP(h)

	if info.Detected {
		t.Error("expected no ECMP detection for single IP")
	}
	if info.PathCount != 1 {
		t.Errorf("expected 1 path, got %d", info.PathCount)
	}
}

func TestECMPDetector_WithECMP(t *testing.T) {
	// Hop with multiple IPs - ECMP detected
	h := hop.NewHop(5)
	h.AddProbe(net.ParseIP("192.168.1.1"), 10)
	h.AddProbe(net.ParseIP("192.168.1.2"), 11)
	h.AddProbe(net.ParseIP("192.168.1.1"), 12)
	h.AddProbe(net.ParseIP("192.168.1.3"), 13)

	info := DetectECMP(h)

	if !info.Detected {
		t.Error("expected ECMP detection for multiple IPs")
	}
	if info.PathCount != 3 {
		t.Errorf("expected 3 paths, got %d", info.PathCount)
	}
}

func TestECMPDetector_AllTimeouts(t *testing.T) {
	// All timeouts - no ECMP
	h := hop.NewHop(5)
	h.AddTimeout()
	h.AddTimeout()
	h.AddTimeout()

	info := DetectECMP(h)

	if info.Detected {
		t.Error("expected no ECMP detection for all timeouts")
	}
	if info.PathCount != 0 {
		t.Errorf("expected 0 paths, got %d", info.PathCount)
	}
}

func TestECMPDetector_MixedTimeouts(t *testing.T) {
	// Mixed responses with timeouts
	h := hop.NewHop(5)
	h.AddProbe(net.ParseIP("10.0.0.1"), 10)
	h.AddTimeout()
	h.AddProbe(net.ParseIP("10.0.0.2"), 12)

	info := DetectECMP(h)

	if !info.Detected {
		t.Error("expected ECMP detection for multiple IPs with timeouts")
	}
	if info.PathCount != 2 {
		t.Errorf("expected 2 paths, got %d", info.PathCount)
	}
}

func TestECMPInfo_String(t *testing.T) {
	info := ECMPInfo{
		Detected:  true,
		PathCount: 3,
		IPs:       []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3")},
	}

	s := info.String()
	if s != "[ECMP:3]" {
		t.Errorf("expected '[ECMP:3]', got %q", s)
	}
}

func TestECMPInfo_String_NoECMP(t *testing.T) {
	info := ECMPInfo{
		Detected:  false,
		PathCount: 1,
	}

	s := info.String()
	if s != "" {
		t.Errorf("expected empty string for no ECMP, got %q", s)
	}
}

func TestGenerateFlowID(t *testing.T) {
	// Generate multiple flow IDs and ensure they're different
	ids := make(map[uint16]bool)
	for i := 0; i < 10; i++ {
		id := GenerateFlowID(i)
		if ids[id] {
			t.Errorf("duplicate flow ID generated: %d", id)
		}
		ids[id] = true
	}
}
