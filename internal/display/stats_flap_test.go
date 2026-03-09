package display

import (
	"net"
	"testing"
	"time"
)

func TestHopStats_HasRouteFlap_Stable(t *testing.T) {
	s := NewHopStats(1)
	ip := net.ParseIP("1.1.1.1")
	for i := 0; i < 20; i++ {
		s.AddProbe(ip, time.Millisecond)
	}

	if s.HasRouteFlap() {
		t.Error("stable single-IP hop should not be flagged as flapping")
	}
}

func TestHopStats_HasRouteFlap_ECMP_TwoIPs(t *testing.T) {
	// Two IPs alternating = ECMP, not flap (UniqueIPCount == 2)
	s := NewHopStats(1)
	ip1 := net.ParseIP("1.1.1.1")
	ip2 := net.ParseIP("2.2.2.2")
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			s.AddProbe(ip1, time.Millisecond)
		} else {
			s.AddProbe(ip2, time.Millisecond)
		}
	}

	if s.HasRouteFlap() {
		t.Error("two-IP alternation should be classified as ECMP, not route flap")
	}
}

func TestHopStats_HasRouteFlap_ThreeIPs(t *testing.T) {
	// Three IPs with many transitions = route flap
	s := NewHopStats(1)
	ips := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2.2.2.2"),
		net.ParseIP("3.3.3.3"),
	}
	for i := 0; i < 20; i++ {
		s.AddProbe(ips[i%3], time.Millisecond)
	}

	if !s.HasRouteFlap() {
		t.Error("three IPs with frequent transitions should be flagged as route flap")
	}
}

func TestHopStats_HasRouteFlap_ColdStart(t *testing.T) {
	// Too few samples to determine
	s := NewHopStats(1)
	s.AddProbe(net.ParseIP("1.1.1.1"), time.Millisecond)
	s.AddProbe(net.ParseIP("2.2.2.2"), time.Millisecond)
	s.AddProbe(net.ParseIP("3.3.3.3"), time.Millisecond)

	if s.HasRouteFlap() {
		t.Error("cold start (Sent <= 10) should not flag route flap")
	}
}

func TestHopStats_TransitionCount(t *testing.T) {
	s := NewHopStats(1)
	ip1 := net.ParseIP("1.1.1.1")
	ip2 := net.ParseIP("2.2.2.2")

	s.AddProbe(ip1, time.Millisecond) // no transition (first)
	s.AddProbe(ip1, time.Millisecond) // same
	s.AddProbe(ip2, time.Millisecond) // transition
	s.AddProbe(ip1, time.Millisecond) // transition
	s.AddProbe(ip2, time.Millisecond) // transition

	if s.TransitionCount != 3 {
		t.Errorf("expected 3 transitions, got %d", s.TransitionCount)
	}
}

func TestHopStats_IPHistory_BoundedRingBuffer(t *testing.T) {
	s := NewHopStats(1)
	for i := 0; i < 150; i++ {
		ip := net.ParseIP("1.1.1.1")
		s.AddProbe(ip, time.Millisecond)
	}

	if len(s.IPHistory) > 100 {
		t.Errorf("IPHistory should be bounded at 100, got %d", len(s.IPHistory))
	}
}

func TestHopStats_Reset_ClearsFlap(t *testing.T) {
	s := NewHopStats(1)
	ips := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2.2.2.2"),
		net.ParseIP("3.3.3.3"),
	}
	for i := 0; i < 20; i++ {
		s.AddProbe(ips[i%3], time.Millisecond)
	}

	s.Reset()

	if s.TransitionCount != 0 {
		t.Errorf("expected TransitionCount to be 0 after reset, got %d", s.TransitionCount)
	}
	if len(s.IPHistory) != 0 {
		t.Errorf("expected IPHistory to be empty after reset, got %d", len(s.IPHistory))
	}
}
