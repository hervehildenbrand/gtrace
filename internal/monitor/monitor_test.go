package monitor

import (
	"net"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestNewMonitor_CreatesMonitor(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMonitor(cfg)

	if m == nil {
		t.Fatal("expected non-nil monitor")
	}
}

func TestMonitorConfig_DefaultValues(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Interval != 10*time.Second {
		t.Errorf("expected interval 10s, got %v", cfg.Interval)
	}
	if cfg.LatencyThreshold != 0 {
		t.Error("expected no latency threshold by default")
	}
	if cfg.LossThreshold != 0 {
		t.Error("expected no loss threshold by default")
	}
}

func TestMonitor_DetectChanges_DetectsRouteChange(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMonitor(cfg)

	// Previous trace
	prev := createTrace([]string{"192.168.1.1", "10.0.0.1", "8.8.8.8"})
	// Current trace with different hop 2
	curr := createTrace([]string{"192.168.1.1", "10.0.0.2", "8.8.8.8"})

	changes := m.DetectChanges(prev, curr)

	if len(changes) == 0 {
		t.Fatal("expected route change to be detected")
	}

	hasRouteChange := false
	for _, c := range changes {
		if c.Type == ChangeTypeRoute {
			hasRouteChange = true
			break
		}
	}
	if !hasRouteChange {
		t.Error("expected ChangeTypeRoute")
	}
}

func TestMonitor_DetectChanges_DetectsNewHop(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMonitor(cfg)

	prev := createTrace([]string{"192.168.1.1", "8.8.8.8"})
	curr := createTrace([]string{"192.168.1.1", "10.0.0.1", "8.8.8.8"})

	changes := m.DetectChanges(prev, curr)

	if len(changes) == 0 {
		t.Fatal("expected changes to be detected")
	}
}

func TestMonitor_DetectChanges_DetectsLatencyIncrease(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LatencyThreshold = 50 * time.Millisecond
	m := NewMonitor(cfg)

	prev := createTraceWithRTT("8.8.8.8", 10*time.Millisecond)
	curr := createTraceWithRTT("8.8.8.8", 100*time.Millisecond)

	changes := m.DetectChanges(prev, curr)

	hasLatencyChange := false
	for _, c := range changes {
		if c.Type == ChangeTypeLatency {
			hasLatencyChange = true
			break
		}
	}
	if !hasLatencyChange {
		t.Error("expected ChangeTypeLatency")
	}
}

func TestMonitor_DetectChanges_DetectsLossIncrease(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LossThreshold = 5.0
	m := NewMonitor(cfg)

	prev := createTraceWithLoss("8.8.8.8", 0)
	curr := createTraceWithLoss("8.8.8.8", 50) // 50% loss

	changes := m.DetectChanges(prev, curr)

	hasLossChange := false
	for _, c := range changes {
		if c.Type == ChangeTypeLoss {
			hasLossChange = true
			break
		}
	}
	if !hasLossChange {
		t.Error("expected ChangeTypeLoss")
	}
}

func TestMonitor_DetectChanges_NoChangeForIdentical(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMonitor(cfg)

	trace := createTrace([]string{"192.168.1.1", "10.0.0.1", "8.8.8.8"})

	changes := m.DetectChanges(trace, trace)

	if len(changes) != 0 {
		t.Errorf("expected no changes, got %d", len(changes))
	}
}

func TestChange_String_FormatsNicely(t *testing.T) {
	change := Change{
		Type:    ChangeTypeRoute,
		Hop:     2,
		Message: "IP changed from 10.0.0.1 to 10.0.0.2",
	}

	str := change.String()

	if str == "" {
		t.Error("expected non-empty string")
	}
}

// Helper functions

func createTrace(ips []string) *hop.TraceResult {
	tr := hop.NewTraceResult("target", ips[len(ips)-1])
	for i, ipStr := range ips {
		h := hop.NewHop(i + 1)
		h.AddProbe(net.ParseIP(ipStr), 5*time.Millisecond)
		tr.AddHop(h)
	}
	return tr
}

func createTraceWithRTT(ip string, rtt time.Duration) *hop.TraceResult {
	tr := hop.NewTraceResult("target", ip)
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP(ip), rtt)
	tr.AddHop(h)
	return tr
}

func createTraceWithLoss(ip string, lossCount int) *hop.TraceResult {
	tr := hop.NewTraceResult("target", ip)
	h := hop.NewHop(1)

	// Add some successful probes and some timeouts
	for i := 0; i < 3-lossCount; i++ {
		h.AddProbe(net.ParseIP(ip), 5*time.Millisecond)
	}
	for i := 0; i < lossCount; i++ {
		h.AddTimeout()
	}

	tr.AddHop(h)
	return tr
}
