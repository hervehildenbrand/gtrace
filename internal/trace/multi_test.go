package trace

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// mockTracer is a simple tracer that returns a fixed result.
type mockTracer struct {
	hops []mockHop
}

type mockHop struct {
	ttl int
	ip  net.IP
	rtt time.Duration
}

func (m *mockTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	result := hop.NewTraceResult(target.String(), target.String())
	result.Protocol = "icmp"
	for _, mh := range m.hops {
		h := hop.NewHop(mh.ttl)
		h.AddProbe(mh.ip, mh.rtt)
		result.AddHop(h)
		if callback != nil {
			callback(h)
		}
	}
	result.ReachedTarget = true
	return result, nil
}

func TestMultiContinuousTracer_RunsAllTargets(t *testing.T) {
	targets := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("8.8.8.8"),
	}

	tracers := []Tracer{
		&mockTracer{hops: []mockHop{
			{ttl: 1, ip: net.ParseIP("192.168.1.1"), rtt: 1 * time.Millisecond},
			{ttl: 2, ip: net.ParseIP("1.1.1.1"), rtt: 5 * time.Millisecond},
		}},
		&mockTracer{hops: []mockHop{
			{ttl: 1, ip: net.ParseIP("192.168.1.1"), rtt: 1 * time.Millisecond},
			{ttl: 2, ip: net.ParseIP("10.0.0.1"), rtt: 3 * time.Millisecond},
			{ttl: 3, ip: net.ParseIP("8.8.8.8"), rtt: 10 * time.Millisecond},
		}},
	}

	cfg := &Config{
		MaxHops:       30,
		PacketsPerHop: 1,
		Timeout:       500 * time.Millisecond,
	}

	mct := NewMultiContinuousTracer(cfg, tracers, targets, 100*time.Millisecond)

	var mu sync.Mutex
	probesByTarget := make(map[int]int) // targetIndex -> probe count
	cyclesByTarget := make(map[int]int)

	probeCallback := func(targetIndex int, pr ProbeResult) {
		mu.Lock()
		probesByTarget[targetIndex]++
		mu.Unlock()
	}

	cycleCallback := func(targetIndex int, cycle int, reached bool) {
		mu.Lock()
		cyclesByTarget[targetIndex]++
		mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	mct.Run(ctx, probeCallback, cycleCallback)

	mu.Lock()
	defer mu.Unlock()

	// Both targets should have received probes
	if probesByTarget[0] == 0 {
		t.Error("target 0 received no probes")
	}
	if probesByTarget[1] == 0 {
		t.Error("target 1 received no probes")
	}

	// Both targets should have completed at least 1 cycle
	if cyclesByTarget[0] == 0 {
		t.Error("target 0 completed no cycles")
	}
	if cyclesByTarget[1] == 0 {
		t.Error("target 1 completed no cycles")
	}
}

func TestMultiContinuousTracer_SingleTarget(t *testing.T) {
	targets := []net.IP{net.ParseIP("1.1.1.1")}
	tracers := []Tracer{
		&mockTracer{hops: []mockHop{
			{ttl: 1, ip: net.ParseIP("1.1.1.1"), rtt: 1 * time.Millisecond},
		}},
	}

	cfg := &Config{
		MaxHops:       30,
		PacketsPerHop: 1,
		Timeout:       500 * time.Millisecond,
	}

	mct := NewMultiContinuousTracer(cfg, tracers, targets, 100*time.Millisecond)

	var probeCount int
	var mu sync.Mutex

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	mct.Run(ctx, func(targetIndex int, pr ProbeResult) {
		mu.Lock()
		probeCount++
		mu.Unlock()
		if targetIndex != 0 {
			t.Errorf("expected targetIndex 0, got %d", targetIndex)
		}
	}, nil)

	mu.Lock()
	defer mu.Unlock()
	if probeCount == 0 {
		t.Error("expected at least one probe")
	}
}

func TestMultiContinuousTracer_ContextCancellation(t *testing.T) {
	targets := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	tracers := []Tracer{
		&mockTracer{hops: []mockHop{{ttl: 1, ip: net.ParseIP("1.1.1.1"), rtt: 1 * time.Millisecond}}},
		&mockTracer{hops: []mockHop{{ttl: 1, ip: net.ParseIP("8.8.8.8"), rtt: 1 * time.Millisecond}}},
	}

	cfg := &Config{MaxHops: 30, PacketsPerHop: 1, Timeout: 500 * time.Millisecond}
	mct := NewMultiContinuousTracer(cfg, tracers, targets, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		mct.Run(ctx, nil, nil)
		close(done)
	}()

	// Cancel quickly
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Should return promptly
	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("MultiContinuousTracer did not stop after context cancellation")
	}
}
