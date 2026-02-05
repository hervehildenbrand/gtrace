package trace

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// mockContinuousTracer is a mock implementation of Tracer for testing.
type mockContinuousTracer struct {
	traceFn func(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error)
}

func (m *mockContinuousTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	return m.traceFn(ctx, target, callback)
}

func TestNewContinuousTracer(t *testing.T) {
	cfg := DefaultConfig()
	mockTracer := &mockContinuousTracer{}

	ct := NewContinuousTracer(cfg, mockTracer, time.Second)

	if ct == nil {
		t.Fatal("expected non-nil ContinuousTracer")
	}
	if ct.interval != time.Second {
		t.Errorf("expected interval 1s, got %v", ct.interval)
	}
}

func TestContinuousTracer_Run_SingleCycle(t *testing.T) {
	cfg := DefaultConfig()

	// Track callback invocations
	var results []ProbeResult
	var mu sync.Mutex

	mockTracer := &mockContinuousTracer{
		traceFn: func(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
			result := hop.NewTraceResult(target.String(), target.String())

			// Simulate 3 hops
			for ttl := 1; ttl <= 3; ttl++ {
				h := hop.NewHop(ttl)
				h.AddProbe(net.ParseIP("192.168.1."+string(rune('0'+ttl))), time.Duration(ttl)*10*time.Millisecond)
				result.AddHop(h)
				if callback != nil {
					callback(h)
				}
			}

			result.ReachedTarget = true
			return result, nil
		},
	}

	ct := NewContinuousTracer(cfg, mockTracer, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	target := net.ParseIP("8.8.8.8")

	probeCallback := func(result ProbeResult) {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}

	cycleCallback := func(cycle int, reached bool) {
		// Cycle completed
	}

	err := ct.Run(ctx, target, probeCallback, cycleCallback)

	// Should complete due to context timeout
	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("unexpected error: %v", err)
	}

	mu.Lock()
	resultCount := len(results)
	mu.Unlock()

	// Should have at least 3 results (from one cycle)
	if resultCount < 3 {
		t.Errorf("expected at least 3 probe results, got %d", resultCount)
	}
}

func TestContinuousTracer_Run_MultipleCycles(t *testing.T) {
	cfg := DefaultConfig()

	cycleCount := 0
	var mu sync.Mutex

	mockTracer := &mockContinuousTracer{
		traceFn: func(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
			mu.Lock()
			cycleCount++
			mu.Unlock()

			result := hop.NewTraceResult(target.String(), target.String())

			h := hop.NewHop(1)
			h.AddProbe(net.ParseIP("192.168.1.1"), 10*time.Millisecond)
			result.AddHop(h)
			if callback != nil {
				callback(h)
			}

			result.ReachedTarget = true
			return result, nil
		},
	}

	ct := NewContinuousTracer(cfg, mockTracer, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	target := net.ParseIP("8.8.8.8")

	err := ct.Run(ctx, target, func(ProbeResult) {}, func(int, bool) {})

	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("unexpected error: %v", err)
	}

	mu.Lock()
	cycles := cycleCount
	mu.Unlock()

	// With 180ms timeout and 50ms interval, should get at least 2 cycles
	if cycles < 2 {
		t.Errorf("expected at least 2 cycles, got %d", cycles)
	}
}

func TestContinuousTracer_Run_CycleCallback(t *testing.T) {
	cfg := DefaultConfig()

	var cycles []int
	var mu sync.Mutex

	mockTracer := &mockContinuousTracer{
		traceFn: func(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
			result := hop.NewTraceResult(target.String(), target.String())
			h := hop.NewHop(1)
			h.AddProbe(net.ParseIP("192.168.1.1"), 10*time.Millisecond)
			result.AddHop(h)
			result.ReachedTarget = true
			return result, nil
		},
	}

	ct := NewContinuousTracer(cfg, mockTracer, 30*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	target := net.ParseIP("8.8.8.8")

	cycleCallback := func(cycle int, reached bool) {
		mu.Lock()
		cycles = append(cycles, cycle)
		mu.Unlock()
	}

	err := ct.Run(ctx, target, func(ProbeResult) {}, cycleCallback)

	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("unexpected error: %v", err)
	}

	mu.Lock()
	cycleList := cycles
	mu.Unlock()

	// Should have at least 2 cycles recorded
	if len(cycleList) < 2 {
		t.Errorf("expected at least 2 cycle callbacks, got %d", len(cycleList))
	}

	// Cycles should be sequential
	for i, c := range cycleList {
		if c != i+1 {
			t.Errorf("expected cycle %d at index %d, got %d", i+1, i, c)
		}
	}
}

func TestContinuousTracer_Run_Cancellation(t *testing.T) {
	cfg := DefaultConfig()

	mockTracer := &mockContinuousTracer{
		traceFn: func(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
			// Check for cancellation
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			result := hop.NewTraceResult(target.String(), target.String())
			h := hop.NewHop(1)
			h.AddProbe(net.ParseIP("192.168.1.1"), 10*time.Millisecond)
			result.AddHop(h)
			return result, nil
		},
	}

	ct := NewContinuousTracer(cfg, mockTracer, time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	target := net.ParseIP("8.8.8.8")

	// Cancel immediately
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := ct.Run(ctx, target, func(ProbeResult) {}, func(int, bool) {})

	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestContinuousTracer_Run_ProbeResultConversion(t *testing.T) {
	cfg := DefaultConfig()

	var results []ProbeResult
	var mu sync.Mutex

	targetIP := net.ParseIP("8.8.8.8")
	hopIP := net.ParseIP("192.168.1.1")

	mockTracer := &mockContinuousTracer{
		traceFn: func(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
			result := hop.NewTraceResult(target.String(), target.String())

			h := hop.NewHop(1)
			h.AddProbe(hopIP, 10*time.Millisecond)
			h.SetMPLS([]hop.MPLSLabel{{Label: 100, Exp: 0, S: true, TTL: 64}})
			result.AddHop(h)

			if callback != nil {
				callback(h)
			}

			result.ReachedTarget = true
			return result, nil
		},
	}

	ct := NewContinuousTracer(cfg, mockTracer, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	probeCallback := func(pr ProbeResult) {
		mu.Lock()
		results = append(results, pr)
		mu.Unlock()
	}

	ct.Run(ctx, targetIP, probeCallback, func(int, bool) {})

	mu.Lock()
	defer mu.Unlock()

	if len(results) < 1 {
		t.Fatal("expected at least 1 probe result")
	}

	pr := results[0]
	if pr.TTL != 1 {
		t.Errorf("expected TTL 1, got %d", pr.TTL)
	}
	if !pr.IP.Equal(hopIP) {
		t.Errorf("expected IP %v, got %v", hopIP, pr.IP)
	}
	if pr.RTT != 10*time.Millisecond {
		t.Errorf("expected RTT 10ms, got %v", pr.RTT)
	}
	if pr.Timeout {
		t.Error("expected Timeout false")
	}
	if len(pr.MPLS) != 1 {
		t.Errorf("expected 1 MPLS label, got %d", len(pr.MPLS))
	}
}

func TestContinuousTracer_Run_TimeoutProbe(t *testing.T) {
	cfg := DefaultConfig()

	var results []ProbeResult
	var mu sync.Mutex

	mockTracer := &mockContinuousTracer{
		traceFn: func(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
			result := hop.NewTraceResult(target.String(), target.String())

			h := hop.NewHop(1)
			h.AddTimeout() // Timeout probe
			result.AddHop(h)

			if callback != nil {
				callback(h)
			}

			return result, nil
		},
	}

	ct := NewContinuousTracer(cfg, mockTracer, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	probeCallback := func(pr ProbeResult) {
		mu.Lock()
		results = append(results, pr)
		mu.Unlock()
	}

	ct.Run(ctx, net.ParseIP("8.8.8.8"), probeCallback, func(int, bool) {})

	mu.Lock()
	defer mu.Unlock()

	if len(results) < 1 {
		t.Fatal("expected at least 1 probe result")
	}

	pr := results[0]
	if !pr.Timeout {
		t.Error("expected Timeout true for timeout probe")
	}
	if pr.IP != nil {
		t.Error("expected nil IP for timeout probe")
	}
}
