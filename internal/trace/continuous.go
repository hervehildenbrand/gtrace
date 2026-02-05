package trace

import (
	"context"
	"net"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// ProbeResult represents a single probe result for continuous tracing.
type ProbeResult struct {
	TTL     int
	IP      net.IP
	RTT     time.Duration
	Timeout bool
	MPLS    []hop.MPLSLabel
}

// ProbeCallback is called for each probe result.
type ProbeCallback func(ProbeResult)

// CycleCallback is called when a trace cycle completes.
type CycleCallback func(cycle int, reached bool)

// ContinuousTracer runs traces continuously in a loop.
type ContinuousTracer struct {
	config   *Config
	tracer   Tracer
	interval time.Duration
}

// NewContinuousTracer creates a new continuous tracer.
func NewContinuousTracer(cfg *Config, tracer Tracer, interval time.Duration) *ContinuousTracer {
	return &ContinuousTracer{
		config:   cfg,
		tracer:   tracer,
		interval: interval,
	}
}

// Run executes continuous traces to the target.
// It calls probeCallback for each probe result and cycleCallback when each cycle completes.
// The function returns when the context is cancelled.
func (ct *ContinuousTracer) Run(ctx context.Context, target net.IP, probeCallback ProbeCallback, cycleCallback CycleCallback) error {
	cycle := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cycle++
		cycleStart := time.Now()

		// Run a single trace
		result, err := ct.tracer.Trace(ctx, target, func(h *hop.Hop) {
			// Convert hop probes to ProbeResults
			for _, p := range h.Probes {
				pr := ProbeResult{
					TTL:     h.TTL,
					IP:      p.IP,
					RTT:     p.RTT,
					Timeout: p.Timeout,
					MPLS:    h.MPLS,
				}
				if probeCallback != nil {
					probeCallback(pr)
				}
			}
		})

		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Log error but continue with next cycle
			continue
		}

		// Notify cycle complete
		reached := result != nil && result.ReachedTarget
		if cycleCallback != nil {
			cycleCallback(cycle, reached)
		}

		// Wait for next cycle interval
		elapsed := time.Since(cycleStart)
		if elapsed < ct.interval {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(ct.interval - elapsed):
			}
		}
	}
}
