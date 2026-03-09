package trace

import (
	"context"
	"net"
	"sync"
	"time"
)

// MultiProbeCallback is called for each probe result with the target index.
type MultiProbeCallback func(targetIndex int, pr ProbeResult)

// MultiCycleCallback is called when a trace cycle completes for a target.
type MultiCycleCallback func(targetIndex int, cycle int, reached bool)

// MultiContinuousTracer runs continuous traces to multiple targets in parallel.
type MultiContinuousTracer struct {
	config   *Config
	tracers  []Tracer
	targets  []net.IP
	interval time.Duration
}

// NewMultiContinuousTracer creates a new multi-target continuous tracer.
func NewMultiContinuousTracer(cfg *Config, tracers []Tracer, targets []net.IP, interval time.Duration) *MultiContinuousTracer {
	return &MultiContinuousTracer{
		config:   cfg,
		tracers:  tracers,
		targets:  targets,
		interval: interval,
	}
}

// Run executes continuous traces to all targets in parallel.
// It blocks until the context is cancelled.
func (mct *MultiContinuousTracer) Run(ctx context.Context, probeCallback MultiProbeCallback, cycleCallback MultiCycleCallback) {
	var wg sync.WaitGroup

	for i := range mct.targets {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ct := NewContinuousTracer(mct.config, mct.tracers[idx], mct.interval)

			pcb := func(pr ProbeResult) {
				if probeCallback != nil {
					probeCallback(idx, pr)
				}
			}

			ccb := func(cycle int, reached bool) {
				if cycleCallback != nil {
					cycleCallback(idx, cycle, reached)
				}
			}

			ct.Run(ctx, mct.targets[idx], pcb, ccb)
		}(i)
	}

	wg.Wait()
}
