// Package monitor provides continuous traceroute monitoring with change detection.
package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// ChangeType represents the type of change detected.
type ChangeType string

const (
	ChangeTypeRoute   ChangeType = "route"
	ChangeTypeLatency ChangeType = "latency"
	ChangeTypeLoss    ChangeType = "loss"
	ChangeTypeMPLS    ChangeType = "mpls"
	ChangeTypeASN     ChangeType = "asn"
)

// Change represents a detected change between traces.
type Change struct {
	Type      ChangeType
	Hop       int
	Message   string
	Timestamp time.Time
	OldValue  interface{}
	NewValue  interface{}
}

// String formats the change for display.
func (c Change) String() string {
	return fmt.Sprintf("[%s] Hop %d: %s", c.Type, c.Hop, c.Message)
}

// Config holds monitoring configuration.
type Config struct {
	Interval         time.Duration // Time between traces
	LatencyThreshold time.Duration // Alert if latency exceeds this
	LossThreshold    float64       // Alert if loss % exceeds this
	AlertOnRoute     bool          // Alert on route changes
	AlertOnMPLS      bool          // Alert on MPLS changes
	AlertOnASN       bool          // Alert on AS path changes
}

// DefaultConfig returns the default monitoring configuration.
func DefaultConfig() *Config {
	return &Config{
		Interval:     10 * time.Second,
		AlertOnRoute: true,
		AlertOnMPLS:  true,
		AlertOnASN:   true,
	}
}

// ChangeCallback is called when changes are detected.
type ChangeCallback func([]Change)

// Monitor performs continuous traceroute monitoring.
type Monitor struct {
	config   *Config
	callback ChangeCallback
	previous *hop.TraceResult
}

// NewMonitor creates a new monitor with the given configuration.
func NewMonitor(cfg *Config) *Monitor {
	return &Monitor{
		config: cfg,
	}
}

// SetCallback sets the callback for change notifications.
func (m *Monitor) SetCallback(cb ChangeCallback) {
	m.callback = cb
}

// DetectChanges compares two traces and returns detected changes.
func (m *Monitor) DetectChanges(prev, curr *hop.TraceResult) []Change {
	if prev == nil {
		return nil
	}

	var changes []Change

	// Compare hops
	maxHops := len(prev.Hops)
	if len(curr.Hops) > maxHops {
		maxHops = len(curr.Hops)
	}

	for i := 0; i < maxHops; i++ {
		var prevHop, currHop *hop.Hop

		if i < len(prev.Hops) {
			prevHop = prev.Hops[i]
		}
		if i < len(curr.Hops) {
			currHop = curr.Hops[i]
		}

		hopChanges := m.compareHops(i+1, prevHop, currHop)
		changes = append(changes, hopChanges...)
	}

	return changes
}

// compareHops compares two hops and returns changes.
func (m *Monitor) compareHops(hopNum int, prev, curr *hop.Hop) []Change {
	var changes []Change

	// New hop appeared
	if prev == nil && curr != nil {
		changes = append(changes, Change{
			Type:      ChangeTypeRoute,
			Hop:       hopNum,
			Message:   fmt.Sprintf("New hop appeared: %s", formatIP(curr.PrimaryIP())),
			Timestamp: time.Now(),
		})
		return changes
	}

	// Hop disappeared
	if prev != nil && curr == nil {
		changes = append(changes, Change{
			Type:      ChangeTypeRoute,
			Hop:       hopNum,
			Message:   fmt.Sprintf("Hop disappeared: %s", formatIP(prev.PrimaryIP())),
			Timestamp: time.Now(),
		})
		return changes
	}

	if prev == nil || curr == nil {
		return changes
	}

	// Route change (IP changed)
	if m.config.AlertOnRoute {
		prevIP := prev.PrimaryIP()
		currIP := curr.PrimaryIP()
		if prevIP != nil && currIP != nil && !prevIP.Equal(currIP) {
			changes = append(changes, Change{
				Type:      ChangeTypeRoute,
				Hop:       hopNum,
				Message:   fmt.Sprintf("IP changed from %s to %s", prevIP, currIP),
				Timestamp: time.Now(),
				OldValue:  prevIP.String(),
				NewValue:  currIP.String(),
			})
		}
	}

	// Latency change
	if m.config.LatencyThreshold > 0 {
		prevRTT := prev.AvgRTT()
		currRTT := curr.AvgRTT()
		if currRTT > m.config.LatencyThreshold && currRTT > prevRTT {
			changes = append(changes, Change{
				Type:      ChangeTypeLatency,
				Hop:       hopNum,
				Message:   fmt.Sprintf("Latency increased from %.1fms to %.1fms (threshold: %.1fms)", msec(prevRTT), msec(currRTT), msec(m.config.LatencyThreshold)),
				Timestamp: time.Now(),
				OldValue:  prevRTT,
				NewValue:  currRTT,
			})
		}
	}

	// Loss change
	if m.config.LossThreshold > 0 {
		prevLoss := prev.LossPercent()
		currLoss := curr.LossPercent()
		if currLoss > m.config.LossThreshold && currLoss > prevLoss {
			changes = append(changes, Change{
				Type:      ChangeTypeLoss,
				Hop:       hopNum,
				Message:   fmt.Sprintf("Loss increased from %.1f%% to %.1f%% (threshold: %.1f%%)", prevLoss, currLoss, m.config.LossThreshold),
				Timestamp: time.Now(),
				OldValue:  prevLoss,
				NewValue:  currLoss,
			})
		}
	}

	// MPLS change
	if m.config.AlertOnMPLS {
		if !mplsEqual(prev.MPLS, curr.MPLS) {
			changes = append(changes, Change{
				Type:      ChangeTypeMPLS,
				Hop:       hopNum,
				Message:   "MPLS label stack changed",
				Timestamp: time.Now(),
			})
		}
	}

	// ASN change
	if m.config.AlertOnASN {
		if prev.Enrichment.ASN != curr.Enrichment.ASN && prev.Enrichment.ASN > 0 && curr.Enrichment.ASN > 0 {
			changes = append(changes, Change{
				Type:      ChangeTypeASN,
				Hop:       hopNum,
				Message:   fmt.Sprintf("ASN changed from AS%d to AS%d", prev.Enrichment.ASN, curr.Enrichment.ASN),
				Timestamp: time.Now(),
				OldValue:  prev.Enrichment.ASN,
				NewValue:  curr.Enrichment.ASN,
			})
		}
	}

	return changes
}

// Run starts the monitoring loop.
func (m *Monitor) Run(ctx context.Context, traceFn func(context.Context) (*hop.TraceResult, error)) error {
	ticker := time.NewTicker(m.config.Interval)
	defer ticker.Stop()

	// Initial trace
	result, err := traceFn(ctx)
	if err != nil {
		return fmt.Errorf("initial trace failed: %w", err)
	}
	m.previous = result

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			result, err := traceFn(ctx)
			if err != nil {
				// Log error but continue
				continue
			}

			changes := m.DetectChanges(m.previous, result)
			if len(changes) > 0 && m.callback != nil {
				m.callback(changes)
			}

			m.previous = result
		}
	}
}

// Helper functions

func formatIP(ip interface{}) string {
	if ip == nil {
		return "*"
	}
	return fmt.Sprintf("%v", ip)
}

func msec(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func mplsEqual(a, b []hop.MPLSLabel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Label != b[i].Label || a[i].TTL != b[i].TTL {
			return false
		}
	}
	return true
}
