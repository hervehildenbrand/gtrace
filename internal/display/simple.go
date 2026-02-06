// Package display provides output rendering for traceroute results.
package display

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// SimpleRenderer renders traceroute results in traditional text format.
type SimpleRenderer struct {
	ShowASN      bool
	ShowHostname bool
}

// NewSimpleRenderer creates a new SimpleRenderer with default settings.
func NewSimpleRenderer() *SimpleRenderer {
	return &SimpleRenderer{
		ShowASN:      true,
		ShowHostname: true,
	}
}

// FormatRTT formats a duration as milliseconds.
func (r *SimpleRenderer) FormatRTT(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	return fmt.Sprintf("%.2fms", ms)
}

// RenderHop renders a single hop as a text line.
func (r *SimpleRenderer) RenderHop(h *hop.Hop) string {
	var parts []string

	// Hop number
	parts = append(parts, fmt.Sprintf("%2d", h.TTL))

	// Collect unique IPs
	ips := r.collectUniqueIPs(h)

	if len(ips) == 0 {
		// All timeouts
		rtts := r.formatProbeRTTs(h)
		parts = append(parts, rtts)
	} else {
		// Show each unique IP with its RTTs
		for i, ip := range ips {
			if i > 0 {
				// ECMP: show additional IPs on same line
				parts = append(parts, ip)
			} else {
				// First IP: include hostname if available
				ipLine := ip
				if r.ShowHostname && h.Enrichment.Hostname != "" {
					ipLine = fmt.Sprintf("%s (%s)", h.Enrichment.Hostname, ip)
				}
				parts = append(parts, ipLine)
			}
		}

		// ASN info
		if r.ShowASN && h.Enrichment.ASN > 0 {
			parts = append(parts, fmt.Sprintf("[AS%d]", h.Enrichment.ASN))
		}

		// RTTs
		rtts := r.formatProbeRTTs(h)
		parts = append(parts, rtts)

		// MPLS labels
		if len(h.MPLS) > 0 {
			for _, label := range h.MPLS {
				parts = append(parts, fmt.Sprintf("[MPLS: %s]", label.String()))
			}
		}

		// NAT indicator
		if h.NAT {
			parts = append(parts, "[NAT]")
		}

		// MTU indicator
		if h.MTU > 0 {
			parts = append(parts, fmt.Sprintf("[MTU:%d]", h.MTU))
		}
	}

	return strings.Join(parts, "  ")
}

// collectUniqueIPs returns unique IP strings from probes.
func (r *SimpleRenderer) collectUniqueIPs(h *hop.Hop) []string {
	seen := make(map[string]bool)
	var ips []string

	for _, p := range h.Probes {
		if p.IP != nil {
			ipStr := p.IP.String()
			if !seen[ipStr] {
				seen[ipStr] = true
				ips = append(ips, ipStr)
			}
		}
	}
	return ips
}

// formatProbeRTTs formats all probe RTTs as a string.
func (r *SimpleRenderer) formatProbeRTTs(h *hop.Hop) string {
	var rtts []string
	for _, p := range h.Probes {
		if p.Timeout {
			rtts = append(rtts, "*")
		} else {
			rtts = append(rtts, r.FormatRTT(p.RTT))
		}
	}
	return strings.Join(rtts, " ")
}

// RenderTrace renders a complete trace result to the writer.
func (r *SimpleRenderer) RenderTrace(w io.Writer, tr *hop.TraceResult) {
	// Header
	fmt.Fprintf(w, "traceroute to %s (%s), %d hops max\n",
		tr.Target, tr.TargetIP, 30) // TODO: make max hops configurable

	// Each hop
	for _, h := range tr.Hops {
		fmt.Fprintln(w, r.RenderHop(h))
	}
}
