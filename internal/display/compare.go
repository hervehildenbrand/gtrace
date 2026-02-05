package display

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

const (
	compareColumnWidth = 35
)

// CompareRenderer renders local and remote trace results side-by-side.
type CompareRenderer struct {
	writer  io.Writer
	noColor bool
}

// NewCompareRenderer creates a new CompareRenderer.
func NewCompareRenderer(w io.Writer, noColor bool) *CompareRenderer {
	return &CompareRenderer{
		writer:  w,
		noColor: noColor,
	}
}

// Render displays local and remote traces side-by-side.
func (r *CompareRenderer) Render(local, remote *hop.TraceResult, remoteLocation string) error {
	// Header
	fmt.Fprintf(r.writer, "Comparing traces to %s\n", local.TargetIP)

	// Column headers
	localHeader := "Local"
	remoteHeader := fmt.Sprintf("%s (GlobalPing)", remoteLocation)
	fmt.Fprintf(r.writer, "%-*s  %s\n", compareColumnWidth, localHeader, remoteHeader)

	// Separator line
	separator := strings.Repeat("\u2500", compareColumnWidth)
	fmt.Fprintf(r.writer, "%s  %s\n", separator, separator)

	// Determine max hops to display
	maxHops := len(local.Hops)
	if len(remote.Hops) > maxHops {
		maxHops = len(remote.Hops)
	}

	// Render each hop row
	for i := 0; i < maxHops; i++ {
		localCol := r.formatHopColumn(local, i)
		remoteCol := r.formatHopColumn(remote, i)
		fmt.Fprintf(r.writer, "%-*s  %s\n", compareColumnWidth, localCol, remoteCol)
	}

	// Summary line
	fmt.Fprintln(r.writer)
	localSummary := r.formatSummary("Local", local)
	remoteSummary := r.formatSummary("Remote", remote)
	fmt.Fprintf(r.writer, "%-*s  %s\n", compareColumnWidth, localSummary, remoteSummary)

	return nil
}

// formatHopColumn formats a single hop for one column.
func (r *CompareRenderer) formatHopColumn(tr *hop.TraceResult, index int) string {
	if index >= len(tr.Hops) {
		return ""
	}

	h := tr.Hops[index]
	ttl := h.TTL

	// Check if all probes timed out
	allTimeout := true
	for _, p := range h.Probes {
		if !p.Timeout {
			allTimeout = false
			break
		}
	}

	if allTimeout {
		return fmt.Sprintf("%2d  * * *", ttl)
	}

	// Get primary IP and RTT
	ip := h.PrimaryIP()
	if ip == nil {
		return fmt.Sprintf("%2d  * * *", ttl)
	}

	// Use hostname if available, otherwise IP
	host := ip.String()
	if h.Enrichment.Hostname != "" {
		host = r.truncateHost(h.Enrichment.Hostname)
	}

	rtt := r.formatRTT(h.AvgRTT())
	return fmt.Sprintf("%2d  %-18s  %s", ttl, host, rtt)
}

// truncateHost truncates a hostname to fit in the column.
func (r *CompareRenderer) truncateHost(host string) string {
	const maxLen = 18
	if len(host) <= maxLen {
		return host
	}
	return host[:maxLen-3] + "..."
}

// formatRTT formats a duration as milliseconds.
func (r *CompareRenderer) formatRTT(d time.Duration) string {
	if d == 0 {
		return "*"
	}
	ms := float64(d) / float64(time.Millisecond)
	return fmt.Sprintf("%.1fms", ms)
}

// formatSummary creates a summary string for a trace result.
func (r *CompareRenderer) formatSummary(label string, tr *hop.TraceResult) string {
	hopWord := "hops"
	if tr.TotalHops() == 1 {
		hopWord = "hop"
	}

	status := "reached target"
	if !tr.ReachedTarget {
		status = "not reached"
	}

	return fmt.Sprintf("%s: %d %s, %s", label, tr.TotalHops(), hopWord, status)
}
