package export

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// TextExporter exports trace results to human-readable text format.
type TextExporter struct{}

// NewTextExporter creates a new text exporter.
func NewTextExporter() *TextExporter {
	return &TextExporter{}
}

// Export writes the trace result as text to the writer.
func (e *TextExporter) Export(w io.Writer, tr *hop.TraceResult) error {
	// Header
	fmt.Fprintf(w, "Traceroute to %s (%s)\n", tr.Target, tr.TargetIP)
	fmt.Fprintf(w, "Protocol: %s\n", tr.Protocol)
	if tr.Source != "" {
		fmt.Fprintf(w, "Source: %s\n", tr.Source)
	}
	fmt.Fprintln(w, strings.Repeat("=", 70))
	fmt.Fprintln(w)

	// Hops
	for _, h := range tr.Hops {
		e.writeHop(w, h)
	}

	// Summary
	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("=", 70))
	if tr.ReachedTarget {
		fmt.Fprintf(w, "Target reached in %d hops\n", tr.TotalHops())
	} else {
		fmt.Fprintf(w, "Target not reached (%d hops)\n", tr.TotalHops())
	}
	if !tr.StartTime.IsZero() && !tr.EndTime.IsZero() {
		fmt.Fprintf(w, "Duration: %v\n", tr.EndTime.Sub(tr.StartTime).Round(time.Millisecond))
	}

	return nil
}

func (e *TextExporter) writeHop(w io.Writer, h *hop.Hop) {
	ip := h.PrimaryIP()
	if ip == nil {
		fmt.Fprintf(w, "%2d  * * * (no response)\n", h.TTL)
		return
	}

	// IP and hostname
	line := fmt.Sprintf("%2d  %s", h.TTL, ip.String())
	if h.Enrichment.Hostname != "" {
		line += fmt.Sprintf(" (%s)", h.Enrichment.Hostname)
	}

	// ASN info
	if h.Enrichment.ASN > 0 {
		line += fmt.Sprintf(" [AS%d %s]", h.Enrichment.ASN, h.Enrichment.ASOrg)
	}

	fmt.Fprintln(w, line)

	// Timings
	var timings []string
	for _, p := range h.Probes {
		if p.Timeout {
			timings = append(timings, "*")
		} else {
			ms := float64(p.RTT) / float64(time.Millisecond)
			timings = append(timings, fmt.Sprintf("%.2fms", ms))
		}
	}
	fmt.Fprintf(w, "    RTT: %s (avg: %.2fms, loss: %.1f%%)\n",
		strings.Join(timings, " "),
		float64(h.AvgRTT())/float64(time.Millisecond),
		h.LossPercent())

	// MPLS labels
	for _, m := range h.MPLS {
		fmt.Fprintf(w, "    MPLS: %s\n", m.String())
	}

	// Geo info
	if h.Enrichment.City != "" || h.Enrichment.Country != "" {
		geo := []string{}
		if h.Enrichment.City != "" {
			geo = append(geo, h.Enrichment.City)
		}
		if h.Enrichment.Country != "" {
			geo = append(geo, h.Enrichment.Country)
		}
		fmt.Fprintf(w, "    Geo: %s\n", strings.Join(geo, ", "))
	}
}
