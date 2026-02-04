package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"github.com/hervehildenbrand/gtr/pkg/hop"
)

// CSVExporter exports trace results to CSV format.
type CSVExporter struct{}

// NewCSVExporter creates a new CSV exporter.
func NewCSVExporter() *CSVExporter {
	return &CSVExporter{}
}

// Export writes the trace result as CSV to the writer.
func (e *CSVExporter) Export(w io.Writer, tr *hop.TraceResult) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	header := []string{
		"ttl", "ip", "hostname", "asn", "as_org",
		"country", "city", "avg_rtt_ms", "loss_percent",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write data rows
	for _, h := range tr.Hops {
		row := e.hopToRow(h)
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	return nil
}

// hopToRow converts a hop to a CSV row.
func (e *CSVExporter) hopToRow(h *hop.Hop) []string {
	ip := ""
	if pip := h.PrimaryIP(); pip != nil {
		ip = pip.String()
	}

	asn := ""
	if h.Enrichment.ASN > 0 {
		asn = fmt.Sprintf("%d", h.Enrichment.ASN)
	}

	avgRTT := float64(h.AvgRTT()) / float64(time.Millisecond)

	return []string{
		fmt.Sprintf("%d", h.TTL),
		ip,
		h.Enrichment.Hostname,
		asn,
		h.Enrichment.ASOrg,
		h.Enrichment.Country,
		h.Enrichment.City,
		fmt.Sprintf("%.2f", avgRTT),
		fmt.Sprintf("%.2f", h.LossPercent()),
	}
}
