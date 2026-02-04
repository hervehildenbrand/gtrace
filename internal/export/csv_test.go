package export

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

func TestCSVExporter_Export_ProducesValidCSV(t *testing.T) {
	tr := createTestTrace()
	exporter := NewCSVExporter()

	var buf bytes.Buffer
	err := exporter.Export(&buf, tr)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid CSV
	reader := csv.NewReader(strings.NewReader(buf.String()))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v", err)
	}
	if len(records) < 2 {
		t.Error("expected at least 2 rows (header + data)")
	}
}

func TestCSVExporter_Export_IncludesHeader(t *testing.T) {
	tr := createTestTrace()
	exporter := NewCSVExporter()

	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	lines := strings.Split(buf.String(), "\n")
	header := lines[0]

	expectedColumns := []string{"ttl", "ip", "hostname", "asn", "as_org", "country", "city", "avg_rtt_ms", "loss_percent"}
	for _, col := range expectedColumns {
		if !strings.Contains(header, col) {
			t.Errorf("expected header to contain %q", col)
		}
	}
}

func TestCSVExporter_Export_IncludesHopData(t *testing.T) {
	tr := createTestTrace()
	exporter := NewCSVExporter()

	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	reader := csv.NewReader(strings.NewReader(buf.String()))
	records, _ := reader.ReadAll()

	// Header + 2 hops
	if len(records) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(records))
	}

	// Check first data row (hop 1)
	row1 := records[1]
	if row1[0] != "1" {
		t.Errorf("expected TTL 1, got %q", row1[0])
	}
	if row1[1] != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %q", row1[1])
	}
}

func TestCSVExporter_Export_HandlesTimeouts(t *testing.T) {
	tr := createTestTrace()
	exporter := NewCSVExporter()

	var buf bytes.Buffer
	_ = exporter.Export(&buf, tr)

	// Hop 2 has a timeout, so loss should be > 0
	if !strings.Contains(buf.String(), "33.") { // 1/3 = 33.33%
		t.Error("expected loss percentage to be shown")
	}
}
