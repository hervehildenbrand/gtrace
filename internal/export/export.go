package export

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// Exporter is the interface for trace result exporters.
type Exporter interface {
	Export(w io.Writer, tr *hop.TraceResult) error
}

// Format represents an export format.
type Format string

const (
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
	FormatText Format = "text"
)

// DetectFormat determines the export format from a filename.
func DetectFormat(filename string) Format {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".json":
		return FormatJSON
	case ".csv":
		return FormatCSV
	case ".txt", ".text":
		return FormatText
	default:
		return FormatJSON // Default to JSON
	}
}

// NewExporter creates an exporter for the given format.
func NewExporter(format Format) (Exporter, error) {
	switch format {
	case FormatJSON:
		return NewJSONExporter(), nil
	case FormatCSV:
		return NewCSVExporter(), nil
	case FormatText, "txt":
		return NewTextExporter(), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// ExportToFile exports a trace result to a file.
func ExportToFile(filename string, format Format, tr *hop.TraceResult) error {
	if format == "" {
		format = DetectFormat(filename)
	}

	exporter, err := NewExporter(format)
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if err := exporter.Export(f, tr); err != nil {
		return fmt.Errorf("failed to export: %w", err)
	}

	return nil
}
