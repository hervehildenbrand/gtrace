package export

import (
	"testing"
)

func TestNewExporter_TxtAlias(t *testing.T) {
	exp, err := NewExporter("txt")
	if err != nil {
		t.Fatalf("NewExporter(\"txt\") returned error: %v", err)
	}
	if exp == nil {
		t.Error("expected non-nil exporter for 'txt' format")
	}
}

func TestNewExporter_TextFormat(t *testing.T) {
	exp, err := NewExporter(FormatText)
	if err != nil {
		t.Fatalf("NewExporter(FormatText) returned error: %v", err)
	}
	if exp == nil {
		t.Error("expected non-nil exporter for 'text' format")
	}
}

func TestNewExporter_UnsupportedFormat(t *testing.T) {
	_, err := NewExporter("invalid")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestDetectFormat_TxtExtension(t *testing.T) {
	f := DetectFormat("output.txt")
	if f != FormatText {
		t.Errorf("expected FormatText for .txt extension, got %q", f)
	}
}
