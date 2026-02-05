package trace

import (
	"testing"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestParseMPLSExtensions_ParsesSingleLabel(t *testing.T) {
	// MPLS Label extension structure (RFC 4950):
	// - 4 bytes: Extension header (version, reserved, checksum)
	// - 4 bytes: Object header (length, class-num, c-type)
	// - 4 bytes per label: label(20) | exp(3) | S(1) | TTL(8)

	// Create a test extension with label 24015, exp=0, S=1, TTL=1
	// MPLS label entry format:
	//   bits 31-12: label (20 bits)
	//   bits 11-9:  exp (3 bits)
	//   bit 8:      S (bottom of stack)
	//   bits 7-0:   TTL (8 bits)
	// For label=24015 (0x5DCF): 24015 << 12 = 0x05DCF000
	// Add S=1: 0x05DCF000 | 0x100 = 0x05DCF100
	// Add TTL=1: 0x05DCF100 | 0x01 = 0x05DCF101
	// Bytes: 0x05, 0xDC, 0xF1, 0x01
	ext := []byte{
		// Extension header
		0x20, 0x00, 0x00, 0x00, // version 2, reserved, checksum placeholder
		// Object header
		0x00, 0x08, // length = 8 (header + 1 label)
		0x01,       // class-num = 1 (MPLS)
		0x01,       // c-type = 1
		// MPLS label stack entry: label=24015, exp=0, S=1, TTL=1
		0x05, 0xDC, 0xF1, 0x01,
	}

	labels := ParseMPLSExtensions(ext)

	if len(labels) != 1 {
		t.Fatalf("expected 1 label, got %d", len(labels))
	}
	if labels[0].Label != 24015 {
		t.Errorf("expected label 24015, got %d", labels[0].Label)
	}
	if labels[0].Exp != 0 {
		t.Errorf("expected exp 0, got %d", labels[0].Exp)
	}
	if !labels[0].S {
		t.Error("expected S bit to be set")
	}
	if labels[0].TTL != 1 {
		t.Errorf("expected TTL 1, got %d", labels[0].TTL)
	}
}

func TestParseMPLSExtensions_ParsesLabelStack(t *testing.T) {
	// Two labels in stack
	ext := []byte{
		// Extension header
		0x20, 0x00, 0x00, 0x00,
		// Object header
		0x00, 0x0C, // length = 12 (header + 2 labels)
		0x01,       // class-num = 1 (MPLS)
		0x01,       // c-type = 1
		// First label: 100, exp=2, S=0, TTL=64
		0x00, 0x06, 0x44, 0x40, // label=100, exp=2, S=0, TTL=64
		// Second label: 200, exp=0, S=1, TTL=63
		0x00, 0x0C, 0x81, 0x3F, // label=200, exp=0, S=1, TTL=63
	}

	labels := ParseMPLSExtensions(ext)

	if len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(labels))
	}

	if labels[0].Label != 100 {
		t.Errorf("expected first label 100, got %d", labels[0].Label)
	}
	if labels[0].S {
		t.Error("expected first label S bit to be 0")
	}

	if labels[1].Label != 200 {
		t.Errorf("expected second label 200, got %d", labels[1].Label)
	}
	if !labels[1].S {
		t.Error("expected second label S bit to be 1")
	}
}

func TestParseMPLSExtensions_ReturnsEmptyForNonMPLS(t *testing.T) {
	// Extension with non-MPLS class
	ext := []byte{
		0x20, 0x00, 0x00, 0x00,
		0x00, 0x08,
		0x02, // class-num = 2 (not MPLS)
		0x01,
		0x00, 0x00, 0x00, 0x00,
	}

	labels := ParseMPLSExtensions(ext)

	if len(labels) != 0 {
		t.Errorf("expected 0 labels for non-MPLS, got %d", len(labels))
	}
}

func TestParseMPLSExtensions_ReturnsEmptyForTooShort(t *testing.T) {
	// Too short to contain valid extension
	ext := []byte{0x20, 0x00, 0x00}

	labels := ParseMPLSExtensions(ext)

	if len(labels) != 0 {
		t.Errorf("expected 0 labels for short data, got %d", len(labels))
	}
}

func TestParseMPLSExtensions_ReturnsEmptyForNil(t *testing.T) {
	labels := ParseMPLSExtensions(nil)

	if len(labels) != 0 {
		t.Errorf("expected 0 labels for nil, got %d", len(labels))
	}
}

func TestParseMPLSLabelEntry_ParsesCorrectly(t *testing.T) {
	// Label 16, exp=7, S=1, TTL=255
	// 16 = 0x10 in 20 bits
	// Full: 0x10 << 12 | 7 << 9 | 1 << 8 | 255 = 0x00010FFF
	entry := []byte{0x00, 0x01, 0x0F, 0xFF}

	label := ParseMPLSLabelEntry(entry)

	if label.Label != 16 {
		t.Errorf("expected label 16, got %d", label.Label)
	}
	if label.Exp != 7 {
		t.Errorf("expected exp 7, got %d", label.Exp)
	}
	if !label.S {
		t.Error("expected S bit to be set")
	}
	if label.TTL != 255 {
		t.Errorf("expected TTL 255, got %d", label.TTL)
	}
}

func TestMPLSLabel_String_FormatsCorrectly(t *testing.T) {
	label := hop.MPLSLabel{
		Label: 24015,
		Exp:   0,
		S:     true,
		TTL:   1,
	}

	result := label.String()
	expected := "L=24015 E=0 S=1 TTL=1"

	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}
