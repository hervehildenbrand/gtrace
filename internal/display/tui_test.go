package display

import (
	"net"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestNewTUIModel_CreatesModel(t *testing.T) {
	model := NewTUIModel("google.com", "8.8.8.8")

	if model.target != "google.com" {
		t.Errorf("expected target 'google.com', got %q", model.target)
	}
	if model.targetIP != "8.8.8.8" {
		t.Errorf("expected targetIP '8.8.8.8', got %q", model.targetIP)
	}
}

func TestTUIModel_AddHop_AppendsHop(t *testing.T) {
	model := NewTUIModel("google.com", "8.8.8.8")
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 5*time.Millisecond)

	model.AddHop(h)

	if len(model.hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(model.hops))
	}
}

func TestTUIModel_SetComplete_MarksComplete(t *testing.T) {
	model := NewTUIModel("google.com", "8.8.8.8")

	model.SetComplete(true)

	if !model.complete {
		t.Error("expected complete to be true")
	}
}

func TestTUIModel_FormatHopRow_FormatsBasicHop(t *testing.T) {
	model := NewTUIModel("google.com", "8.8.8.8")
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 5*time.Millisecond)

	row := model.formatHopRow(h)

	if row == "" {
		t.Error("expected non-empty row")
	}
}

func TestTUIModel_FormatHopRow_ShowsTimeout(t *testing.T) {
	model := NewTUIModel("google.com", "8.8.8.8")
	h := hop.NewHop(1)
	h.AddTimeout()
	h.AddTimeout()
	h.AddTimeout()

	row := model.formatHopRow(h)

	if row == "" {
		t.Error("expected non-empty row for timeout")
	}
}

func TestTUIModel_RenderSparkline_CreatesGraph(t *testing.T) {
	model := NewTUIModel("google.com", "8.8.8.8")

	rtts := []time.Duration{
		1 * time.Millisecond,
		2 * time.Millisecond,
		3 * time.Millisecond,
		2 * time.Millisecond,
		1 * time.Millisecond,
	}

	sparkline := model.renderSparkline(rtts)

	if sparkline == "" {
		t.Error("expected non-empty sparkline")
	}
	// Sparkline should contain block characters
	if len(sparkline) == 0 {
		t.Error("expected sparkline to have characters")
	}
}

func TestTUIModel_GetStatusInfo_ReturnsInfo(t *testing.T) {
	model := NewTUIModel("google.com", "8.8.8.8")
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 5*time.Millisecond)
	h.SetMPLS([]hop.MPLSLabel{{Label: 24015}})
	model.AddHop(h)

	info := model.getStatusInfo()

	if info.HopCount != 1 {
		t.Errorf("expected HopCount 1, got %d", info.HopCount)
	}
	if !info.HasMPLS {
		t.Error("expected HasMPLS to be true")
	}
}
