package display

import (
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestSplitMTRModel_Init(t *testing.T) {
	targets := []string{"google.com", "cloudflare.com"}
	targetIPs := []string{"142.250.80.46", "1.1.1.1"}

	model := NewSplitMTRModel(targets, targetIPs)

	if len(model.models) != 2 {
		t.Errorf("expected 2 sub-models, got %d", len(model.models))
	}
	if model.models[0].target != "google.com" {
		t.Errorf("expected first target 'google.com', got %q", model.models[0].target)
	}
	if model.models[1].target != "cloudflare.com" {
		t.Errorf("expected second target 'cloudflare.com', got %q", model.models[1].target)
	}
}

func TestSplitMTRModel_ProbeRoutesToCorrectTarget(t *testing.T) {
	targets := []string{"target-a", "target-b"}
	targetIPs := []string{"1.1.1.1", "8.8.8.8"}

	model := NewSplitMTRModel(targets, targetIPs)

	// Send probe to target 0
	msg := MultiProbeResultMsg{
		TargetIndex: 0,
		Probe: ProbeResultMsg{
			TTL: 1,
			IP:  net.ParseIP("192.168.1.1"),
			RTT: 1 * time.Millisecond,
		},
	}
	updated, _ := model.Update(msg)
	model = updated.(*SplitMTRModel)

	// Target 0 should have stats, target 1 should not
	stats0 := model.models[0].stats
	stats1 := model.models[1].stats

	if len(stats0) != 1 {
		t.Errorf("expected 1 hop stat for target 0, got %d", len(stats0))
	}
	if len(stats1) != 0 {
		t.Errorf("expected 0 hop stats for target 1, got %d", len(stats1))
	}
}

func TestSplitMTRModel_CycleRoutesToCorrectTarget(t *testing.T) {
	targets := []string{"target-a", "target-b"}
	targetIPs := []string{"1.1.1.1", "8.8.8.8"}

	model := NewSplitMTRModel(targets, targetIPs)

	msg := MultiCycleCompleteMsg{
		TargetIndex: 1,
		Cycle:       5,
		Reached:     true,
	}
	updated, _ := model.Update(msg)
	model = updated.(*SplitMTRModel)

	if model.models[1].cycles != 5 {
		t.Errorf("expected target 1 cycles=5, got %d", model.models[1].cycles)
	}
	if model.models[0].cycles != 0 {
		t.Errorf("expected target 0 cycles=0, got %d", model.models[0].cycles)
	}
}

func TestSplitMTRModel_QuitKey(t *testing.T) {
	model := NewSplitMTRModel([]string{"a"}, []string{"1.1.1.1"})

	_, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	if cmd == nil {
		t.Error("expected quit command from 'q' key")
	}
}

func TestSplitMTRModel_ViewContainsBothTargets(t *testing.T) {
	targets := []string{"alpha.com", "beta.com"}
	targetIPs := []string{"10.0.0.1", "10.0.0.2"}

	model := NewSplitMTRModel(targets, targetIPs)
	model.width = 120
	model.height = 40

	view := model.View()

	if !strings.Contains(view, "alpha.com") {
		t.Error("view should contain first target name")
	}
	if !strings.Contains(view, "beta.com") {
		t.Error("view should contain second target name")
	}
}

func TestSplitMTRModel_PauseToggle(t *testing.T) {
	model := NewSplitMTRModel([]string{"a", "b"}, []string{"1.1.1.1", "2.2.2.2"})

	// Press 'p' to pause all
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	model = updated.(*SplitMTRModel)

	for i, m := range model.models {
		if !m.paused {
			t.Errorf("target %d should be paused", i)
		}
	}

	// Press 'p' again to unpause
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	model = updated.(*SplitMTRModel)

	for i, m := range model.models {
		if m.paused {
			t.Errorf("target %d should be unpaused", i)
		}
	}
}

func TestSplitMTRModel_ResetAll(t *testing.T) {
	model := NewSplitMTRModel([]string{"a"}, []string{"1.1.1.1"})

	// Add some data
	model.models[0].handleProbeResult(ProbeResultMsg{
		TTL: 1,
		IP:  net.ParseIP("192.168.1.1"),
		RTT: 1 * time.Millisecond,
		MPLS: []hop.MPLSLabel{},
	})

	if len(model.models[0].stats) != 1 {
		t.Fatal("expected stats before reset")
	}

	// Press 'r' to reset
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	model = updated.(*SplitMTRModel)

	if len(model.models[0].stats) != 0 {
		t.Error("expected stats cleared after reset")
	}
}
