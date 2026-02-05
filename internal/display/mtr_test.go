package display

import (
	"net"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestNewMTRModel(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	if model.target != "google.com" {
		t.Errorf("expected target 'google.com', got %s", model.target)
	}
	if model.targetIP != "8.8.8.8" {
		t.Errorf("expected targetIP '8.8.8.8', got %s", model.targetIP)
	}
	if model.running != true {
		t.Errorf("expected running true, got false")
	}
	if model.paused != false {
		t.Errorf("expected paused false, got true")
	}
	if model.cycles != 0 {
		t.Errorf("expected cycles 0, got %d", model.cycles)
	}
}

func TestMTRModel_ProbeResultMsg_NewHop(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("192.168.1.1")

	msg := ProbeResultMsg{
		TTL:     1,
		IP:      ip,
		RTT:     10 * time.Millisecond,
		Timeout: false,
	}

	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	if len(m.stats) != 1 {
		t.Fatalf("expected 1 stats entry, got %d", len(m.stats))
	}

	stats := m.stats[1]
	if stats == nil {
		t.Fatal("expected stats for TTL 1")
	}
	if stats.Sent != 1 {
		t.Errorf("expected Sent 1, got %d", stats.Sent)
	}
	if stats.Recv != 1 {
		t.Errorf("expected Recv 1, got %d", stats.Recv)
	}
}

func TestMTRModel_ProbeResultMsg_Timeout(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	msg := ProbeResultMsg{
		TTL:     1,
		Timeout: true,
	}

	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	stats := m.stats[1]
	if stats.Sent != 1 {
		t.Errorf("expected Sent 1, got %d", stats.Sent)
	}
	if stats.Recv != 0 {
		t.Errorf("expected Recv 0, got %d", stats.Recv)
	}
}

func TestMTRModel_ProbeResultMsg_WithMPLS(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("192.168.1.1")

	labels := []hop.MPLSLabel{
		{Label: 100, Exp: 0, S: true, TTL: 64},
	}

	msg := ProbeResultMsg{
		TTL:     1,
		IP:      ip,
		RTT:     10 * time.Millisecond,
		Timeout: false,
		MPLS:    labels,
	}

	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	stats := m.stats[1]
	if len(stats.MPLS) != 1 {
		t.Errorf("expected 1 MPLS label, got %d", len(stats.MPLS))
	}
}

func TestMTRModel_ProbeResultMsg_WithEnrichment(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("192.168.1.1")

	enrichment := hop.Enrichment{
		ASN:      12345,
		ASOrg:    "Test Org",
		Hostname: "router.test.com",
	}

	msg := ProbeResultMsg{
		TTL:        1,
		IP:         ip,
		RTT:        10 * time.Millisecond,
		Timeout:    false,
		Enrichment: enrichment,
	}

	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	stats := m.stats[1]
	if stats.Enrichment.ASN != 12345 {
		t.Errorf("expected ASN 12345, got %d", stats.Enrichment.ASN)
	}
}

func TestMTRModel_CycleCompleteMsg(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	msg := CycleCompleteMsg{Cycle: 1, Reached: true}
	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	if m.cycles != 1 {
		t.Errorf("expected cycles 1, got %d", m.cycles)
	}
}

func TestMTRModel_KeyMsg_Quit(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	_, cmd := model.Update(msg)

	// Should return tea.Quit
	if cmd == nil {
		t.Error("expected tea.Quit command, got nil")
	}
}

func TestMTRModel_KeyMsg_Pause(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}}
	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	if !m.paused {
		t.Error("expected paused true after 'p' key")
	}

	// Press again to unpause
	newModel, _ = m.Update(msg)
	m = newModel.(*MTRModel)

	if m.paused {
		t.Error("expected paused false after second 'p' key")
	}
}

func TestMTRModel_KeyMsg_Reset(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("192.168.1.1")

	// Add some data
	probeMsg := ProbeResultMsg{TTL: 1, IP: ip, RTT: 10 * time.Millisecond}
	newModel, _ := model.Update(probeMsg)
	cycleMsg := CycleCompleteMsg{Cycle: 1, Reached: false}
	newModel, _ = newModel.Update(cycleMsg)
	m := newModel.(*MTRModel)

	// Press 'r' to reset
	resetMsg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}}
	newModel, _ = m.Update(resetMsg)
	m = newModel.(*MTRModel)

	if m.cycles != 0 {
		t.Errorf("expected cycles 0 after reset, got %d", m.cycles)
	}
	if len(m.stats) != 0 {
		t.Errorf("expected empty stats after reset, got %d", len(m.stats))
	}
}

func TestMTRModel_View_Header(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	view := model.View()

	// Check that view contains key elements
	if len(view) == 0 {
		t.Error("expected non-empty view")
	}
}

func TestMTRModel_GetStats(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("192.168.1.1")

	// Add probes for TTL 1, 2, 3
	var m tea.Model = model
	for ttl := 1; ttl <= 3; ttl++ {
		msg := ProbeResultMsg{TTL: ttl, IP: ip, RTT: time.Duration(ttl) * 10 * time.Millisecond}
		m, _ = m.Update(msg)
	}

	mtr := m.(*MTRModel)
	orderedStats := mtr.GetOrderedStats()

	if len(orderedStats) != 3 {
		t.Fatalf("expected 3 ordered stats, got %d", len(orderedStats))
	}

	// Should be ordered by TTL
	for i, stats := range orderedStats {
		expectedTTL := i + 1
		if stats.TTL != expectedTTL {
			t.Errorf("expected TTL %d at index %d, got %d", expectedTTL, i, stats.TTL)
		}
	}
}

func TestMTRModel_MaxTTL(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("192.168.1.1")

	// Add probes for TTL 1, 5, 3 (out of order)
	var m tea.Model = model
	for _, ttl := range []int{1, 5, 3} {
		msg := ProbeResultMsg{TTL: ttl, IP: ip, RTT: 10 * time.Millisecond}
		m, _ = m.Update(msg)
	}

	mtr := m.(*MTRModel)
	if mtr.maxTTL != 5 {
		t.Errorf("expected maxTTL 5, got %d", mtr.maxTTL)
	}
}
