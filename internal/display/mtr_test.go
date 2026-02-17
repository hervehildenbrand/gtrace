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

func TestMTRModel_KeyMsg_ToggleDisplayMode(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	// Initial mode should be DisplayModeHostname
	if model.displayMode != DisplayModeHostname {
		t.Errorf("expected initial displayMode to be DisplayModeHostname, got %d", model.displayMode)
	}

	// Press 'n' to toggle to DisplayModeIP
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}}
	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	if m.displayMode != DisplayModeIP {
		t.Errorf("expected displayMode DisplayModeIP after first 'n', got %d", m.displayMode)
	}

	// Press 'n' again to toggle to DisplayModeBoth
	newModel, _ = m.Update(msg)
	m = newModel.(*MTRModel)

	if m.displayMode != DisplayModeBoth {
		t.Errorf("expected displayMode DisplayModeBoth after second 'n', got %d", m.displayMode)
	}

	// Press 'n' again to wrap back to DisplayModeHostname
	newModel, _ = m.Update(msg)
	m = newModel.(*MTRModel)

	if m.displayMode != DisplayModeHostname {
		t.Errorf("expected displayMode DisplayModeHostname after third 'n', got %d", m.displayMode)
	}
}

func TestMTRModel_IPv6Detection(t *testing.T) {
	// IPv4 target
	modelV4 := NewMTRModel("google.com", "8.8.8.8")
	if modelV4.isIPv6 {
		t.Error("expected isIPv6 false for IPv4 target")
	}
	if modelV4.getHostColumnWidth() != colHostIPv4 {
		t.Errorf("expected column width %d for IPv4, got %d", colHostIPv4, modelV4.getHostColumnWidth())
	}

	// IPv6 target
	modelV6 := NewMTRModel("google.com", "2001:4860:4860::8888")
	if !modelV6.isIPv6 {
		t.Error("expected isIPv6 true for IPv6 target")
	}
	if modelV6.getHostColumnWidth() != colHostIPv6 {
		t.Errorf("expected column width %d for IPv6, got %d", colHostIPv6, modelV6.getHostColumnWidth())
	}
}

func TestMTRModel_View_DisplayModeIndicator(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")

	// DisplayModeHostname (default) should show [DNS]
	view := model.View()
	if !containsString(view, "[DNS]") {
		t.Error("expected [DNS] indicator in view for DisplayModeHostname")
	}

	// Toggle to DisplayModeIP
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}}
	newModel, _ := model.Update(msg)
	m := newModel.(*MTRModel)

	view = m.View()
	if !containsString(view, "[IP]") {
		t.Error("expected [IP] indicator in view for DisplayModeIP")
	}

	// Toggle to DisplayModeBoth
	newModel, _ = m.Update(msg)
	m = newModel.(*MTRModel)

	view = m.View()
	if !containsString(view, "[Both]") {
		t.Error("expected [Both] indicator in view for DisplayModeBoth")
	}
}

func TestMTRModel_View_StdDevColumn(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("192.168.1.1")

	// Add varied RTT probes to generate non-zero StdDev
	var m tea.Model = model
	rtts := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		15 * time.Millisecond,
		25 * time.Millisecond,
	}
	for _, rtt := range rtts {
		msg := ProbeResultMsg{TTL: 1, IP: ip, RTT: rtt}
		m, _ = m.Update(msg)
	}

	mtr := m.(*MTRModel)
	view := mtr.View()

	// Verify the header contains the StDev column
	if !containsString(view, "StDev") {
		t.Error("expected 'StDev' column header in MTR view")
	}

	// Verify the stats row contains a non-zero StdDev value
	stats := mtr.stats[1]
	if stats == nil {
		t.Fatal("expected stats for TTL 1")
	}
	stdDev := stats.StdDev()
	if stdDev == 0 {
		t.Error("expected non-zero StdDev for varied RTTs")
	}
}

// containsString checks if a string contains a substring (helper for tests)
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestMTRModel_ECMP_Detection(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	// Two different IPs at the same TTL = ECMP
	var m tea.Model = model
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip1, RTT: 10 * time.Millisecond})
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip2, RTT: 12 * time.Millisecond})

	mtr := m.(*MTRModel)
	stats := mtr.stats[2]
	if stats == nil {
		t.Fatal("expected stats for TTL 2")
	}
	if !stats.HasECMP() {
		t.Error("expected HasECMP true for two IPs at same TTL")
	}
	if stats.UniqueIPCount() != 2 {
		t.Errorf("expected UniqueIPCount 2, got %d", stats.UniqueIPCount())
	}
}

func TestMTRModel_ECMP_StatusBar(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	var m tea.Model = model
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip1, RTT: 10 * time.Millisecond})
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip2, RTT: 12 * time.Millisecond})

	mtr := m.(*MTRModel)
	view := mtr.View()

	if !containsString(view, "ECMP") {
		t.Error("expected 'ECMP' in status bar when ECMP is detected")
	}
	if !containsString(view, "[ECMP:2]") {
		t.Error("expected '[ECMP:2]' indicator in hop row")
	}
}

func TestMTRModel_NoECMP_SingleIP(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip := net.ParseIP("10.0.0.1")

	var m tea.Model = model
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip, RTT: 10 * time.Millisecond})
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip, RTT: 12 * time.Millisecond})

	mtr := m.(*MTRModel)
	stats := mtr.stats[2]
	if stats.HasECMP() {
		t.Error("expected HasECMP false for single IP")
	}

	view := mtr.View()
	if containsString(view, "[ECMP") {
		t.Error("expected no ECMP indicator for single IP")
	}
}

func TestMTRModel_ECMP_WithEnrichment(t *testing.T) {
	model := NewMTRModel("google.com", "8.8.8.8")
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	e1 := hop.Enrichment{ASN: 100, Hostname: "router1.example.com"}
	e2 := hop.Enrichment{ASN: 200, Hostname: "router2.example.com"}

	var m tea.Model = model
	// ip1 seen 3 times, ip2 seen once — ip1 is primary
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip1, RTT: 10 * time.Millisecond, Enrichment: e1})
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip1, RTT: 11 * time.Millisecond})
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip1, RTT: 12 * time.Millisecond})
	m, _ = m.Update(ProbeResultMsg{TTL: 2, IP: ip2, RTT: 15 * time.Millisecond, Enrichment: e2})

	mtr := m.(*MTRModel)
	stats := mtr.stats[2]

	primary := stats.PrimaryIP()
	if !primary.Equal(ip1) {
		t.Errorf("expected primary IP %v, got %v", ip1, primary)
	}
	pe := stats.PrimaryEnrichment()
	if pe.ASN != 100 {
		t.Errorf("expected primary enrichment ASN 100, got %d", pe.ASN)
	}
}
