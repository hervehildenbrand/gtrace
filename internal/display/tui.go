package display

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// Styles for the TUI
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("240"))

	hopStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	ipStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("39"))

	hostnameStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243"))

	rttStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82"))

	timeoutStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	asnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("208"))

	mplsStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("141"))

	statusStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("235")).
			Padding(0, 1)

	completeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")).
			Bold(true)
)

// Sparkline characters (from low to high)
var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// StatusInfo contains status bar information
type StatusInfo struct {
	HopCount  int
	HasMPLS   bool
	HasECMP   bool
	HasNAT    bool
	AvgRTT    time.Duration
	LossTotal float64
}

// HopMsg is sent when a new hop is received
type HopMsg struct {
	Hop *hop.Hop
}

// CompleteMsg is sent when the trace is complete
type CompleteMsg struct {
	Reached bool
}

// TUIModel is the Bubbletea model for the traceroute TUI
type TUIModel struct {
	mu        sync.RWMutex
	target    string
	targetIP  string
	hops      []*hop.Hop
	complete  bool
	reached   bool
	spinner   spinner.Model
	width     int
	height    int
	startTime time.Time
}

// NewTUIModel creates a new TUI model
func NewTUIModel(target, targetIP string) *TUIModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return &TUIModel{
		target:    target,
		targetIP:  targetIP,
		hops:      make([]*hop.Hop, 0),
		spinner:   s,
		startTime: time.Now(),
	}
}

// AddHop adds a hop to the model
func (m *TUIModel) AddHop(h *hop.Hop) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hops = append(m.hops, h)
}

// SetComplete marks the trace as complete
func (m *TUIModel) SetComplete(reached bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.complete = true
	m.reached = reached
}

// Init implements tea.Model
func (m *TUIModel) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update implements tea.Model
func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "e":
			// TODO: Export
		case "?":
			// TODO: Help
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case HopMsg:
		m.AddHop(msg.Hop)

	case CompleteMsg:
		m.SetComplete(msg.Reached)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View implements tea.Model
func (m *TUIModel) View() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder

	// Title
	title := fmt.Sprintf("gtr → %s (%s)", m.target, m.targetIP)
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")

	// Header
	header := fmt.Sprintf("%-4s %-16s %-20s %-8s %-6s %-8s",
		"Hop", "IP Address", "Hostname/ASN", "Loss", "Avg", "Graph")
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 70))
	b.WriteString("\n")

	// Hops
	for _, h := range m.hops {
		b.WriteString(m.formatHopRow(h))
		b.WriteString("\n")
	}

	// Status bar
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 70))
	b.WriteString("\n")
	b.WriteString(m.renderStatusBar())

	// Help
	b.WriteString("\n")
	if m.complete {
		if m.reached {
			b.WriteString(completeStyle.Render("✓ Target reached"))
		} else {
			b.WriteString(timeoutStyle.Render("✗ Target not reached"))
		}
		b.WriteString(" | Press 'q' to quit")
	} else {
		b.WriteString(m.spinner.View())
		b.WriteString(" Tracing... Press 'q' to cancel")
	}

	return b.String()
}

// formatHopRow formats a single hop row
func (m *TUIModel) formatHopRow(h *hop.Hop) string {
	var b strings.Builder

	// TTL
	b.WriteString(hopStyle.Render(fmt.Sprintf("%-4d", h.TTL)))

	// IP
	ip := h.PrimaryIP()
	if ip == nil {
		b.WriteString(timeoutStyle.Render("*"))
		b.WriteString(strings.Repeat(" ", 15))
	} else {
		ipStr := ip.String()
		if len(ipStr) > 15 {
			ipStr = ipStr[:15]
		}
		b.WriteString(ipStyle.Render(fmt.Sprintf("%-16s", ipStr)))
	}

	// Hostname/ASN
	info := ""
	if h.Enrichment.Hostname != "" {
		info = h.Enrichment.Hostname
		if len(info) > 18 {
			info = info[:15] + "..."
		}
	}
	if h.Enrichment.ASN > 0 {
		asn := fmt.Sprintf("AS%d", h.Enrichment.ASN)
		if info != "" {
			info = asn + " " + info
		} else {
			info = asn
		}
	}
	if len(info) > 20 {
		info = info[:17] + "..."
	}
	b.WriteString(hostnameStyle.Render(fmt.Sprintf("%-20s", info)))

	// Loss
	loss := h.LossPercent()
	lossStr := fmt.Sprintf("%5.1f%%", loss)
	if loss > 0 {
		b.WriteString(timeoutStyle.Render(fmt.Sprintf("%-8s", lossStr)))
	} else {
		b.WriteString(hopStyle.Render(fmt.Sprintf("%-8s", lossStr)))
	}

	// Avg RTT
	avg := h.AvgRTT()
	if avg > 0 {
		avgMs := float64(avg) / float64(time.Millisecond)
		b.WriteString(rttStyle.Render(fmt.Sprintf("%-6.1f", avgMs)))
	} else {
		b.WriteString(timeoutStyle.Render(fmt.Sprintf("%-6s", "-")))
	}

	// Sparkline
	rtts := m.collectRTTs(h)
	if len(rtts) > 0 {
		b.WriteString(" ")
		b.WriteString(m.renderSparkline(rtts))
	}

	// MPLS indicator
	if len(h.MPLS) > 0 {
		b.WriteString(" ")
		b.WriteString(mplsStyle.Render("[MPLS]"))
	}

	return b.String()
}

// collectRTTs collects RTT values from probes
func (m *TUIModel) collectRTTs(h *hop.Hop) []time.Duration {
	var rtts []time.Duration
	for _, p := range h.Probes {
		if !p.Timeout && p.RTT > 0 {
			rtts = append(rtts, p.RTT)
		}
	}
	return rtts
}

// renderSparkline renders a sparkline graph from RTT values
func (m *TUIModel) renderSparkline(rtts []time.Duration) string {
	if len(rtts) == 0 {
		return ""
	}

	// Find min/max
	minRTT, maxRTT := rtts[0], rtts[0]
	for _, rtt := range rtts {
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}

	// If all same, use middle char
	if minRTT == maxRTT {
		return strings.Repeat(string(sparkChars[3]), len(rtts))
	}

	// Scale to sparkline characters
	var b strings.Builder
	rng := float64(maxRTT - minRTT)
	for _, rtt := range rtts {
		idx := int(float64(rtt-minRTT) / rng * float64(len(sparkChars)-1))
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		b.WriteRune(sparkChars[idx])
	}

	return rttStyle.Render(b.String())
}

// renderStatusBar renders the status bar
func (m *TUIModel) renderStatusBar() string {
	info := m.getStatusInfo()

	parts := []string{
		fmt.Sprintf("Hops: %d", info.HopCount),
	}

	if info.HasMPLS {
		parts = append(parts, mplsStyle.Render("MPLS"))
	}
	if info.HasECMP {
		parts = append(parts, asnStyle.Render("ECMP"))
	}
	if info.HasNAT {
		parts = append(parts, timeoutStyle.Render("NAT"))
	}

	elapsed := time.Since(m.startTime).Round(time.Millisecond)
	parts = append(parts, fmt.Sprintf("Time: %v", elapsed))

	return statusStyle.Render(strings.Join(parts, " │ "))
}

// getStatusInfo collects status information
func (m *TUIModel) getStatusInfo() StatusInfo {
	info := StatusInfo{
		HopCount: len(m.hops),
	}

	var totalRTT time.Duration
	var rttCount int
	var totalLoss float64

	for _, h := range m.hops {
		if len(h.MPLS) > 0 {
			info.HasMPLS = true
		}
		if h.HasMultipleIPs() {
			info.HasECMP = true
		}
		if h.NAT {
			info.HasNAT = true
		}

		if avg := h.AvgRTT(); avg > 0 {
			totalRTT += avg
			rttCount++
		}
		totalLoss += h.LossPercent()
	}

	if rttCount > 0 {
		info.AvgRTT = totalRTT / time.Duration(rttCount)
	}
	if len(m.hops) > 0 {
		info.LossTotal = totalLoss / float64(len(m.hops))
	}

	return info
}

// RunTUI runs the TUI program
func RunTUI(target, targetIP string, hopChan <-chan *hop.Hop, doneChan <-chan bool) error {
	model := NewTUIModel(target, targetIP)

	p := tea.NewProgram(model)

	// Goroutine to receive hops
	go func() {
		for {
			select {
			case h, ok := <-hopChan:
				if !ok {
					return
				}
				p.Send(HopMsg{Hop: h})
			case reached, ok := <-doneChan:
				if !ok {
					return
				}
				p.Send(CompleteMsg{Reached: reached})
				return
			}
		}
	}()

	_, err := p.Run()
	return err
}
