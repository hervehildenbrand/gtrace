package display

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// ProbeResultMsg is sent when a probe result is received.
type ProbeResultMsg struct {
	TTL        int
	IP         net.IP
	RTT        time.Duration
	Timeout    bool
	MPLS       []hop.MPLSLabel
	Enrichment hop.Enrichment
}

// CycleCompleteMsg is sent when a trace cycle completes.
type CycleCompleteMsg struct {
	Cycle   int
	Reached bool
}

// TickMsg is sent periodically to refresh the display.
type TickMsg struct{}

// DisplayMode controls how hosts are shown in the display.
type DisplayMode int

const (
	// DisplayModeHostname shows hostname with IP in parentheses (default)
	DisplayModeHostname DisplayMode = iota
	// DisplayModeIP shows IP address with hostname in parentheses
	DisplayModeIP
	// DisplayModeBoth shows both (current behavior)
	DisplayModeBoth
)

// MTRModel is the Bubbletea model for the MTR-style continuous TUI.
type MTRModel struct {
	mu          sync.RWMutex
	target      string
	targetIP    string
	stats       map[int]*HopStats // Keyed by TTL
	maxTTL      int               // Highest TTL seen
	cycles      int
	running     bool
	paused      bool
	interval    time.Duration
	startTime   time.Time
	spinner     spinner.Model
	width       int
	height      int
	displayMode DisplayMode // Toggle between hostname/IP display
	isIPv6      bool        // Track if target is IPv6 for column sizing
}

// NewMTRModel creates a new MTR model.
func NewMTRModel(target, targetIP string) *MTRModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// Check if target is IPv6 (contains colon)
	isIPv6 := strings.Contains(targetIP, ":")

	return &MTRModel{
		target:      target,
		targetIP:    targetIP,
		stats:       make(map[int]*HopStats),
		running:     true,
		paused:      false,
		interval:    time.Second,
		startTime:   time.Now(),
		spinner:     s,
		displayMode: DisplayModeHostname, // Default: show hostname first
		isIPv6:      isIPv6,
	}
}

// Init implements tea.Model.
func (m *MTRModel) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update implements tea.Model.
func (m *MTRModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.running = false
			return m, tea.Quit
		case "p":
			m.mu.Lock()
			m.paused = !m.paused
			m.mu.Unlock()
		case "r":
			m.mu.Lock()
			m.stats = make(map[int]*HopStats)
			m.maxTTL = 0
			m.cycles = 0
			m.startTime = time.Now()
			m.mu.Unlock()
		case "n":
			// Toggle display mode (like real mtr)
			m.mu.Lock()
			m.displayMode = (m.displayMode + 1) % 3
			m.mu.Unlock()
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case ProbeResultMsg:
		m.handleProbeResult(msg)

	case CycleCompleteMsg:
		m.mu.Lock()
		m.cycles = msg.Cycle
		m.mu.Unlock()

	case TickMsg:
		// Just refresh display

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// handleProbeResult processes a probe result message.
func (m *MTRModel) handleProbeResult(msg ProbeResultMsg) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get or create stats for this TTL
	stats, ok := m.stats[msg.TTL]
	if !ok {
		stats = NewHopStats(msg.TTL)
		m.stats[msg.TTL] = stats
	}

	// Update max TTL
	if msg.TTL > m.maxTTL {
		m.maxTTL = msg.TTL
	}

	// Record the probe result
	if msg.Timeout {
		stats.AddTimeout()
	} else {
		stats.AddProbe(msg.IP, msg.RTT)

		// Update enrichment if provided (only on first response)
		if msg.Enrichment.ASN != 0 || msg.Enrichment.Hostname != "" {
			stats.SetEnrichment(msg.Enrichment)
		}

		// Update MPLS labels
		if len(msg.MPLS) > 0 {
			stats.SetMPLS(msg.MPLS)
		}
	}
}

// Column widths for consistent alignment
const (
	colHop      = 4
	colHostIPv4 = 40 // Width for IPv4 hosts
	colHostIPv6 = 52 // Width for IPv6 hosts (IPv6 addresses are up to 39 chars)
	colLoss     = 7
	colSnt      = 6
	colRecv     = 6
	colBest     = 8
	colAvg      = 8
	colWrst     = 8
	colLast     = 8
)

// getHostColumnWidth returns the appropriate host column width.
func (m *MTRModel) getHostColumnWidth() int {
	if m.isIPv6 {
		return colHostIPv6
	}
	return colHostIPv4
}

// View implements tea.Model.
func (m *MTRModel) View() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder

	// Title
	title := fmt.Sprintf("gtr → %s (%s)", m.target, m.targetIP)
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")

	// Header (mtr-style columns)
	colHost := m.getHostColumnWidth()
	header := fmt.Sprintf("%-*s %-*s %*s %*s %*s %*s %*s %*s %*s %s",
		colHop, "Hop",
		colHost, "Host",
		colLoss, "Loss%",
		colSnt, "Snt",
		colRecv, "Recv",
		colBest, "Best",
		colAvg, "Avg",
		colWrst, "Wrst",
		colLast, "Last",
		"Graph")
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")
	lineWidth := colHop + 1 + colHost + 1 + colLoss + 1 + colSnt + 1 + colRecv + 1 + colBest + 1 + colAvg + 1 + colWrst + 1 + colLast + 10
	b.WriteString(strings.Repeat("─", lineWidth))
	b.WriteString("\n")

	// Hops (ordered by TTL)
	orderedStats := m.getOrderedStatsLocked()
	for _, stats := range orderedStats {
		b.WriteString(m.formatStatsRow(stats))
		b.WriteString("\n")
	}

	// Status bar
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", lineWidth))
	b.WriteString("\n")
	b.WriteString(m.renderStatusBar())

	// Help
	b.WriteString("\n")
	if m.paused {
		b.WriteString(timeoutStyle.Render("PAUSED"))
		b.WriteString(" | ")
	} else {
		b.WriteString(m.spinner.View())
		b.WriteString(" ")
	}

	// Show display mode indicator
	modeStr := ""
	switch m.displayMode {
	case DisplayModeHostname:
		modeStr = "[DNS]"
	case DisplayModeIP:
		modeStr = "[IP]"
	case DisplayModeBoth:
		modeStr = "[Both]"
	}
	b.WriteString(fmt.Sprintf("%s Press 'n' to toggle DNS/IP, 'p' pause, 'r' reset, 'q' quit", modeStr))

	return b.String()
}

// formatStatsRow formats a single stats row.
func (m *MTRModel) formatStatsRow(stats *HopStats) string {
	var b strings.Builder

	// TTL - pad then style
	ttlStr := fmt.Sprintf("%-*d", colHop, stats.TTL)
	b.WriteString(hopStyle.Render(ttlStr))
	b.WriteString(" ")

	// Host info - build styled string with proper padding
	b.WriteString(m.formatHostColumn(stats))
	b.WriteString(" ")

	// Loss% - pad then style
	loss := stats.LossPercent()
	lossStr := fmt.Sprintf("%*.1f%%", colLoss-1, loss)
	if loss > 0 {
		b.WriteString(timeoutStyle.Render(lossStr))
	} else {
		b.WriteString(hopStyle.Render(lossStr))
	}
	b.WriteString(" ")

	// Sent - no styling needed
	b.WriteString(fmt.Sprintf("%*d", colSnt, stats.Sent))
	b.WriteString(" ")

	// Recv - no styling needed
	b.WriteString(fmt.Sprintf("%*d", colRecv, stats.Recv))
	b.WriteString(" ")

	// Best RTT - pad then style
	if stats.BestRTT > 0 {
		bestStr := fmt.Sprintf("%*.1f", colBest, float64(stats.BestRTT)/float64(time.Millisecond))
		b.WriteString(rttStyle.Render(bestStr))
	} else {
		b.WriteString(timeoutStyle.Render(fmt.Sprintf("%*s", colBest, "-")))
	}
	b.WriteString(" ")

	// Avg RTT - pad then style
	avg := stats.AvgRTT()
	if avg > 0 {
		avgStr := fmt.Sprintf("%*.1f", colAvg, float64(avg)/float64(time.Millisecond))
		b.WriteString(rttStyle.Render(avgStr))
	} else {
		b.WriteString(timeoutStyle.Render(fmt.Sprintf("%*s", colAvg, "-")))
	}
	b.WriteString(" ")

	// Worst RTT - pad then style
	if stats.WorstRTT > 0 {
		wrstStr := fmt.Sprintf("%*.1f", colWrst, float64(stats.WorstRTT)/float64(time.Millisecond))
		b.WriteString(rttStyle.Render(wrstStr))
	} else {
		b.WriteString(timeoutStyle.Render(fmt.Sprintf("%*s", colWrst, "-")))
	}
	b.WriteString(" ")

	// Last RTT - pad then style
	if stats.LastRTT > 0 {
		lastStr := fmt.Sprintf("%*.1f", colLast, float64(stats.LastRTT)/float64(time.Millisecond))
		b.WriteString(rttStyle.Render(lastStr))
	} else {
		b.WriteString(timeoutStyle.Render(fmt.Sprintf("%*s", colLast, "-")))
	}
	b.WriteString(" ")

	// Sparkline
	if len(stats.RTTHistory) > 0 {
		b.WriteString(m.renderSparkline(stats.RTTHistory))
	}

	// MPLS indicator
	if len(stats.MPLS) > 0 {
		b.WriteString(" ")
		b.WriteString(mplsStyle.Render("[MPLS]"))
	}

	return b.String()
}

// formatHostColumn formats the host column with proper padding and styling.
// This handles ANSI codes correctly by padding plain text first.
// Display modes:
//   - DisplayModeHostname: hostname [ASN] (IP) - like real mtr default
//   - DisplayModeIP: IP [ASN] (hostname)
//   - DisplayModeBoth: IP [ASN] (hostname) - legacy behavior
func (m *MTRModel) formatHostColumn(stats *HopStats) string {
	colWidth := m.getHostColumnWidth()

	if stats.LastIP == nil {
		// Timeout - pad asterisk to full width
		padded := fmt.Sprintf("%-*s", colWidth, "*")
		return timeoutStyle.Render(padded)
	}

	// Build plain text first to calculate length
	var plainParts []string
	var styledParts []string

	ipStr := stats.LastIP.String()
	hostname := stats.Enrichment.Hostname

	// Determine max hostname length based on display mode and available space
	maxHostnameLen := 30
	if m.isIPv6 {
		maxHostnameLen = 35
	}

	switch m.displayMode {
	case DisplayModeHostname:
		// Hostname first (or IP if no hostname)
		if hostname != "" {
			displayHost := hostname
			if len(displayHost) > maxHostnameLen {
				displayHost = displayHost[:maxHostnameLen-3] + "..."
			}
			plainParts = append(plainParts, displayHost)
			styledParts = append(styledParts, hostnameStyle.Render(displayHost))
		} else {
			plainParts = append(plainParts, ipStr)
			styledParts = append(styledParts, ipStyle.Render(ipStr))
		}

		// ASN
		if stats.Enrichment.ASN > 0 {
			asnStr := fmt.Sprintf("[AS%d]", stats.Enrichment.ASN)
			plainParts = append(plainParts, asnStr)
			styledParts = append(styledParts, asnStyle.Render(asnStr))
		}

	case DisplayModeIP:
		// IP address first
		plainParts = append(plainParts, ipStr)
		styledParts = append(styledParts, ipStyle.Render(ipStr))

		// ASN
		if stats.Enrichment.ASN > 0 {
			asnStr := fmt.Sprintf("[AS%d]", stats.Enrichment.ASN)
			plainParts = append(plainParts, asnStr)
			styledParts = append(styledParts, asnStyle.Render(asnStr))
		}

	case DisplayModeBoth:
		// IP address
		plainParts = append(plainParts, ipStr)
		styledParts = append(styledParts, ipStyle.Render(ipStr))

		// ASN
		if stats.Enrichment.ASN > 0 {
			asnStr := fmt.Sprintf("[AS%d]", stats.Enrichment.ASN)
			plainParts = append(plainParts, asnStr)
			styledParts = append(styledParts, asnStyle.Render(asnStr))
		}

		// Hostname in parentheses (truncated)
		if hostname != "" {
			displayHost := hostname
			if len(displayHost) > 20 {
				displayHost = displayHost[:17] + "..."
			}
			hostStr := "(" + displayHost + ")"
			plainParts = append(plainParts, hostStr)
			styledParts = append(styledParts, hostnameStyle.Render(hostStr))
		}
	}

	// Calculate plain text length (with spaces between parts)
	plainText := strings.Join(plainParts, " ")
	plainLen := len(plainText)

	// Truncate if too long
	if plainLen > colWidth {
		// Rebuild with truncation
		truncated := plainText[:colWidth-3] + "..."
		return hopStyle.Render(truncated)
	}

	// Build styled output with padding
	styled := strings.Join(styledParts, " ")
	padding := colWidth - plainLen
	if padding > 0 {
		styled += strings.Repeat(" ", padding)
	}

	return styled
}

// renderSparkline renders a sparkline graph from RTT history.
func (m *MTRModel) renderSparkline(rtts []time.Duration) string {
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
		return rttStyle.Render(strings.Repeat(string(sparkChars[3]), len(rtts)))
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

// renderStatusBar renders the status bar.
func (m *MTRModel) renderStatusBar() string {
	parts := []string{
		fmt.Sprintf("Cycles: %d", m.cycles),
		fmt.Sprintf("Hops: %d", len(m.stats)),
	}

	// Check for MPLS
	hasMPLS := false
	for _, stats := range m.stats {
		if len(stats.MPLS) > 0 {
			hasMPLS = true
			break
		}
	}
	if hasMPLS {
		parts = append(parts, mplsStyle.Render("MPLS"))
	}

	elapsed := time.Since(m.startTime).Round(time.Millisecond)
	parts = append(parts, fmt.Sprintf("Time: %v", elapsed))

	return statusStyle.Render(strings.Join(parts, " │ "))
}

// getOrderedStatsLocked returns stats ordered by TTL. Must be called with lock held.
func (m *MTRModel) getOrderedStatsLocked() []*HopStats {
	result := make([]*HopStats, 0, len(m.stats))
	for _, stats := range m.stats {
		result = append(result, stats)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TTL < result[j].TTL
	})
	return result
}

// GetOrderedStats returns stats ordered by TTL (public, thread-safe).
func (m *MTRModel) GetOrderedStats() []*HopStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getOrderedStatsLocked()
}

// IsRunning returns whether the model is still running.
func (m *MTRModel) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// IsPaused returns whether the model is paused.
func (m *MTRModel) IsPaused() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.paused
}

// RunMTR runs the MTR TUI program.
func RunMTR(target, targetIP string, resultChan <-chan ProbeResultMsg, cycleChan <-chan CycleCompleteMsg, doneChan <-chan struct{}) error {
	model := NewMTRModel(target, targetIP)

	p := tea.NewProgram(model)

	// Goroutine to receive results
	go func() {
		for {
			select {
			case result, ok := <-resultChan:
				if !ok {
					return
				}
				p.Send(result)
			case cycle, ok := <-cycleChan:
				if !ok {
					return
				}
				p.Send(cycle)
			case <-doneChan:
				return
			}
		}
	}()

	_, err := p.Run()
	return err
}
