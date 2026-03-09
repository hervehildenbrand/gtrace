package display

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// MultiProbeResultMsg wraps a ProbeResultMsg with a target index.
type MultiProbeResultMsg struct {
	TargetIndex int
	Probe       ProbeResultMsg
}

// MultiCycleCompleteMsg wraps a CycleCompleteMsg with a target index.
type MultiCycleCompleteMsg struct {
	TargetIndex int
	Cycle       int
	Reached     bool
}

// SplitMTRModel is a Bubbletea model that renders multiple MTR targets side-by-side.
type SplitMTRModel struct {
	models []*MTRModel
	width  int
	height int
}

// NewSplitMTRModel creates a split-pane model with one sub-model per target.
func NewSplitMTRModel(targets, targetIPs []string) *SplitMTRModel {
	models := make([]*MTRModel, len(targets))
	for i := range targets {
		models[i] = NewMTRModel(targets[i], targetIPs[i])
	}
	return &SplitMTRModel{
		models: models,
	}
}

// Init implements tea.Model.
func (m *SplitMTRModel) Init() tea.Cmd {
	if len(m.models) > 0 {
		return m.models[0].Init()
	}
	return nil
}

// Update implements tea.Model.
func (m *SplitMTRModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			for _, model := range m.models {
				model.mu.Lock()
				model.running = false
				model.mu.Unlock()
			}
			return m, tea.Quit
		case "p":
			for _, model := range m.models {
				model.mu.Lock()
				model.paused = !model.paused
				model.mu.Unlock()
			}
		case "r":
			for _, model := range m.models {
				model.mu.Lock()
				model.stats = make(map[int]*HopStats)
				model.maxTTL = 0
				model.cycles = 0
				model.mu.Unlock()
			}
		case "n":
			for _, model := range m.models {
				model.mu.Lock()
				model.displayMode = (model.displayMode + 1) % 3
				model.mu.Unlock()
			}
		case "e":
			for _, model := range m.models {
				model.mu.Lock()
				model.showECMP = !model.showECMP
				model.mu.Unlock()
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case MultiProbeResultMsg:
		if msg.TargetIndex >= 0 && msg.TargetIndex < len(m.models) {
			m.models[msg.TargetIndex].handleProbeResult(msg.Probe)
		}

	case MultiCycleCompleteMsg:
		if msg.TargetIndex >= 0 && msg.TargetIndex < len(m.models) {
			model := m.models[msg.TargetIndex]
			model.mu.Lock()
			model.cycles = msg.Cycle
			model.updateRateLimitFlags()
			model.updateECMPClassification()
			model.mu.Unlock()
		}

	case TickMsg:
		// Refresh

	case interface{ isSpinnerTick() }:
		// Forward spinner ticks to first model
		if len(m.models) > 0 {
			var cmd tea.Cmd
			var updated tea.Model
			updated, cmd = m.models[0].Update(msg)
			if um, ok := updated.(*MTRModel); ok {
				m.models[0] = um
			}
			return m, cmd
		}
	}

	return m, nil
}

// View implements tea.Model.
func (m *SplitMTRModel) View() string {
	if len(m.models) == 0 {
		return ""
	}

	// Single target: delegate to standard view
	if len(m.models) == 1 {
		return m.models[0].View()
	}

	// Multi-target: render side-by-side
	paneWidth := m.width / len(m.models)
	if paneWidth < 40 {
		paneWidth = 40
	}

	// Render each pane independently
	panes := make([][]string, len(m.models))
	maxLines := 0
	for i, model := range m.models {
		panes[i] = m.renderPane(model, paneWidth)
		if len(panes[i]) > maxLines {
			maxLines = len(panes[i])
		}
	}

	// Pad short panes
	for i := range panes {
		for len(panes[i]) < maxLines {
			panes[i] = append(panes[i], strings.Repeat(" ", paneWidth))
		}
	}

	// Merge lines side-by-side
	var b strings.Builder
	sep := " │ "
	for line := 0; line < maxLines; line++ {
		for i, pane := range panes {
			if i > 0 {
				b.WriteString(sep)
			}
			b.WriteString(pane[line])
		}
		b.WriteString("\n")
	}

	// Shared help bar
	b.WriteString("\n")
	b.WriteString("Press 'e' expand ECMP, 'n' DNS/IP, 'p' pause all, 'r' reset all, 'q' quit")

	return b.String()
}

// renderPane renders a single target's MTR view as lines, truncated/padded to paneWidth.
func (m *SplitMTRModel) renderPane(model *MTRModel, paneWidth int) []string {
	model.mu.RLock()
	defer model.mu.RUnlock()

	var lines []string

	// Title
	title := fmt.Sprintf("gtr → %s (%s)", model.target, model.targetIP)
	if len(title) > paneWidth {
		title = title[:paneWidth-3] + "..."
	}
	lines = append(lines, padOrTruncate(title, paneWidth))
	lines = append(lines, strings.Repeat("─", paneWidth))

	// Compact header
	header := fmt.Sprintf("%-3s %-15s %5s %4s %7s %7s", "Hop", "Host", "Loss%", "Snt", "Avg", "Last")
	lines = append(lines, padOrTruncate(header, paneWidth))
	lines = append(lines, strings.Repeat("─", paneWidth))

	// Hops
	orderedStats := model.getOrderedStatsLocked()
	for _, stats := range orderedStats {
		line := m.formatCompactRow(stats, paneWidth)
		lines = append(lines, padOrTruncate(line, paneWidth))
	}

	// Status
	lines = append(lines, strings.Repeat("─", paneWidth))
	status := fmt.Sprintf("Cycles: %d | Hops: %d", model.cycles, len(model.stats))
	lines = append(lines, padOrTruncate(status, paneWidth))

	return lines
}

// formatCompactRow formats a compact hop row for split-pane display.
func (m *SplitMTRModel) formatCompactRow(stats *HopStats, paneWidth int) string {
	ip := stats.PrimaryIP()
	host := "*"
	if ip != nil {
		host = ip.String()
		e := stats.PrimaryEnrichment()
		if e.Hostname != "" {
			host = e.Hostname
		}
	}

	// Truncate host to fit
	maxHost := 15
	if len(host) > maxHost {
		host = host[:maxHost-3] + "..."
	}

	avg := float64(stats.AvgRTT()) / float64(1e6) // nanoseconds to ms
	last := float64(stats.LastRTT) / float64(1e6)

	return fmt.Sprintf("%3d %-15s %4.1f%% %4d %6.1fms %6.1fms",
		stats.TTL, host, stats.LossPercent(), stats.Sent, avg, last)
}

// padOrTruncate ensures a string is exactly the given width.
func padOrTruncate(s string, width int) string {
	// Simple approach: works for ASCII. ANSI codes would need special handling,
	// but split pane uses plain text rendering.
	if len(s) > width {
		return s[:width]
	}
	if len(s) < width {
		return s + strings.Repeat(" ", width-len(s))
	}
	return s
}

// RunSplitMTR runs the split-pane MTR TUI program.
func RunSplitMTR(targets, targetIPs []string, resultChans []<-chan MultiProbeResultMsg, cycleChans []<-chan MultiCycleCompleteMsg, doneChan <-chan struct{}) error {
	model := NewSplitMTRModel(targets, targetIPs)

	p := tea.NewProgram(model)

	// Goroutine to receive results from all targets
	go func() {
		cases := make([]struct {
			resultCh <-chan MultiProbeResultMsg
			cycleCh  <-chan MultiCycleCompleteMsg
		}, len(resultChans))

		for i := range resultChans {
			cases[i].resultCh = resultChans[i]
			cases[i].cycleCh = cycleChans[i]
		}

		// Simple fan-in using goroutines per channel
		for i := range cases {
			go func(idx int) {
				for msg := range resultChans[idx] {
					p.Send(msg)
				}
			}(i)
			go func(idx int) {
				for msg := range cycleChans[idx] {
					p.Send(msg)
				}
			}(i)
		}

		<-doneChan
	}()

	_, err := p.Run()
	return err
}
