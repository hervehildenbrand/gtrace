package display

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
	"golang.org/x/term"
)

const (
	colWidthMin = 25
	colWidthMax = 45
)

// Source colors for up to 5 sources.
var sourceColors = []lipgloss.Color{
	lipgloss.Color("39"),  // Cyan
	lipgloss.Color("208"), // Orange
	lipgloss.Color("141"), // Purple
	lipgloss.Color("82"),  // Green
	lipgloss.Color("205"), // Pink
}

// CompareRenderer renders trace results from multiple sources.
type CompareRenderer struct {
	writer    io.Writer
	noColor   bool
	termWidth int
}

// NewCompareRenderer creates a new CompareRenderer.
func NewCompareRenderer(w io.Writer, noColor bool) *CompareRenderer {
	width := 80
	if fd, ok := w.(*os.File); ok {
		if w, _, err := term.GetSize(int(fd.Fd())); err == nil && w > 0 {
			width = w
		}
	}
	return &CompareRenderer{
		writer:    w,
		noColor:   noColor,
		termWidth: width,
	}
}

// Render is the backward-compatible entry point for comparing local vs a single remote.
func (r *CompareRenderer) Render(local, remote *hop.TraceResult, remoteLocation string) error {
	if remote.Source == "" {
		remote.Source = remoteLocation
	}
	if local.Source == "" {
		local.Source = "Local"
	}
	return r.RenderAll([]*hop.TraceResult{local, remote})
}

// RenderAll renders a comparison of all provided trace sources.
// For <= 3 sources it uses a unified multi-column table.
// For > 3 sources it uses a stacked boxed layout.
func (r *CompareRenderer) RenderAll(sources []*hop.TraceResult) error {
	if len(sources) == 0 {
		return fmt.Errorf("no trace results to compare")
	}

	// Determine target from first source
	target := sources[0].TargetIP
	if target == "" {
		target = sources[0].Target
	}

	fmt.Fprintf(r.writer, "Comparing traces to %s\n\n", target)

	if len(sources) <= 3 {
		return r.renderUnified(sources)
	}
	return r.renderStacked(sources)
}

// calcColumnWidth computes the width for each data column in unified layout.
func calcColumnWidth(termWidth, numCols int) int {
	// "Hop │ " prefix = 6 chars, " │ " separator between columns = 3 chars
	available := termWidth - 6 - 3*(numCols-1)
	w := available / numCols
	if w < colWidthMin {
		w = colWidthMin
	}
	if w > colWidthMax {
		w = colWidthMax
	}
	return w
}

// renderUnified renders a multi-column table for up to 3 sources.
func (r *CompareRenderer) renderUnified(sources []*hop.TraceResult) error {
	numCols := len(sources)
	colWidth := calcColumnWidth(r.termWidth, numCols)
	common := computeCommonHops(sources)

	// Find max TTL across all sources
	maxTTL := 0
	for _, src := range sources {
		for _, h := range src.Hops {
			if h.TTL > maxTTL {
				maxTTL = h.TTL
			}
		}
	}

	// Header row: Hop │ Source1 │ Source2 │ ...
	headerParts := make([]string, numCols)
	for i, src := range sources {
		name := src.Source
		if name == "" {
			name = fmt.Sprintf("Source %d", i+1)
		}
		if len(name) > colWidth {
			name = name[:colWidth-3] + "..."
		}
		headerParts[i] = r.colorize(fmt.Sprintf("%-*s", colWidth, name), i)
	}
	fmt.Fprintf(r.writer, "Hop │ %s\n", strings.Join(headerParts, " │ "))

	// Separator row
	sepParts := make([]string, numCols)
	for i := range sepParts {
		sepParts[i] = strings.Repeat("─", colWidth)
	}
	fmt.Fprintf(r.writer, "────┼─%s\n", strings.Join(sepParts, "─┼─"))

	// Data rows by TTL
	for ttl := 1; ttl <= maxTTL; ttl++ {
		cols := make([]string, numCols)
		// Compute max RTT at this TTL for spark scaling
		var maxRTT time.Duration
		for _, src := range sources {
			if h := src.GetHop(ttl); h != nil {
				if avg := h.AvgRTT(); avg > maxRTT {
					maxRTT = avg
				}
			}
		}

		for i, src := range sources {
			h := src.GetHop(ttl)
			cell := r.formatHopCell(h, colWidth, maxRTT, common, ttl)
			cols[i] = r.colorize(cell, i)
		}
		fmt.Fprintf(r.writer, "%3d │ %s\n", ttl, strings.Join(cols, " │ "))
	}

	// Summary separator
	sumSepParts := make([]string, numCols)
	for i := range sumSepParts {
		sumSepParts[i] = strings.Repeat("─", colWidth)
	}
	fmt.Fprintf(r.writer, "────┼─%s\n", strings.Join(sumSepParts, "─┼─"))

	// Summary row
	sumParts := make([]string, numCols)
	for i, src := range sources {
		summary := r.formatSummary(src)
		if len(summary) > colWidth {
			summary = summary[:colWidth]
		}
		sumParts[i] = fmt.Sprintf("%-*s", colWidth, summary)
	}
	fmt.Fprintf(r.writer, "    │ %s\n", strings.Join(sumParts, " │ "))

	return nil
}

// renderStacked renders each source in its own bordered box.
func (r *CompareRenderer) renderStacked(sources []*hop.TraceResult) error {
	common := computeCommonHops(sources)
	boxWidth := r.termWidth - 4 // account for border chars + padding
	if boxWidth < 40 {
		boxWidth = 40
	}
	if boxWidth > 80 {
		boxWidth = 80
	}

	for i, src := range sources {
		name := src.Source
		if name == "" {
			name = fmt.Sprintf("Source %d", i+1)
		}

		// Compute max RTT across all hops in this source
		var maxRTT time.Duration
		for _, h := range src.Hops {
			if avg := h.AvgRTT(); avg > maxRTT {
				maxRTT = avg
			}
		}

		// Build box content
		var content strings.Builder
		for _, h := range src.Hops {
			cell := r.formatHopCell(h, boxWidth-8, maxRTT, common, h.TTL)
			fmt.Fprintf(&content, "  %s\n", cell)
		}
		fmt.Fprintf(&content, "\n  %s", r.formatSummary(src))

		// Render box with lipgloss
		color := sourceColors[i%len(sourceColors)]
		style := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(color).
			Width(boxWidth).
			Padding(0, 1)

		if r.noColor {
			style = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				Width(boxWidth).
				Padding(0, 1)
		}

		// Title line
		titleLine := fmt.Sprintf("─ %s ", name)
		box := style.Render(content.String())

		// Insert title into top border
		if len(box) > 3+len(titleLine) {
			lines := strings.Split(box, "\n")
			if len(lines) > 0 {
				topBorder := lines[0]
				runes := []rune(topBorder)
				titleRunes := []rune(titleLine)
				// Insert title after the first corner char (╭)
				if len(runes) > 2+len(titleRunes) {
					for j, tr := range titleRunes {
						runes[2+j] = tr
					}
					lines[0] = string(runes)
				}
				box = strings.Join(lines, "\n")
			}
		}

		fmt.Fprintln(r.writer, box)

		if i < len(sources)-1 {
			fmt.Fprintln(r.writer)
		}
	}

	return nil
}

// formatHopCell formats a single hop within a column of given width.
func (r *CompareRenderer) formatHopCell(h *hop.Hop, colWidth int, maxRTT time.Duration, common map[int]map[string]int, ttl int) string {
	if h == nil {
		return fmt.Sprintf("%-*s", colWidth, "")
	}

	// Check if all probes timed out
	allTimeout := true
	for _, p := range h.Probes {
		if !p.Timeout {
			allTimeout = false
			break
		}
	}

	if allTimeout {
		return fmt.Sprintf("%-*s", colWidth, "* * *")
	}

	ip := h.PrimaryIP()
	if ip == nil {
		return fmt.Sprintf("%-*s", colWidth, "* * *")
	}

	// Use hostname if available, otherwise IP
	host := ip.String()
	if h.Enrichment.Hostname != "" {
		host = h.Enrichment.Hostname
	}

	// ASN tag
	asnTag := ""
	if h.Enrichment.ASN > 0 {
		asnTag = fmt.Sprintf("AS%d", h.Enrichment.ASN)
	} else if h.Enrichment.ASOrg != "" {
		asnTag = h.Enrichment.ASOrg
		if len(asnTag) > 10 {
			asnTag = asnTag[:7] + "..."
		}
	}

	// RTT
	rtt := h.AvgRTT()
	rttStr := formatRTT(rtt)

	// Spark char
	spark := string(rttSparkChar(rtt, maxRTT))

	// Is this a common hop?
	isCommon := false
	if ipCounts, ok := common[ttl]; ok {
		if count, ok := ipCounts[ip.String()]; ok && count >= 2 {
			isCommon = true
		}
	}
	_ = isCommon // Used for styling in color mode (bold), not visible in noColor

	// Build the cell content, fitting within colWidth
	// Layout: host ASN rttStr spark
	// Reserve space for RTT + spark: rttStr + " " + spark = ~10 chars
	rttPart := rttStr + " " + spark
	rttPartLen := len(rttStr) + 1 + 1 // spark is 1 rune (3 bytes but 1 display width)

	hostAsnWidth := colWidth - rttPartLen - 1 // -1 for space before rtt
	if hostAsnWidth < 10 {
		hostAsnWidth = 10
	}

	var hostAsn string
	if asnTag != "" {
		// host + " " + asn
		asnLen := len(asnTag)
		hostMaxLen := hostAsnWidth - asnLen - 1
		if hostMaxLen < 5 {
			hostMaxLen = 5
		}
		if len(host) > hostMaxLen {
			host = host[:hostMaxLen-3] + "..."
		}
		hostAsn = fmt.Sprintf("%-*s %s", hostMaxLen, host, asnTag)
	} else {
		if len(host) > hostAsnWidth {
			host = host[:hostAsnWidth-3] + "..."
		}
		hostAsn = fmt.Sprintf("%-*s", hostAsnWidth, host)
	}

	cell := fmt.Sprintf("%s %s", hostAsn, rttPart)
	// Pad to colWidth using rune count (display width) not byte length,
	// since spark chars are multi-byte UTF-8 but single display width.
	displayLen := runeDisplayWidth(cell)
	if displayLen < colWidth {
		cell = cell + strings.Repeat(" ", colWidth-displayLen)
	}

	return cell
}

// runeDisplayWidth returns the display width of a string,
// counting each rune as 1 column (sufficient for ASCII + sparkline chars).
func runeDisplayWidth(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

// colorize applies source-specific color to text if colors are enabled.
func (r *CompareRenderer) colorize(text string, sourceIdx int) string {
	if r.noColor {
		return text
	}
	color := sourceColors[sourceIdx%len(sourceColors)]
	return lipgloss.NewStyle().Foreground(color).Render(text)
}

// computeCommonHops returns TTL -> IP -> count map across all sources.
func computeCommonHops(sources []*hop.TraceResult) map[int]map[string]int {
	result := make(map[int]map[string]int)

	for _, src := range sources {
		for _, h := range src.Hops {
			ip := h.PrimaryIP()
			if ip == nil {
				continue
			}
			if result[h.TTL] == nil {
				result[h.TTL] = make(map[string]int)
			}
			result[h.TTL][ip.String()]++
		}
	}

	return result
}

// rttSparkChar returns a sparkline character proportional to rtt relative to maxRTT.
func rttSparkChar(rtt, maxRTT time.Duration) rune {
	if maxRTT == 0 || rtt == 0 {
		return sparkChars[0]
	}
	idx := int(float64(rtt) / float64(maxRTT) * float64(len(sparkChars)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sparkChars) {
		idx = len(sparkChars) - 1
	}
	return sparkChars[idx]
}

// formatRTT formats a duration as milliseconds.
func formatRTT(d time.Duration) string {
	if d == 0 {
		return "*"
	}
	ms := float64(d) / float64(time.Millisecond)
	return fmt.Sprintf("%.1fms", ms)
}

// formatSummary creates a summary string for a trace result.
func (r *CompareRenderer) formatSummary(tr *hop.TraceResult) string {
	hopWord := "hops"
	if tr.TotalHops() == 1 {
		hopWord = "hop"
	}

	status := "reached"
	if !tr.ReachedTarget {
		status = "not reached"
	}

	return fmt.Sprintf("%d %s, %s", tr.TotalHops(), hopWord, status)
}
