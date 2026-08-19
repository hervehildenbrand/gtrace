package display

import (
	"fmt"
	"strings"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// asBlock is a run of consecutive hops inside the same network.
type asBlock struct {
	asn     uint32
	org     string
	count   int
	private bool
}

// sameNet reports whether a hop classified as (asn, private) continues b.
func (b asBlock) sameNet(asn uint32, private bool) bool {
	return b.asn == asn && b.private == private
}

// asPath aggregates a trace's hops into consecutive AS blocks. Timeout hops
// carry no AS information and are skipped without splitting a run.
func asPath(tr *hop.TraceResult) []asBlock {
	var blocks []asBlock
	for _, h := range tr.Hops {
		if allTimeout(h) {
			continue
		}
		ip := h.PrimaryIP()
		if ip == nil {
			continue
		}
		asn := h.Enrichment.ASN
		private := asn == 0 && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
		if n := len(blocks); n > 0 && blocks[n-1].sameNet(asn, private) {
			blocks[n-1].count++
			if blocks[n-1].org == "" {
				blocks[n-1].org = h.Enrichment.ASOrg
			}
			continue
		}
		blocks = append(blocks, asBlock{asn: asn, org: h.Enrichment.ASOrg, count: 1, private: private})
	}
	return blocks
}

// shortOrg trims a Cymru-style org ("GOOGLE - Google LLC, US") to its name.
func shortOrg(org string) string {
	if i := strings.Index(org, " - "); i > 0 {
		org = org[:i]
	}
	if i := strings.Index(org, ","); i > 0 {
		org = org[:i]
	}
	org = strings.TrimSpace(org)
	if runes := []rune(org); len(runes) > 14 {
		org = string(runes[:14])
	}
	return org
}

// blockLabel formats one AS block, e.g. "AS15169 GOOGLE ×4".
func blockLabel(b asBlock, withOrg bool) string {
	var label string
	switch {
	case b.private:
		label = "private"
	case b.asn == 0:
		label = "?"
	default:
		label = fmt.Sprintf("AS%d", b.asn)
		if withOrg && b.org != "" {
			label += " " + shortOrg(b.org)
		}
	}
	if b.count > 1 {
		label += fmt.Sprintf(" ×%d", b.count)
	}
	return label
}

// renderASOverview draws the horizontal AS-level multipath summary: one row
// per source, consecutive same-AS hops collapsed, reached rows joining into
// the target with a brace column.
func (r *GraphRenderer) renderASOverview(results []*hop.TraceResult) {
	nameW := 0
	names := make([]string, len(results))
	for i, tr := range results {
		names[i] = tr.Source
		if names[i] == "" {
			names[i] = "Local"
		}
		if w := runeDisplayWidth(names[i]); w > nameW {
			nameW = w
		}
	}

	target := results[0].TargetIP
	if target == "" {
		target = results[0].Target
	}

	build := func(withOrg bool) []string {
		rows := make([]string, len(results))
		for i, tr := range results {
			blocks := asPath(tr)
			if len(blocks) == 0 {
				rows[i] = fmt.Sprintf("%-*s ○ (no data)", nameW, names[i])
				continue
			}
			parts := make([]string, len(blocks))
			for j, b := range blocks {
				parts[j] = blockLabel(b, withOrg)
			}
			rows[i] = fmt.Sprintf("%-*s ○─▶ %s", nameW, names[i], strings.Join(parts, " ─▶ "))
		}
		return rows
	}
	maxWidth := func(rows []string) int {
		m := 0
		for _, row := range rows {
			if w := runeDisplayWidth(row); w > m {
				m = w
			}
		}
		return m
	}

	// " ─" + brace glyph + "─▶ ◎ " + target must fit after the widest row
	budget := r.termWidth - runeDisplayWidth(" ──┼─▶ ◎ "+target)
	rows := build(true)
	if maxWidth(rows) > budget {
		rows = build(false)
	}
	if maxWidth(rows) > budget {
		for i, row := range rows {
			rows[i] = truncateText(row, budget)
		}
	}
	maxW := maxWidth(rows)

	var reached []int
	for i, tr := range results {
		if tr.ReachedTarget && len(asPath(tr)) > 0 {
			reached = append(reached, i)
		}
	}
	isReached := map[int]bool{}
	for _, i := range reached {
		isReached[i] = true
	}
	mid := -1
	if len(reached) > 0 {
		mid = reached[len(reached)/2]
	}

	for i, row := range rows {
		fill := " " + strings.Repeat("─", maxW-runeDisplayWidth(row)+1)
		var suffix string
		switch {
		case !isReached[i]:
			suffix = " ✕"
		case len(reached) == 1:
			suffix = fill + "─▶ ◎ " + target
		case i == mid && i == reached[0]:
			suffix = fill + "─┬─▶ ◎ " + target
		case i == mid && i == reached[len(reached)-1]:
			suffix = fill + "─┴─▶ ◎ " + target
		case i == mid:
			suffix = fill + "─┼─▶ ◎ " + target
		case i == reached[0]:
			suffix = fill + "─┐"
		case i == reached[len(reached)-1]:
			suffix = fill + "─┘"
		default:
			suffix = fill + "─┤"
		}
		fmt.Fprintln(r.writer, r.paint(row, i)+suffix)
	}
	fmt.Fprintln(r.writer)
}
