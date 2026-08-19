package display

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
	"golang.org/x/term"
)

// graphNode is one router (or synthetic source / timeout placeholder) in the
// merged path DAG. Nodes are keyed by bare IP so the same router reached from
// several sources becomes a single node — a convergence point.
type graphNode struct {
	key       string
	label     string // IP string, source label, or "*" for timeouts
	enrich    hop.Enrichment
	rtt       time.Duration
	loss      float64
	hasMPLS   bool
	nat       bool
	sources   map[int]bool // source indices whose path crosses this node
	depth     int          // max TTL across sources (0 for source nodes)
	count     int          // consecutive silent hops collapsed into a timeout node
	isSource  bool
	isTarget  bool
	isTimeout bool
}

// pathGraph is the merged DAG built from one or more trace results.
// Edge values are the source indices using that edge.
type pathGraph struct {
	nodes        map[string]*graphNode
	edges        map[[2]string]map[int]bool
	sourceLabels []string
}

func (g *pathGraph) touchNode(n *graphNode, source int) {
	existing := g.nodes[n.key]
	if existing == nil {
		n.sources = map[int]bool{source: true}
		g.nodes[n.key] = n
		return
	}
	existing.sources[source] = true
	if n.depth > existing.depth {
		existing.depth = n.depth
	}
}

func (g *pathGraph) addEdge(from, to string, source int) {
	key := [2]string{from, to}
	if g.edges[key] == nil {
		g.edges[key] = map[int]bool{}
	}
	g.edges[key][source] = true
}

func allTimeout(h *hop.Hop) bool {
	for _, p := range h.Probes {
		if !p.Timeout {
			return false
		}
	}
	return true
}

// ipAvgRTT averages the RTTs of the probes answering from ip.
func ipAvgRTT(h *hop.Hop, ip string) time.Duration {
	var total time.Duration
	var count int
	for _, p := range h.Probes {
		if !p.Timeout && p.IP != nil && p.IP.String() == ip {
			total += p.RTT
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}

// flowIPs maps FlowID -> responding IP for hops probed with --ecmp-flows.
func flowIPs(h *hop.Hop) map[int]string {
	m := map[int]string{}
	for _, p := range h.Probes {
		if !p.Timeout && p.IP != nil && p.FlowID > 0 {
			if _, ok := m[p.FlowID]; !ok {
				m[p.FlowID] = p.IP.String()
			}
		}
	}
	return m
}

// connectHops wires the previous hop's nodes to the current hop's nodes.
// When both hops carry FlowIDs (--ecmp-flows), same-flow nodes connect
// pairwise so each real path renders as its own strand; anything the flow
// pass leaves unwired falls back to the full mesh so no node dangles.
func (g *pathGraph) connectHops(prevHop, curHop *hop.Hop, prev, cur []string, source int) {
	if prevHop != nil && curHop != nil {
		pf, cf := flowIPs(prevHop), flowIPs(curHop)
		if len(pf) > 0 && len(cf) > 0 {
			keyByLabel := func(keys []string, label string) string {
				for _, k := range keys {
					if g.nodes[k].label == label {
						return k
					}
				}
				return ""
			}
			linkedIn, linkedOut := map[string]bool{}, map[string]bool{}
			for f, pip := range pf {
				cip, ok := cf[f]
				if !ok {
					continue
				}
				pk, ck := keyByLabel(prev, pip), keyByLabel(cur, cip)
				if pk == "" || ck == "" {
					continue
				}
				g.addEdge(pk, ck, source)
				linkedOut[pk], linkedIn[ck] = true, true
			}
			for _, c := range cur {
				if !linkedIn[c] {
					for _, p := range prev {
						g.addEdge(p, c, source)
					}
				}
			}
			for _, p := range prev {
				if !linkedOut[p] {
					for _, c := range cur {
						g.addEdge(p, c, source)
					}
				}
			}
			return
		}
	}
	for _, p := range prev {
		for _, c := range cur {
			g.addEdge(p, c, source)
		}
	}
}

// distinctIPs returns the distinct responding IPs of a hop in probe order.
func distinctIPs(h *hop.Hop) []string {
	var ips []string
	seen := map[string]bool{}
	for _, p := range h.Probes {
		if p.Timeout || p.IP == nil {
			continue
		}
		s := p.IP.String()
		if !seen[s] {
			seen[s] = true
			ips = append(ips, s)
		}
	}
	return ips
}

// buildGraph merges trace results into a path DAG. Consecutive hops connect
// per-flow when FlowIDs were tracked (--ecmp-flows), else as a full mesh.
func buildGraph(results []*hop.TraceResult) *pathGraph {
	g := &pathGraph{
		nodes:        map[string]*graphNode{},
		edges:        map[[2]string]map[int]bool{},
		sourceLabels: make([]string, len(results)),
	}

	for i, tr := range results {
		label := tr.Source
		if label == "" {
			label = "Local"
		}
		g.sourceLabels[i] = label

		srcKey := fmt.Sprintf("src:%d", i)
		g.touchNode(&graphNode{key: srcKey, label: label, isSource: true}, i)

		// Trim trailing all-timeout hops (same convention as MTR display).
		hops := tr.Hops
		for len(hops) > 0 && allTimeout(hops[len(hops)-1]) {
			hops = hops[:len(hops)-1]
		}

		visits := map[string]int{} // per-source IP revisit counter (loop guard)
		prev := []string{srcKey}
		var prevH *hop.Hop // nil for source and timeout nodes (no flow data)
		for hi := 0; hi < len(hops); hi++ {
			h := hops[hi]
			curH := h
			var cur []string
			if allTimeout(h) {
				curH = nil
				// collapse a run of consecutive silent hops into one node
				run := 1
				for hi+run < len(hops) && allTimeout(hops[hi+run]) {
					run++
				}
				key := fmt.Sprintf("t:%d:%d", i, h.TTL)
				g.touchNode(&graphNode{key: key, label: "*", depth: hops[hi+run-1].TTL, count: run, isTimeout: true}, i)
				hi += run - 1
				cur = []string{key}
			} else {
				ips := distinctIPs(h)
				ecmp := len(ips) > 1
				for _, ip := range ips {
					key := ip
					if n := visits[ip]; n > 0 {
						key = fmt.Sprintf("%s#%d", ip, n)
					}
					node := &graphNode{
						key:     key,
						label:   ip,
						enrich:  h.Enrichment,
						rtt:     ipAvgRTT(h, ip),
						depth:   h.TTL,
						hasMPLS: len(h.MPLS) > 0,
						nat:     h.NAT,
					}
					if !ecmp {
						// Loss is per-hop; with ECMP siblings it cannot be
						// attributed to a single IP.
						node.loss = h.LossPercent()
					}
					g.touchNode(node, i)
					cur = append(cur, key)
				}
				for _, ip := range ips {
					visits[ip]++
				}
			}
			g.connectHops(prevH, curH, prev, cur, i)
			prev, prevH = cur, curH
		}

		if tr.ReachedTarget {
			if n := g.nodes[tr.TargetIP]; n != nil {
				n.isTarget = true
			}
		}
	}

	return g
}

// orderNodes returns the node keys in render order: a topological sort that
// follows one path at a time so each source's strand stays contiguous. The
// next node is picked by tier — (0) a ready successor of the last emitted
// node, (1) a ready node sharing a source with it, (2) any ready node — each
// tie-broken by (depth, key). Two sources can traverse a pair of routers in
// opposite orders, creating a cross-source cycle that starves the ready set —
// the stall-breaker then force-emits the shallowest remaining node, dropping
// its unsatisfied in-edges.
func orderNodes(g *pathGraph) []string {
	indeg := make(map[string]int, len(g.nodes))
	out := map[string][]string{}
	for k := range g.nodes {
		indeg[k] = 0
	}
	for e := range g.edges {
		out[e[0]] = append(out[e[0]], e[1])
		indeg[e[1]]++
	}

	before := func(a, b string) bool {
		na, nb := g.nodes[a], g.nodes[b]
		if na.depth != nb.depth {
			return na.depth < nb.depth
		}
		return a < b
	}

	ready := map[string]bool{}
	for k, d := range indeg {
		if d == 0 {
			ready[k] = true
		}
	}

	order := make([]string, 0, len(g.nodes))
	emitted := make(map[string]bool, len(g.nodes))
	last := ""
	for len(order) < len(g.nodes) {
		if len(ready) == 0 {
			// stall-breaker: pick the shallowest unemitted node
			pick := ""
			for k := range g.nodes {
				if !emitted[k] && (pick == "" || before(k, pick)) {
					pick = k
				}
			}
			ready[pick] = true
		}

		succ := map[string]bool{}
		var lastSources map[int]bool
		if last != "" {
			for _, s := range out[last] {
				succ[s] = true
			}
			lastSources = g.nodes[last].sources
		}
		sharesSource := func(k string) bool {
			for s := range g.nodes[k].sources {
				if lastSources[s] {
					return true
				}
			}
			return false
		}
		tierOf := func(k string) int {
			switch {
			case succ[k]:
				return 0
			case sharesSource(k):
				return 1
			default:
				return 2
			}
		}

		pick, pickTier := "", 3
		for k := range ready {
			t := tierOf(k)
			if pick == "" || t < pickTier || (t == pickTier && before(k, pick)) {
				pick, pickTier = k, t
			}
		}

		delete(ready, pick)
		emitted[pick] = true
		order = append(order, pick)
		last = pick
		for _, next := range out[pick] {
			indeg[next]--
			if indeg[next] == 0 && !emitted[next] {
				ready[next] = true
			}
		}
	}
	return order
}

// GraphRenderer renders traceroute paths as a terminal Unicode DAG,
// git-log --graph style: one row per router, lane glyphs on the left.
type GraphRenderer struct {
	writer    io.Writer
	noColor   bool
	termWidth int
}

// NewGraphRenderer creates a renderer with terminal width detection.
func NewGraphRenderer(w io.Writer, noColor bool) *GraphRenderer {
	width := 80
	if f, ok := w.(*os.File); ok {
		if tw, _, err := term.GetSize(int(f.Fd())); err == nil && tw > 0 {
			width = tw
		}
	}
	return &GraphRenderer{writer: w, noColor: noColor, termWidth: width}
}

// laneCell is one 2-column glyph cell of a rendered row.
type laneCell struct {
	glyph string
	src   int // owning source index for coloring, -1 = neutral
}

// graphRow is a laid-out output row: lane cells plus optional node text.
type graphRow struct {
	cells []laneCell
	text  string
	node  *graphNode // nil for connector rows
}

// lane tracks an edge in flight toward its next node.
type lane struct {
	expect string // node key this lane flows toward; "" = free
	src    int    // owning source index, -1 = shared
}

func singleSource(sources map[int]bool) int {
	if len(sources) == 1 {
		for s := range sources {
			return s
		}
	}
	return -1
}

// layoutRows walks the ordered nodes and produces rows with lane glyphs.
// Merge connectors precede a node's row; fork connectors follow it.
func layoutRows(g *pathGraph, order []string, nSources int) []graphRow {
	out := map[string][]string{}
	for e := range g.edges {
		out[e[0]] = append(out[e[0]], e[1])
	}
	pos := make(map[string]int, len(order))
	for i, k := range order {
		pos[k] = i
	}
	for k := range out {
		ts := out[k]
		sort.Slice(ts, func(i, j int) bool { return pos[ts[i]] < pos[ts[j]] })
	}

	var lanes []lane
	var rows []graphRow

	snapshot := func() []laneCell {
		cs := make([]laneCell, len(lanes))
		for i, l := range lanes {
			if l.expect == "" {
				cs[i] = laneCell{"  ", -1}
			} else {
				cs[i] = laneCell{"│ ", l.src}
			}
		}
		return cs
	}

	for _, k := range order {
		n := g.nodes[k]

		var in []int
		for i := range lanes {
			if lanes[i].expect == k {
				in = append(in, i)
			}
		}

		var nodeLane int
		if len(in) == 0 {
			// source node (or stall-broken orphan): open a fresh lane
			nodeLane = len(lanes)
			for i := range lanes {
				if lanes[i].expect == "" {
					nodeLane = i
					break
				}
			}
			if nodeLane == len(lanes) {
				lanes = append(lanes, lane{})
			}
			lanes[nodeLane] = lane{expect: k, src: singleSource(n.sources)}
		} else {
			nodeLane = in[0]
		}

		// merge connector: all other incoming lanes close into nodeLane
		if len(in) > 1 {
			cs := snapshot()
			last := in[len(in)-1]
			closing := map[int]bool{}
			for _, i := range in[1:] {
				closing[i] = true
			}
			for i := nodeLane; i <= last; i++ {
				switch {
				case i == nodeLane:
					cs[i] = laneCell{"├─", lanes[i].src}
				case i == last:
					cs[i] = laneCell{"╯ ", lanes[i].src}
				case closing[i]:
					cs[i] = laneCell{"┴─", lanes[i].src}
				case lanes[i].expect == "":
					cs[i] = laneCell{"──", -1}
				default:
					cs[i] = laneCell{"┼─", lanes[i].src}
				}
			}
			rows = append(rows, graphRow{cells: cs})
			for _, i := range in[1:] {
				lanes[i] = lane{}
			}
			// compact freed trailing lanes so the node row hugs its glyphs
			for len(lanes) > 0 && lanes[len(lanes)-1].expect == "" {
				lanes = lanes[:len(lanes)-1]
			}
		}

		// node row
		cs := snapshot()
		marker := "● "
		switch {
		case n.isSource:
			marker = "○ "
		case n.isTarget:
			marker = "◎ "
		case n.isTimeout:
			marker = "* "
		case len(n.sources) > 1 && nSources > 1:
			marker = "◉ "
		}
		cs[nodeLane] = laneCell{marker, singleSource(n.sources)}
		rows = append(rows, graphRow{cells: cs, text: nodeText(n, g, nSources), node: n})

		// outgoing edges: first continues in nodeLane, others fork right
		targets := out[k]
		if len(targets) == 0 {
			lanes[nodeLane] = lane{}
		} else {
			edgeSrc := func(to string) int {
				return singleSource(g.edges[[2]string{k, to}])
			}
			lanes[nodeLane] = lane{expect: targets[0], src: edgeSrc(targets[0])}
			if len(targets) > 1 {
				var newLanes []int
				for _, t := range targets[1:] {
					li := -1
					for i := nodeLane + 1; i < len(lanes); i++ {
						if lanes[i].expect == "" {
							li = i
							break
						}
					}
					if li == -1 {
						lanes = append(lanes, lane{})
						li = len(lanes) - 1
					}
					lanes[li] = lane{expect: t, src: edgeSrc(t)}
					newLanes = append(newLanes, li)
				}
				cs := snapshot()
				last := newLanes[len(newLanes)-1]
				opening := map[int]bool{}
				for _, i := range newLanes {
					opening[i] = true
				}
				for i := nodeLane; i <= last; i++ {
					switch {
					case i == nodeLane:
						cs[i] = laneCell{"├─", lanes[i].src}
					case i == last:
						cs[i] = laneCell{"╮ ", lanes[i].src}
					case opening[i]:
						cs[i] = laneCell{"┬─", lanes[i].src}
					case lanes[i].expect == "":
						cs[i] = laneCell{"──", -1}
					default:
						cs[i] = laneCell{"┼─", lanes[i].src}
					}
				}
				rows = append(rows, graphRow{cells: cs})
			}
		}

		// drop trailing free lanes
		for len(lanes) > 0 && lanes[len(lanes)-1].expect == "" {
			lanes = lanes[:len(lanes)-1]
		}
	}

	return rows
}

// nodeText formats the info column for a node row.
func nodeText(n *graphNode, g *pathGraph, nSources int) string {
	if n.isSource {
		return n.label
	}
	if n.isTimeout {
		if n.count > 1 {
			return fmt.Sprintf("(no response ×%d)", n.count)
		}
		return "(no response)"
	}
	parts := []string{n.label}
	e := n.enrich
	if e.Hostname != "" && e.Hostname != n.label {
		parts = append(parts, e.Hostname)
	}
	if e.ASN > 0 {
		asn := fmt.Sprintf("AS%d", e.ASN)
		if e.ASOrg != "" {
			asn += " " + e.ASOrg
		}
		parts = append(parts, asn)
	} else if e.ASOrg != "" {
		parts = append(parts, e.ASOrg)
	}
	if e.City != "" || e.Country != "" {
		loc := e.City
		if e.Country != "" {
			if loc != "" {
				loc += ","
			}
			loc += e.Country
		}
		parts = append(parts, loc)
	}
	if n.rtt > 0 {
		parts = append(parts, formatRTT(n.rtt))
	}
	if n.loss > 0 {
		parts = append(parts, fmt.Sprintf("%.0f%% loss", n.loss))
	}
	if n.hasMPLS {
		parts = append(parts, "[MPLS]")
	}
	if n.nat {
		parts = append(parts, "[NAT]")
	}
	if e.IX != "" {
		parts = append(parts, "[IX "+e.IX+"]")
	}
	if len(n.sources) > 1 && nSources > 1 {
		idxs := make([]int, 0, len(n.sources))
		for s := range n.sources {
			idxs = append(idxs, s)
		}
		sort.Ints(idxs)
		labels := make([]string, len(idxs))
		for i, s := range idxs {
			labels[i] = g.sourceLabels[s]
		}
		parts = append(parts, "⇐ "+strings.Join(labels, " + "))
	}
	return strings.Join(parts, "  ")
}

// paint applies the source's lane color unless colors are off or the
// element is shared/neutral (src < 0).
func (r *GraphRenderer) paint(s string, src int) string {
	if r.noColor || src < 0 {
		return s
	}
	return lipgloss.NewStyle().Foreground(sourceColors[src%len(sourceColors)]).Render(s)
}

// truncateText cuts text to max display columns, ending with "...".
func truncateText(text string, max int) string {
	if max < 10 {
		max = 10
	}
	if runeDisplayWidth(text) <= max {
		return text
	}
	runes := []rune(text)
	return string(runes[:max-3]) + "..."
}

// Render draws a DAG for one or more trace results.
func (r *GraphRenderer) Render(results []*hop.TraceResult) error {
	if len(results) == 0 {
		return fmt.Errorf("no trace results to render")
	}

	g := buildGraph(results)
	order := orderNodes(g)
	rows := layoutRows(g, order, len(results))

	target := results[0].Target
	targetIP := results[0].TargetIP
	srcWord := "sources"
	if len(results) == 1 {
		srcWord = "source"
	}
	if targetIP != "" && targetIP != target {
		fmt.Fprintf(r.writer, "Path graph to %s (%s), %d %s\n\n", target, targetIP, len(results), srcWord)
	} else {
		fmt.Fprintf(r.writer, "Path graph to %s, %d %s\n\n", target, len(results), srcWord)
	}

	r.renderASOverview(results)

	for _, row := range rows {
		var b strings.Builder
		for _, c := range row.cells {
			b.WriteString(r.paint(c.glyph, c.src))
		}
		line := strings.TrimRight(b.String(), " ")
		if row.text != "" {
			text := truncateText(row.text, r.termWidth-2*len(row.cells)-1)
			if row.node != nil && row.node.isSource {
				text = r.paint(text, singleSource(row.node.sources))
			}
			line = b.String() + " " + text
		}
		fmt.Fprintln(r.writer, strings.TrimRight(line, " "))
	}

	reached := 0
	for _, tr := range results {
		if tr.ReachedTarget {
			reached++
		}
	}
	if reached > 0 {
		fmt.Fprintf(r.writer, "\ntarget reached (%d/%d sources)\n", reached, len(results))
	} else {
		fmt.Fprintf(r.writer, "\ntarget not reached\n")
	}

	return nil
}
