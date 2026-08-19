package display

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// testTrace builds a TraceResult where each element of hopIPs is the list of
// responding IPs at that TTL (nil element = all-timeout hop).
func testTrace(source, target, targetIP string, reached bool, hopIPs ...[]string) *hop.TraceResult {
	tr := hop.NewTraceResult(target, targetIP)
	tr.Source = source
	tr.ReachedTarget = reached
	for i, ips := range hopIPs {
		h := hop.NewHop(i + 1)
		if len(ips) == 0 {
			h.AddTimeout()
		} else {
			for _, ip := range ips {
				h.AddProbe(net.ParseIP(ip), 10*time.Millisecond)
			}
		}
		tr.AddHop(h)
	}
	return tr
}

func TestBuildGraph_SingleLinearPath_NodesAndEdges(t *testing.T) {
	tr := testTrace("", "dns.example", "8.8.8.8", true,
		[]string{"10.0.0.1"}, []string{"10.0.0.2"}, []string{"8.8.8.8"})

	g := buildGraph([]*hop.TraceResult{tr})

	// source node + 3 hop nodes
	if len(g.nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(g.nodes))
	}
	src := g.nodes["src:0"]
	if src == nil || !src.isSource || src.label != "Local" {
		t.Fatalf("expected synthetic source node labeled Local, got %+v", src)
	}
	for _, want := range [][2]string{
		{"src:0", "10.0.0.1"}, {"10.0.0.1", "10.0.0.2"}, {"10.0.0.2", "8.8.8.8"},
	} {
		if g.edges[want] == nil {
			t.Errorf("missing edge %v -> %v", want[0], want[1])
		}
	}
	tgt := g.nodes["8.8.8.8"]
	if tgt == nil || !tgt.isTarget {
		t.Error("expected 8.8.8.8 to be marked as target")
	}
	if g.nodes["10.0.0.2"].depth != 2 {
		t.Errorf("expected depth 2 for second hop, got %d", g.nodes["10.0.0.2"].depth)
	}
}

func TestBuildGraph_ECMPHop_SiblingNodes(t *testing.T) {
	tr := testTrace("", "t", "9.9.9.9", true,
		[]string{"10.0.0.1"}, []string{"172.16.0.1", "172.16.0.2"}, []string{"9.9.9.9"})

	g := buildGraph([]*hop.TraceResult{tr})

	if g.nodes["172.16.0.1"] == nil || g.nodes["172.16.0.2"] == nil {
		t.Fatal("expected one node per ECMP sibling IP")
	}
	// fan out from hop 1 and reconverge on hop 3
	for _, want := range [][2]string{
		{"10.0.0.1", "172.16.0.1"}, {"10.0.0.1", "172.16.0.2"},
		{"172.16.0.1", "9.9.9.9"}, {"172.16.0.2", "9.9.9.9"},
	} {
		if g.edges[want] == nil {
			t.Errorf("missing edge %v -> %v", want[0], want[1])
		}
	}
}

func TestBuildGraph_ECMPHop_PerIPRTT(t *testing.T) {
	tr := hop.NewTraceResult("t", "9.9.9.9")
	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("172.16.0.1"), 10*time.Millisecond)
	h.AddProbe(net.ParseIP("172.16.0.2"), 30*time.Millisecond)
	tr.AddHop(h)

	g := buildGraph([]*hop.TraceResult{tr})

	if got := g.nodes["172.16.0.1"].rtt; got != 10*time.Millisecond {
		t.Errorf("expected per-IP RTT 10ms, got %v", got)
	}
	if got := g.nodes["172.16.0.2"].rtt; got != 30*time.Millisecond {
		t.Errorf("expected per-IP RTT 30ms, got %v", got)
	}
}

func TestBuildGraph_TwoSources_SharedNodeMerged(t *testing.T) {
	a := testTrace("Paris, FR", "t", "8.8.8.8", true,
		[]string{"10.1.0.1"}, []string{"8.8.4.1"}, []string{"8.8.8.8"})
	b := testTrace("Tokyo, JP", "t", "8.8.8.8", true,
		[]string{"10.2.0.1"}, []string{"10.2.0.2"}, []string{"8.8.4.1"}, []string{"8.8.8.8"})

	g := buildGraph([]*hop.TraceResult{a, b})

	shared := g.nodes["8.8.4.1"]
	if shared == nil {
		t.Fatal("expected shared node 8.8.4.1")
	}
	if !shared.sources[0] || !shared.sources[1] {
		t.Errorf("expected node shared by both sources, got %v", shared.sources)
	}
	if shared.depth != 3 {
		t.Errorf("expected depth = max TTL (3), got %d", shared.depth)
	}
	if g.sourceLabels[0] != "Paris, FR" || g.sourceLabels[1] != "Tokyo, JP" {
		t.Errorf("unexpected source labels %v", g.sourceLabels)
	}
}

func TestBuildGraph_RoutingLoop_UniqueKeys(t *testing.T) {
	tr := testTrace("", "t", "9.9.9.9", false,
		[]string{"10.0.0.1"}, []string{"10.0.0.2"}, []string{"10.0.0.1"})

	g := buildGraph([]*hop.TraceResult{tr})

	if g.nodes["10.0.0.1"] == nil || g.nodes["10.0.0.1#1"] == nil {
		t.Fatalf("expected loop revisit to get a distinct key, nodes: %d", len(g.nodes))
	}
	if g.edges[[2]string{"10.0.0.2", "10.0.0.1#1"}] == nil {
		t.Error("expected edge to the revisited node's unique key")
	}
}

func TestBuildGraph_TrailingTimeouts_Trimmed(t *testing.T) {
	tr := testTrace("", "t", "9.9.9.9", false,
		[]string{"10.0.0.1"}, []string{"10.0.0.2"}, nil, nil)

	g := buildGraph([]*hop.TraceResult{tr})

	// src + 2 responding hops only; trailing timeout hops trimmed
	if len(g.nodes) != 3 {
		t.Fatalf("expected trailing timeouts trimmed (3 nodes), got %d", len(g.nodes))
	}
}

func TestBuildGraph_IntermediateTimeout_StarNode(t *testing.T) {
	tr := testTrace("", "t", "9.9.9.9", true,
		[]string{"10.0.0.1"}, nil, []string{"9.9.9.9"})

	g := buildGraph([]*hop.TraceResult{tr})

	n := g.nodes["t:0:2"]
	if n == nil || !n.isTimeout {
		t.Fatal("expected intermediate timeout node t:0:2")
	}
	if g.edges[[2]string{"10.0.0.1", "t:0:2"}] == nil || g.edges[[2]string{"t:0:2", "9.9.9.9"}] == nil {
		t.Error("expected timeout node chained between neighbors")
	}
}

func TestOrderNodes_TopologicalDepthOrder(t *testing.T) {
	a := testTrace("A", "t", "8.8.8.8", true,
		[]string{"10.1.0.1"}, []string{"8.8.4.1"}, []string{"8.8.8.8"})
	b := testTrace("B", "t", "8.8.8.8", true,
		[]string{"10.2.0.1"}, []string{"10.2.0.2"}, []string{"8.8.4.1"}, []string{"8.8.8.8"})
	g := buildGraph([]*hop.TraceResult{a, b})

	order := orderNodes(g)

	if len(order) != len(g.nodes) {
		t.Fatalf("expected %d nodes in order, got %d", len(g.nodes), len(order))
	}
	pos := map[string]int{}
	for i, k := range order {
		if _, dup := pos[k]; dup {
			t.Fatalf("node %s emitted twice", k)
		}
		pos[k] = i
	}
	for e := range g.edges {
		if pos[e[0]] >= pos[e[1]] {
			t.Errorf("edge %s -> %s violates topological order", e[0], e[1])
		}
	}
	// sources (depth 0) come first, in index order
	if order[0] != "src:0" || order[1] != "src:1" {
		t.Errorf("expected source nodes first, got %v", order[:2])
	}
}

func TestOrderNodes_CrossSourceCycle_Terminates(t *testing.T) {
	// Source A visits X then Y; source B visits Y then X: X->Y and Y->X.
	a := testTrace("A", "t", "9.9.9.9", false,
		[]string{"10.0.0.1"}, []string{"10.0.0.2"})
	b := testTrace("B", "t", "9.9.9.9", false,
		[]string{"10.0.0.2"}, []string{"10.0.0.1"})
	g := buildGraph([]*hop.TraceResult{a, b})

	order := orderNodes(g)

	if len(order) != len(g.nodes) {
		t.Fatalf("expected all %d nodes emitted despite cycle, got %d", len(g.nodes), len(order))
	}
}

func TestGraphRenderer_EmptyResults_ReturnsError(t *testing.T) {
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render(nil); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestGraphRenderer_SingleLinearPath_RendersChain(t *testing.T) {
	tr := testTrace("", "dns.example", "8.8.8.8", true,
		[]string{"10.0.0.1"}, []string{"10.0.0.2"}, []string{"8.8.8.8"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{tr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Path graph to dns.example (8.8.8.8), 1 source",
		"○  Local",
		"●  10.0.0.1",
		"●  10.0.0.2",
		"◎  8.8.8.8",
		"10.0ms",
		"target reached (1/1 sources)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestGraphRenderer_ECMPHop_ForkAndMergeGlyphs(t *testing.T) {
	tr := testTrace("", "t", "9.9.9.9", true,
		[]string{"10.0.0.1"}, []string{"172.16.0.1", "172.16.0.2"}, []string{"9.9.9.9"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{tr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "├─╮") {
		t.Errorf("expected fork connector ├─╮ in output:\n%s", out)
	}
	if !strings.Contains(out, "├─╯") {
		t.Errorf("expected merge connector ├─╯ in output:\n%s", out)
	}
	if !strings.Contains(out, "● │  172.16.0.1") || !strings.Contains(out, "│ ●  172.16.0.2") {
		t.Errorf("expected sibling rows in their own lanes:\n%s", out)
	}
}

func TestGraphRenderer_TwoSources_ConvergenceMarked(t *testing.T) {
	a := testTrace("Paris", "t", "8.8.8.8", true,
		[]string{"10.1.0.1"}, []string{"8.8.4.1"}, []string{"8.8.8.8"})
	b := testTrace("Tokyo", "t", "8.8.8.8", true,
		[]string{"10.2.0.1"}, []string{"8.8.4.1"}, []string{"8.8.8.8"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{a, b}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "◉  8.8.4.1") {
		t.Errorf("expected convergence marker ◉ for shared node:\n%s", out)
	}
	if !strings.Contains(out, "⇐ Paris + Tokyo") {
		t.Errorf("expected convergence annotation with source names:\n%s", out)
	}
	if !strings.Contains(out, "├─╯") {
		t.Errorf("expected merge connector before convergence node:\n%s", out)
	}
	if !strings.Contains(out, "target reached (2/2 sources)") {
		t.Errorf("expected 2/2 summary:\n%s", out)
	}
}

func TestGraphRenderer_ConvergeThenDiverge_ReSplitsLanes(t *testing.T) {
	a := testTrace("A", "t", "9.9.9.9", false,
		[]string{"10.0.0.9"}, []string{"2.2.2.1"})
	b := testTrace("B", "t", "9.9.9.9", false,
		[]string{"10.0.0.9"}, []string{"3.3.3.1"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{a, b}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "◉  10.0.0.9") {
		t.Errorf("expected convergence at shared first hop:\n%s", out)
	}
	if !strings.Contains(out, "├─╮") {
		t.Errorf("expected fork connector after convergence (divergence):\n%s", out)
	}
	if !strings.Contains(out, "● │  2.2.2.1") || !strings.Contains(out, "●  3.3.3.1") {
		t.Errorf("expected diverged nodes in separate lanes:\n%s", out)
	}
}

func TestGraphRenderer_UnreachedTarget_SummaryLine(t *testing.T) {
	tr := testTrace("", "t", "9.9.9.9", false,
		[]string{"10.0.0.1"}, []string{"10.0.0.2"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{tr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "◎") {
		t.Errorf("expected no target marker when unreached:\n%s", out)
	}
	if !strings.Contains(out, "target not reached") {
		t.Errorf("expected 'target not reached' summary:\n%s", out)
	}
}

func TestGraphRenderer_TimeoutHop_Star(t *testing.T) {
	tr := testTrace("", "t", "9.9.9.9", true,
		[]string{"10.0.0.1"}, nil, []string{"9.9.9.9"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{tr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "*  (no response)") {
		t.Errorf("expected timeout star row:\n%s", out)
	}
}
