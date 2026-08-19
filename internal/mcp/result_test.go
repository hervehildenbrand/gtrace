package mcp

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/internal/export"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// resultTestTrace fabricates a small enriched trace for seam tests.
func resultTestTrace() *hop.TraceResult {
	tr := hop.NewTraceResult("example.com", "93.184.216.34")
	tr.Protocol = "icmp"
	tr.ReachedTarget = true

	h1 := hop.NewHop(1)
	h1.AddProbe(net.ParseIP("192.168.1.1"), 1*time.Millisecond)
	h1.SetEnrichment(hop.Enrichment{Hostname: "gw.local", ASN: 64496, ASOrg: "Example ISP"})
	tr.AddHop(h1)

	h2 := hop.NewHop(2)
	h2.AddTimeout()
	tr.AddHop(h2)

	h3 := hop.NewHop(3)
	h3.AddProbe(net.ParseIP("93.184.216.34"), 10*time.Millisecond)
	tr.AddHop(h3)

	return tr
}

func resultText(t *testing.T, res *mcplib.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := res.Content[0].(mcplib.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want TextContent", res.Content[0])
	}
	return tc.Text
}

func TestTracerouteResult_TextDefault_MatchesFormatTraceResult(t *testing.T) {
	tr := resultTestTrace()

	res := tracerouteResult(tr, "text", "table")

	if got, want := resultText(t, res), formatTraceResult(tr); got != want {
		t.Errorf("text output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if res.StructuredContent != nil {
		t.Error("text format must not set structuredContent")
	}
}

func TestTracerouteResult_JSON_MatchesExportedTrace(t *testing.T) {
	tr := resultTestTrace()

	res := tracerouteResult(tr, "json", "table")

	exported, ok := res.StructuredContent.(*export.ExportedTrace)
	if !ok {
		t.Fatalf("structuredContent is %T, want *export.ExportedTrace", res.StructuredContent)
	}
	if exported.Target != "example.com" {
		t.Errorf("target = %q, want example.com", exported.Target)
	}
	if len(exported.Hops) != 3 {
		t.Errorf("hops = %d, want 3", len(exported.Hops))
	}
	if exported.Hops[0].ASN != 64496 {
		t.Errorf("hop1 ASN = %d, want 64496", exported.Hops[0].ASN)
	}
	if resultText(t, res) == "" {
		t.Error("json format must keep a text fallback")
	}
}

func TestTracerouteResult_GraphView_ContainsLaneGlyphs(t *testing.T) {
	tr := resultTestTrace()

	res := tracerouteResult(tr, "text", "graph")

	text := resultText(t, res)
	if !strings.Contains(text, "●") {
		t.Errorf("graph view missing hop glyph ●:\n%s", text)
	}
	if !strings.Contains(text, "○") {
		t.Errorf("graph view missing timeout glyph ○:\n%s", text)
	}
	if strings.Contains(text, "\x1b[") {
		t.Error("graph view must not contain ANSI escapes")
	}
}

func TestTracerouteResult_JSONIgnoresView(t *testing.T) {
	res := tracerouteResult(resultTestTrace(), "json", "graph")

	if res.StructuredContent == nil {
		t.Error("format=json must win over view=graph")
	}
}
