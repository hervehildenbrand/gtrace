package mcp

import (
	"bytes"
	"fmt"

	"github.com/hervehildenbrand/gtrace/internal/display"
	"github.com/hervehildenbrand/gtrace/internal/export"
	"github.com/hervehildenbrand/gtrace/pkg/hop"
	"github.com/mark3labs/mcp-go/mcp"
)

// tracerouteResult renders a completed trace as a CallToolResult.
// format "json" returns structured content; view "graph" renders the
// path graph instead of the classic table (text format only).
func tracerouteResult(tr *hop.TraceResult, format, view string) *mcp.CallToolResult {
	if format == "json" {
		return mcp.NewToolResultStructured(export.ConvertTrace(tr), traceSummary(tr))
	}
	if view == "graph" {
		return graphResult([]*hop.TraceResult{tr})
	}
	return mcp.NewToolResultText(formatTraceResult(tr))
}

// graphResult renders one or more traces as the ANSI-free path graph.
func graphResult(results []*hop.TraceResult) *mcp.CallToolResult {
	for _, tr := range results {
		if tr.Source == "" {
			tr.Source = "Local"
		}
	}
	var buf bytes.Buffer
	if err := display.NewGraphRenderer(&buf, true).Render(results); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("graph rendering failed: %v", err))
	}
	return mcp.NewToolResultText(buf.String())
}

// traceSummary is the short text fallback accompanying structured trace output.
func traceSummary(tr *hop.TraceResult) string {
	reached := "target not reached"
	if tr.ReachedTarget {
		reached = "target reached"
	}
	return fmt.Sprintf("Traceroute to %s (%s): %d hops, %s", tr.Target, tr.TargetIP, tr.TotalHops(), reached)
}
