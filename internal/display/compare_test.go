package display

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// --- Backward-compatible Render() tests ---

func TestCompareRenderer_Render_BothReachTarget(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "80.10.255.25", rtt: 1500 * time.Microsecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
		{ttl: 2, ip: "10.162.9.142", rtt: 500 * time.Microsecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 300 * time.Microsecond},
	})
	remote.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.Render(local, remote, "London, GB")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should contain header with target
	if !strings.Contains(output, "8.8.8.8") {
		t.Error("output should contain target IP")
	}

	// Should show column headers
	if !strings.Contains(output, "Local") {
		t.Error("output should contain 'Local' column header")
	}
	if !strings.Contains(output, "London") {
		t.Error("output should contain remote location header")
	}

	// Should show both reached target
	if !strings.Contains(output, "reached") {
		t.Error("output should indicate targets were reached")
	}

	// Should show hop data from both traces
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("output should contain local hop IP")
	}
	if !strings.Contains(output, "51.89.217.252") {
		t.Error("output should contain remote hop IP")
	}
}

func TestCompareRenderer_Render_LocalReachesRemoteDoesNot(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", false, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
		{ttl: 2, ip: "", rtt: 0, timeout: true},
		{ttl: 3, ip: "", rtt: 0, timeout: true},
	})
	remote.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.Render(local, remote, "London, GB")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "reached") {
		t.Error("output should indicate local reached target")
	}
	if !strings.Contains(output, "not reached") {
		t.Error("output should indicate remote did not reach target")
	}
}

func TestCompareRenderer_Render_DifferentHopCounts(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
		{ttl: 2, ip: "10.162.9.142", rtt: 500 * time.Microsecond},
		{ttl: 3, ip: "10.72.5.34", rtt: 300 * time.Microsecond},
		{ttl: 4, ip: "8.8.8.8", rtt: 200 * time.Microsecond},
	})
	remote.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.Render(local, remote, "London, GB")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "2 hops") {
		t.Error("output should show local hop count")
	}
	if !strings.Contains(output, "4 hops") {
		t.Error("output should show remote hop count")
	}
}

func TestCompareRenderer_Render_TimeoutsAtVariousHops(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "", rtt: 0, timeout: true},
		{ttl: 3, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "", rtt: 0, timeout: true},
		{ttl: 2, ip: "10.162.9.142", rtt: 500 * time.Microsecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 300 * time.Microsecond},
	})
	remote.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.Render(local, remote, "London, GB")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "*") {
		t.Error("output should contain timeout markers (*)")
	}
}

func TestCompareRenderer_Render_NoColor(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
	})
	remote.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true) // noColor = true
	err := renderer.Render(local, remote, "London, GB")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if strings.Contains(output, "\033[") {
		t.Error("output should not contain ANSI escape codes when noColor is true")
	}
}

// --- New unified table tests ---

func TestRenderUnified_TwoSources(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 1200 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 15200 * time.Microsecond},
	})
	local.Source = "Local"

	paris := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "10.0.0.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 8300 * time.Microsecond},
	})
	paris.Source = "Paris, FR"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true) // noColor for easy assertion
	err := renderer.RenderAll([]*hop.TraceResult{local, paris})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should have unified header
	if !strings.Contains(output, "Comparing traces to 8.8.8.8") {
		t.Error("output should contain unified header with target IP")
	}

	// Should use │ column separators
	if !strings.Contains(output, "│") {
		t.Error("output should use │ (U+2502) as column separators")
	}

	// Should show "Hop" column header
	if !strings.Contains(output, "Hop") {
		t.Error("output should contain 'Hop' column header")
	}

	// Should show source names as column headers
	if !strings.Contains(output, "Local") {
		t.Error("output should contain 'Local' column header")
	}
	if !strings.Contains(output, "Paris, FR") {
		t.Error("output should contain 'Paris, FR' column header")
	}

	// Should show hop IPs from both sources
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("output should contain local hop IP")
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("output should contain Paris hop IP")
	}

	// Should have summary line
	if !strings.Contains(output, "2 hops") {
		t.Error("output should contain hop count summary")
	}

	// Should NOT contain === separators (unified view)
	if strings.Contains(output, "===") {
		t.Error("unified view should not contain === separators")
	}
}

func TestRenderUnified_ThreeSources(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 1200 * time.Microsecond},
		{ttl: 2, ip: "80.10.255.25", rtt: 8500 * time.Microsecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 15200 * time.Microsecond},
	})
	local.Source = "Local"

	paris := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "10.0.0.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "51.89.217.252", rtt: 2100 * time.Microsecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 8300 * time.Microsecond},
	})
	paris.Source = "Paris, FR"

	tokyo := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "172.16.0.1", rtt: 800 * time.Microsecond},
		{ttl: 2, ip: "203.0.113.1", rtt: 12300 * time.Microsecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 45200 * time.Microsecond},
	})
	tokyo.Source = "Tokyo, JP"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.RenderAll([]*hop.TraceResult{local, paris, tokyo})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// All three source headers should be present
	if !strings.Contains(output, "Local") {
		t.Error("output should contain 'Local' header")
	}
	if !strings.Contains(output, "Paris, FR") {
		t.Error("output should contain 'Paris, FR' header")
	}
	if !strings.Contains(output, "Tokyo, JP") {
		t.Error("output should contain 'Tokyo, JP' header")
	}

	// All hop IPs should be present
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("output should contain local hop IP")
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("output should contain Paris hop IP")
	}
	if !strings.Contains(output, "172.16.0.1") {
		t.Error("output should contain Tokyo hop IP")
	}

	// Should use unified layout with │ separators (3 sources = unified)
	if !strings.Contains(output, "│") {
		t.Error("output should use │ separators in unified layout")
	}
}

func TestRenderStacked_FourSources(t *testing.T) {
	sources := make([]*hop.TraceResult, 4)
	sourceNames := []string{"Local", "Paris, FR", "Tokyo, JP", "Frankfurt, DE"}
	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "10.10.0.1"}

	for i := 0; i < 4; i++ {
		sources[i] = createTestTraceResult("8.8.8.8", true, []testHop{
			{ttl: 1, ip: ips[i], rtt: time.Duration(1+i) * time.Millisecond},
			{ttl: 2, ip: "8.8.8.8", rtt: time.Duration(10+i*5) * time.Millisecond},
		})
		sources[i].Source = sourceNames[i]
	}

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.RenderAll(sources)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// All source names should appear
	for _, name := range sourceNames {
		if !strings.Contains(output, name) {
			t.Errorf("output should contain source name %q", name)
		}
	}

	// All first-hop IPs should appear
	for _, ip := range ips {
		if !strings.Contains(output, ip) {
			t.Errorf("output should contain hop IP %q", ip)
		}
	}

	// Stacked layout uses box borders (╭ or ─)
	if !strings.Contains(output, "╭") && !strings.Contains(output, "┌") {
		t.Error("stacked layout should use box-drawing characters for borders")
	}
}

func TestComputeCommonHops(t *testing.T) {
	s1 := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 1 * time.Millisecond},
		{ttl: 2, ip: "10.0.0.1", rtt: 5 * time.Millisecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 15 * time.Millisecond},
	})
	s2 := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "172.16.0.1", rtt: 1 * time.Millisecond},
		{ttl: 2, ip: "10.0.0.1", rtt: 3 * time.Millisecond}, // same IP at TTL 2
		{ttl: 3, ip: "8.8.8.8", rtt: 10 * time.Millisecond}, // same IP at TTL 3
	})

	common := computeCommonHops([]*hop.TraceResult{s1, s2})

	// TTL 2: 10.0.0.1 appears in both sources
	ttl2, ok := common[2]
	if !ok {
		t.Fatal("expected TTL 2 in common hops map")
	}
	if ttl2["10.0.0.1"] != 2 {
		t.Errorf("expected 10.0.0.1 count=2 at TTL 2, got %d", ttl2["10.0.0.1"])
	}

	// TTL 3: 8.8.8.8 appears in both
	ttl3, ok := common[3]
	if !ok {
		t.Fatal("expected TTL 3 in common hops map")
	}
	if ttl3["8.8.8.8"] != 2 {
		t.Errorf("expected 8.8.8.8 count=2 at TTL 3, got %d", ttl3["8.8.8.8"])
	}

	// TTL 1: different IPs, both should have count 1
	ttl1, ok := common[1]
	if !ok {
		t.Fatal("expected TTL 1 in common hops map")
	}
	if ttl1["192.168.1.1"] != 1 {
		t.Errorf("expected 192.168.1.1 count=1 at TTL 1, got %d", ttl1["192.168.1.1"])
	}
	if ttl1["172.16.0.1"] != 1 {
		t.Errorf("expected 172.16.0.1 count=1 at TTL 1, got %d", ttl1["172.16.0.1"])
	}
}

func TestRttSparkChar(t *testing.T) {
	tests := []struct {
		name   string
		rtt    time.Duration
		maxRTT time.Duration
		want   rune
	}{
		{
			name:   "zero RTT returns lowest spark",
			rtt:    0,
			maxRTT: 100 * time.Millisecond,
			want:   '▁',
		},
		{
			name:   "max RTT returns highest spark",
			rtt:    100 * time.Millisecond,
			maxRTT: 100 * time.Millisecond,
			want:   '█',
		},
		{
			name:   "half RTT returns middle spark",
			rtt:    50 * time.Millisecond,
			maxRTT: 100 * time.Millisecond,
			want:   sparkChars[3], // 0.5 * 7 = 3.5 -> int(3.5) = 3
		},
		{
			name:   "zero maxRTT returns lowest spark",
			rtt:    0,
			maxRTT: 0,
			want:   '▁',
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rttSparkChar(tt.rtt, tt.maxRTT)
			if got != tt.want {
				t.Errorf("rttSparkChar(%v, %v) = %c, want %c", tt.rtt, tt.maxRTT, got, tt.want)
			}
		})
	}
}

func TestRenderAll_NoLocal(t *testing.T) {
	// Simulate --no-local: only remote sources, no "Local" entry
	paris := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "10.0.0.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 8300 * time.Microsecond},
	})
	paris.Source = "Paris, FR"

	london := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 5100 * time.Microsecond},
	})
	london.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.RenderAll([]*hop.TraceResult{paris, london})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should NOT contain "Local" since no local trace was included
	if strings.Contains(output, "Local") {
		t.Error("no-local output should not contain 'Local'")
	}

	// Should contain both remote sources
	if !strings.Contains(output, "Paris, FR") {
		t.Error("output should contain 'Paris, FR'")
	}
	if !strings.Contains(output, "London, GB") {
		t.Error("output should contain 'London, GB'")
	}

	// Should contain hop IPs from both
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("output should contain Paris hop IP")
	}
	if !strings.Contains(output, "51.89.217.252") {
		t.Error("output should contain London hop IP")
	}
}

func TestColumnWidthCalculation(t *testing.T) {
	tests := []struct {
		name      string
		termWidth int
		numCols   int
		wantMin   int
		wantMax   int
	}{
		{
			name:      "standard terminal 2 cols",
			termWidth: 80,
			numCols:   2,
			wantMin:   25,
			wantMax:   45,
		},
		{
			name:      "wide terminal 3 cols",
			termWidth: 160,
			numCols:   3,
			wantMin:   25,
			wantMax:   45,
		},
		{
			name:      "narrow terminal clamps to min",
			termWidth: 40,
			numCols:   2,
			wantMin:   25,
			wantMax:   25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calcColumnWidth(tt.termWidth, tt.numCols)
			if got < tt.wantMin {
				t.Errorf("calcColumnWidth(%d, %d) = %d, want >= %d", tt.termWidth, tt.numCols, got, tt.wantMin)
			}
			if got > tt.wantMax {
				t.Errorf("calcColumnWidth(%d, %d) = %d, want <= %d", tt.termWidth, tt.numCols, got, tt.wantMax)
			}
		})
	}
}

// --- Backward-compatible RenderAll(local, remotes) via Render() ---

func TestCompareRenderer_BackwardCompat_RenderAll_MultipleRemotes(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remoteNY := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "10.0.0.1", rtt: 300 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 1500 * time.Microsecond},
	})
	remoteNY.Source = "New York, US"

	remoteLon := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 300 * time.Microsecond},
	})
	remoteLon.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)

	// Use the new RenderAll with flat list (local + remotes)
	err := renderer.RenderAll([]*hop.TraceResult{local, remoteNY, remoteLon})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// All sources should appear
	if !strings.Contains(output, "Local") {
		t.Error("output should contain 'Local'")
	}
	if !strings.Contains(output, "New York, US") {
		t.Error("output should contain 'New York, US'")
	}
	if !strings.Contains(output, "London, GB") {
		t.Error("output should contain 'London, GB'")
	}

	// All IPs should appear
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("output should contain New York hop IP")
	}
	if !strings.Contains(output, "51.89.217.252") {
		t.Error("output should contain London hop IP")
	}
}

func TestCompareRenderer_BackwardCompat_RenderAll_UsesRemoteSource(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 300 * time.Microsecond},
	})
	remote.Source = "London, GB, OVH SAS"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.RenderAll([]*hop.TraceResult{local, remote})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "London, GB, OVH SAS") {
		t.Error("output should contain remote source location 'London, GB, OVH SAS' in header")
	}
}

func TestRenderUnified_RTTSparkBars(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 1 * time.Millisecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 50 * time.Millisecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "10.0.0.1", rtt: 1 * time.Millisecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 10 * time.Millisecond},
	})
	remote.Source = "Paris, FR"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true)
	err := renderer.RenderAll([]*hop.TraceResult{local, remote})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should contain sparkline characters
	hasSparkChar := false
	for _, ch := range sparkChars {
		if strings.ContainsRune(output, ch) {
			hasSparkChar = true
			break
		}
	}
	if !hasSparkChar {
		t.Error("output should contain RTT spark bar characters")
	}
}

func TestRenderUnified_CommonHopHighlight(t *testing.T) {
	// Both sources share 8.8.8.8 at TTL 2 - should be rendered
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 1 * time.Millisecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 15 * time.Millisecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "10.0.0.1", rtt: 1 * time.Millisecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 8 * time.Millisecond},
	})
	remote.Source = "Paris, FR"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, true) // noColor = true, so no bold/highlight ANSI codes
	err := renderer.RenderAll([]*hop.TraceResult{local, remote})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// The common IP (8.8.8.8) should appear in both columns at TTL 2
	// Count occurrences of 8.8.8.8 in hop data (excluding header line)
	lines := strings.Split(output, "\n")
	count := 0
	for _, line := range lines {
		if strings.Contains(line, "│") && strings.Contains(line, "8.8.8.8") {
			// Count 8.8.8.8 appearances in hop data lines (not header/summary)
			count += strings.Count(line, "8.8.8.8")
		}
	}
	// Should appear at least twice (once per column at TTL 2)
	if count < 2 {
		t.Errorf("expected 8.8.8.8 to appear at least 2 times in hop data, got %d", count)
	}
}

// Helper types and functions

type testHop struct {
	ttl     int
	ip      string
	rtt     time.Duration
	timeout bool
}

func createTestTraceResult(targetIP string, reached bool, hops []testHop) *hop.TraceResult {
	result := hop.NewTraceResult(targetIP, targetIP)
	result.ReachedTarget = reached

	for _, th := range hops {
		h := hop.NewHop(th.ttl)
		if th.timeout {
			h.AddTimeout()
		} else {
			ip := net.ParseIP(th.ip)
			h.AddProbe(ip, th.rtt)
		}
		result.AddHop(h)
	}

	return result
}
