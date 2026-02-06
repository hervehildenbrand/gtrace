package display

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

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
	renderer := NewCompareRenderer(&buf, false)
	err := renderer.Render(local, remote, "London")

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
		{ttl: 2, ip: "", rtt: 0, timeout: true}, // timeout
		{ttl: 3, ip: "", rtt: 0, timeout: true}, // timeout
	})
	remote.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, false)
	err := renderer.Render(local, remote, "London")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should indicate local reached but remote didn't
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
	renderer := NewCompareRenderer(&buf, false)
	err := renderer.Render(local, remote, "London")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should show both hop counts in summary
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
		{ttl: 2, ip: "", rtt: 0, timeout: true}, // timeout
		{ttl: 3, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remote := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "", rtt: 0, timeout: true}, // timeout
		{ttl: 2, ip: "10.162.9.142", rtt: 500 * time.Microsecond},
		{ttl: 3, ip: "8.8.8.8", rtt: 300 * time.Microsecond},
	})
	remote.Source = "London, GB"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, false)
	err := renderer.Render(local, remote, "London")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should show timeout markers
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
	err := renderer.Render(local, remote, "London")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should not contain ANSI escape codes
	if strings.Contains(output, "\033[") {
		t.Error("output should not contain ANSI escape codes when noColor is true")
	}
}

func TestCompareRenderer_RenderAll_MultipleRemotes(t *testing.T) {
	local := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "192.168.1.1", rtt: 500 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 2000 * time.Microsecond},
	})
	local.Source = "Local"

	remoteNY := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "10.0.0.1", rtt: 300 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 1500 * time.Microsecond},
	})
	remoteNY.Source = "New York, US, Comcast"

	remoteLon := createTestTraceResult("8.8.8.8", true, []testHop{
		{ttl: 1, ip: "51.89.217.252", rtt: 400 * time.Microsecond},
		{ttl: 2, ip: "8.8.8.8", rtt: 300 * time.Microsecond},
	})
	remoteLon.Source = "London, GB, OVH SAS"

	var buf bytes.Buffer
	renderer := NewCompareRenderer(&buf, false)
	err := renderer.RenderAll(local, []*hop.TraceResult{remoteNY, remoteLon})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Both remotes should appear in output
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("output should contain New York hop IP")
	}
	if !strings.Contains(output, "51.89.217.252") {
		t.Error("output should contain London hop IP")
	}

	// Separator should appear between comparisons
	if !strings.Contains(output, "===") {
		t.Error("output should contain === separator between comparisons")
	}
}

func TestCompareRenderer_RenderAll_SingleRemote_NoSeparator(t *testing.T) {
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
	renderer := NewCompareRenderer(&buf, false)
	err := renderer.RenderAll(local, []*hop.TraceResult{remote})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should show the comparison
	if !strings.Contains(output, "51.89.217.252") {
		t.Error("output should contain remote hop IP")
	}

	// Should NOT have separator for single remote
	if strings.Contains(output, "===") {
		t.Error("output should not contain === separator for single remote")
	}
}

func TestCompareRenderer_RenderAll_UsesRemoteSource(t *testing.T) {
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
	renderer := NewCompareRenderer(&buf, false)
	err := renderer.RenderAll(local, []*hop.TraceResult{remote})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should use remote.Source (from formatProbeLocation) as column header
	if !strings.Contains(output, "London, GB, OVH SAS") {
		t.Error("output should contain remote source location 'London, GB, OVH SAS' in header")
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
