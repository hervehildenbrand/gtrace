package display

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// asTrace builds a trace whose hops carry the given (ip, asn, org) triples.
func asTrace(source, targetIP string, reached bool, hops ...struct {
	ip  string
	asn uint32
	org string
}) *hop.TraceResult {
	tr := hop.NewTraceResult(targetIP, targetIP)
	tr.Source = source
	tr.ReachedTarget = reached
	for i, spec := range hops {
		h := hop.NewHop(i + 1)
		if spec.ip == "" {
			h.AddTimeout()
		} else {
			h.AddProbe(net.ParseIP(spec.ip), 10*time.Millisecond)
			h.Enrichment = hop.Enrichment{ASN: spec.asn, ASOrg: spec.org}
		}
		tr.AddHop(h)
	}
	return tr
}

type asHop = struct {
	ip  string
	asn uint32
	org string
}

func TestASPath_AggregatesConsecutiveASNs(t *testing.T) {
	tr := asTrace("A", "8.8.8.8", true,
		asHop{"62.1.1.1", 65001, "Orange S.A., FR"},
		asHop{"62.1.1.2", 65001, ""},
		asHop{"8.8.4.1", 65002, "GOOGLE - Google LLC, US"},
		asHop{"8.8.8.8", 65002, ""},
	)

	blocks := asPath(tr)

	if len(blocks) != 2 {
		t.Fatalf("expected 2 AS blocks, got %d: %+v", len(blocks), blocks)
	}
	if blocks[0].asn != 65001 || blocks[0].count != 2 {
		t.Errorf("expected AS65001 ×2, got %+v", blocks[0])
	}
	if blocks[1].asn != 65002 || blocks[1].count != 2 {
		t.Errorf("expected AS65002 ×2, got %+v", blocks[1])
	}
}

func TestASPath_PrivateUnknownAndTimeouts(t *testing.T) {
	tr := asTrace("A", "9.9.9.9", false,
		asHop{"192.168.1.1", 0, ""}, // private
		asHop{"", 0, ""},            // timeout: skipped, must not split the run
		asHop{"10.0.0.1", 0, ""},    // private
		asHop{"203.0.113.7", 0, ""}, // public, no ASN
	)

	blocks := asPath(tr)

	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks (private ×2, ? ×1), got %+v", blocks)
	}
	if !blocks[0].private || blocks[0].count != 2 {
		t.Errorf("expected private ×2, got %+v", blocks[0])
	}
	if blocks[1].private || blocks[1].asn != 0 || blocks[1].count != 1 {
		t.Errorf("expected unknown ×1, got %+v", blocks[1])
	}
}

func TestBlockLabel_ShortOrgAndCount(t *testing.T) {
	got := blockLabel(asBlock{asn: 15169, org: "GOOGLE - Google LLC, US", count: 4}, true)
	if got != "AS15169 GOOGLE ×4" {
		t.Errorf("expected 'AS15169 GOOGLE ×4', got %q", got)
	}
	if got := blockLabel(asBlock{asn: 12876, org: "Scaleway, FR", count: 1}, true); got != "AS12876 Scaleway" {
		t.Errorf("expected count suppressed at 1, got %q", got)
	}
	if got := blockLabel(asBlock{asn: 12876, org: "Scaleway", count: 2}, false); got != "AS12876 ×2" {
		t.Errorf("expected org dropped when withOrg=false, got %q", got)
	}
	if got := blockLabel(asBlock{private: true, count: 2}, true); got != "private ×2" {
		t.Errorf("expected 'private ×2', got %q", got)
	}
}

func TestGraphRenderer_ASOverview_MultiSourceJoins(t *testing.T) {
	a := asTrace("Paris", "8.8.8.8", true,
		asHop{"62.1.1.1", 65001, "Orange"}, asHop{"8.8.8.8", 15169, "GOOGLE"})
	b := asTrace("London", "8.8.8.8", true,
		asHop{"81.2.2.1", 65002, "BT"}, asHop{"8.8.8.8", 15169, "GOOGLE"})
	c := asTrace("Tokyo", "8.8.8.8", true,
		asHop{"43.3.3.1", 65003, "IIJ"}, asHop{"8.8.8.8", 15169, "GOOGLE"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{a, b, c}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Paris", "○─▶ AS65001 Orange", "AS65002 BT", "AS65003 IIJ",
		"┐", "┼─▶ ◎ 8.8.8.8", "┘",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("AS overview missing %q:\n%s", want, out)
		}
	}
}

func TestGraphRenderer_ASOverview_SingleSourceArrow(t *testing.T) {
	tr := asTrace("", "8.8.8.8", true,
		asHop{"62.1.1.1", 65001, "Orange"}, asHop{"8.8.8.8", 15169, "GOOGLE"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{tr}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "─▶ ◎ 8.8.8.8") {
		t.Errorf("expected single-source arrow into target:\n%s", out)
	}
	if strings.Contains(out, "┼") || strings.Contains(out, "┐") {
		t.Errorf("expected no join braces for a single source:\n%s", out)
	}
}

func TestGraphRenderer_ASOverview_UnreachedRowMarked(t *testing.T) {
	a := asTrace("Paris", "8.8.8.8", true,
		asHop{"62.1.1.1", 65001, "Orange"}, asHop{"8.8.8.8", 15169, "GOOGLE"})
	b := asTrace("Madrid", "8.8.8.8", false,
		asHop{"81.2.2.1", 65002, "IONOS"})
	buf := new(bytes.Buffer)
	r := NewGraphRenderer(buf, true)

	if err := r.Render([]*hop.TraceResult{a, b}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	found := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Madrid") && strings.HasSuffix(strings.TrimRight(line, " "), "✕") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Madrid's overview row to end with ✕:\n%s", out)
	}
}
