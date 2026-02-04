package globalping

import (
	"testing"
)

func TestMeasurementRequest_ValidateTarget(t *testing.T) {
	req := &MeasurementRequest{
		Type:   "traceroute",
		Target: "google.com",
		Locations: []Location{
			{Magic: "London"},
		},
	}

	if err := req.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMeasurementRequest_ValidateRejectsEmptyTarget(t *testing.T) {
	req := &MeasurementRequest{
		Type:   "traceroute",
		Target: "",
		Locations: []Location{
			{Magic: "London"},
		},
	}

	if err := req.Validate(); err == nil {
		t.Error("expected error for empty target")
	}
}

func TestMeasurementRequest_ValidateRejectsNoLocations(t *testing.T) {
	req := &MeasurementRequest{
		Type:      "traceroute",
		Target:    "google.com",
		Locations: []Location{},
	}

	if err := req.Validate(); err == nil {
		t.Error("expected error for empty locations")
	}
}

func TestLocation_ParseMagic_City(t *testing.T) {
	loc := ParseLocationString("London")

	if loc.Magic != "London" {
		t.Errorf("expected magic 'London', got %q", loc.Magic)
	}
}

func TestLocation_ParseMagic_Country(t *testing.T) {
	loc := ParseLocationString("DE")

	if loc.Magic != "DE" {
		t.Errorf("expected magic 'DE', got %q", loc.Magic)
	}
}

func TestLocation_ParseMagic_ASN(t *testing.T) {
	loc := ParseLocationString("AS13335")

	if loc.Magic != "AS13335" {
		t.Errorf("expected magic 'AS13335', got %q", loc.Magic)
	}
}

func TestLocation_ParseMagic_CloudRegion(t *testing.T) {
	loc := ParseLocationString("AWS+us-east-1")

	if loc.Magic != "AWS+us-east-1" {
		t.Errorf("expected magic 'AWS+us-east-1', got %q", loc.Magic)
	}
}

func TestParseLocationStrings_ParsesMultiple(t *testing.T) {
	locs := ParseLocationStrings("London,Tokyo,NYC")

	if len(locs) != 3 {
		t.Fatalf("expected 3 locations, got %d", len(locs))
	}
	if locs[0].Magic != "London" {
		t.Errorf("expected first location 'London', got %q", locs[0].Magic)
	}
	if locs[1].Magic != "Tokyo" {
		t.Errorf("expected second location 'Tokyo', got %q", locs[1].Magic)
	}
	if locs[2].Magic != "NYC" {
		t.Errorf("expected third location 'NYC', got %q", locs[2].Magic)
	}
}

func TestMeasurementStatus_IsComplete(t *testing.T) {
	tests := []struct {
		status   string
		expected bool
	}{
		{"finished", true},
		{"in-progress", false},
		{"failed", true},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			ms := MeasurementStatus(tt.status)
			if ms.IsComplete() != tt.expected {
				t.Errorf("IsComplete() = %v, want %v", ms.IsComplete(), tt.expected)
			}
		})
	}
}

func TestTracerouteHop_ToHop_ConvertsCorrectly(t *testing.T) {
	th := &TracerouteHop{
		Resolvers: []HopResolver{
			{
				Address: "192.168.1.1",
				Hostname: "router.local",
				ASN:     12345,
				Timings: []HopTiming{
					{RTT: 5.5},
					{RTT: 6.0},
				},
			},
		},
	}

	h := th.ToHop(1)

	if h.TTL != 1 {
		t.Errorf("expected TTL 1, got %d", h.TTL)
	}
	if len(h.Probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(h.Probes))
	}
	if h.Enrichment.ASN != 12345 {
		t.Errorf("expected ASN 12345, got %d", h.Enrichment.ASN)
	}
}
