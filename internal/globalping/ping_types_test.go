package globalping

import (
	"encoding/json"
	"testing"
)

func TestPingMeasurementResult_DeserializesFromJSON(t *testing.T) {
	raw := `{
		"id": "ping-test-id",
		"type": "ping",
		"status": "finished",
		"results": [
			{
				"probe": {
					"continent": "EU",
					"region": "Western Europe",
					"country": "FR",
					"city": "Paris",
					"asn": 16276,
					"network": "OVH SAS"
				},
				"result": {
					"status": "finished",
					"rawOutput": "PING 8.8.8.8 ...",
					"resolvedAddress": "8.8.8.8",
					"resolvedHostname": "dns.google",
					"stats": {
						"min": 1.2,
						"avg": 1.5,
						"max": 1.8,
						"total": 3,
						"rcv": 3,
						"drop": 0,
						"loss": 0.0
					},
					"timings": [
						{"rtt": 1.2, "ttl": 57},
						{"rtt": 1.5, "ttl": 57},
						{"rtt": 1.8, "ttl": 57}
					]
				}
			}
		]
	}`

	var result PingMeasurementResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.ID != "ping-test-id" {
		t.Errorf("expected ID 'ping-test-id', got %q", result.ID)
	}
	if result.Type != MeasurementTypePing {
		t.Errorf("expected type 'ping', got %q", result.Type)
	}
	if result.Status != StatusFinished {
		t.Errorf("expected status 'finished', got %q", result.Status)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}

	pr := result.Results[0]
	if pr.Probe.City != "Paris" {
		t.Errorf("expected City 'Paris', got %q", pr.Probe.City)
	}
	if pr.Probe.ASN != 16276 {
		t.Errorf("expected ASN 16276, got %d", pr.Probe.ASN)
	}

	r := pr.Result
	if r.ResolvedAddress != "8.8.8.8" {
		t.Errorf("expected resolved address '8.8.8.8', got %q", r.ResolvedAddress)
	}
	if r.ResolvedHostname != "dns.google" {
		t.Errorf("expected resolved hostname 'dns.google', got %q", r.ResolvedHostname)
	}

	// Stats
	if r.Stats.Total != 3 {
		t.Errorf("expected Total 3, got %d", r.Stats.Total)
	}
	if r.Stats.Rcv != 3 {
		t.Errorf("expected Rcv 3, got %d", r.Stats.Rcv)
	}
	if r.Stats.Drop != 0 {
		t.Errorf("expected Drop 0, got %d", r.Stats.Drop)
	}
	if r.Stats.Loss != 0.0 {
		t.Errorf("expected Loss 0.0, got %f", r.Stats.Loss)
	}
	if r.Stats.Min == nil || *r.Stats.Min != 1.2 {
		t.Errorf("expected Min 1.2, got %v", r.Stats.Min)
	}
	if r.Stats.Avg == nil || *r.Stats.Avg != 1.5 {
		t.Errorf("expected Avg 1.5, got %v", r.Stats.Avg)
	}
	if r.Stats.Max == nil || *r.Stats.Max != 1.8 {
		t.Errorf("expected Max 1.8, got %v", r.Stats.Max)
	}

	// Timings
	if len(r.Timings) != 3 {
		t.Fatalf("expected 3 timings, got %d", len(r.Timings))
	}
	if r.Timings[0].RTT != 1.2 {
		t.Errorf("expected first RTT 1.2, got %f", r.Timings[0].RTT)
	}
	if r.Timings[0].TTL != 57 {
		t.Errorf("expected first TTL 57, got %d", r.Timings[0].TTL)
	}
}

func TestPingResult_NullableStats(t *testing.T) {
	// When all packets are lost, min/avg/max are null
	raw := `{
		"status": "finished",
		"resolvedAddress": "10.0.0.1",
		"stats": {
			"min": null,
			"avg": null,
			"max": null,
			"total": 3,
			"rcv": 0,
			"drop": 3,
			"loss": 100.0
		},
		"timings": []
	}`

	var result PingResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.Stats.Min != nil {
		t.Errorf("expected Min nil, got %v", result.Stats.Min)
	}
	if result.Stats.Avg != nil {
		t.Errorf("expected Avg nil, got %v", result.Stats.Avg)
	}
	if result.Stats.Max != nil {
		t.Errorf("expected Max nil, got %v", result.Stats.Max)
	}
	if result.Stats.Loss != 100.0 {
		t.Errorf("expected Loss 100.0, got %f", result.Stats.Loss)
	}
	if result.Stats.Drop != 3 {
		t.Errorf("expected Drop 3, got %d", result.Stats.Drop)
	}
}
