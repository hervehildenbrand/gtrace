package globalping

import (
	"encoding/json"
	"testing"
)

func TestDNSMeasurementResult_DeserializesFromJSON(t *testing.T) {
	raw := `{
		"id": "dns-test-id",
		"type": "dns",
		"status": "finished",
		"results": [
			{
				"probe": {
					"continent": "EU",
					"country": "FR",
					"city": "Paris",
					"asn": 16276,
					"network": "OVH SAS"
				},
				"result": {
					"status": "finished",
					"rawOutput": ";; ANSWER SECTION:\nexample.com. 3600 IN A 93.184.216.34",
					"statusCode": 0,
					"statusCodeName": "NOERROR",
					"resolver": "213.186.33.99",
					"answers": [
						{
							"name": "example.com.",
							"type": "A",
							"ttl": 3600,
							"class": "IN",
							"value": "93.184.216.34"
						}
					],
					"timings": {
						"total": 12.3
					}
				}
			}
		]
	}`

	var result DNSMeasurementResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.ID != "dns-test-id" {
		t.Errorf("expected ID 'dns-test-id', got %q", result.ID)
	}
	if result.Type != MeasurementTypeDNS {
		t.Errorf("expected type 'dns', got %q", result.Type)
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

	r := pr.Result
	if r.StatusCode != 0 {
		t.Errorf("expected StatusCode 0, got %d", r.StatusCode)
	}
	if r.StatusCodeName != "NOERROR" {
		t.Errorf("expected StatusCodeName 'NOERROR', got %q", r.StatusCodeName)
	}
	if r.Resolver != "213.186.33.99" {
		t.Errorf("expected Resolver '213.186.33.99', got %q", r.Resolver)
	}

	// Answers
	if len(r.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(r.Answers))
	}
	a := r.Answers[0]
	if a.Name != "example.com." {
		t.Errorf("expected Name 'example.com.', got %q", a.Name)
	}
	if a.Type != "A" {
		t.Errorf("expected Type 'A', got %q", a.Type)
	}
	if a.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", a.TTL)
	}
	if a.Class != "IN" {
		t.Errorf("expected Class 'IN', got %q", a.Class)
	}
	if a.Value != "93.184.216.34" {
		t.Errorf("expected Value '93.184.216.34', got %q", a.Value)
	}

	// Timings
	if r.Timings.Total != 12.3 {
		t.Errorf("expected Total timing 12.3, got %f", r.Timings.Total)
	}
}

func TestDNSResult_MultipleAnswers(t *testing.T) {
	raw := `{
		"status": "finished",
		"statusCode": 0,
		"statusCodeName": "NOERROR",
		"resolver": "1.1.1.1",
		"answers": [
			{"name": "gmail.com.", "type": "MX", "ttl": 300, "class": "IN", "value": "5 gmail-smtp-in.l.google.com."},
			{"name": "gmail.com.", "type": "MX", "ttl": 300, "class": "IN", "value": "10 alt1.gmail-smtp-in.l.google.com."}
		],
		"timings": {"total": 5.1}
	}`

	var result DNSResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(result.Answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(result.Answers))
	}
	if result.Answers[0].Type != "MX" {
		t.Errorf("expected MX type, got %q", result.Answers[0].Type)
	}
}

func TestDNSResult_TraceMode(t *testing.T) {
	raw := `{
		"status": "finished",
		"rawOutput": ";; trace output",
		"hops": [
			{
				"resolver": "a.root-servers.net",
				"answers": [
					{"name": "com.", "type": "NS", "ttl": 172800, "class": "IN", "value": "a.gtld-servers.net."}
				],
				"timings": {"total": 15.2}
			},
			{
				"resolver": "a.gtld-servers.net",
				"answers": [
					{"name": "example.com.", "type": "A", "ttl": 3600, "class": "IN", "value": "93.184.216.34"}
				],
				"timings": {"total": 8.1}
			}
		]
	}`

	var result DNSTraceResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(result.Hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(result.Hops))
	}
	if result.Hops[0].Resolver != "a.root-servers.net" {
		t.Errorf("expected resolver 'a.root-servers.net', got %q", result.Hops[0].Resolver)
	}
	if result.Hops[0].Timings.Total != 15.2 {
		t.Errorf("expected timing 15.2, got %f", result.Hops[0].Timings.Total)
	}
	if len(result.Hops[0].Answers) != 1 {
		t.Fatalf("expected 1 answer in first hop, got %d", len(result.Hops[0].Answers))
	}
}

func TestMeasurementOptions_DNSFields(t *testing.T) {
	opts := MeasurementOptions{
		Protocol: "UDP",
		Port:     53,
		Resolver: "1.1.1.1",
		Trace:    true,
		Query:    &DNSQuery{Type: "MX"},
	}

	data, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed["resolver"] != "1.1.1.1" {
		t.Errorf("expected resolver '1.1.1.1', got %v", parsed["resolver"])
	}
	if parsed["trace"] != true {
		t.Errorf("expected trace true, got %v", parsed["trace"])
	}
	q, ok := parsed["query"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected query object, got %T", parsed["query"])
	}
	if q["type"] != "MX" {
		t.Errorf("expected query type 'MX', got %v", q["type"])
	}
}
