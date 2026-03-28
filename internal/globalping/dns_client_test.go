package globalping

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_GetDNSMeasurement_ReturnsResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/measurements/dns-id" {
			t.Errorf("expected /v1/measurements/dns-id, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DNSMeasurementResult{
			ID:     "dns-id",
			Type:   MeasurementTypeDNS,
			Status: StatusFinished,
			Results: []DNSProbeResult{
				{
					Probe: ProbeInfo{City: "Paris", Country: "FR"},
					Result: DNSResult{
						Status:         "finished",
						StatusCode:     0,
						StatusCodeName: "NOERROR",
						Resolver:       "1.1.1.1",
						Answers: []DNSAnswer{
							{Name: "example.com.", Type: "A", TTL: 3600, Class: "IN", Value: "93.184.216.34"},
						},
						Timings: DNSTiming{Total: 12.3},
					},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL

	result, err := client.GetDNSMeasurement(context.Background(), "dns-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "dns-id" {
		t.Errorf("expected ID 'dns-id', got %q", result.ID)
	}
	if result.Type != MeasurementTypeDNS {
		t.Errorf("expected type 'dns', got %q", result.Type)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if len(result.Results[0].Result.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(result.Results[0].Result.Answers))
	}
}

func TestClient_WaitForDNSMeasurement_PollsUntilComplete(t *testing.T) {
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		status := StatusInProgress
		if calls >= 2 {
			status = StatusFinished
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DNSMeasurementResult{
			ID:     "dns-id",
			Type:   MeasurementTypeDNS,
			Status: status,
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond

	result, err := client.WaitForDNSMeasurement(context.Background(), "dns-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusFinished {
		t.Errorf("expected status 'finished', got %q", result.Status)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 calls, got %d", calls)
	}
}

func TestClient_RunDNSMeasurement_CreatesAndWaits(t *testing.T) {
	var receivedReq MeasurementRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "POST" {
			json.NewDecoder(r.Body).Decode(&receivedReq)
			json.NewEncoder(w).Encode(MeasurementResponse{
				ID:          "dns-id",
				ProbesCount: 1,
			})
			return
		}

		json.NewEncoder(w).Encode(DNSMeasurementResult{
			ID:     "dns-id",
			Type:   MeasurementTypeDNS,
			Status: StatusFinished,
			Results: []DNSProbeResult{
				{
					Probe: ProbeInfo{City: "Paris"},
					Result: DNSResult{
						StatusCodeName: "NOERROR",
						Answers: []DNSAnswer{
							{Name: "example.com.", Type: "A", Value: "93.184.216.34"},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond

	req := &MeasurementRequest{
		Type:      MeasurementTypeDNS,
		Target:    "example.com",
		Locations: []Location{{Magic: "Paris"}},
		Options: MeasurementOptions{
			Query: &DNSQuery{Type: "A"},
		},
	}

	result, err := client.RunDNSMeasurement(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "dns-id" {
		t.Errorf("expected ID 'dns-id', got %q", result.ID)
	}
	if receivedReq.Type != MeasurementTypeDNS {
		t.Errorf("expected request type 'dns', got %q", receivedReq.Type)
	}
	if receivedReq.Options.Query == nil || receivedReq.Options.Query.Type != "A" {
		t.Errorf("expected query type 'A' in request")
	}
}
