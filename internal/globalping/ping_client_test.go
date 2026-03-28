package globalping

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_GetPingMeasurement_ReturnsResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/measurements/ping-id" {
			t.Errorf("expected /v1/measurements/ping-id, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PingMeasurementResult{
			ID:     "ping-id",
			Type:   MeasurementTypePing,
			Status: StatusFinished,
			Results: []PingProbeResult{
				{
					Probe: ProbeInfo{City: "Paris", Country: "FR"},
					Result: PingResult{
						Status:          "finished",
						ResolvedAddress: "8.8.8.8",
						Stats: PingStats{
							Total: 3,
							Rcv:   3,
							Loss:  0,
						},
						Timings: []PingTiming{
							{RTT: 1.2, TTL: 57},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL

	result, err := client.GetPingMeasurement(context.Background(), "ping-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "ping-id" {
		t.Errorf("expected ID 'ping-id', got %q", result.ID)
	}
	if result.Type != MeasurementTypePing {
		t.Errorf("expected type 'ping', got %q", result.Type)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if result.Results[0].Result.Stats.Total != 3 {
		t.Errorf("expected Total 3, got %d", result.Results[0].Result.Stats.Total)
	}
}

func TestClient_WaitForPingMeasurement_PollsUntilComplete(t *testing.T) {
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		status := StatusInProgress
		if calls >= 2 {
			status = StatusFinished
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PingMeasurementResult{
			ID:     "ping-id",
			Type:   MeasurementTypePing,
			Status: status,
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond

	result, err := client.WaitForPingMeasurement(context.Background(), "ping-id")
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

func TestClient_RunPingMeasurement_CreatesAndWaits(t *testing.T) {
	var receivedReq MeasurementRequest
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "POST" {
			json.NewDecoder(r.Body).Decode(&receivedReq)
			json.NewEncoder(w).Encode(MeasurementResponse{
				ID:          "ping-id",
				ProbesCount: 1,
			})
			return
		}

		calls++
		json.NewEncoder(w).Encode(PingMeasurementResult{
			ID:     "ping-id",
			Type:   MeasurementTypePing,
			Status: StatusFinished,
			Results: []PingProbeResult{
				{
					Probe:  ProbeInfo{City: "Paris"},
					Result: PingResult{Stats: PingStats{Total: 3, Rcv: 3}},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond

	req := &MeasurementRequest{
		Type:      MeasurementTypePing,
		Target:    "8.8.8.8",
		Locations: []Location{{Magic: "Paris"}},
	}

	result, err := client.RunPingMeasurement(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "ping-id" {
		t.Errorf("expected ID 'ping-id', got %q", result.ID)
	}
	if receivedReq.Type != MeasurementTypePing {
		t.Errorf("expected request type 'ping', got %q", receivedReq.Type)
	}
}
