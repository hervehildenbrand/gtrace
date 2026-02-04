package globalping

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient_CreatesClientWithDefaults(t *testing.T) {
	client := NewClient("")

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.baseURL != DefaultBaseURL {
		t.Errorf("expected base URL %q, got %q", DefaultBaseURL, client.baseURL)
	}
}

func TestNewClient_AcceptsAPIKey(t *testing.T) {
	client := NewClient("test-api-key")

	if client.apiKey != "test-api-key" {
		t.Errorf("expected API key 'test-api-key', got %q", client.apiKey)
	}
}

func TestClient_CreateMeasurement_SendsCorrectRequest(t *testing.T) {
	var receivedReq MeasurementRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/measurements" {
			t.Errorf("expected /v1/measurements, got %s", r.URL.Path)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedReq); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MeasurementResponse{
			ID:          "test-measurement-id",
			ProbesCount: 1,
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL

	req := &MeasurementRequest{
		Type:   MeasurementTypeTraceroute,
		Target: "google.com",
		Locations: []Location{
			{Magic: "London"},
		},
	}

	resp, err := client.CreateMeasurement(context.Background(), req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "test-measurement-id" {
		t.Errorf("expected ID 'test-measurement-id', got %q", resp.ID)
	}
	if receivedReq.Target != "google.com" {
		t.Errorf("expected target 'google.com', got %q", receivedReq.Target)
	}
}

func TestClient_CreateMeasurement_IncludesAPIKey(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MeasurementResponse{ID: "id"})
	}))
	defer server.Close()

	client := NewClient("my-api-key")
	client.baseURL = server.URL

	req := &MeasurementRequest{
		Type:   MeasurementTypeTraceroute,
		Target: "google.com",
		Locations: []Location{{Magic: "London"}},
	}

	_, _ = client.CreateMeasurement(context.Background(), req)

	if receivedAuth != "Bearer my-api-key" {
		t.Errorf("expected 'Bearer my-api-key', got %q", receivedAuth)
	}
}

func TestClient_GetMeasurement_ReturnsResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/measurements/test-id" {
			t.Errorf("expected /v1/measurements/test-id, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MeasurementResult{
			ID:     "test-id",
			Status: StatusFinished,
			Results: []ProbeResult{
				{
					Probe: ProbeInfo{City: "London", Country: "GB"},
					Result: TracerouteResult{
						Status:          "finished",
						ResolvedAddress: "8.8.8.8",
						Hops: []TracerouteHop{
							{
								Resolvers: []HopResolver{
									{
										Address: "192.168.1.1",
										Timings: []HopTiming{{RTT: 5.0}},
									},
								},
							},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL

	result, err := client.GetMeasurement(context.Background(), "test-id")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "test-id" {
		t.Errorf("expected ID 'test-id', got %q", result.ID)
	}
	if result.Status != StatusFinished {
		t.Errorf("expected status 'finished', got %q", result.Status)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
}

func TestClient_WaitForMeasurement_PollsUntilComplete(t *testing.T) {
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		status := StatusInProgress
		if calls >= 3 {
			status = StatusFinished
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MeasurementResult{
			ID:     "test-id",
			Status: status,
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond

	result, err := client.WaitForMeasurement(context.Background(), "test-id")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusFinished {
		t.Errorf("expected status 'finished', got %q", result.Status)
	}
	if calls < 3 {
		t.Errorf("expected at least 3 calls, got %d", calls)
	}
}

func TestClient_WaitForMeasurement_RespectsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MeasurementResult{
			ID:     "test-id",
			Status: StatusInProgress,
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.pollInterval = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.WaitForMeasurement(ctx, "test-id")

	if err == nil {
		t.Error("expected error due to context cancellation")
	}
}
