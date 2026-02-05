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

func TestClient_GetMTRMeasurement_ReturnsResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MTRMeasurementResult{
			ID:     "test-mtr-id",
			Type:   MeasurementTypeMTR,
			Status: StatusFinished,
			Results: []MTRProbeResult{
				{
					Probe: ProbeInfo{City: "London", Country: "GB"},
					Result: MTRResult{
						Status:          "finished",
						ResolvedAddress: "8.8.8.8",
						Hops: []MTRHop{
							{
								Resolvers: []MTRHopResolver{
									{
										Address:  "192.168.1.1",
										Hostname: "router.local",
										Stats: MTRStats{
											Total: 10,
											Rcv:   10,
											Loss:  0,
											Avg:   5.0,
										},
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

	result, err := client.GetMTRMeasurement(context.Background(), "test-mtr-id")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "test-mtr-id" {
		t.Errorf("expected ID 'test-mtr-id', got %q", result.ID)
	}
	if result.Type != MeasurementTypeMTR {
		t.Errorf("expected type 'mtr', got %q", result.Type)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if len(result.Results[0].Result.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(result.Results[0].Result.Hops))
	}
}

func TestClient_WaitForMTRMeasurement_PollsUntilComplete(t *testing.T) {
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		status := StatusInProgress
		if calls >= 2 {
			status = StatusFinished
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MTRMeasurementResult{
			ID:     "test-mtr-id",
			Type:   MeasurementTypeMTR,
			Status: status,
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.pollInterval = 10 * time.Millisecond

	result, err := client.WaitForMTRMeasurement(context.Background(), "test-mtr-id")

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

func TestClient_GetMeasurement_RetriesOn429(t *testing.T) {
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			// Return 429 for first two calls
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":{"type":"too_many_requests","message":"Too many requests"}}`))
			return
		}
		// Third call succeeds
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MeasurementResult{
			ID:     "test-id",
			Status: StatusFinished,
		})
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.retryDelay = 10 * time.Millisecond // Fast retry for tests

	result, err := client.GetMeasurement(context.Background(), "test-id")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != "test-id" {
		t.Errorf("expected ID 'test-id', got %q", result.ID)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls (2 retries + 1 success), got %d", calls)
	}
}

func TestClient_GetMeasurement_FailsAfterMaxRetries(t *testing.T) {
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// Always return 429
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"type":"too_many_requests","message":"Too many requests"}}`))
	}))
	defer server.Close()

	client := NewClient("")
	client.baseURL = server.URL
	client.retryDelay = 10 * time.Millisecond
	client.maxRetries = 3

	_, err := client.GetMeasurement(context.Background(), "test-id")

	if err == nil {
		t.Fatal("expected error after max retries")
	}
	if calls != 4 {
		t.Errorf("expected 4 calls (1 initial + 3 retries), got %d", calls)
	}
}
