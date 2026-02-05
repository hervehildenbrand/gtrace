package globalping

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// DefaultBaseURL is the GlobalPing API base URL.
	DefaultBaseURL = "https://api.globalping.io"

	// DefaultPollInterval is the default interval for polling measurement status.
	DefaultPollInterval = 500 * time.Millisecond

	// DefaultTimeout is the default HTTP client timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultRetryDelay is the default delay between retries on rate limit.
	DefaultRetryDelay = 5 * time.Second

	// DefaultMaxRetries is the default number of retries on rate limit.
	DefaultMaxRetries = 3
)

// RetryCallback is called when a retry is about to happen.
type RetryCallback func(attempt int, delay time.Duration)

// Client is a GlobalPing API client.
type Client struct {
	baseURL       string
	apiKey        string
	httpClient    *http.Client
	pollInterval  time.Duration
	retryDelay    time.Duration
	maxRetries    int
	retryCallback RetryCallback
}

// NewClient creates a new GlobalPing API client.
func NewClient(apiKey string) *Client {
	return &Client{
		baseURL: DefaultBaseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		pollInterval: DefaultPollInterval,
		retryDelay:   DefaultRetryDelay,
		maxRetries:   DefaultMaxRetries,
	}
}

// SetRetryCallback sets a callback to be called when retrying after rate limit.
func (c *Client) SetRetryCallback(cb RetryCallback) {
	c.retryCallback = cb
}

// CreateMeasurement creates a new measurement.
func (c *Client) CreateMeasurement(ctx context.Context, req *MeasurementRequest) (*MeasurementResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/measurements", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result MeasurementResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetMeasurement retrieves the current state of a measurement.
// Retries on rate limit (429) errors.
func (c *Client) GetMeasurement(ctx context.Context, id string) (*MeasurementResult, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		result, err := c.getMeasurementOnce(ctx, id)
		if err == nil {
			return result, nil
		}

		// Check if it's a rate limit error
		if !isRateLimitError(err) {
			return nil, err
		}

		lastErr = err

		// Don't retry if we've exhausted retries
		if attempt >= c.maxRetries {
			break
		}

		// Notify callback about retry
		if c.retryCallback != nil {
			c.retryCallback(attempt+1, c.retryDelay)
		}

		// Wait before retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.retryDelay):
			// Continue to retry
		}
	}

	return nil, lastErr
}

// getMeasurementOnce performs a single measurement retrieval.
func (c *Client) getMeasurementOnce(ctx context.Context, id string) (*MeasurementResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/measurements/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result MeasurementResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// APIError represents an API error response.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Body)
}

// isRateLimitError checks if an error is a rate limit (429) error.
func isRateLimitError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == http.StatusTooManyRequests
	}
	return false
}

// WaitForMeasurement polls until the measurement is complete.
func (c *Client) WaitForMeasurement(ctx context.Context, id string) (*MeasurementResult, error) {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		result, err := c.GetMeasurement(ctx, id)
		if err != nil {
			return nil, err
		}

		if result.Status.IsComplete() {
			return result, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			// Continue polling
		}
	}
}

// RunMeasurement creates a measurement and waits for completion.
func (c *Client) RunMeasurement(ctx context.Context, req *MeasurementRequest) (*MeasurementResult, error) {
	resp, err := c.CreateMeasurement(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create measurement: %w", err)
	}

	return c.WaitForMeasurement(ctx, resp.ID)
}

// setHeaders sets common request headers.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
}

// GetMTRMeasurement retrieves the current state of an MTR measurement.
// Retries on rate limit (429) errors.
func (c *Client) GetMTRMeasurement(ctx context.Context, id string) (*MTRMeasurementResult, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		result, err := c.getMTRMeasurementOnce(ctx, id)
		if err == nil {
			return result, nil
		}

		// Check if it's a rate limit error
		if !isRateLimitError(err) {
			return nil, err
		}

		lastErr = err

		// Don't retry if we've exhausted retries
		if attempt >= c.maxRetries {
			break
		}

		// Notify callback about retry
		if c.retryCallback != nil {
			c.retryCallback(attempt+1, c.retryDelay)
		}

		// Wait before retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.retryDelay):
			// Continue to retry
		}
	}

	return nil, lastErr
}

// getMTRMeasurementOnce performs a single MTR measurement retrieval.
func (c *Client) getMTRMeasurementOnce(ctx context.Context, id string) (*MTRMeasurementResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/measurements/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result MTRMeasurementResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// WaitForMTRMeasurement polls until the MTR measurement is complete.
func (c *Client) WaitForMTRMeasurement(ctx context.Context, id string) (*MTRMeasurementResult, error) {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		result, err := c.GetMTRMeasurement(ctx, id)
		if err != nil {
			return nil, err
		}

		if result.Status.IsComplete() {
			return result, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			// Continue polling
		}
	}
}

// RunMTRMeasurement creates an MTR measurement and waits for completion.
func (c *Client) RunMTRMeasurement(ctx context.Context, req *MeasurementRequest) (*MTRMeasurementResult, error) {
	// Ensure we're using MTR type
	req.Type = MeasurementTypeMTR

	resp, err := c.CreateMeasurement(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create measurement: %w", err)
	}

	return c.WaitForMTRMeasurement(ctx, resp.ID)
}
