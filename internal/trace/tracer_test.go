package trace

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestTracerConfig_DefaultValues(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxHops != 30 {
		t.Errorf("expected MaxHops 30, got %d", cfg.MaxHops)
	}
	// MTR-style defaults: 1 packet per hop, 500ms timeout
	if cfg.PacketsPerHop != 1 {
		t.Errorf("expected PacketsPerHop 1 (MTR-style), got %d", cfg.PacketsPerHop)
	}
	if cfg.Timeout != 500*time.Millisecond {
		t.Errorf("expected Timeout 500ms (MTR-style), got %v", cfg.Timeout)
	}
	if cfg.Protocol != ProtocolICMP {
		t.Errorf("expected Protocol ICMP, got %v", cfg.Protocol)
	}
}

func TestTracerConfig_Validate_RejectsInvalidProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = Protocol("invalid")

	err := cfg.Validate()

	if err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestTracerConfig_Validate_RejectsZeroMaxHops(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxHops = 0

	err := cfg.Validate()

	if err == nil {
		t.Error("expected error for zero max hops")
	}
}

func TestTracerConfig_Validate_RejectsNegativeTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = -1 * time.Second

	err := cfg.Validate()

	if err == nil {
		t.Error("expected error for negative timeout")
	}
}

func TestResolveTarget_ResolvesHostname(t *testing.T) {
	ip, err := ResolveTarget("localhost", AddressFamilyAuto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// localhost should resolve to 127.0.0.1 or ::1
	if ip == nil {
		t.Error("expected non-nil IP")
	}
}

func TestResolveTarget_AcceptsIPAddress(t *testing.T) {
	ip, err := ResolveTarget("8.8.8.8", AddressFamilyAuto)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8, got %v", ip)
	}
}

func TestResolveTarget_RejectsInvalidHostname(t *testing.T) {
	_, err := ResolveTarget("this.hostname.definitely.does.not.exist.invalid", AddressFamilyAuto)

	if err == nil {
		t.Error("expected error for invalid hostname")
	}
}

func TestResolveTarget_IPv4Literal_WithIPv4Family(t *testing.T) {
	ip, err := ResolveTarget("8.8.8.8", AddressFamilyIPv4)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8, got %v", ip)
	}
}

func TestResolveTarget_IPv6Literal_WithIPv6Family(t *testing.T) {
	ip, err := ResolveTarget("2001:4860:4860::8888", AddressFamilyIPv6)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := net.ParseIP("2001:4860:4860::8888")
	if !ip.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ip)
	}
}

func TestResolveTarget_IPv4Literal_WithIPv6Family_Rejects(t *testing.T) {
	_, err := ResolveTarget("8.8.8.8", AddressFamilyIPv6)

	if err == nil {
		t.Error("expected error when forcing IPv6 on IPv4 literal")
	}
}

func TestResolveTarget_IPv6Literal_WithIPv4Family_Rejects(t *testing.T) {
	_, err := ResolveTarget("2001:4860:4860::8888", AddressFamilyIPv4)

	if err == nil {
		t.Error("expected error when forcing IPv4 on IPv6 literal")
	}
}

func TestAddressFamily_Constants(t *testing.T) {
	// Verify constant values are distinct
	if AddressFamilyAuto == AddressFamilyIPv4 {
		t.Error("AddressFamilyAuto should not equal AddressFamilyIPv4")
	}
	if AddressFamilyAuto == AddressFamilyIPv6 {
		t.Error("AddressFamilyAuto should not equal AddressFamilyIPv6")
	}
	if AddressFamilyIPv4 == AddressFamilyIPv6 {
		t.Error("AddressFamilyIPv4 should not equal AddressFamilyIPv6")
	}
}

// MockTracer for testing the trace flow without raw sockets
type MockTracer struct {
	hops []*hop.Hop
	err  error
}

func (m *MockTracer) Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error) {
	if m.err != nil {
		return nil, m.err
	}

	result := hop.NewTraceResult("mock", target.String())
	for _, h := range m.hops {
		result.AddHop(h)
		if callback != nil {
			callback(h)
		}
	}
	return result, nil
}

func TestTracer_Interface_AcceptsCallback(t *testing.T) {
	mockHop := hop.NewHop(1)
	mockHop.AddProbe(net.ParseIP("192.168.1.1"), 5*time.Millisecond)

	tracer := &MockTracer{
		hops: []*hop.Hop{mockHop},
	}

	var receivedHops []*hop.Hop
	callback := func(h *hop.Hop) {
		receivedHops = append(receivedHops, h)
	}

	result, err := tracer.Trace(context.Background(), net.ParseIP("8.8.8.8"), callback)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivedHops) != 1 {
		t.Errorf("expected 1 callback, got %d", len(receivedHops))
	}
	if result.TotalHops() != 1 {
		t.Errorf("expected 1 hop, got %d", result.TotalHops())
	}
}
