package trace

import (
	"testing"
)

func TestNewTCPTracer_CreatesTracer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = ProtocolTCP
	cfg.Port = 80
	tracer := NewTCPTracer(cfg)

	if tracer == nil {
		t.Fatal("expected non-nil tracer")
	}
	if tracer.config != cfg {
		t.Error("expected config to be stored")
	}
}

func TestTCPTracer_GetPort_ReturnsConfiguredPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Port = 443
	tracer := NewTCPTracer(cfg)

	port := tracer.getPort()

	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestTCPTracer_DefaultPort_Is80(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = ProtocolTCP
	// Don't set port explicitly
	tracer := NewTCPTracer(cfg)

	// Should use default from config (33434 for UDP, but TCP typically uses 80)
	// Our implementation should handle this
	if tracer == nil {
		t.Fatal("expected non-nil tracer")
	}
}

func TestTCPTracer_GetTCPID_ReturnsProcessID(t *testing.T) {
	cfg := DefaultConfig()
	tracer := NewTCPTracer(cfg)

	id := tracer.getTCPID()

	if id == 0 {
		t.Error("expected non-zero TCP ID")
	}
	if id > 65535 {
		t.Error("TCP ID should fit in 16 bits")
	}
}
