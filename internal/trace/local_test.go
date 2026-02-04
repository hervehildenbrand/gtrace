package trace

import (
	"testing"
)

func TestNewLocalTracer_CreatesICMPByDefault(t *testing.T) {
	cfg := DefaultConfig()

	tracer, err := NewLocalTracer(cfg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tracer == nil {
		t.Fatal("expected non-nil tracer")
	}
	if _, ok := tracer.(*ICMPTracer); !ok {
		t.Error("expected ICMP tracer by default")
	}
}

func TestNewLocalTracer_CreatesUDPTracer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = ProtocolUDP

	tracer, err := NewLocalTracer(cfg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := tracer.(*UDPTracer); !ok {
		t.Error("expected UDP tracer")
	}
}

func TestNewLocalTracer_CreatesTCPTracer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = ProtocolTCP

	tracer, err := NewLocalTracer(cfg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := tracer.(*TCPTracer); !ok {
		t.Error("expected TCP tracer")
	}
}

func TestNewLocalTracer_RejectsInvalidProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = Protocol("invalid")

	_, err := NewLocalTracer(cfg)

	if err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestNewLocalTracer_ValidatesConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxHops = 0 // Invalid

	_, err := NewLocalTracer(cfg)

	if err == nil {
		t.Error("expected error for invalid config")
	}
}
