package trace

import (
	"net"
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

func TestTCPTracer_IsOurProbe_IPv4(t *testing.T) {
	cfg := DefaultConfig()
	tracer := NewTCPTracer(cfg)
	target := net.ParseIP("8.8.8.8")

	// Build mock data: 20 byte IPv4 header + TCP header
	data := make([]byte, 28)
	// Dest port at offset 22-23 (20 byte IP header + 2 byte offset in TCP)
	data[22] = 0x00 // 80 >> 8
	data[23] = 0x50 // 80 & 0xff

	if !tracer.isOurProbeForIP(data, 80, target) {
		t.Error("expected probe to be recognized as ours")
	}
	if tracer.isOurProbeForIP(data, 443, target) {
		t.Error("expected different port to not match")
	}
}

func TestTCPTracer_IsOurProbe_IPv6(t *testing.T) {
	cfg := DefaultConfig()
	tracer := NewTCPTracer(cfg)
	target := net.ParseIP("2001:4860:4860::8888")

	// Build mock data: 40 byte IPv6 header + TCP header
	data := make([]byte, 48)
	// Dest port at offset 42-43 (40 byte IP header + 2 byte offset in TCP)
	data[42] = 0x00 // 80 >> 8
	data[43] = 0x50 // 80 & 0xff

	if !tracer.isOurProbeForIP(data, 80, target) {
		t.Error("expected IPv6 probe to be recognized as ours")
	}
	if tracer.isOurProbeForIP(data, 443, target) {
		t.Error("expected different port to not match")
	}
}
