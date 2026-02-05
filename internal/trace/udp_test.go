package trace

import (
	"net"
	"syscall"
	"testing"
)

func TestNewUDPTracer_CreatesTracer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Protocol = ProtocolUDP
	tracer := NewUDPTracer(cfg)

	if tracer == nil {
		t.Fatal("expected non-nil tracer")
	}
	if tracer.config != cfg {
		t.Error("expected config to be stored")
	}
}

func TestUDPTracer_GetPort_ReturnsSequentialPorts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Port = 33434
	tracer := NewUDPTracer(cfg)

	port1 := tracer.getPort(1)
	port2 := tracer.getPort(2)
	port3 := tracer.getPort(3)

	if port1 != 33434 {
		t.Errorf("expected port 33434, got %d", port1)
	}
	if port2 != 33435 {
		t.Errorf("expected port 33435, got %d", port2)
	}
	if port3 != 33436 {
		t.Errorf("expected port 33436, got %d", port3)
	}
}

func TestUDPTracer_BuildPayload_CreatesValidPayload(t *testing.T) {
	cfg := DefaultConfig()
	tracer := NewUDPTracer(cfg)

	payload := tracer.buildPayload(1, 1)

	if len(payload) == 0 {
		t.Error("expected non-empty payload")
	}
}

func TestUDPTracer_GetUDPID_ReturnsProcessID(t *testing.T) {
	cfg := DefaultConfig()
	tracer := NewUDPTracer(cfg)

	id := tracer.getUDPID()

	if id == 0 {
		t.Error("expected non-zero UDP ID")
	}
	if id > 65535 {
		t.Error("UDP ID should fit in 16 bits")
	}
}

func TestUDPTracer_BuildSockaddr_IPv4(t *testing.T) {
	target := net.ParseIP("8.8.8.8")
	port := 33434

	sa := buildSockaddr(target, port)

	sa4, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("expected SockaddrInet4, got %T", sa)
	}
	if sa4.Port != port {
		t.Errorf("expected port %d, got %d", port, sa4.Port)
	}
	// 8.8.8.8
	expected := [4]byte{8, 8, 8, 8}
	if sa4.Addr != expected {
		t.Errorf("expected addr %v, got %v", expected, sa4.Addr)
	}
}

func TestUDPTracer_BuildSockaddr_IPv6(t *testing.T) {
	target := net.ParseIP("2001:4860:4860::8888")
	port := 33434

	sa := buildSockaddr(target, port)

	sa6, ok := sa.(*syscall.SockaddrInet6)
	if !ok {
		t.Fatalf("expected SockaddrInet6, got %T", sa)
	}
	if sa6.Port != port {
		t.Errorf("expected port %d, got %d", port, sa6.Port)
	}
	// Verify first bytes match
	if sa6.Addr[0] != 0x20 || sa6.Addr[1] != 0x01 {
		t.Errorf("expected addr to start with 2001, got %x%x", sa6.Addr[0], sa6.Addr[1])
	}
}

func TestUDPTracer_IsOurProbe_IPv4(t *testing.T) {
	cfg := DefaultConfig()
	tracer := NewUDPTracer(cfg)
	target := net.ParseIP("8.8.8.8")

	// Build mock data: 20 byte IPv4 header + 8 byte UDP header
	data := make([]byte, 28)
	// Dest port at offset 22-23 (20 byte IP header + 2 byte offset in UDP)
	data[22] = 0x82 // 33434 >> 8
	data[23] = 0x9a // 33434 & 0xff

	if !tracer.isOurProbeForIP(data, 33434, target) {
		t.Error("expected probe to be recognized as ours")
	}
	if tracer.isOurProbeForIP(data, 33435, target) {
		t.Error("expected different port to not match")
	}
}

func TestUDPTracer_IsOurProbe_IPv6(t *testing.T) {
	cfg := DefaultConfig()
	tracer := NewUDPTracer(cfg)
	target := net.ParseIP("2001:4860:4860::8888")

	// Build mock data: 40 byte IPv6 header + 8 byte UDP header
	data := make([]byte, 48)
	// Dest port at offset 42-43 (40 byte IP header + 2 byte offset in UDP)
	data[42] = 0x82 // 33434 >> 8
	data[43] = 0x9a // 33434 & 0xff

	if !tracer.isOurProbeForIP(data, 33434, target) {
		t.Error("expected IPv6 probe to be recognized as ours")
	}
	if tracer.isOurProbeForIP(data, 33435, target) {
		t.Error("expected different port to not match")
	}
}
