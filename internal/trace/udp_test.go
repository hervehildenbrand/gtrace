package trace

import (
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
