package trace

import (
	"net"
	"syscall"
	"testing"
)

func TestSetDontFragmentProbe_AppliesToUDPSocket(t *testing.T) {
	fd, err := createRawSocket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer closeSocket(fd)

	if err := setDontFragmentProbe(fd); err != nil {
		t.Errorf("setDontFragmentProbe() = %v, want nil", err)
	}
}

func TestSetDontFragmentV6_AppliesToUDP6Socket(t *testing.T) {
	fd, err := createRawSocket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer closeSocket(fd)

	if err := setDontFragmentV6(fd); err != nil {
		t.Errorf("setDontFragmentV6() = %v, want nil", err)
	}
}

func TestApplyDontFragment_IPv4PacketConn(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	if err := applyDontFragment(pc, false); err != nil {
		t.Errorf("applyDontFragment(v4) = %v, want nil", err)
	}
}

func TestApplyDontFragment_IPv6PacketConn(t *testing.T) {
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer pc.Close()

	if err := applyDontFragment(pc, true); err != nil {
		t.Errorf("applyDontFragment(v6) = %v, want nil", err)
	}
}
