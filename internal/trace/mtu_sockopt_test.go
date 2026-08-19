package trace

import (
	"net"
	"runtime"
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

func TestGetSocketMTU_ConnectedSocket(t *testing.T) {
	fd, err := createRawSocket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer closeSocket(fd)

	sa := &syscall.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}
	if err := connectSocket(fd, sa); err != nil {
		t.Fatalf("connect: %v", err)
	}

	mtu, err := getSocketMTU(fd)
	if runtime.GOOS == "linux" {
		if err != nil || mtu < MinMTU {
			t.Errorf("getSocketMTU() = (%d, %v), want (>=%d, nil) on linux", mtu, err, MinMTU)
		}
	} else {
		// No IP_MTU getsockopt on Darwin: callers fall back to binary search.
		if err == nil {
			t.Errorf("getSocketMTU() err = nil, want unsupported error on %s", runtime.GOOS)
		}
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
