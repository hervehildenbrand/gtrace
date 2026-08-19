package trace

import (
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
