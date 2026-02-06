//go:build !windows

package trace

import (
	"syscall"
	"testing"
)

func TestSetDontFragment_ValidSocket(t *testing.T) {
	// Create a UDP socket for testing
	fd, err := createRawSocket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		t.Skipf("cannot create socket (may need elevated privileges): %v", err)
	}
	defer closeSocket(fd)

	err = setDontFragment(fd)
	if err != nil {
		t.Errorf("setDontFragment() error = %v", err)
	}
}

func TestSetDontFragment_InvalidSocket(t *testing.T) {
	err := setDontFragment(invalidSocket)
	if err == nil {
		t.Error("expected error for invalid socket")
	}
}
