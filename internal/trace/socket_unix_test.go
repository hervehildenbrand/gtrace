//go:build !windows

package trace

import (
	"syscall"
	"testing"
)

func TestSetDontFragmentProbe_ValidSocket(t *testing.T) {
	// Create a UDP socket for testing
	fd, err := createRawSocket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		t.Skipf("cannot create socket (may need elevated privileges): %v", err)
	}
	defer closeSocket(fd)

	err = setDontFragmentProbe(fd)
	if err != nil {
		t.Errorf("setDontFragmentProbe() error = %v", err)
	}
}

func TestSetDontFragmentProbe_InvalidSocket(t *testing.T) {
	err := setDontFragmentProbe(invalidSocket)
	if err == nil {
		t.Error("expected error for invalid socket")
	}
}
