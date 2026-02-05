//go:build linux

package trace

import "syscall"

// selectWrite checks if a file descriptor is writable using select.
// On Linux, syscall.Select returns (n int, err error).
func selectWrite(fd int) (ready bool, err error) {
	var writeSet syscall.FdSet
	writeSet.Bits[fd/64] |= 1 << (uint(fd) % 64)

	tv := syscall.Timeval{Sec: 0, Usec: 0}
	n, err := syscall.Select(fd+1, nil, &writeSet, nil, &tv)
	if err != nil {
		return false, err
	}
	if n <= 0 {
		return false, nil
	}

	// Check if our fd is set in the write set
	ready = writeSet.Bits[fd/64]&(1<<(uint(fd)%64)) != 0
	return ready, nil
}
