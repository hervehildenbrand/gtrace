//go:build darwin

package trace

import "syscall"

// setDontFragment sets the Don't Fragment (DF) bit on an IPv4 socket.
// On macOS/BSD this uses IP_DONTFRAG (28).
func setDontFragment(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 28, 1)
}
