//go:build linux

package trace

import "syscall"

// setDontFragment sets the Don't Fragment (DF) bit on an IPv4 socket.
// On Linux this uses IP_MTU_DISCOVER (10) with IP_PMTUDISC_DO (2).
func setDontFragment(fd socketFD) error {
	const (
		ipMTUDiscover = 10 // IP_MTU_DISCOVER
		ipPMTUDiscDo  = 2  // IP_PMTUDISC_DO
	)
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscDo)
}
