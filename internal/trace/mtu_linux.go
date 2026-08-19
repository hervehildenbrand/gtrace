//go:build linux

package trace

import "syscall"

// Linux IP-level socket option numbers not exposed by the syscall package.
const (
	ipMTUDiscover   = 10 // IP_MTU_DISCOVER
	ipPMTUDiscDo    = 2  // IP_PMTUDISC_DO: DF set, kernel enforces PMTU cache
	ipPMTUDiscProbe = 3  // IP_PMTUDISC_PROBE: DF set, cache ignored (for probing)
	ipMTU           = 14 // IP_MTU (getsockopt, connected sockets only)
	ipv6MTUDiscover = 23 // IPV6_MTU_DISCOVER
)

// setDontFragment sets the Don't Fragment (DF) bit on an IPv4 socket.
// The kernel enforces its PMTU cache: oversized sends fail with EMSGSIZE.
func setDontFragment(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscDo)
}

// setDontFragmentProbe sets DF while bypassing the kernel PMTU cache so
// deliberately oversized probes actually leave the host (tracepath-style).
func setDontFragmentProbe(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscProbe)
}

// setDontFragmentV6 is the IPv6 equivalent of setDontFragmentProbe.
func setDontFragmentV6(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6MTUDiscover, ipPMTUDiscProbe)
}

// getSocketMTU reads the kernel's cached path MTU for a connected socket.
// Used to turn a local EMSGSIZE into a discovery signal.
func getSocketMTU(fd socketFD) (int, error) {
	return syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTU)
}
