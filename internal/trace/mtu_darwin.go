//go:build darwin

package trace

import "syscall"

// Darwin socket option numbers not exposed by the syscall package.
const (
	ipDontFrag   = 28 // IP_DONTFRAG
	ipv6DontFrag = 62 // IPV6_DONTFRAG
)

// setDontFragmentProbe sets the Don't Fragment (DF) bit for active probing.
// Darwin has no PMTU-cache enforcement mode, so plain IP_DONTFRAG suffices.
func setDontFragmentProbe(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipDontFrag, 1)
}

// setDontFragmentV6 sets the IPv6 don't-fragment option.
func setDontFragmentV6(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6DontFrag, 1)
}
