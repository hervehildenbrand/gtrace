//go:build darwin

package trace

import (
	"errors"
	"syscall"
)

// Darwin socket option numbers not exposed by the syscall package.
const (
	ipDontFrag   = 28 // IP_DONTFRAG
	ipv6DontFrag = 62 // IPV6_DONTFRAG
)

// setDontFragment sets the Don't Fragment (DF) bit on an IPv4 socket.
func setDontFragment(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipDontFrag, 1)
}

// setDontFragmentProbe sets DF for active probing. Darwin has no PMTU-cache
// enforcement mode, so this is identical to setDontFragment.
func setDontFragmentProbe(fd socketFD) error {
	return setDontFragment(fd)
}

// setDontFragmentV6 sets the IPv6 don't-fragment option.
func setDontFragmentV6(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6DontFrag, 1)
}

// getSocketMTU is unsupported on Darwin (no IP_MTU getsockopt); callers
// fall back to binary search on local EMSGSIZE.
func getSocketMTU(fd socketFD) (int, error) {
	return 0, errors.New("socket MTU query not supported on darwin")
}
