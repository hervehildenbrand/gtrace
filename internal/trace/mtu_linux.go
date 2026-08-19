//go:build linux

package trace

import "syscall"

// Linux IP-level socket option numbers not exposed by the syscall package.
const (
	ipMTUDiscover   = 10 // IP_MTU_DISCOVER
	ipPMTUDiscProbe = 3  // IP_PMTUDISC_PROBE: DF set, kernel PMTU cache ignored
	ipv6MTUDiscover = 23 // IPV6_MTU_DISCOVER
)

// setDontFragmentProbe sets DF while bypassing the kernel PMTU cache so
// deliberately oversized probes actually leave the host (tracepath-style).
// IP_PMTUDISC_DO would fail such sends locally once the cache warms.
func setDontFragmentProbe(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTUDiscover, ipPMTUDiscProbe)
}

// setDontFragmentV6 is the IPv6 equivalent of setDontFragmentProbe.
func setDontFragmentV6(fd socketFD) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6MTUDiscover, ipPMTUDiscProbe)
}
