package trace

import (
	"net"
	"syscall"
)

// IsIPv6 returns true if the IP is an IPv6 address (not IPv4 or IPv4-mapped).
func IsIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// IsIPv4 returns true if the IP is an IPv4 address (including IPv4-mapped IPv6).
func IsIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

// SocketDomain returns the socket domain (AF_INET or AF_INET6) for the given IP.
func SocketDomain(ip net.IP) int {
	if IsIPv6(ip) {
		return syscall.AF_INET6
	}
	return syscall.AF_INET
}

// ICMPProtocol returns the ICMP protocol string for use with icmp.ListenPacket.
// Returns "ip4:icmp" for IPv4 or "ip6:ipv6-icmp" for IPv6.
func ICMPProtocol(ip net.IP) string {
	if IsIPv6(ip) {
		return "ip6:ipv6-icmp"
	}
	return "ip4:icmp"
}

// ICMPProtocolNum returns the ICMP protocol number for parsing ICMP messages.
// Returns 1 for IPv4 ICMP or 58 for IPv6 ICMPv6.
func ICMPProtocolNum(ip net.IP) int {
	if IsIPv6(ip) {
		return 58 // ICMPv6
	}
	return 1 // ICMPv4
}

// ListenAddress returns the appropriate listen address for the given IP version.
// Returns "0.0.0.0" for IPv4 or "::" for IPv6.
func ListenAddress(ip net.IP) string {
	if IsIPv6(ip) {
		return "::"
	}
	return "0.0.0.0"
}

// TTLSocketOption returns the socket option for setting TTL/hop limit.
// Returns IP_TTL for IPv4 or IPV6_UNICAST_HOPS for IPv6.
func TTLSocketOption(ip net.IP) int {
	if IsIPv6(ip) {
		return syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IP_TTL
}

// ProtocolLevel returns the protocol level for socket options.
// Returns IPPROTO_IP for IPv4 or IPPROTO_IPV6 for IPv6.
func ProtocolLevel(ip net.IP) int {
	if IsIPv6(ip) {
		return syscall.IPPROTO_IPV6
	}
	return syscall.IPPROTO_IP
}

// IPHeaderSize returns the IP header size in bytes.
// Returns 20 for IPv4 or 40 for IPv6.
func IPHeaderSize(ip net.IP) int {
	if IsIPv6(ip) {
		return 40
	}
	return 20
}
