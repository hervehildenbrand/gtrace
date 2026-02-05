package trace

import (
	"net"
	"syscall"
	"testing"
)

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected bool
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), false},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), true},
		{"IPv4-mapped IPv6", net.ParseIP("::ffff:8.8.8.8"), false}, // Should return false (it's really IPv4)
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), false},
		{"Loopback IPv6", net.ParseIP("::1"), true},
		{"nil IP", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIPv6(tt.ip)
			if result != tt.expected {
				t.Errorf("IsIPv6(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected bool
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), true},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), false},
		{"IPv4-mapped IPv6", net.ParseIP("::ffff:8.8.8.8"), true}, // Should return true (it's really IPv4)
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), true},
		{"Loopback IPv6", net.ParseIP("::1"), false},
		{"nil IP", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIPv4(tt.ip)
			if result != tt.expected {
				t.Errorf("IsIPv4(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestSocketDomain(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected int
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), syscall.AF_INET},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), syscall.AF_INET6},
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), syscall.AF_INET},
		{"Loopback IPv6", net.ParseIP("::1"), syscall.AF_INET6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SocketDomain(tt.ip)
			if result != tt.expected {
				t.Errorf("SocketDomain(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestICMPProtocol(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), "ip4:icmp"},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), "ip6:ipv6-icmp"},
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), "ip4:icmp"},
		{"Loopback IPv6", net.ParseIP("::1"), "ip6:ipv6-icmp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ICMPProtocol(tt.ip)
			if result != tt.expected {
				t.Errorf("ICMPProtocol(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestICMPProtocolNum(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected int
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), 1},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), 58},
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), 1},
		{"Loopback IPv6", net.ParseIP("::1"), 58},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ICMPProtocolNum(tt.ip)
			if result != tt.expected {
				t.Errorf("ICMPProtocolNum(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestListenAddress(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), "0.0.0.0"},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), "::"},
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), "0.0.0.0"},
		{"Loopback IPv6", net.ParseIP("::1"), "::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ListenAddress(tt.ip)
			if result != tt.expected {
				t.Errorf("ListenAddress(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestTTLSocketOption(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected int
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), syscall.IP_TTL},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), syscall.IPV6_UNICAST_HOPS},
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), syscall.IP_TTL},
		{"Loopback IPv6", net.ParseIP("::1"), syscall.IPV6_UNICAST_HOPS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TTLSocketOption(tt.ip)
			if result != tt.expected {
				t.Errorf("TTLSocketOption(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestProtocolLevel(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected int
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), syscall.IPPROTO_IP},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), syscall.IPPROTO_IPV6},
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), syscall.IPPROTO_IP},
		{"Loopback IPv6", net.ParseIP("::1"), syscall.IPPROTO_IPV6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ProtocolLevel(tt.ip)
			if result != tt.expected {
				t.Errorf("ProtocolLevel(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIPHeaderSize(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected int
	}{
		{"IPv4 address", net.ParseIP("8.8.8.8"), 20},
		{"IPv6 address", net.ParseIP("2001:4860:4860::8888"), 40},
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), 20},
		{"Loopback IPv6", net.ParseIP("::1"), 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IPHeaderSize(tt.ip)
			if result != tt.expected {
				t.Errorf("IPHeaderSize(%v) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}
