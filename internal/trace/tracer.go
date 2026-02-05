// Package trace implements traceroute functionality using various protocols.
package trace

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// Protocol represents the traceroute protocol to use.
type Protocol string

const (
	ProtocolICMP Protocol = "icmp"
	ProtocolUDP  Protocol = "udp"
	ProtocolTCP  Protocol = "tcp"
)

// AddressFamily specifies the preferred IP version for target resolution.
type AddressFamily int

const (
	// AddressFamilyAuto prefers IPv4 but accepts IPv6 if no IPv4 available.
	AddressFamilyAuto AddressFamily = iota
	// AddressFamilyIPv4 forces IPv4 only.
	AddressFamilyIPv4
	// AddressFamilyIPv6 forces IPv6 only.
	AddressFamilyIPv6
)

// Config holds traceroute configuration.
type Config struct {
	Protocol      Protocol
	MaxHops       int
	PacketsPerHop int
	Timeout       time.Duration
	Port          int    // For UDP/TCP
	SourceAddr    string // Source address to use
}

// DefaultConfig returns the default traceroute configuration.
// Uses MTR-style defaults: 1 packet per hop, 500ms timeout for faster response.
func DefaultConfig() *Config {
	return &Config{
		Protocol:      ProtocolICMP,
		MaxHops:       30,
		PacketsPerHop: 1,                      // MTR-style: 1 probe per hop per cycle
		Timeout:       500 * time.Millisecond, // MTR-style: faster timeout
		Port:          33434,                  // Default UDP port
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	switch c.Protocol {
	case ProtocolICMP, ProtocolUDP, ProtocolTCP:
		// Valid
	default:
		return errors.New("invalid protocol: must be icmp, udp, or tcp")
	}

	if c.MaxHops <= 0 {
		return errors.New("max hops must be positive")
	}

	if c.PacketsPerHop <= 0 {
		return errors.New("packets per hop must be positive")
	}

	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	return nil
}

// HopCallback is called when a hop is received during tracing.
type HopCallback func(*hop.Hop)

// Tracer is the interface for traceroute implementations.
type Tracer interface {
	// Trace performs a traceroute to the target IP.
	// The callback is called for each hop as it's discovered.
	Trace(ctx context.Context, target net.IP, callback HopCallback) (*hop.TraceResult, error)
}

// ResolveTarget resolves a hostname or IP string to a net.IP.
// The af parameter controls IP version preference:
//   - AddressFamilyAuto: Prefer IPv4, fall back to IPv6
//   - AddressFamilyIPv4: Only return IPv4 addresses
//   - AddressFamilyIPv6: Only return IPv6 addresses
func ResolveTarget(target string, af AddressFamily) (net.IP, error) {
	// First, try to parse as an IP address
	ip := net.ParseIP(target)
	if ip != nil {
		// Validate IP matches requested address family
		isV4 := ip.To4() != nil
		switch af {
		case AddressFamilyIPv4:
			if !isV4 {
				return nil, errors.New("IPv6 address provided but IPv4 required (-4 flag)")
			}
		case AddressFamilyIPv6:
			if isV4 {
				return nil, errors.New("IPv4 address provided but IPv6 required (-6 flag)")
			}
		}
		return ip, nil
	}

	// Otherwise, resolve as hostname
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, errors.New("no IP addresses found for hostname")
	}

	// Filter and select based on address family
	var v4Addrs, v6Addrs []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4Addrs = append(v4Addrs, ip)
		} else {
			v6Addrs = append(v6Addrs, ip)
		}
	}

	switch af {
	case AddressFamilyIPv4:
		if len(v4Addrs) == 0 {
			return nil, errors.New("no IPv4 address found for hostname (try without -4 flag)")
		}
		return v4Addrs[0], nil
	case AddressFamilyIPv6:
		if len(v6Addrs) == 0 {
			return nil, errors.New("no IPv6 address found for hostname (try without -6 flag)")
		}
		return v6Addrs[0], nil
	default: // AddressFamilyAuto
		// Prefer IPv4
		if len(v4Addrs) > 0 {
			return v4Addrs[0], nil
		}
		if len(v6Addrs) > 0 {
			return v6Addrs[0], nil
		}
		return nil, errors.New("no IP addresses found for hostname")
	}
}
