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
func ResolveTarget(target string) (net.IP, error) {
	// First, try to parse as an IP address
	ip := net.ParseIP(target)
	if ip != nil {
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

	// Prefer IPv4
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}

	return ips[0], nil
}
