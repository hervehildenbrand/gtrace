package enrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// RDNSLookup performs reverse DNS lookups.
type RDNSLookup struct {
	resolver *net.Resolver
}

// NewRDNSLookup creates a new reverse DNS lookup instance.
func NewRDNSLookup() *RDNSLookup {
	return &RDNSLookup{
		resolver: net.DefaultResolver,
	}
}

// Lookup performs a reverse DNS lookup for the given IP.
func (l *RDNSLookup) Lookup(ctx context.Context, ip net.IP) (string, error) {
	if ip == nil {
		return "", errors.New("nil IP address")
	}

	names, err := l.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return "", fmt.Errorf("reverse DNS lookup failed: %w", err)
	}

	if len(names) == 0 {
		return "", nil
	}

	// Return the first hostname, cleaned up
	return l.cleanHostname(names[0]), nil
}

// formatPTRQuery creates the PTR query string (for testing/debugging).
// Supports both IPv4 (.in-addr.arpa) and IPv6 (.ip6.arpa) formats.
func (l *RDNSLookup) formatPTRQuery(ip net.IP) string {
	// Check for IPv4
	ip4 := ip.To4()
	if ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa",
			ip4[3], ip4[2], ip4[1], ip4[0])
	}

	// IPv6 format: nibble-reversed + ".ip6.arpa"
	ip16 := ip.To16()
	if ip16 == nil {
		return ""
	}

	var parts []string
	for i := len(ip16) - 1; i >= 0; i-- {
		// Each byte contributes 2 nibbles (4 bits each)
		// Low nibble first, then high nibble (reversed)
		parts = append(parts, fmt.Sprintf("%x", ip16[i]&0x0f))
		parts = append(parts, fmt.Sprintf("%x", ip16[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}

// cleanHostname removes the trailing dot from DNS names.
func (l *RDNSLookup) cleanHostname(hostname string) string {
	return strings.TrimSuffix(hostname, ".")
}
