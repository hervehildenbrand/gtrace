// Package enrich provides IP enrichment functionality (ASN, GeoIP, rDNS).
package enrich

import (
	"context"
	"errors"
	"net"
)

// IXResult contains the result of an Internet Exchange lookup.
type IXResult struct {
	Matched bool   // Whether the IP belongs to an IX
	Name    string // IX name
	City    string // IX location city
	Country string // IX location country
}

// String returns a formatted IX string.
func (i IXResult) String() string {
	if !i.Matched || i.Name == "" {
		return ""
	}
	return "IX:" + i.Name
}

// IsIX returns true if the IP belongs to an Internet Exchange.
func (i IXResult) IsIX() bool {
	return i.Matched
}

// IXLookup performs Internet Exchange lookups.
type IXLookup struct {
	// prefixes contains known IX prefixes for fast local lookup
	prefixes map[string]ixPrefixInfo
}

type ixPrefixInfo struct {
	name    string
	city    string
	country string
	prefix  *net.IPNet
}

// NewIXLookup creates a new IX lookup instance with known prefixes.
func NewIXLookup() *IXLookup {
	l := &IXLookup{
		prefixes: make(map[string]ixPrefixInfo),
	}
	l.loadKnownPrefixes()
	return l
}

// loadKnownPrefixes loads commonly known IX peering LAN prefixes.
// These are well-known prefixes used by major Internet Exchanges.
func (l *IXLookup) loadKnownPrefixes() {
	knownIXPrefixes := []struct {
		cidr    string
		name    string
		city    string
		country string
	}{
		// DE-CIX Frankfurt
		{"80.81.192.0/21", "DE-CIX", "Frankfurt", "DE"},
		{"2001:7f8::/32", "DE-CIX", "Frankfurt", "DE"},

		// AMS-IX Amsterdam
		{"80.249.208.0/21", "AMS-IX", "Amsterdam", "NL"},
		{"2001:7f8:1::/48", "AMS-IX", "Amsterdam", "NL"},

		// LINX London
		{"195.66.224.0/21", "LINX", "London", "GB"},
		{"2001:7f8:4::/48", "LINX", "London", "GB"},

		// Equinix Ashburn
		{"206.126.236.0/22", "Equinix Ashburn", "Ashburn", "US"},

		// Equinix Chicago
		{"206.223.116.0/22", "Equinix Chicago", "Chicago", "US"},

		// Equinix San Jose
		{"206.223.143.0/24", "Equinix San Jose", "San Jose", "US"},

		// JPNAP Tokyo
		{"210.171.224.0/23", "JPNAP", "Tokyo", "JP"},

		// HKIX Hong Kong
		{"202.40.161.0/24", "HKIX", "Hong Kong", "HK"},

		// SIX Seattle
		{"206.81.80.0/23", "SIX", "Seattle", "US"},

		// NYIIX New York
		{"198.32.160.0/23", "NYIIX", "New York", "US"},

		// France-IX Paris
		{"37.49.236.0/22", "France-IX", "Paris", "FR"},

		// MSK-IX Moscow
		{"193.232.244.0/23", "MSK-IX", "Moscow", "RU"},

		// SGIX Singapore
		{"103.16.102.0/23", "SGIX", "Singapore", "SG"},

		// IX.br São Paulo
		{"187.16.216.0/21", "IX.br", "São Paulo", "BR"},
	}

	for _, ix := range knownIXPrefixes {
		_, ipNet, err := net.ParseCIDR(ix.cidr)
		if err != nil {
			continue
		}
		l.prefixes[ix.cidr] = ixPrefixInfo{
			name:    ix.name,
			city:    ix.city,
			country: ix.country,
			prefix:  ipNet,
		}
	}
}

// Lookup checks if an IP belongs to a known Internet Exchange.
func (l *IXLookup) Lookup(ctx context.Context, ip net.IP) (*IXResult, error) {
	if ip == nil {
		return nil, errors.New("nil IP address")
	}

	// Skip private IPs
	if IsPrivateIP(ip) {
		return &IXResult{}, nil
	}

	// Check against known prefixes
	for _, info := range l.prefixes {
		if info.prefix.Contains(ip) {
			return &IXResult{
				Matched: true,
				Name:    info.name,
				City:    info.city,
				Country: info.country,
			}, nil
		}
	}

	// Not found in known prefixes
	return &IXResult{}, nil
}

// IsKnownIXPrefix checks if an IP belongs to a known IX prefix.
func IsKnownIXPrefix(ip net.IP) bool {
	if ip == nil {
		return false
	}

	lookup := NewIXLookup()
	result, err := lookup.Lookup(nil, ip)
	if err != nil {
		return false
	}
	return result.IsIX()
}

// GetIXNameFromPrefix returns the IX name for an IP, or empty string if not an IX.
func GetIXNameFromPrefix(ip net.IP) string {
	if ip == nil {
		return ""
	}

	lookup := NewIXLookup()
	result, err := lookup.Lookup(nil, ip)
	if err != nil || !result.IsIX() {
		return ""
	}
	return result.Name
}

// KnownIXCount returns the number of known IX prefixes.
func (l *IXLookup) KnownIXCount() int {
	return len(l.prefixes)
}
