// Package enrich provides IP enrichment functionality (ASN, GeoIP, rDNS).
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// GeoResult contains the result of a GeoIP lookup.
type GeoResult struct {
	City       string  // City name
	Country    string  // Country code (ISO 3166-1 alpha-2)
	CountryName string // Full country name
	Region     string  // Region/state
	Latitude   float64 // Latitude
	Longitude  float64 // Longitude
	Timezone   string  // Timezone
}

// String returns a formatted location string.
func (g GeoResult) String() string {
	if g.City != "" && g.Country != "" {
		return g.City + ", " + g.Country
	}
	if g.City != "" {
		return g.City
	}
	if g.Country != "" {
		return g.Country
	}
	return ""
}

// IsEmpty returns true if the result contains no location data.
func (g GeoResult) IsEmpty() bool {
	return g.City == "" && g.Country == "" && g.Region == ""
}

const defaultGeoAPIBaseURL = "http://ip-api.com"

// GeoLookup performs GeoIP lookups.
type GeoLookup struct {
	dbPath     string // Path to MaxMind database file (optional)
	apiBaseURL string // Base URL for ip-api.com (overridable for testing)
}

// NewGeoLookup creates a new GeoIP lookup instance.
func NewGeoLookup() *GeoLookup {
	return &GeoLookup{
		dbPath:     DefaultGeoDBPath(),
		apiBaseURL: defaultGeoAPIBaseURL,
	}
}

// NewGeoLookupWithDB creates a GeoIP lookup with a specific database path.
func NewGeoLookupWithDB(dbPath string) *GeoLookup {
	return &GeoLookup{
		dbPath:     dbPath,
		apiBaseURL: defaultGeoAPIBaseURL,
	}
}

// Lookup performs a GeoIP lookup for the given IP.
func (l *GeoLookup) Lookup(ctx context.Context, ip net.IP) (*GeoResult, error) {
	if ip == nil {
		return nil, errors.New("nil IP address")
	}

	// Skip private/local IPs
	if IsPrivateIP(ip) {
		return &GeoResult{}, nil
	}

	// Try database lookup first if available
	if l.dbPath != "" {
		if _, err := os.Stat(l.dbPath); err == nil {
			result, err := l.lookupFromDB(ip)
			if err == nil {
				return result, nil
			}
			// Fall through to API on DB error
		}
	}

	// Fallback to ip-api.com
	result, err := l.lookupAPI(ctx, ip)
	if err == nil && result != nil && !result.IsEmpty() {
		return result, nil
	}

	return &GeoResult{}, nil
}

// geoAPIResponse represents the response from ip-api.com.
type geoAPIResponse struct {
	Status      string  `json:"status"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
}

// lookupAPI performs geo lookup via ip-api.com.
func (l *GeoLookup) lookupAPI(ctx context.Context, ip net.IP) (*GeoResult, error) {
	url := fmt.Sprintf("%s/json/%s?fields=status,city,country,countryCode,regionName,lat,lon,timezone", l.apiBaseURL, ip.String())

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp geoAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	if apiResp.Status != "success" {
		return nil, errors.New("ip-api geo lookup failed")
	}

	return &GeoResult{
		City:        apiResp.City,
		Country:     apiResp.CountryCode,
		CountryName: apiResp.Country,
		Region:      apiResp.RegionName,
		Latitude:    apiResp.Lat,
		Longitude:   apiResp.Lon,
		Timezone:    apiResp.Timezone,
	}, nil
}

// lookupFromDB looks up IP in MaxMind database.
func (l *GeoLookup) lookupFromDB(ip net.IP) (*GeoResult, error) {
	// Placeholder for MaxMind database lookup
	return nil, errors.New("database lookup not implemented")
}

// HasDatabase returns true if a GeoIP database is available.
func (l *GeoLookup) HasDatabase() bool {
	if l.dbPath == "" {
		return false
	}
	_, err := os.Stat(l.dbPath)
	return err == nil
}

// DefaultGeoDBPath returns the default path for GeoIP database.
func DefaultGeoDBPath() string {
	// Check common locations
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	// Check ~/.gtr/data/GeoLite2-City.mmdb
	gtrPath := filepath.Join(home, ".gtr", "data", "GeoLite2-City.mmdb")
	if _, err := os.Stat(gtrPath); err == nil {
		return gtrPath
	}

	// Return the expected path even if file doesn't exist
	return gtrPath
}

// IsPrivateIP checks if an IP address is private/local.
// Supports both IPv4 and IPv6 addresses.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	} else {
		// IPv6 - check for Unique Local Addresses (ULA)
		// fc00::/7 - first byte is 0xfc or 0xfd
		ip16 := ip.To16()
		if ip16 != nil && len(ip16) == 16 {
			// fc00::/7 means first 7 bits are 1111110
			// This covers both fc00::/8 and fd00::/8
			if (ip16[0] & 0xfe) == 0xfc {
				return true
			}
		}
	}

	return false
}

// GeoDBInfo contains information about a GeoIP database.
type GeoDBInfo struct {
	Path      string // File path
	Type      string // "city" or "country"
	BuildDate string // Database build date
	Size      int64  // File size in bytes
}

// GetGeoDBInfo returns information about the installed GeoIP database.
func GetGeoDBInfo(dbPath string) (*GeoDBInfo, error) {
	info, err := os.Stat(dbPath)
	if err != nil {
		return nil, err
	}

	return &GeoDBInfo{
		Path: dbPath,
		Type: "city", // Assume city database
		Size: info.Size(),
	}, nil
}
