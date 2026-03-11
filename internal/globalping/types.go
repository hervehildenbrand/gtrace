// Package globalping provides a client for the GlobalPing API.
package globalping

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// structuredKeys are recognized keys for structured location syntax.
var structuredKeys = map[string]bool{
	"country": true,
	"city":    true,
	"asn":     true,
	"network": true,
	"region":  true,
	"tag":     true,
}

// MaxLocations is the maximum number of GlobalPing probe locations per request.
const MaxLocations = 5

// Probe represents a GlobalPing probe.
type Probe struct {
	Version  string        `json:"version"`
	Location ProbeLocation `json:"location"`
	Tags     []string      `json:"tags,omitempty"`
	Status   string        `json:"status"`
}

// ProbeLocation contains the geographic details of a probe.
type ProbeLocation struct {
	Continent string  `json:"continent"`
	Region    string  `json:"region"`
	Country   string  `json:"country"`
	State     string  `json:"state,omitempty"`
	City      string  `json:"city"`
	ASN       int     `json:"asn"`
	Network   string  `json:"network"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// ProbeFilter specifies criteria for filtering probes.
type ProbeFilter struct {
	Country string
	City    string
	ASN     int
	Network string
	Tag     string
	Status  string // default "ready"
}

// MeasurementType represents the type of measurement.
type MeasurementType string

const (
	MeasurementTypeTraceroute MeasurementType = "traceroute"
	MeasurementTypePing       MeasurementType = "ping"
	MeasurementTypeDNS        MeasurementType = "dns"
	MeasurementTypeMTR        MeasurementType = "mtr"
	MeasurementTypeHTTP       MeasurementType = "http"
)

// MeasurementStatus represents the status of a measurement.
type MeasurementStatus string

const (
	StatusInProgress MeasurementStatus = "in-progress"
	StatusFinished   MeasurementStatus = "finished"
	StatusFailed     MeasurementStatus = "failed"
)

// IsComplete returns true if the measurement has finished.
func (s MeasurementStatus) IsComplete() bool {
	return s == StatusFinished || s == StatusFailed
}

// Location specifies where to run the measurement.
type Location struct {
	Magic     string `json:"magic,omitempty"`     // Flexible location string
	Country   string `json:"country,omitempty"`   // ISO country code
	Region    string `json:"region,omitempty"`    // Geographic region
	City      string `json:"city,omitempty"`      // City name
	ASN       int    `json:"asn,omitempty"`       // AS number
	Network   string `json:"network,omitempty"`   // Network/provider name
	Tags      []string `json:"tags,omitempty"`    // Provider tags
	Limit     int    `json:"limit,omitempty"`     // Max probes from this location
}

// isStructuredLocation checks if a string uses the key:value structured syntax.
// Returns true if the first segment before ':' is a known key.
func isStructuredLocation(s string) bool {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return false
	}
	// Extract the key part (before first colon), handling comma-separated fields
	// e.g. "city:Tokyo,asn:2497" - first key is "city"
	firstPart := s[:idx]
	// If there's a comma before the colon, it's not structured (e.g. "Paris, city:foo" won't hit here)
	if strings.Contains(firstPart, ",") {
		firstPart = firstPart[strings.LastIndex(firstPart, ",")+1:]
	}
	firstPart = strings.TrimSpace(firstPart)
	return structuredKeys[strings.ToLower(firstPart)]
}

// ParseLocationString parses a location string into a Location.
// Supports formats:
//   - Plain: "Paris", "DE", "AS13335", "AWS+us-east-1" → Location{Magic: s}
//   - Structured: "country:DE", "city:Tokyo,asn:2497" → Location{Country: "DE"}, etc.
//   - Limit suffix: "country:US@3" → Location{Country: "US", Limit: 3}
func ParseLocationString(s string) Location {
	s = strings.TrimSpace(s)
	if !isStructuredLocation(s) {
		return Location{Magic: s}
	}
	return parseStructuredLocation(s)
}

// parseStructuredLocation parses "key:value,key:value[@limit]" syntax.
func parseStructuredLocation(s string) Location {
	var loc Location

	// Check for @limit suffix
	if idx := strings.LastIndex(s, "@"); idx > 0 {
		limitStr := s[idx+1:]
		if n, err := strconv.Atoi(limitStr); err == nil {
			loc.Limit = n
		}
		s = s[:idx]
	}

	// Split on comma for multiple key:value pairs
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		idx := strings.Index(pair, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(pair[:idx]))
		value := strings.TrimSpace(pair[idx+1:])
		switch key {
		case "country":
			loc.Country = value
		case "city":
			loc.City = value
		case "asn":
			if n, err := strconv.Atoi(value); err == nil {
				loc.ASN = n
			}
		case "network":
			loc.Network = value
		case "region":
			loc.Region = value
		case "tag":
			loc.Tags = append(loc.Tags, value)
		}
	}

	return loc
}

// ParseLocationStrings parses a list of locations separated by semicolons or commas.
// Semicolons are used as the primary separator to avoid ambiguity with structured
// syntax that uses commas internally (e.g. "city:Tokyo,asn:2497").
// Plain comma-separated locations still work when no structured syntax is detected.
func ParseLocationStrings(s string) []Location {
	// If semicolons are present, use them as separators
	if strings.Contains(s, ";") {
		return parseLocationsByDelimiter(s, ";")
	}

	// If any part looks structured (contains key:value), treat commas within
	// structured expressions as field separators, not location separators.
	// Heuristic: if the string contains a structured key followed by ':', parse as single location.
	if isStructuredLocation(s) {
		loc := ParseLocationString(s)
		return []Location{loc}
	}

	// Default: comma-separated plain locations
	return parseLocationsByDelimiter(s, ",")
}

func parseLocationsByDelimiter(s, delim string) []Location {
	parts := strings.Split(s, delim)
	locs := make([]Location, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			locs = append(locs, ParseLocationString(p))
		}
	}
	return locs
}

// MeasurementOptions contains options for the measurement.
type MeasurementOptions struct {
	Protocol  string `json:"protocol,omitempty"`  // icmp, tcp, udp
	Port      int    `json:"port,omitempty"`      // Destination port
	Packets   int    `json:"packets,omitempty"`   // Number of packets
	IPVersion int    `json:"ipVersion,omitempty"` // IP version: 4 or 6 (default: auto)
}

// MeasurementRequest represents a request to create a measurement.
type MeasurementRequest struct {
	Type        MeasurementType    `json:"type"`
	Target      string             `json:"target"`
	Locations   []Location         `json:"locations"`
	Options     MeasurementOptions `json:"measurementOptions,omitempty"`
	Limit       int                `json:"limit,omitempty"`       // Total probe limit
	InProgressUpdates bool         `json:"inProgressUpdates,omitempty"`
}

// Validate checks if the request is valid.
func (r *MeasurementRequest) Validate() error {
	if r.Target == "" {
		return errors.New("target is required")
	}
	if len(r.Locations) == 0 {
		return errors.New("at least one location is required")
	}
	if len(r.Locations) > MaxLocations {
		return fmt.Errorf("too many locations: %d (maximum %d)", len(r.Locations), MaxLocations)
	}
	return nil
}

// MeasurementResponse is the response from creating a measurement.
type MeasurementResponse struct {
	ID          string   `json:"id"`
	ProbesCount int      `json:"probesCount"`
}

// MeasurementResult contains the results of a measurement.
type MeasurementResult struct {
	ID        string              `json:"id"`
	Type      MeasurementType     `json:"type"`
	Status    MeasurementStatus   `json:"status"`
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
	Results   []ProbeResult       `json:"results"`
}

// ProbeResult contains results from a single probe.
type ProbeResult struct {
	Probe     ProbeInfo        `json:"probe"`
	Result    TracerouteResult `json:"result"`
}

// ProbeInfo contains information about the probe.
type ProbeInfo struct {
	Continent string   `json:"continent"`
	Region    string   `json:"region"`
	Country   string   `json:"country"`
	State     string   `json:"state,omitempty"`
	City      string   `json:"city"`
	ASN       int      `json:"asn"`
	Network   string   `json:"network"`
	Tags      []string `json:"tags,omitempty"`
}

// TracerouteResult contains the traceroute data.
type TracerouteResult struct {
	Status      string          `json:"status"`
	ResolvedAddress string      `json:"resolvedAddress"`
	ResolvedHostname string     `json:"resolvedHostname"`
	Hops        []TracerouteHop `json:"hops"`
}

// TracerouteHop represents a single hop in the traceroute.
// Supports both the simple format (resolvedAddress/resolvedHostname/timings)
// and the detailed format with resolvers array.
type TracerouteHop struct {
	// Simple format fields
	ResolvedAddress  string      `json:"resolvedAddress,omitempty"`
	ResolvedHostname string      `json:"resolvedHostname,omitempty"`
	Timings          []HopTiming `json:"timings,omitempty"`

	// Detailed format fields
	Resolvers []HopResolver `json:"resolvers,omitempty"`
}

// HopResolver contains information about a router at this hop.
type HopResolver struct {
	Address  string      `json:"address"`
	Hostname string      `json:"hostname"`
	ASN      uint32      `json:"asn"`
	Network  string      `json:"network"`
	Timings  []HopTiming `json:"timings"`
}

// HopTiming contains RTT information.
type HopTiming struct {
	RTT float64 `json:"rtt"` // Round-trip time in milliseconds
}

// ToHop converts a TracerouteHop to our internal Hop type.
func (th *TracerouteHop) ToHop(ttl int) *hop.Hop {
	h := hop.NewHop(ttl)

	// Handle simple format (resolvedAddress + timings)
	if th.ResolvedAddress != "" {
		ip := net.ParseIP(th.ResolvedAddress)
		if len(th.Timings) == 0 {
			h.AddTimeout()
		} else {
			for _, t := range th.Timings {
				rtt := time.Duration(t.RTT * float64(time.Millisecond))
				h.AddProbe(ip, rtt)
			}
		}
		if th.ResolvedHostname != "" {
			h.SetEnrichment(hop.Enrichment{
				Hostname: th.ResolvedHostname,
			})
		}
		return h
	}

	// Handle detailed format with resolvers array
	if len(th.Resolvers) == 0 {
		// Timeout - no responses
		h.AddTimeout()
		return h
	}

	// Process each resolver (may have multiple due to ECMP)
	for _, r := range th.Resolvers {
		ip := net.ParseIP(r.Address)

		// Add probes for each timing
		if len(r.Timings) == 0 {
			h.AddTimeout()
		} else {
			for _, t := range r.Timings {
				rtt := time.Duration(t.RTT * float64(time.Millisecond))
				h.AddProbe(ip, rtt)
			}
		}

		// Set enrichment from first resolver
		if h.Enrichment.ASN == 0 && r.ASN > 0 {
			h.SetEnrichment(hop.Enrichment{
				ASN:      r.ASN,
				ASOrg:    r.Network,
				Hostname: r.Hostname,
			})
		}
	}

	return h
}

// ToTraceResult converts a ProbeResult to our internal TraceResult type.
func (pr *ProbeResult) ToTraceResult(target string) *hop.TraceResult {
	result := hop.NewTraceResult(target, pr.Result.ResolvedAddress)
	result.Source = formatProbeLocation(&pr.Probe)

	for i, th := range pr.Result.Hops {
		h := th.ToHop(i + 1)
		result.AddHop(h)

		// Check if we reached the target
		if h.PrimaryIP() != nil && h.PrimaryIP().String() == pr.Result.ResolvedAddress {
			result.ReachedTarget = true
		}
	}

	return result
}

// formatProbeLocation creates a human-readable location string.
func formatProbeLocation(p *ProbeInfo) string {
	parts := []string{}
	if p.City != "" {
		parts = append(parts, p.City)
	}
	if p.Country != "" {
		parts = append(parts, p.Country)
	}
	if p.Network != "" {
		parts = append(parts, p.Network)
	}
	return strings.Join(parts, ", ")
}

// MTR result types for GlobalPing MTR measurement

// MTRStats contains statistics for an MTR hop.
type MTRStats struct {
	Total int     `json:"total"` // Total packets sent
	Rcv   int     `json:"rcv"`   // Packets received
	Drop  int     `json:"drop"`  // Packets dropped
	Loss  float64 `json:"loss"`  // Loss percentage (0-100)
	Min   float64 `json:"min"`   // Minimum RTT in ms
	Avg   float64 `json:"avg"`   // Average RTT in ms
	Max   float64 `json:"max"`   // Maximum RTT in ms
	StDev float64 `json:"stDev"` // Standard deviation in ms
}

// MTRHopResolver contains information about a router at an MTR hop (legacy format).
type MTRHopResolver struct {
	Address  string   `json:"address"`
	Hostname string   `json:"hostname"`
	ASN      uint32   `json:"asn"`
	Network  string   `json:"network"`
	Stats    MTRStats `json:"stats"`
}

// MTRHop represents a single hop in an MTR result.
// GlobalPing returns hops directly with stats, not nested in resolvers.
type MTRHop struct {
	// Direct format (actual GlobalPing API response)
	ResolvedAddress  string      `json:"resolvedAddress,omitempty"`
	ResolvedHostname string      `json:"resolvedHostname,omitempty"`
	Stats            MTRStats    `json:"stats,omitempty"`
	ASN              []uint32    `json:"asn,omitempty"`
	Timings          []HopTiming `json:"timings,omitempty"`

	// Legacy format (for backwards compatibility with tests)
	Resolvers []MTRHopResolver `json:"resolvers,omitempty"`
}

// ToHop converts an MTRHop to our internal Hop type.
func (mh *MTRHop) ToHop(ttl int) *hop.Hop {
	h := hop.NewHop(ttl)

	// Handle direct format (actual GlobalPing API response)
	if mh.ResolvedAddress != "" {
		ip := net.ParseIP(mh.ResolvedAddress)

		// Add probes from timings
		if len(mh.Timings) > 0 {
			for _, t := range mh.Timings {
				rtt := time.Duration(t.RTT * float64(time.Millisecond))
				h.AddProbe(ip, rtt)
			}
		} else if mh.Stats.Avg > 0 {
			// Fallback to stats average
			rtt := time.Duration(mh.Stats.Avg * float64(time.Millisecond))
			h.AddProbe(ip, rtt)
		} else {
			h.AddTimeout()
		}

		// Set enrichment
		var asn uint32
		if len(mh.ASN) > 0 {
			asn = mh.ASN[0]
		}
		if asn > 0 || mh.ResolvedHostname != "" {
			h.SetEnrichment(hop.Enrichment{
				ASN:      asn,
				Hostname: mh.ResolvedHostname,
			})
		}
		return h
	}

	// Handle legacy format with resolvers array (for tests)
	if len(mh.Resolvers) == 0 {
		h.AddTimeout()
		return h
	}

	for _, r := range mh.Resolvers {
		ip := net.ParseIP(r.Address)

		if r.Stats.Avg > 0 {
			rtt := time.Duration(r.Stats.Avg * float64(time.Millisecond))
			h.AddProbe(ip, rtt)
		} else {
			h.AddTimeout()
		}

		if h.Enrichment.ASN == 0 && r.ASN > 0 {
			h.SetEnrichment(hop.Enrichment{
				ASN:      r.ASN,
				ASOrg:    r.Network,
				Hostname: r.Hostname,
			})
		}
	}

	return h
}

// MTRResult contains the MTR measurement data.
type MTRResult struct {
	Status          string   `json:"status"`
	ResolvedAddress string   `json:"resolvedAddress"`
	ResolvedHostname string  `json:"resolvedHostname"`
	Hops            []MTRHop `json:"hops"`
}

// MTRProbeResult contains MTR results from a single probe.
type MTRProbeResult struct {
	Probe  ProbeInfo `json:"probe"`
	Result MTRResult `json:"result"`
}

// ToTraceResult converts an MTRProbeResult to our internal TraceResult type.
func (pr *MTRProbeResult) ToTraceResult(target string) *hop.TraceResult {
	result := hop.NewTraceResult(target, pr.Result.ResolvedAddress)
	result.Source = formatProbeLocation(&pr.Probe)

	for i, mh := range pr.Result.Hops {
		h := mh.ToHop(i + 1)
		result.AddHop(h)

		// Check if we reached the target
		if h.PrimaryIP() != nil && h.PrimaryIP().String() == pr.Result.ResolvedAddress {
			result.ReachedTarget = true
		}
	}

	return result
}

// MTRMeasurementResult contains the full MTR measurement results.
type MTRMeasurementResult struct {
	ID        string           `json:"id"`
	Type      MeasurementType  `json:"type"`
	Status    MeasurementStatus `json:"status"`
	CreatedAt time.Time        `json:"createdAt"`
	UpdatedAt time.Time        `json:"updatedAt"`
	Results   []MTRProbeResult `json:"results"`
}
