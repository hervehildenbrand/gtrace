// Package enrich provides IP enrichment functionality (ASN, GeoIP, rDNS).
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ASNResult contains the result of an ASN lookup.
type ASNResult struct {
	ASN      uint32 // AS number
	Prefix   string // IP prefix (CIDR)
	Country  string // Country code
	Registry string // RIR (arin, ripe, apnic, etc.)
	Date     string // Allocation date
	Name     string // AS organization name
}

// ASNLookup performs ASN lookups via Team Cymru DNS.
type ASNLookup struct {
	resolver *net.Resolver
}

// NewASNLookup creates a new ASN lookup instance.
func NewASNLookup() *ASNLookup {
	return &ASNLookup{
		resolver: net.DefaultResolver,
	}
}

// Lookup performs an ASN lookup for the given IP.
// Uses Team Cymru DNS first, falls back to ip-api.com for better coverage.
func (l *ASNLookup) Lookup(ctx context.Context, ip net.IP) (*ASNResult, error) {
	if ip == nil {
		return nil, errors.New("nil IP address")
	}

	// Skip private IPs
	if IsPrivateIP(ip) {
		return nil, errors.New("private IP address")
	}

	// Only IPv4 for now
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("IPv6 not yet supported")
	}

	// Try Team Cymru DNS first
	result, err := l.lookupCymru(ctx, ip4)
	if err == nil && result.ASN > 0 {
		return result, nil
	}

	// Fallback to ip-api.com for better coverage
	return l.lookupIPAPI(ctx, ip)
}

// lookupCymru performs ASN lookup via Team Cymru DNS.
func (l *ASNLookup) lookupCymru(ctx context.Context, ip4 net.IP) (*ASNResult, error) {
	// Query origin ASN
	query := l.formatQuery(ip4)
	records, err := l.resolver.LookupTXT(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	if len(records) == 0 {
		return nil, errors.New("no TXT records found")
	}

	result, err := l.parseResponse(records[0])
	if err != nil {
		return nil, err
	}

	// Optionally lookup ASN name
	if result.ASN > 0 {
		name, err := l.lookupASNName(ctx, result.ASN)
		if err == nil {
			result.Name = name
		}
	}

	return result, nil
}

// ipAPIResponse represents the response from ip-api.com
type ipAPIResponse struct {
	Status  string `json:"status"`
	AS      string `json:"as"`      // e.g., "AS3215 Orange S.A."
	ASName  string `json:"asname"`  // e.g., "Orange S.A."
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	Country string `json:"countryCode"`
}

// lookupIPAPI performs ASN lookup via ip-api.com (fallback).
func (l *ASNLookup) lookupIPAPI(ctx context.Context, ip net.IP) (*ASNResult, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,as,asname,isp,org,countryCode", ip.String())

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

	var apiResp ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	if apiResp.Status != "success" {
		return nil, errors.New("ip-api lookup failed")
	}

	// Parse ASN from "AS3215 Orange S.A." format
	var asn uint32
	if apiResp.AS != "" {
		parts := strings.SplitN(apiResp.AS, " ", 2)
		if len(parts) > 0 && strings.HasPrefix(parts[0], "AS") {
			asnNum, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "AS"), 10, 32)
			if err == nil {
				asn = uint32(asnNum)
			}
		}
	}

	// Get organization name: prefer ASName, then ISP, then Org
	name := apiResp.ASName
	if name == "" {
		name = apiResp.ISP
	}
	if name == "" {
		name = apiResp.Org
	}

	return &ASNResult{
		ASN:     asn,
		Name:    name,
		Country: apiResp.Country,
	}, nil
}

// formatQuery creates the DNS query for IP to ASN lookup.
// Format: reversed octets + ".origin.asn.cymru.com"
func (l *ASNLookup) formatQuery(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com",
		ip4[3], ip4[2], ip4[1], ip4[0])
}

// parseResponse parses the Team Cymru TXT response.
// Format: "AS_NUMBER | IP_PREFIX | COUNTRY | RIR | DATE"
func (l *ASNLookup) parseResponse(response string) (*ASNResult, error) {
	response = strings.TrimSpace(response)
	if response == "" {
		return nil, errors.New("empty response")
	}

	parts := strings.Split(response, "|")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid response format: %q", response)
	}

	// Parse ASN (may have multiple space-separated ASNs)
	asnStr := strings.TrimSpace(parts[0])
	asnParts := strings.Fields(asnStr)
	if len(asnParts) == 0 {
		return nil, errors.New("no ASN in response")
	}

	asn, err := strconv.ParseUint(asnParts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid ASN: %w", err)
	}

	result := &ASNResult{
		ASN: uint32(asn),
	}

	if len(parts) > 1 {
		result.Prefix = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		result.Country = strings.TrimSpace(parts[2])
	}
	if len(parts) > 3 {
		result.Registry = strings.TrimSpace(parts[3])
	}
	if len(parts) > 4 {
		result.Date = strings.TrimSpace(parts[4])
	}

	return result, nil
}

// lookupASNName looks up the organization name for an ASN.
func (l *ASNLookup) lookupASNName(ctx context.Context, asn uint32) (string, error) {
	query := l.formatASNNameQuery(asn)
	records, err := l.resolver.LookupTXT(ctx, query)
	if err != nil {
		return "", err
	}

	if len(records) == 0 {
		return "", errors.New("no TXT records")
	}

	return l.parseASNName(records[0])
}

// formatASNNameQuery creates the DNS query for ASN to name lookup.
func (l *ASNLookup) formatASNNameQuery(asn uint32) string {
	return fmt.Sprintf("AS%d.asn.cymru.com", asn)
}

// parseASNName parses the ASN name response.
// Format: "AS_NUMBER | COUNTRY | RIR | DATE | ORG_NAME"
func (l *ASNLookup) parseASNName(response string) (string, error) {
	response = strings.TrimSpace(response)
	if response == "" {
		return "", errors.New("empty response")
	}

	parts := strings.Split(response, "|")
	if len(parts) < 5 {
		return "", fmt.Errorf("invalid response format: %q", response)
	}

	return strings.TrimSpace(parts[4]), nil
}
