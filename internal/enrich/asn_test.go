package enrich

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestASNLookup_FormatQuery_ReversesIP(t *testing.T) {
	lookup := NewASNLookup()

	query := lookup.formatQuery(net.ParseIP("8.8.8.8"))

	expected := "8.8.8.8.origin.asn.cymru.com"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestASNLookup_FormatQuery_HandlesAllOctets(t *testing.T) {
	lookup := NewASNLookup()

	query := lookup.formatQuery(net.ParseIP("192.168.1.100"))

	expected := "100.1.168.192.origin.asn.cymru.com"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestASNLookup_ParseResponse_ExtractsASN(t *testing.T) {
	lookup := NewASNLookup()

	// Team Cymru response format: "AS_NUMBER | IP_PREFIX | COUNTRY | RIR | DATE"
	response := "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"

	result, err := lookup.parseResponse(response)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != 15169 {
		t.Errorf("expected ASN 15169, got %d", result.ASN)
	}
	if result.Prefix != "8.8.8.0/24" {
		t.Errorf("expected prefix '8.8.8.0/24', got %q", result.Prefix)
	}
	if result.Country != "US" {
		t.Errorf("expected country 'US', got %q", result.Country)
	}
	if result.Registry != "arin" {
		t.Errorf("expected registry 'arin', got %q", result.Registry)
	}
}

func TestASNLookup_ParseResponse_HandlesMultipleASNs(t *testing.T) {
	lookup := NewASNLookup()

	// Some IPs may have multiple origin ASNs
	response := "13335 15169 | 1.1.1.0/24 | US | arin | 2010-07-14"

	result, err := lookup.parseResponse(response)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should take the first ASN
	if result.ASN != 13335 {
		t.Errorf("expected ASN 13335, got %d", result.ASN)
	}
}

func TestASNLookup_ParseResponse_ReturnsErrorForInvalid(t *testing.T) {
	lookup := NewASNLookup()

	_, err := lookup.parseResponse("invalid response")

	if err == nil {
		t.Error("expected error for invalid response")
	}
}

func TestASNLookup_ParseResponse_HandlesEmptyResponse(t *testing.T) {
	lookup := NewASNLookup()

	_, err := lookup.parseResponse("")

	if err == nil {
		t.Error("expected error for empty response")
	}
}

func TestASNLookup_LookupASNName_FormatsQuery(t *testing.T) {
	lookup := NewASNLookup()

	query := lookup.formatASNNameQuery(15169)

	expected := "AS15169.asn.cymru.com"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestASNLookup_ParseASNName_ExtractsOrgName(t *testing.T) {
	lookup := NewASNLookup()

	// Format: "AS_NUMBER | COUNTRY | RIR | DATE | ORG_NAME"
	response := "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"

	name, err := lookup.parseASNName(response)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "GOOGLE - Google LLC, US" {
		t.Errorf("expected 'GOOGLE - Google LLC, US', got %q", name)
	}
}

// Integration test - skip if no network
func TestASNLookup_Lookup_ReturnsRealData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	lookup := NewASNLookup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Google DNS - well-known ASN
	result, err := lookup.Lookup(ctx, net.ParseIP("8.8.8.8"))

	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if result.ASN != 15169 {
		t.Errorf("expected ASN 15169 (Google), got %d", result.ASN)
	}
}
