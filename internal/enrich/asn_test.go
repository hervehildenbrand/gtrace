package enrich

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestASNLookup_ParseRIPEResponse_ExtractsASNFromRouteObject(t *testing.T) {
	lookup := NewASNLookup()

	// Simulated RIPE REST DB JSON response with a route object
	response := `{
		"objects": {
			"object": [
				{
					"type": "route",
					"attributes": {
						"attribute": [
							{"name": "route", "value": "80.10.248.0/21"},
							{"name": "descr", "value": "France Telecom"},
							{"name": "origin", "value": "AS3215"},
							{"name": "mnt-by", "value": "FT-BRX"},
							{"name": "source", "value": "RIPE"}
						]
					}
				}
			]
		}
	}`

	result, err := lookup.parseRIPEResponse([]byte(response))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != 3215 {
		t.Errorf("expected ASN 3215, got %d", result.ASN)
	}
	if result.Prefix != "80.10.248.0/21" {
		t.Errorf("expected prefix '80.10.248.0/21', got %q", result.Prefix)
	}
	if result.Name != "France Telecom" {
		t.Errorf("expected name 'France Telecom', got %q", result.Name)
	}
}

func TestASNLookup_ParseRIPEResponse_NoRouteObject(t *testing.T) {
	lookup := NewASNLookup()

	// Response with only inetnum, no route object
	response := `{
		"objects": {
			"object": [
				{
					"type": "inetnum",
					"attributes": {
						"attribute": [
							{"name": "inetnum", "value": "193.253.80.0 - 193.253.95.255"},
							{"name": "netname", "value": "RBCI"},
							{"name": "descr", "value": "France Telecom IP backbone"}
						]
					}
				}
			]
		}
	}`

	_, err := lookup.parseRIPEResponse([]byte(response))

	if err == nil {
		t.Error("expected error when no route object present")
	}
}

func TestASNLookup_ParseRIPEResponse_MultipleObjectsPicksRoute(t *testing.T) {
	lookup := NewASNLookup()

	// Response with both inetnum and route objects
	response := `{
		"objects": {
			"object": [
				{
					"type": "inetnum",
					"attributes": {
						"attribute": [
							{"name": "inetnum", "value": "80.10.252.0 - 80.10.255.255"},
							{"name": "netname", "value": "IP2000-ADSL-BAS"}
						]
					}
				},
				{
					"type": "route",
					"attributes": {
						"attribute": [
							{"name": "route", "value": "80.10.248.0/21"},
							{"name": "descr", "value": "France Telecom"},
							{"name": "origin", "value": "AS3215"}
						]
					}
				}
			]
		}
	}`

	result, err := lookup.parseRIPEResponse([]byte(response))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != 3215 {
		t.Errorf("expected ASN 3215, got %d", result.ASN)
	}
}

func TestASNLookup_ParseRIPEResponse_EmptyObjects(t *testing.T) {
	lookup := NewASNLookup()

	response := `{"objects": {"object": []}}`

	_, err := lookup.parseRIPEResponse([]byte(response))

	if err == nil {
		t.Error("expected error for empty objects")
	}
}

func TestASNLookup_LookupRIPE_UsesHTTPServer(t *testing.T) {
	// Start a test HTTP server that returns RIPE-like JSON
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify correct query parameters
		query := r.URL.Query().Get("query-string")
		if query != "80.10.255.25" {
			t.Errorf("expected query-string '80.10.255.25', got %q", query)
		}
		typeFilter := r.URL.Query().Get("type-filter")
		if typeFilter != "route" {
			t.Errorf("expected type-filter 'route', got %q", typeFilter)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"objects": {
				"object": [
					{
						"type": "route",
						"attributes": {
							"attribute": [
								{"name": "route", "value": "80.10.248.0/21"},
								{"name": "descr", "value": "France Telecom"},
								{"name": "origin", "value": "AS3215"}
							]
						}
					}
				]
			}
		}`)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	lookup := NewASNLookup()
	lookup.ripeBaseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := lookup.lookupRIPE(ctx, net.ParseIP("80.10.255.25"))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != 3215 {
		t.Errorf("expected ASN 3215, got %d", result.ASN)
	}
	if result.Name != "France Telecom" {
		t.Errorf("expected name 'France Telecom', got %q", result.Name)
	}
}

func TestASNLookup_LookupRIPE_ReturnsErrorOnNoRoute(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"objects": {
				"object": [
					{
						"type": "inetnum",
						"attributes": {
							"attribute": [
								{"name": "inetnum", "value": "193.253.80.0 - 193.253.95.255"},
								{"name": "netname", "value": "RBCI"}
							]
						}
					}
				]
			}
		}`)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	lookup := NewASNLookup()
	lookup.ripeBaseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := lookup.lookupRIPE(ctx, net.ParseIP("193.253.83.98"))

	if err == nil {
		t.Error("expected error when RIPE returns no route object")
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

func TestASNLookup_FormatQueryV6_NibbleReverses(t *testing.T) {
	lookup := NewASNLookup()

	// Google Public DNS IPv6: 2001:4860:4860::8888
	query := lookup.formatQueryV6(net.ParseIP("2001:4860:4860::8888"))

	expected := "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestASNLookup_FormatQueryV6_FullAddress(t *testing.T) {
	lookup := NewASNLookup()

	// Full IPv6 address
	query := lookup.formatQueryV6(net.ParseIP("2606:4700:4700::1111"))

	// 2606:4700:4700::1111 expands to 2606:4700:4700:0000:0000:0000:0000:1111
	expected := "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.origin6.asn.cymru.com"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestASNLookup_DetectsIPv6(t *testing.T) {
	lookup := NewASNLookup()

	// IPv4 should use formatQuery (ends with origin.asn.cymru.com)
	v4Query := lookup.formatQueryForIP(net.ParseIP("8.8.8.8"))
	if v4Query != "8.8.8.8.origin.asn.cymru.com" {
		t.Errorf("expected IPv4 query, got %q", v4Query)
	}

	// IPv6 should use formatQueryV6 (ends with origin6.asn.cymru.com)
	v6Query := lookup.formatQueryForIP(net.ParseIP("2001:4860:4860::8888"))
	if v6Query == "" {
		t.Error("expected non-empty IPv6 query")
	}
	if v6Query[len(v6Query)-len("origin6.asn.cymru.com"):] != "origin6.asn.cymru.com" {
		t.Errorf("expected IPv6 query to end with origin6.asn.cymru.com, got %q", v6Query)
	}
}

// Integration test for IPv6 - skip if no network
func TestASNLookup_Lookup_IPv6(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	lookup := NewASNLookup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Google DNS IPv6 - well-known ASN
	result, err := lookup.Lookup(ctx, net.ParseIP("2001:4860:4860::8888"))

	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	// Google's ASN should be returned
	if result.ASN == 0 {
		t.Error("expected non-zero ASN for Google IPv6 DNS")
	}
}
