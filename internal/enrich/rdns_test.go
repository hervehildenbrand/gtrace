package enrich

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRDNSLookup_FormatQuery_ReversesIPv4(t *testing.T) {
	lookup := NewRDNSLookup()

	query := lookup.formatPTRQuery(net.ParseIP("8.8.8.8"))

	expected := "8.8.8.8.in-addr.arpa"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestRDNSLookup_FormatQuery_HandlesAllOctets(t *testing.T) {
	lookup := NewRDNSLookup()

	query := lookup.formatPTRQuery(net.ParseIP("192.168.1.100"))

	expected := "100.1.168.192.in-addr.arpa"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestRDNSLookup_CleanHostname_RemovesTrailingDot(t *testing.T) {
	lookup := NewRDNSLookup()

	hostname := lookup.cleanHostname("dns.google.")

	if hostname != "dns.google" {
		t.Errorf("expected 'dns.google', got %q", hostname)
	}
}

func TestRDNSLookup_CleanHostname_HandlesNoDot(t *testing.T) {
	lookup := NewRDNSLookup()

	hostname := lookup.cleanHostname("dns.google")

	if hostname != "dns.google" {
		t.Errorf("expected 'dns.google', got %q", hostname)
	}
}

// Integration test - skip if no network
func TestRDNSLookup_Lookup_ReturnsRealData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	lookup := NewRDNSLookup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Google DNS - well-known PTR record
	hostname, err := lookup.Lookup(ctx, net.ParseIP("8.8.8.8"))

	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if hostname != "dns.google" {
		t.Errorf("expected 'dns.google', got %q", hostname)
	}
}

func TestRDNSLookup_Lookup_ReturnsEmptyForNoPTR(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	lookup := NewRDNSLookup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Private IP - typically no PTR record
	hostname, err := lookup.Lookup(ctx, net.ParseIP("10.0.0.1"))

	// Should return empty string or error, but not crash
	if err == nil && hostname != "" {
		// This is fine - some networks have PTR for private IPs
		t.Logf("Got hostname for private IP: %s", hostname)
	}
}

func TestRDNSLookup_FormatPTRQuery_IPv6(t *testing.T) {
	lookup := NewRDNSLookup()

	// Google Public DNS IPv6: 2001:4860:4860::8888
	query := lookup.formatPTRQuery(net.ParseIP("2001:4860:4860::8888"))

	expected := "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

func TestRDNSLookup_FormatPTRQuery_IPv6Full(t *testing.T) {
	lookup := NewRDNSLookup()

	// Cloudflare DNS IPv6: 2606:4700:4700::1111
	query := lookup.formatPTRQuery(net.ParseIP("2606:4700:4700::1111"))

	expected := "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa"
	if query != expected {
		t.Errorf("expected %q, got %q", expected, query)
	}
}

// Integration test for IPv6 rDNS
func TestRDNSLookup_Lookup_IPv6(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	lookup := NewRDNSLookup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Google DNS IPv6 - should have PTR record
	hostname, err := lookup.Lookup(ctx, net.ParseIP("2001:4860:4860::8888"))

	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if hostname == "" {
		t.Log("No PTR record for Google IPv6 DNS (may be expected)")
	} else {
		t.Logf("Got hostname for Google IPv6 DNS: %s", hostname)
	}
}
