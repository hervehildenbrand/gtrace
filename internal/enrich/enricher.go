package enrich

import (
	"context"
	"net"
	"sync"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

// EnricherInterface defines the contract for IP enrichment.
// This interface allows for dependency injection and easier testing.
type EnricherInterface interface {
	// EnrichIP performs all enrichment lookups for a single IP.
	EnrichIP(ctx context.Context, ip net.IP) (*hop.Enrichment, error)

	// EnrichHop enriches a hop with ASN, hostname, etc.
	EnrichHop(ctx context.Context, h *hop.Hop)

	// EnrichTrace enriches all hops in a trace result.
	EnrichTrace(ctx context.Context, tr *hop.TraceResult)
}

// Enricher provides IP enrichment by combining ASN, GeoIP, IX, and rDNS lookups.
type Enricher struct {
	asn   *ASNLookup
	geo   *GeoLookup
	ix    *IXLookup
	rdns  *RDNSLookup
	cache *Cache
}

// NewEnricher creates a new enricher with default settings.
func NewEnricher() *Enricher {
	return &Enricher{
		asn:   NewASNLookup(),
		geo:   NewGeoLookup(),
		ix:    NewIXLookup(),
		rdns:  NewRDNSLookup(),
		cache: NewCache(10000), // Cache up to 10k IPs
	}
}

// EnrichIP performs all enrichment lookups for a single IP.
func (e *Enricher) EnrichIP(ctx context.Context, ip net.IP) (*hop.Enrichment, error) {
	if ip == nil {
		return &hop.Enrichment{}, nil
	}

	key := ip.String()

	// Check cache first
	if cached, ok := e.cache.Get(key); ok {
		return cached, nil
	}

	result := &hop.Enrichment{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	// ASN lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		asnResult, err := e.asn.Lookup(ctx, ip)
		if err == nil && asnResult != nil {
			mu.Lock()
			result.ASN = asnResult.ASN
			result.ASOrg = asnResult.Name
			if result.Country == "" {
				result.Country = asnResult.Country
			}
			mu.Unlock()
		}
	}()

	// GeoIP lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		geoResult, err := e.geo.Lookup(ctx, ip)
		if err == nil && geoResult != nil && !geoResult.IsEmpty() {
			mu.Lock()
			if geoResult.City != "" {
				result.City = geoResult.City
			}
			if geoResult.Country != "" && result.Country == "" {
				result.Country = geoResult.Country
			}
			mu.Unlock()
		}
	}()

	// IX lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ixResult, err := e.ix.Lookup(ctx, ip)
		if err == nil && ixResult != nil && ixResult.IsIX() {
			mu.Lock()
			result.IX = ixResult.Name
			mu.Unlock()
		}
	}()

	// Reverse DNS lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hostname, err := e.rdns.Lookup(ctx, ip)
		if err == nil && hostname != "" {
			mu.Lock()
			result.Hostname = hostname
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Cache the result
	e.cache.Set(key, result)

	return result, nil
}

// EnrichHop enriches a hop with ASN, hostname, etc.
func (e *Enricher) EnrichHop(ctx context.Context, h *hop.Hop) {
	ip := h.PrimaryIP()
	if ip == nil {
		return
	}

	enrichment, _ := e.EnrichIP(ctx, ip)
	if enrichment != nil {
		h.SetEnrichment(*enrichment)
	}
}

// EnrichTrace enriches all hops in a trace result.
func (e *Enricher) EnrichTrace(ctx context.Context, tr *hop.TraceResult) {
	var wg sync.WaitGroup

	for _, h := range tr.Hops {
		wg.Add(1)
		go func(h *hop.Hop) {
			defer wg.Done()
			e.EnrichHop(ctx, h)
		}(h)
	}

	wg.Wait()
}

// CacheStats returns cache statistics.
func (e *Enricher) CacheStats() CacheStats {
	return e.cache.Stats()
}
