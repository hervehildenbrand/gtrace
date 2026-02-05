package enrich

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hervehildenbrand/gtr/pkg/hop"
)

func TestNewEnricher_CreatesWithDefaults(t *testing.T) {
	e := NewEnricher()

	if e == nil {
		t.Fatal("expected non-nil enricher")
	}
	if e.cache == nil {
		t.Error("expected cache to be initialized")
	}
}

func TestEnricher_EnrichIP_ReturnsEnrichment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	e := NewEnricher()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := e.EnrichIP(ctx, net.ParseIP("8.8.8.8"))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ASN != 15169 {
		t.Errorf("expected ASN 15169, got %d", result.ASN)
	}
	if result.Hostname == "" {
		t.Error("expected hostname to be set")
	}
}

func TestEnricher_EnrichIP_CachesResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	e := NewEnricher()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ip := net.ParseIP("8.8.8.8")

	// First call
	result1, _ := e.EnrichIP(ctx, ip)

	// Second call should be cached
	result2, _ := e.EnrichIP(ctx, ip)

	if result1.ASN != result2.ASN {
		t.Error("expected same ASN from cache")
	}

	// Check cache hit
	stats := e.CacheStats()
	if stats.Hits == 0 {
		t.Error("expected cache hit")
	}
}

func TestEnricher_EnrichHop_EnrichesAllProbes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	e := NewEnricher()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("8.8.8.8"), 5*time.Millisecond)

	e.EnrichHop(ctx, h)

	if h.Enrichment.ASN == 0 {
		t.Error("expected ASN to be set")
	}
	if h.Enrichment.Hostname == "" {
		t.Error("expected hostname to be set")
	}
}

func TestEnricher_EnrichHop_HandlesPrivateIPs(t *testing.T) {
	e := NewEnricher()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := hop.NewHop(1)
	h.AddProbe(net.ParseIP("192.168.1.1"), 5*time.Millisecond)

	// Should not error on private IPs
	e.EnrichHop(ctx, h)

	// Private IPs won't have ASN, but should still work
	// The enrichment may be empty, which is fine
}

func TestEnricher_EnrichHop_SkipsTimeouts(t *testing.T) {
	e := NewEnricher()
	ctx := context.Background()

	h := hop.NewHop(1)
	h.AddTimeout()
	h.AddTimeout()

	// Should not error when all probes are timeouts
	e.EnrichHop(ctx, h)

	if h.Enrichment.ASN != 0 {
		t.Error("expected no ASN for timeout hop")
	}
}

func TestCache_GetSet_StoresValue(t *testing.T) {
	c := NewCache(100)

	enrichment := &hop.Enrichment{
		ASN:      12345,
		Hostname: "test.example.com",
	}

	c.Set("192.168.1.1", enrichment)
	result, ok := c.Get("192.168.1.1")

	if !ok {
		t.Fatal("expected cache hit")
	}
	if result.ASN != 12345 {
		t.Errorf("expected ASN 12345, got %d", result.ASN)
	}
}

func TestCache_Get_ReturnsFalseForMiss(t *testing.T) {
	c := NewCache(100)

	_, ok := c.Get("192.168.1.1")

	if ok {
		t.Error("expected cache miss")
	}
}

func TestCache_Stats_TracksHitsMisses(t *testing.T) {
	c := NewCache(100)

	c.Set("key1", &hop.Enrichment{ASN: 1})
	c.Get("key1") // Hit
	c.Get("key2") // Miss

	stats := c.Stats()

	if stats.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}
