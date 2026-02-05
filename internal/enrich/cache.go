package enrich

import (
	"sync"

	"github.com/hervehildenbrand/gtr/pkg/hop"
)

// CacheStats contains cache statistics.
type CacheStats struct {
	Hits   int64
	Misses int64
	Size   int
}

// Cache provides thread-safe caching of enrichment results.
type Cache struct {
	mu       sync.RWMutex
	entries  map[string]*hop.Enrichment
	maxSize  int
	hits     int64
	misses   int64
}

// NewCache creates a new cache with the given maximum size.
func NewCache(maxSize int) *Cache {
	return &Cache{
		entries: make(map[string]*hop.Enrichment),
		maxSize: maxSize,
	}
}

// Get retrieves an enrichment from the cache.
func (c *Cache) Get(key string) (*hop.Enrichment, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[key]
	if ok {
		c.mu.RUnlock()
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		c.mu.RLock()
		return e, true
	}

	c.mu.RUnlock()
	c.mu.Lock()
	c.misses++
	c.mu.Unlock()
	c.mu.RLock()

	return nil, false
}

// Set stores an enrichment in the cache.
func (c *Cache) Set(key string, e *hop.Enrichment) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if at max size, clear oldest entries
	if len(c.entries) >= c.maxSize {
		// Simple strategy: clear half the cache
		count := 0
		for k := range c.entries {
			delete(c.entries, k)
			count++
			if count >= c.maxSize/2 {
				break
			}
		}
	}

	c.entries[key] = e
}

// Stats returns cache statistics.
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CacheStats{
		Hits:   c.hits,
		Misses: c.misses,
		Size:   len(c.entries),
	}
}
