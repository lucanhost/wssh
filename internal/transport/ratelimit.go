package transport

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxEntries bounds the per-IP entry map so spoofed or distributed sources
// cannot grow it without limit between sweeps.
const maxEntries = 10000

type rlEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter is a per-key (client IP) token-bucket rate limiter with idle
// eviction and a bounded entry count.
//
// Each key gets its own limiter created on first use. Entries idle longer
// than the TTL are dropped by a background sweep goroutine; when the entry
// map reaches its maximum size, stale entries are evicted and, if none are
// stale, the least-recently-seen entry is dropped, so spoofed sources cannot
// grow the map without limit.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rlEntry
	rate    rate.Limit
	burst   int
	ttl     time.Duration
	stop    chan struct{}
}

// NewRateLimiter returns a RateLimiter admitting ratePerSec requests per
// second per key with the given burst, and starts a background goroutine
// that sweeps every idleTTL, dropping entries idle longer than idleTTL.
// A ratePerSec of 0 or less disables limiting: Allow always returns true.
// Call Close to stop the sweep goroutine.
func NewRateLimiter(ratePerSec float64, burst int, idleTTL time.Duration) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string]*rlEntry),
		rate:    rate.Limit(ratePerSec),
		burst:   burst,
		ttl:     idleTTL,
		stop:    make(chan struct{}),
	}
	go rl.sweep()
	return rl
}

// Allow reports whether a request from ip may proceed, recording the access
// time for eviction purposes. It always returns true when limiting is
// disabled.
func (rl *RateLimiter) Allow(ip string) bool {
	if rl.rate <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		if len(rl.entries) >= maxEntries {
			rl.evictLocked()
		}
		e = &rlEntry{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// evictLocked makes room for one new entry: it first drops entries idle past
// the TTL; if none are stale, it drops the least-recently-seen entry.
// Caller must hold rl.mu.
func (rl *RateLimiter) evictLocked() {
	cutoff := time.Now().Add(-rl.ttl)
	for ip, e := range rl.entries {
		if e.lastSeen.Before(cutoff) {
			delete(rl.entries, ip)
		}
	}
	if len(rl.entries) < maxEntries {
		return
	}
	var oldestIP string
	var oldest time.Time
	for ip, e := range rl.entries {
		if oldestIP == "" || e.lastSeen.Before(oldest) {
			oldestIP, oldest = ip, e.lastSeen
		}
	}
	delete(rl.entries, oldestIP)
}

func (rl *RateLimiter) sweep() {
	ticker := time.NewTicker(rl.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-rl.ttl)
			rl.mu.Lock()
			for ip, e := range rl.entries {
				if e.lastSeen.Before(cutoff) {
					delete(rl.entries, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Close stops the background eviction goroutine. The limiter must not be
// used after Close.
func (rl *RateLimiter) Close() {
	close(rl.stop)
}
