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

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rlEntry
	rate    rate.Limit
	burst   int
	ttl     time.Duration
	stop    chan struct{}
}

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

func (rl *RateLimiter) Close() {
	close(rl.stop)
}
