package transport

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

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
		e = &rlEntry{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
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
