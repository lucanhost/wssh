package transport

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiterBurstThenDeny(t *testing.T) {
	rl := NewRateLimiter(1, 2, time.Minute)
	defer rl.Close()
	for i := 0; i < 2; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("request beyond burst allowed")
	}
	if !rl.Allow("5.6.7.8") {
		t.Fatal("other IP denied")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := NewRateLimiter(0, 0, time.Minute)
	defer rl.Close()
	for i := 0; i < 100; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatal("disabled limiter denied a request")
		}
	}
}

func TestRateLimiterEvictsIdle(t *testing.T) {
	rl := NewRateLimiter(1, 1, 20*time.Millisecond)
	defer rl.Close()
	if !rl.Allow("1.2.3.4") {
		t.Fatal("first request denied")
	}
	time.Sleep(150 * time.Millisecond)
	rl.mu.Lock()
	n := len(rl.entries)
	rl.mu.Unlock()
	if n != 0 {
		t.Fatalf("idle entry not evicted, %d remain", n)
	}
}

func TestRateLimiterCapsEntries(t *testing.T) {
	rl := NewRateLimiter(1000, 1000, time.Hour)
	defer rl.Close()
	for i := 0; i < maxEntries; i++ {
		if !rl.Allow(fmt.Sprintf("ip-%d", i)) {
			t.Fatalf("ip-%d denied before cap", i)
		}
	}
	rl.mu.Lock()
	n := len(rl.entries)
	rl.mu.Unlock()
	if n > maxEntries {
		t.Fatalf("entries = %d, exceeds cap %d", n, maxEntries)
	}
	if !rl.Allow("ip-overflow") {
		t.Fatal("new IP denied at capacity")
	}
	rl.mu.Lock()
	n = len(rl.entries)
	_, oldestPresent := rl.entries["ip-0"]
	rl.mu.Unlock()
	if n > maxEntries {
		t.Fatalf("map grew past cap: %d entries", n)
	}
	if oldestPresent {
		t.Fatal("oldest entry not evicted at capacity")
	}
	if !rl.Allow("ip-1") {
		t.Fatal("recently-seen entry denied after eviction")
	}
}
