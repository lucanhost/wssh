package transport

import (
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
