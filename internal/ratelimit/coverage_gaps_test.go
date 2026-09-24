package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterNewClampsBurst(t *testing.T) {
	l := New(1, 0)
	if l.burst != 1 {
		t.Fatalf("burst = %v, want 1", l.burst)
	}
	l = New(1, -5)
	if l.burst != 1 {
		t.Fatalf("negative burst = %v, want 1", l.burst)
	}
}

func TestLimiterRetryAfterBranches(t *testing.T) {
	l := New(1, 2)
	if got := l.RetryAfter("unknown"); got != 0 {
		t.Fatalf("RetryAfter(unknown key) = %v, want 0", got)
	}
	if !l.Allow("k") {
		t.Fatal("first request denied")
	}
	if got := l.RetryAfter("k"); got != 0 {
		t.Fatalf("RetryAfter with a spare token = %v, want 0", got)
	}

	zero := New(0, 1)
	if !zero.Allow("k") {
		t.Fatal("burst token must be available at zero rate")
	}
	if got := zero.RetryAfter("k"); got != time.Hour {
		t.Fatalf("RetryAfter at zero rate = %v, want 1h", got)
	}

	slow := New(0.5, 1)
	if !slow.Allow("k") {
		t.Fatal("burst token must be available")
	}
	if got := slow.RetryAfter("k"); got <= 0 || got > time.Hour {
		t.Fatalf("RetryAfter at low rate = %v", got)
	}
}

// TestLimiterHardCapEvictsLRU pins the G2-A regression: a flood of distinct
// keys keeps the bucket map hard-capped at maxBuckets (it never grows to 4x or
// beyond as the old idle-only sweep allowed), the most recently used keys
// survive, and each Allow call stays O(1).
func TestLimiterHardCapEvictsLRU(t *testing.T) {
	l := New(1, 1)
	total := maxBuckets * 4
	for i := 0; i < total; i++ {
		l.Allow(fmt.Sprintf("k%d", i))
	}
	if got := len(l.buckets); got > maxBuckets {
		t.Fatalf("bucket map = %d, want <= %d", got, maxBuckets)
	}
	if got := l.Len(); got != len(l.buckets) {
		t.Fatalf("Len = %d, map = %d", got, len(l.buckets))
	}
	// The most recently inserted key is resident; the oldest are evicted.
	if _, ok := l.buckets[fmt.Sprintf("k%d", total-1)]; !ok {
		t.Fatal("most-recently-used bucket evicted")
	}
	if _, ok := l.buckets["k0"]; ok {
		t.Fatal("least-recently-used bucket survived the cap")
	}
	// Touching an old-but-resident key protects it from the next eviction.
	old := fmt.Sprintf("k%d", total-maxBuckets)
	l.Allow(old) // move to front
	for i := 0; i < 10; i++ {
		l.Allow(fmt.Sprintf("new%d", i))
	}
	if _, ok := l.buckets[old]; !ok {
		t.Fatal("recently touched bucket evicted despite LRU order")
	}
}

func TestKeyFallbackBranches(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := Key(r); got != "ip:203.0.113.7" {
		t.Fatalf("Key(host:port) = %q", got)
	}
	r.RemoteAddr = "203.0.113.7"
	if got := Key(r); got != "ip:203.0.113.7" {
		t.Fatalf("Key(bare host) = %q", got)
	}
	r.RemoteAddr = ""
	if got := Key(r); got != "ip:unknown" {
		t.Fatalf("Key(empty RemoteAddr) = %q", got)
	}
	// A runner-tier path without a credential falls back to the IP, never
	// the path-derived id.
	r.RemoteAddr = "203.0.113.7:1"
	r.URL.Path = "/api/v1/runners/runner-9/next"
	if got := Key(r); got != "ip:203.0.113.7" {
		t.Fatalf("Key(runner path, no credential) = %q", got)
	}
	// A malformed Authorization scheme is not treated as a credential.
	r.Header.Set("Authorization", "Token abc")
	if got := Key(r); got != "ip:203.0.113.7" {
		t.Fatalf("Key(non-bearer scheme) = %q", got)
	}
}
