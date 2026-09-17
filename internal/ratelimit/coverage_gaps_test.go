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

func TestLimiterSweepEvictsIdleFullBuckets(t *testing.T) {
	l := New(1, 1)
	old := time.Now().Add(-2 * time.Minute)
	for i := 0; i <= maxBuckets; i++ {
		l.buckets[fmt.Sprintf("k%d", i)] = &bucket{tokens: 1, last: old}
	}
	l.buckets["fresh"] = &bucket{tokens: 0, last: time.Now()}
	l.Allow("trigger")
	if len(l.buckets) >= maxBuckets {
		t.Fatalf("sweep did not evict idle buckets: %d remain", len(l.buckets))
	}
	if _, ok := l.buckets["fresh"]; !ok {
		t.Fatal("sweep must keep buckets that are not at full capacity")
	}
	if _, ok := l.buckets["k0"]; ok {
		t.Fatal("sweep must drop idle full buckets")
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
	r.RemoteAddr = "203.0.113.7:1"
	r.URL.Path = "/api/v1/runners/runner-9/next"
	if got := Key(r); got != "runner:runner-9" {
		t.Fatalf("Key(runner path) = %q", got)
	}
}
