package ratelimit

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestLimiterCraftedBucketEdges pins the defensive LRU paths: a bucket that
// exists in the map with no list position is linked lazily on first use, and
// an over-cap map whose LRU list is empty (crafted state) is still evicted
// down to the cap instead of leaking.
func TestLimiterCraftedBucketEdges(t *testing.T) {
	l := New(1, 1)
	l.buckets["crafted"] = &bucket{tokens: 5, last: time.Now(), key: "crafted"}
	if !l.Allow("crafted") {
		t.Fatal("crafted unlinked bucket was not admitted")
	}
	if l.buckets["crafted"].el == nil {
		t.Fatal("touchLocked did not link an unlinked bucket")
	}

	over := New(1, 1)
	for i := 0; i < maxBuckets+5; i++ {
		key := "raw" + strconv.Itoa(i)
		over.buckets[key] = &bucket{tokens: 1, last: time.Now(), key: key}
	}
	if len(over.buckets) <= maxBuckets {
		t.Fatal("test setup: map is not over the cap")
	}
	over.Allow("fresh")
	if got := len(over.buckets); got > maxBuckets {
		t.Fatalf("crafted over-cap map stayed at %d buckets, want <= %d", got, maxBuckets)
	}
}

// TestRunnerTierPath pins the credential-authenticated route classifier: only
// the runner credential/mTLS routes are keyed by credential, so a bearer token
// on a public route can never mint buckets.
func TestRunnerTierPath(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/api/v1/runners/register", true},
		{http.MethodGet, "/api/v1/runners/register", false},
		{http.MethodPost, "/api/v1/runners/r1/next", true},
		{http.MethodGet, "/api/v1/runners/r1/next", false},
		{http.MethodPost, "/api/v1/jobs/j1/heartbeat", true},
		{http.MethodPost, "/api/v1/jobs/j1/log", true},
		{http.MethodPost, "/api/v1/jobs/j1/complete", true},
		{http.MethodPost, "/api/v1/jobs/j1/generated", true},
		{http.MethodPost, "/api/v1/jobs/j1/secrets", true},
		{http.MethodPost, "/api/v1/jobs/j1/tests", true},
		{http.MethodPost, "/api/v1/jobs/j1/snapshots", true},
		{http.MethodGet, "/api/v1/jobs/j1/test-shards", true},
		{http.MethodPost, "/api/v1/jobs/j1/log/batch", true},
		{http.MethodPut, "/api/v1/jobs/j1/artifacts/a1", true},
		{http.MethodGet, "/api/v1/jobs/j1/dependencies/d1/x", true},
		{http.MethodGet, "/api/v1/jobs/j1/cache/k", true},
		{http.MethodPut, "/api/v1/jobs/j1/cache/k", true},
		// Negative / structural edges.
		{http.MethodGet, "/api/v1/jobs/j1/unknown", false},
		{http.MethodDelete, "/api/v1/jobs/j1/cache/k", false},
		{http.MethodPost, "/api/v1/jobs/j1/test-shards", false},
		{http.MethodGet, "/api/v1/runners/r1/next", false},
		{http.MethodPost, "/api/v1/jobs/j1/heartbeat/extra", false},
		{http.MethodPost, "/api/v1/runners", false},
		{http.MethodPost, "/other/v1/jobs/j1/log", false},
		{http.MethodGet, "/", false},
	}
	for _, tc := range cases {
		if got := runnerTierPath(tc.method, tc.path); got != tc.want {
			t.Errorf("runnerTierPath(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}
