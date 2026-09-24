package config

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/ratelimit"
)

// TestRateLimitClassesEngageForRealRoutes is the G2-B regression: the
// configured per-class rates must produce buckets for the REAL login, logs
// and cache-upload routes. Before the classifier fix those routes were
// classified as "default" (login) or mismatched entirely, so the per-class
// buckets were dead.
func TestRateLimitClassesEngageForRealRoutes(t *testing.T) {
	cfg := Default()
	cfg.RateLimit.LoginPerSecond = 5
	cfg.RateLimit.LogsPerSecond = 6
	cfg.RateLimit.CacheUploadPerSecond = 7
	m := cfg.RateLimitMiddleware()
	if m == nil {
		t.Fatal("expected an enabled middleware")
	}
	cases := []struct {
		method, path, class string
	}{
		{http.MethodPost, "/api/v1/login", ratelimit.ClassLogin},
		{http.MethodPost, "/api/v1/jobs/j1/log/batch", ratelimit.ClassLogs},
		{http.MethodPost, "/api/v1/jobs/j1/log", ratelimit.ClassLogs},
		{http.MethodGet, "/api/v1/runs/r1/logs", ratelimit.ClassLogs},
		{http.MethodPut, "/api/v1/jobs/j1/cache/key", ratelimit.ClassCacheUpload},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if got := ratelimit.Classify(r); got != c.class {
			t.Errorf("Classify(%s %s) = %q, want %q", c.method, c.path, got, c.class)
			continue
		}
		if _, ok := m.ByClass[c.class]; !ok {
			t.Errorf("no limiter bucket for class %q (real route %s %s)", c.class, c.method, c.path)
		}
	}
}
