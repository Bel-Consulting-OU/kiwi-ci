package config

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestDefaultRateLimitsAreFiniteForPublicClasses pins the Finding 4 default:
// a config that never mentions rate_limit still installs finite buckets for
// the public/body-authenticated classes (webhooks, oidc, enroll) instead of
// leaving them unlimited.
func TestDefaultRateLimitsAreFiniteForPublicClasses(t *testing.T) {
	cfg := Default()
	classes := cfg.RateLimitClasses()
	m := cfg.RateLimitMiddleware()
	if m == nil {
		t.Fatal("Default() produced no rate limiter")
	}
	if cfg.RateLimitBurst() <= 0 {
		t.Fatalf("default burst = %d, want a positive bucket", cfg.RateLimitBurst())
	}
	for _, class := range []string{ratelimit.ClassWebhooks, ratelimit.ClassOIDC, ratelimit.ClassEnroll, ratelimit.ClassRegister, ratelimit.ClassLogin} {
		if classes[class] <= 0 {
			t.Errorf("default class %q rate = %v, want finite", class, classes[class])
		}
		if _, ok := m.ByClass[class]; !ok {
			t.Errorf("no limiter bucket for default class %q", class)
		}
	}
	// A finite limiter must actually refuse eventually (burst tokens then no
	// refill within the same instant).
	l := m.ByClass[ratelimit.ClassWebhooks]
	if l == nil {
		t.Fatal("webhooks limiter missing")
	}
	for i := 0; i <= cfg.RateLimitBurst(); i++ {
		l.Allow("burst-probe")
	}
	if l.Allow("burst-probe") {
		t.Fatal("finite webhook limiter admitted an unbounded burst")
	}
}

// TestProductionValidationRequiresFinitePublicRates: production refuses an
// explicitly-zeroed public class with a rate_limit.* error, while dev keeps
// the explicit 0 = unlimited semantics.
func TestProductionValidationRequiresFinitePublicRates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"webhooks", func(c *Config) { c.RateLimit.WebhooksPerSecond = 0 }},
		{"oidc", func(c *Config) { c.RateLimit.OIDCPerSecond = 0 }},
		{"enroll", func(c *Config) { c.RateLimit.EnrollPerSecond = 0 }},
		{"register", func(c *Config) { c.RateLimit.RegisterPerSecond = 0 }},
		{"login", func(c *Config) { c.RateLimit.LoginPerSecond = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(cfg)
			cfg.Server.Mode = "production"
			cfg.Server.ExternalURL = "https://ci.example.com"
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("production accepted a zero %s rate", tc.name)
			}
			if !strings.Contains(err.Error(), "rate_limit."+tc.name) {
				t.Fatalf("production zero-rate error %q does not mention rate_limit.%s", err, tc.name)
			}
			// The same explicit 0 in dev means unlimited.
			dev := Default()
			tc.mutate(dev)
			dev.Server.Mode = "dev"
			if err := dev.Validate(); err != nil {
				t.Fatalf("dev explicit 0 = unlimited rejected: %v", err)
			}
			want := 0.0
			if tc.name == "login" {
				// Login is never unlimited: an explicit 0 still keeps the
				// always-on floor of 1/s.
				want = 1
			}
			if got := dev.RateLimitClasses()[tc.name]; got != want {
				t.Fatalf("dev explicit 0 class %s = %v, want %v", tc.name, got, want)
			}
		})
	}
}
