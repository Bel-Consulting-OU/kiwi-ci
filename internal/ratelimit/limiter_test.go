package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

func TestLimiterBurst(t *testing.T) {
	l := New(100, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("request %d denied within burst", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th request admitted, want burst exhaustion")
	}
	if wait := l.RetryAfter("k"); wait <= 0 {
		t.Fatalf("RetryAfter = %v, want positive", wait)
	}
}

func TestLimiterKeyIsolation(t *testing.T) {
	l := New(100, 1)
	if !l.Allow("a") {
		t.Fatal("first key denied")
	}
	if !l.Allow("b") {
		t.Fatal("second key denied; budgets must be independent")
	}
	if l.Allow("a") {
		t.Fatal("key a over-admitted")
	}
}

func TestLimiterRefill(t *testing.T) {
	// 100 tokens/s: after 60ms the bucket holds 6 tokens, enough for the
	// requests after the initial burst.
	l := New(100, 2)
	l.Allow("k")
	l.Allow("k")
	if l.Allow("k") {
		t.Fatal("burst not enforced")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("token not refilled after wait")
	}
}

func TestLimiterZeroRate(t *testing.T) {
	l := New(0, 2)
	if !l.Allow("k") {
		t.Fatal("first burst token should be available even at zero rate")
	}
	if !l.Allow("k") {
		t.Fatal("second burst token should be available even at zero rate")
	}
	if l.Allow("k") {
		t.Fatal("zero rate must deny after burst")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{http.MethodPost, "/hooks/github", ClassWebhooks},
		{http.MethodPost, "/login", ClassLogin},
		{http.MethodPost, "/api/v1/runners/enroll", ClassEnroll},
		{http.MethodPost, "/api/v1/runners/register", ClassRegister},
		{http.MethodPost, "/api/v1/runners/r1/next", ClassNext},
		{http.MethodPost, "/api/v1/jobs/j1/heartbeat", ClassHeartbeat},
		{http.MethodPost, "/api/v1/jobs/j1/oidc", ClassOIDC},
		{http.MethodPost, "/api/v1/jobs/j1/secrets", ClassSecrets},
		{http.MethodGet, "/api/v1/runs/run1/logs", ClassLogs},
		{http.MethodPost, "/api/v1/jobs/j1/log", ClassLogs},
		{http.MethodPut, "/api/v1/jobs/j1/artifacts/dist", ClassArtifactUpload},
		{http.MethodPut, "/api/v1/cache/my-key", ClassCacheUpload},
		{http.MethodGet, "/api/v1/cache/my-key", ClassDefault},
		{http.MethodPost, "/api/v1/runs", ClassDispatch},
		{http.MethodGet, "/api/v1/runs", ClassDefault},
		{http.MethodGet, "/metrics", ClassDefault},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if got := Classify(r); got != c.want {
			t.Errorf("Classify(%s %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestRunnerIDFromPath(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/api/v1/runners/r1/next", "r1"},
		{"/api/v1/runners/r2/drain", "r2"},
		{"/api/v1/runners/register", ""},
		{"/api/v1/runners/enroll", ""},
		{"/api/v1/runners", ""},
		{"/api/v1/jobs/j1/log", ""},
	}
	for _, c := range cases {
		if got := RunnerIDFromPath(c.path); got != c.want {
			t.Errorf("RunnerIDFromPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestKeyPriority(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/runners/r1/next", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	if got := Key(r); got != "runner:r1" {
		t.Errorf("Key = %q, want runner:r1", got)
	}
	r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Subject: "svc-1"}))
	if got := Key(r); got != "principal:svc-1" {
		t.Errorf("Key with principal = %q, want principal:svc-1", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	r2.RemoteAddr = "10.0.0.2:5678"
	if got := Key(r2); got != "ip:10.0.0.2" {
		t.Errorf("Key by IP = %q, want ip:10.0.0.2", got)
	}
}

func TestMiddleware429(t *testing.T) {
	m := NewMiddleware(map[string]float64{ClassDefault: 100, ClassLogs: 100}, 2)
	hits := 0
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	do := func(path string, remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("/api/v1/runs", "10.0.0.1:1"); w.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", w.Code)
	}
	if w := do("/api/v1/runs", "10.0.0.1:1"); w.Code != http.StatusOK {
		t.Fatalf("second request = %d, want 200", w.Code)
	}
	w := do("/api/v1/runs", "10.0.0.1:1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third request = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 missing Retry-After header")
	}
	if hits != 2 {
		t.Errorf("handler called %d times, want 2", hits)
	}
	// A different IP has an independent budget.
	if w := do("/api/v1/runs", "10.0.0.2:1"); w.Code != http.StatusOK {
		t.Errorf("different IP denied: %d", w.Code)
	}
	// Per-class budgets are independent: logs class has its own tokens.
	if w := do("/api/v1/runs/r1/logs", "10.0.0.1:1"); w.Code != http.StatusOK {
		t.Errorf("logs class denied under default budget: %d", w.Code)
	}
}

func TestMiddlewareClassFallback(t *testing.T) {
	// No default limiter: an unlimited class passes through.
	m := NewMiddleware(map[string]float64{ClassNext: 100}, 1)
	called := false
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	r.RemoteAddr = "10.0.0.9:1"
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("request without a class limiter did not pass through")
	}
}

func TestMiddlewareUnlimitedWithoutRates(t *testing.T) {
	m := NewMiddleware(map[string]float64{ClassDefault: 0}, 1)
	called := false
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.9:1"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if !called {
		t.Fatal("zero-rate limiter should not exist")
	}
}
