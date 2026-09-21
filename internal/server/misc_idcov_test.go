package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/ratelimit"
)

// TestIDCovLoadCRLPaths covers the CRL loader and the persistence-failure
// log path of revocation.
func TestIDCovLoadCRLPaths(t *testing.T) {
	if err := New("t").loadCRL(""); err != nil {
		t.Fatalf("loadCRL(\"\") = %v", err)
	}
	empty := t.TempDir()
	s := New("t")
	if err := s.loadCRL(empty); err != nil || len(s.crl) != 0 {
		t.Fatalf("loadCRL(missing) = %v (%v)", err, s.crl)
	}
	// A directory at the CRL path is a read error.
	dirPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirPath, crlFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadCRL(dirPath); err == nil {
		t.Fatal("directory as CRL = nil error")
	}
	// Corrupt JSON is refused.
	corrupt := t.TempDir()
	writeTestFile(t, filepath.Join(corrupt, crlFile), []byte("{"))
	if err := New("t").loadCRL(corrupt); err == nil {
		t.Fatal("corrupt CRL = nil error")
	}
	// Valid state loads.
	good := t.TempDir()
	writeTestFile(t, filepath.Join(good, crlFile), []byte(`{"deadbeef":"runner-a"}`))
	s2 := New("t")
	if err := s2.loadCRL(good); err != nil || s2.crl["deadbeef"] != "runner-a" {
		t.Fatalf("valid CRL = %v (%v)", err, s2.crl)
	}

	// A failed persist is logged, not fatal, and the revocation still lands
	// in memory.
	broken := New("t")
	blocker := filepath.Join(t.TempDir(), "blocker")
	writeTestFile(t, blocker, []byte("x"))
	broken.dataDir = blocker
	broken.revokeRunnerCert(context.Background(), model.Runner{ID: "runner-b", CertSerial: "serial-b"}, "admin")
	if !crlRevoked(t, broken, "serial-b") {
		t.Fatal("revocation lost after a failed persist")
	}
	// An empty serial is never revoked.
	broken.revokeRunnerCert(context.Background(), model.Runner{ID: "runner-c"}, "admin")
	if len(broken.crl) != 1 {
		t.Fatalf("empty-serial revocation wrote %v", broken.crl)
	}
}

// TestIDCovValidateRunnerRegistrationNil covers the nil-registration guard.
func TestIDCovValidateRunnerRegistrationNil(t *testing.T) {
	if err := validateRunnerRegistration(nil); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil registration = %v", err)
	}
}

// TestIDCovMetricsPanicsAndCaps covers the unknown-name panics and the
// cardinality caps for histograms and gauges.
func TestIDCovMetricsPanicsAndCaps(t *testing.T) {
	t.Run("unknown histogram panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("Observe with an unknown histogram did not panic")
			}
		}()
		NewMetrics().Observe("kiwi_nope_seconds", 1, nil)
	})
	t.Run("unknown gauge panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("SetGauge with an unknown gauge did not panic")
			}
		}()
		NewMetrics().SetGauge("kiwi_nope", 1, nil)
	})
	t.Run("histogram cardinality cap", func(t *testing.T) {
		m := NewMetrics()
		for i := 0; i < maxLabelSets+25; i++ {
			m.Observe("kiwi_step_duration_seconds", 0.01, map[string]string{"step": fmt.Sprintf("%d%s", i, strings.Repeat("x", i/40))})
		}
		m.mu.Lock()
		n := len(m.histograms["kiwi_step_duration_seconds"])
		m.mu.Unlock()
		if n != maxLabelSets {
			t.Fatalf("histogram label sets = %d, want capped at %d", n, maxLabelSets)
		}
	})
	t.Run("gauge cardinality cap", func(t *testing.T) {
		m := NewMetrics()
		for i := 0; i < maxLabelSets+25; i++ {
			m.SetGauge("kiwi_db_pool", 1, map[string]string{"stat": fmt.Sprintf("%d%s", i, strings.Repeat("x", i/40))})
		}
		m.mu.Lock()
		n := len(m.gauges["kiwi_db_pool"])
		m.mu.Unlock()
		if n != maxLabelSets {
			t.Fatalf("gauge label sets = %d, want capped at %d", n, maxLabelSets)
		}
		// A new label set past the cap is dropped silently.
		m.SetGauge("kiwi_db_pool", 2, map[string]string{"stat": "one-too-many"})
		m.mu.Lock()
		_, exists := m.gauges["kiwi_db_pool"]["stat=\"one-too-many\""]
		m.mu.Unlock()
		if exists {
			t.Fatal("gauge beyond the cap was recorded")
		}
	})
	t.Run("labeled histogram rendering", func(t *testing.T) {
		m := NewMetrics()
		m.Observe("kiwi_step_duration_seconds", 0.02, map[string]string{"step": "build"})
		var b strings.Builder
		m.WritePrometheus(&b)
		out := b.String()
		if !strings.Contains(out, `kiwi_step_duration_seconds_bucket{le="0.025",step="build"}`) {
			t.Fatalf("labeled bucket lines missing: %s", out)
		}
		if !strings.Contains(out, `kiwi_step_duration_seconds_sum{step="build"}`) {
			t.Fatalf("labeled sum lines missing: %s", out)
		}
	})
}

// TestIDCovServerMetricHelpersNilAndSet covers metricSet and the nil-registry
// no-ops.
func TestIDCovServerMetricHelpersNilAndSet(t *testing.T) {
	bare := &Server{}
	bare.metricAdd("kiwi_oidc_issues_total", 1, nil)
	bare.metricObserve("kiwi_job_duration_seconds", 1, nil)
	bare.metricSet("kiwi_runner_saturation", 1, nil)

	s := New("t")
	s.metricSet("kiwi_runner_saturation", 0.5, map[string]string{"runner": "r1"})
	s.Metrics.mu.Lock()
	got, ok := s.Metrics.gauges["kiwi_runner_saturation"]["runner=\"r1\""]
	s.Metrics.mu.Unlock()
	if !ok || got != 0.5 {
		t.Fatalf("metricSet = %v (ok=%v)", got, ok)
	}
}

// TestIDCovObserveHTTPCountsSilentHandler covers the zero-status default: a
// handler that writes nothing is recorded as 200.
func TestIDCovObserveHTTPCountsSilentHandler(t *testing.T) {
	s := New("t")
	s.Metrics.Reset()
	h := s.observeHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/liveness", nil))
	s.Metrics.mu.Lock()
	got, ok := s.Metrics.counters["kiwi_http_requests_total"]["code=\"200\",method=\"GET\",path_class=\"health\""]
	s.Metrics.mu.Unlock()
	if !ok || got != 1 {
		t.Fatalf("silent handler count = %v (ok=%v)", got, ok)
	}
}

// TestIDCovRequestIDMiddleware covers the echo, the regenerate-on-hostile
// branch and the context propagation.
func TestIDCovRequestIDMiddleware(t *testing.T) {
	seen := ""
	h := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = requestIDFrom(r)
	}))
	cases := []struct {
		name, in, want string
	}{
		{"valid", "abc-123_DEF.456", "abc-123_DEF.456"},
		{"space rejected", "bad id", ""},
		{"slash rejected", "a/b", ""},
		{"overlong rejected", strings.Repeat("a", 129), ""},
		{"empty minted", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen = ""
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.in != "" {
				r.Header.Set("X-Kiwi-Request-ID", tc.in)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			echo := w.Header().Get("X-Kiwi-Request-ID")
			if tc.want != "" {
				if echo != tc.want || seen != tc.want {
					t.Fatalf("echo = %q seen = %q, want %q", echo, seen, tc.want)
				}
				return
			}
			if len(echo) != 32 || seen != echo {
				t.Fatalf("minted id = %q seen = %q", echo, seen)
			}
		})
	}
	if requestIDFrom(httptest.NewRequest(http.MethodGet, "/", nil)) != "" {
		t.Fatal("requestIDFrom on a bare request = non-empty")
	}
}

// TestIDCovRecovererConvertsPanics covers both recoverer constructors: the
// client sees an opaque 500 with the request id, never the panic text.
func TestIDCovRecovererConvertsPanics(t *testing.T) {
	const secretPanic = "super-secret-panic-text"
	s := New("t")
	h := requestID(s.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(secretPanic)
	})))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/boom", nil)
	r.Header.Set("X-Kiwi-Request-ID", "req-1")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), secretPanic) {
		t.Fatalf("panic text leaked: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "req-1") {
		t.Fatalf("request id missing from the panic response: %s", w.Body.String())
	}

	// The package-level recoverer logs via the standard logger.
	hp := requestID(recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("package-level boom")
	})))
	wp := httptest.NewRecorder()
	hp.ServeHTTP(wp, httptest.NewRequest(http.MethodPost, "/boom2", nil))
	if wp.Code != http.StatusInternalServerError {
		t.Fatalf("package recoverer status = %d, want 500", wp.Code)
	}
}

// TestIDCovDecodeLimitHardening covers the strict decode limits: unknown
// fields, trailing data and oversized bodies.
func TestIDCovDecodeLimitHardening(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	cases := []struct {
		name string
		body string
		max  int64
	}{
		{"unknown field", `{"name":"a","extra":1}`, 1 << 20},
		{"trailing data", `{"name":"a"}{"name":"b"}`, 1 << 20},
		{"oversized", `{"name":"` + strings.Repeat("x", 64) + `"}`, 16},
		{"bad json", `{`, 1 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			var out payload
			if decodeLimit(w, r, &out, tc.max) {
				t.Fatalf("decodeLimit accepted %s", tc.name)
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
		})
	}
	// A valid payload passes.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"}`))
	var out payload
	if !decodeLimit(w, r, &out, 1<<20) || out.Name != "ok" {
		t.Fatalf("valid payload rejected: %d %s", w.Code, w.Body.String())
	}
}

// TestIDCovRateLimiterWiring covers the 429 path with the limiter wrapped
// inside the real Handler chain.
func TestIDCovRateLimiterWiring(t *testing.T) {
	s := New("admin")
	s.RateLimiter = ratelimit.NewMiddleware(map[string]float64{
		ratelimit.ClassDefault: 0.0001,
	}, 1)
	h := s.Handler()
	first := doJSON(t, s, http.MethodGet, "/api/v1/runs", "admin", "")
	if first.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", first.Code)
	}
	second := doJSON(t, s, http.MethodGet, "/api/v1/runs", "admin", "")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	_ = h
}

// TestIDCovUIRoutes covers the dashboard and static asset route shapes.
func TestIDCovUIRoutes(t *testing.T) {
	s := testWebServer(t, "admin")
	// The dashboard is only served at "/": an authenticated request to
	// another path that the catch-all pattern matches gets the 404.
	if w := doJSON(t, s, http.MethodGet, "/dashboard", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("non-root dashboard path = %d, want 404", w.Code)
	}
	// Static assets exist and unknown ones 404.
	for _, path := range []string{"/static/app.js", "/static/app.css", "/static/missing.js"} {
		w := doJSON(t, s, http.MethodGet, path, "", "")
		if path == "/static/missing.js" && w.Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404", path, w.Code)
		}
		if path != "/static/missing.js" && w.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", path, w.Code)
		}
	}
}

// TestIDCovReadinessDraining covers the draining readiness refusal.
func TestIDCovReadinessDraining(t *testing.T) {
	s := New("t")
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining readiness = %d, want 503", w.Code)
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatal("draining header missing")
	}
	if w := doJSON(t, s, http.MethodGet, "/liveness", "", ""); w.Code != http.StatusOK {
		t.Fatalf("liveness while draining = %d, want 200", w.Code)
	}
}

// TestIDCovHealthAndMetricsEndpoints covers the admin metrics endpoint and
// the health paths end to end.
func TestIDCovHealthAndMetricsEndpoints(t *testing.T) {
	s := New("admin")
	w := doJSON(t, s, http.MethodGet, "/metrics", "admin", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "kiwi_http_requests_total") {
		t.Fatalf("metrics = %d: %s", w.Code, w.Body.String())
	}
	if doJSON(t, s, http.MethodGet, "/metrics", "wrong", "").Code != http.StatusUnauthorized {
		t.Fatal("metrics accepted a wrong token")
	}
}

// TestIDCovDrainEndpointWiring covers the drain endpoints' admin gate and
// state transitions.
func TestIDCovDrainEndpointWiring(t *testing.T) {
	s := New("admin")
	if w := doJSON(t, s, http.MethodGet, "/api/v1/drain", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("drain status = %d", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/drain", "admin", "{}"); w.Code != http.StatusOK {
		t.Fatalf("drain = %d: %s", w.Code, w.Body.String())
	}
	if !s.isDraining() {
		t.Fatal("drain flag not set")
	}
	// The public health endpoints reflect the drain state.
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining readiness = %d", w.Code)
	}
}
