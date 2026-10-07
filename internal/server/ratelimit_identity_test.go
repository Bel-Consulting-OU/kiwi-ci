package server

// Finding 1: mTLS-only runners behind one NAT/proxy must not share one
// rate-limit bucket. The runner tier gate binds the identity it PROVED
// (certificate subject mapping / per-runner bearer) to the request context,
// and the limiter keys on it — never on the attacker-controlled path id.

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/ratelimit"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// TestMTLSRunnerRateLimitUsesAuthenticatedIdentity drives the real handler
// chain: every request has the SAME RemoteAddr (httptest's default), so
// before the fix one runner exhausting the shared IP bucket 429s unrelated
// authentic runners behind the same NAT.
func TestMTLSRunnerRateLimitUsesAuthenticatedIdentity(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.RunnerCA = ca
	s.RequireRunnerClientCerts = true
	// One token for runner-a's bucket, zero refill so exhaustion is stable.
	s.RateLimiter = ratelimit.NewMiddleware(map[string]float64{ratelimit.ClassNext: 0.000001}, 1)
	h := s.Handler()
	_, certA := pkiSignRunner(t, ca, "runner-a")
	_, certB := pkiSignRunner(t, ca, "runner-b")

	do := func(path string, cert *x509.Certificate) int {
		t.Helper()
		w := pkiRequest(t, h, http.MethodPost, path, map[string]any{}, "runner-tok", cert)
		return w.Code
	}

	if code := do("/api/v1/runners/runner-a/next", certA); code == http.StatusTooManyRequests {
		t.Fatalf("first request for runner-a was 429: %d", code)
	}
	if code := do("/api/v1/runners/runner-a/next", certA); code != http.StatusTooManyRequests {
		t.Fatalf("runner-a second request = %d, want 429 (bucket must exhaust)", code)
	}
	// runner-b authenticates from the SAME RemoteAddr: a separate bucket.
	if code := do("/api/v1/runners/runner-b/next", certB); code == http.StatusTooManyRequests {
		t.Fatal("runner-b was 429'd by runner-a's exhausted IP bucket: mTLS runners share the NAT bucket")
	}
	// A forged path under runner-a's certificate stays on runner-a's bucket
	// (the path id is attacker-controlled and never a limiter identity).
	if code := do("/api/v1/runners/forged-id/next", certA); code != http.StatusTooManyRequests {
		t.Fatalf("forged-path request with runner-a identity = %d, want 429 on the authenticated bucket", code)
	}
}

// TestRunnerRateLimitUnauthenticatedFallsBackToIP: without a proven runner
// credential the limiter still uses the client IP; the tier gate refuses the
// request before the limiter when no credential is configured, so this pins
// the key derivation on the middleware directly.
func TestRunnerRateLimitUnauthenticatedFallsBackToIP(t *testing.T) {
	m := ratelimit.NewMiddleware(map[string]float64{ratelimit.ClassNext: 100}, 1)
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	do := func() int {
		req, _ := http.NewRequest(http.MethodPost, "/api/v1/runners/r1/next", nil)
		req.RemoteAddr = "198.51.100.9:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	if code := do(); code != http.StatusOK {
		t.Fatalf("first unauthenticated request = %d, want 200", code)
	}
	if code := do(); code != http.StatusTooManyRequests {
		t.Fatalf("second unauthenticated request = %d, want 429 from the IP bucket", code)
	}
}
