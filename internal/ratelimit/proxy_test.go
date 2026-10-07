package ratelimit

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

func mustCIDR(t *testing.T, raw string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", raw, err)
	}
	return n
}

// TestCanonicalClientIPTrustedProxy pins the trusted-proxy algorithm: only a
// trusted direct peer may contribute X-Forwarded-For, and the chain is
// walked from the RIGHT, skipping trusted hops.
func TestCanonicalClientIPTrustedProxy(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR(t, "10.0.0.0/8"), mustCIDR(t, "192.168.0.0/16")}
	cases := []struct {
		name        string
		remote      string
		xff         []string
		wantIP      string
		wantTrusted bool
		wantForward bool
	}{
		{
			name:   "untrusted peer ignores spoofed XFF",
			remote: "198.51.100.7:1234", xff: []string{"203.0.113.9"},
			wantIP: "198.51.100.7",
		},
		{
			name:   "trusted peer single hop",
			remote: "10.0.0.7:1234", xff: []string{"203.0.113.9"},
			wantIP: "203.0.113.9", wantTrusted: true, wantForward: true,
		},
		{
			name:   "multi-hop rightmost untrusted wins",
			remote: "10.0.0.7:1234", xff: []string{"203.0.113.9", "192.168.1.5"},
			wantIP: "203.0.113.9", wantTrusted: true, wantForward: true,
		},
		{
			name:   "spoofed left entries cannot move the client",
			remote: "10.0.0.7:1234", xff: []string{"1.2.3.4", "203.0.113.9", "10.0.0.5"},
			wantIP: "203.0.113.9", wantTrusted: true, wantForward: true,
		},
		{
			name:   "malformed chain falls back to peer",
			remote: "10.0.0.7:1234", xff: []string{"not-an-ip"},
			wantIP: "10.0.0.7", wantTrusted: true,
		},
		{
			name:   "partially malformed chain falls back to peer",
			remote: "10.0.0.7:1234", xff: []string{"203.0.113.9", "garbage"},
			wantIP: "10.0.0.7", wantTrusted: true,
		},
		{
			name:   "entirely trusted chain falls back to peer",
			remote: "10.0.0.7:1234", xff: []string{"10.0.0.5", "192.168.1.9"},
			wantIP: "10.0.0.7", wantTrusted: true,
		},
		{
			name:   "missing header falls back to peer",
			remote: "10.0.0.7:1234",
			wantIP: "10.0.0.7", wantTrusted: true,
		},
		{
			name:   "hop with port parses",
			remote: "10.0.0.7:1234", xff: []string{"203.0.113.9:4711"},
			wantIP: "203.0.113.9", wantTrusted: true, wantForward: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanonicalClientIP(tc.remote, tc.xff, trusted)
			if got.IP != tc.wantIP || got.TrustedPeer != tc.wantTrusted || got.Forwarded != tc.wantForward {
				t.Fatalf("CanonicalClientIP(%q, %v) = %+v, want ip=%s trusted=%v forwarded=%v",
					tc.remote, tc.xff, got, tc.wantIP, tc.wantTrusted, tc.wantForward)
			}
		})
	}
}

// TestKeyPrefersAuthenticatedRunnerIdentity pins finding 1 at the key level:
// the server-proven runner identity, never the attacker-controlled path, is
// the rate-limit identity; the IP fallback still applies without a proven
// credential.
func TestKeyPrefersAuthenticatedRunnerIdentity(t *testing.T) {
	mk := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.RemoteAddr = "10.0.0.9:1234"
		return r
	}
	r := mk("/api/v1/runners/r1/next")
	r = r.WithContext(auth.WithRunnerIdentity(r.Context(), "runner-authenticated"))
	if got := Key(r); got != "runner:runner-authenticated" {
		t.Fatalf("Key = %q, want runner:runner-authenticated", got)
	}
	// The forged path id does not change the bucket: same authenticated
	// identity -> same key.
	forged := mk("/api/v1/runners/forged-id/next")
	forged = forged.WithContext(auth.WithRunnerIdentity(forged.Context(), "runner-authenticated"))
	if got, want := Key(forged), Key(r); got != want {
		t.Fatalf("forged path key = %q, want the authenticated identity key %q", got, want)
	}
	// A different authenticated runner gets its own bucket even from the same
	// RemoteAddr.
	other := mk("/api/v1/runners/r1/next")
	other = other.WithContext(auth.WithRunnerIdentity(other.Context(), "runner-other"))
	if Key(other) == Key(r) {
		t.Fatal("distinct authenticated runners shared one bucket")
	}
	// Without a proven credential the request falls back to the canonical
	// client IP.
	bare := mk("/api/v1/runners/r1/next")
	if got := Key(bare); got != "ip:10.0.0.9" {
		t.Fatalf("unauthenticated key = %q, want ip:10.0.0.9", got)
	}
}

// TestKeyUsesCanonicalClientIP: when the middleware recorded a trusted-proxy
// decision, the limiter uses the canonical client IP, not the proxy address.
func TestKeyUsesCanonicalClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	r.RemoteAddr = "10.0.0.7:1234"
	r = r.WithContext(auth.WithClientIPInfo(r.Context(), auth.ClientIPInfo{IP: "203.0.113.9", TrustedPeer: true, Forwarded: true}))
	if got := Key(r); got != "ip:203.0.113.9" {
		t.Fatalf("Key = %q, want ip:203.0.113.9", got)
	}
}

// TestMiddlewareCanonicalizesTrustedProxyTraffic proves the middleware
// resolves (and records) the canonical client IP before keying: two clients
// behind one trusted proxy get independent budgets while an untrusted peer
// with a spoofed header is keyed by its real address.
func TestMiddlewareCanonicalizesTrustedProxyTraffic(t *testing.T) {
	m := NewMiddleware(map[string]float64{ClassDefault: 0.0001}, 1)
	m.TrustedProxies = []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}
	hits := 0
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if _, ok := auth.ClientIPInfoFrom(r); !ok {
			t.Error("request reached the handler without a recorded canonical client IP")
		}
	}))
	do := func(remote, xff string) int {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := do("10.0.0.7:1", "203.0.113.9"); code != http.StatusOK {
		t.Fatalf("client A first = %d, want 200", code)
	}
	if code := do("10.0.0.7:1", "203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("client A second = %d, want 429", code)
	}
	// A different XFF client through the SAME proxy has its own bucket.
	if code := do("10.0.0.7:1", "203.0.113.10"); code != http.StatusOK {
		t.Fatalf("client B = %d, want 200", code)
	}
	// An untrusted peer spoofing client A's XFF is keyed by its real address,
	// so A's exhausted bucket does not deny it.
	if code := do("198.51.100.7:1", "203.0.113.9"); code != http.StatusOK {
		t.Fatalf("spoofing untrusted peer = %d, want 200", code)
	}
	if code := do("198.51.100.7:1", "203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("spoofing untrusted peer second = %d, want 429", code)
	}
	if hits != 3 {
		t.Fatalf("handler hits = %d, want 3", hits)
	}
}

// TestWebhookStagesHaveSeparateBucketMaps pins the two-stage webhook
// contract at the limiter level: the pre-auth per-IP class bucket and the
// post-HMAC per-forge bucket never share state.
func TestWebhookStagesHaveSeparateBucketMaps(t *testing.T) {
	m := NewMiddleware(map[string]float64{ClassWebhooks: 100}, 1)
	if m.ByClass[ClassWebhooks] == nil || m.WebhookForge == nil {
		t.Fatal("both webhook limiter stages must exist")
	}
	if m.ByClass[ClassWebhooks] == m.WebhookForge {
		t.Fatal("pre-auth and post-HMAC webhook stages share one limiter")
	}
	// Exhaust the attacker's pre-auth bucket.
	if !m.ByClass[ClassWebhooks].Allow("ip:198.51.100.7") {
		t.Fatal("first pre-auth token denied")
	}
	if m.ByClass[ClassWebhooks].Allow("ip:198.51.100.7") {
		t.Fatal("pre-auth bucket not exhausted")
	}
	// A valid authenticated forge delivery is unaffected.
	if !m.WebhookForge.Allow("hook:github:repo") {
		t.Fatal("pre-auth flood consumed the post-HMAC forge bucket")
	}
	// And a forge flood does not consume a fresh client's pre-auth budget.
	for i := 0; i < 2; i++ {
		m.WebhookForge.Allow("hook:github:repo")
	}
	if !m.ByClass[ClassWebhooks].Allow("ip:203.0.113.9") {
		t.Fatal("forge flood consumed the pre-auth client bucket")
	}
}
