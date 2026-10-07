package server

// Finding 2: webhook limiting behind a reverse proxy. The coarse
// pre-authentication ClassWebhooks bucket is keyed by the CANONICAL client IP
// (trusted-proxy X-Forwarded-For resolution), so a forged-junk flood from one
// client cannot consume another client's intake budget; the POST-HMAC stage
// is a separate limiter keyed by the authenticated forge/repository identity.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/ratelimit"
)

// webhookClient posts one GitHub webhook with the given remote address and
// (optional) X-Forwarded-For header.
func webhookClient(t *testing.T, h http.Handler, remote, xff, signature, delivery, sha string) int {
	t.Helper()
	body := pushPayload(sha)
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(body))
	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", signature)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

const badSignature = "sha256=0000000000000000000000000000000000000000000000000000000000000000"

// TestWebhookInvalidHMACFloodDoesNotConsumeOtherClients: invalid-signature
// posts consume only the attacker's pre-auth client bucket; a valid webhook
// from another client is admitted.
func TestWebhookInvalidHMACFloodDoesNotConsumeOtherClients(t *testing.T) {
	s, _ := newGitHubHookServer(t, "hunter2")
	m := ratelimit.NewMiddleware(map[string]float64{ratelimit.ClassWebhooks: 0.000001}, 1)
	m.WebhookForge = ratelimit.New(1000, 100)
	s.RateLimiter = m
	h := s.Handler()

	if code := webhookClient(t, h, "198.51.100.7:1234", "", badSignature, "junk-1", "9049f1265b7d61be4a8904a9a27120d2064dab3b"); code != http.StatusUnauthorized {
		t.Fatalf("first invalid-HMAC post = %d, want 401", code)
	}
	if code := webhookClient(t, h, "198.51.100.7:1234", "", badSignature, "junk-2", "9049f1265b7d61be4a8904a9a27120d2064dab3b"); code != http.StatusTooManyRequests {
		t.Fatalf("second invalid-HMAC post = %d, want 429 (attacker bucket exhausted)", code)
	}
	// A DIFFERENT client with a valid signature must not inherit the flood's
	// exhausted bucket.
	body := pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b")
	valid := signGitHubPayload("hunter2", []byte(body))
	if code := webhookClient(t, h, "203.0.113.9:4321", "", valid, "valid-1", "9049f1265b7d61be4a8904a9a27120d2064dab3b"); code != http.StatusAccepted {
		t.Fatalf("valid webhook from another client = %d, want 202: %s", code, body)
	}
}

// TestWebhookPostHMACForgeBucketSharedAcrossSourceIPs: valid deliveries for
// one forge/repository share the authenticated forge bucket independent of
// their source addresses.
func TestWebhookPostHMACForgeBucketSharedAcrossSourceIPs(t *testing.T) {
	s, _ := newGitHubHookServer(t, "hunter2")
	m := ratelimit.NewMiddleware(map[string]float64{ratelimit.ClassWebhooks: 1000}, 100)
	m.WebhookForge = ratelimit.New(0.000001, 1)
	s.RateLimiter = m
	h := s.Handler()

	body1 := pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b")
	if code := webhookClient(t, h, "198.51.100.1:1", "", signGitHubPayload("hunter2", []byte(body1)), "forge-1", "9049f1265b7d61be4a8904a9a27120d2064dab3b"); code != http.StatusAccepted {
		t.Fatalf("first valid webhook = %d, want 202", code)
	}
	body2 := pushPayload("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if code := webhookClient(t, h, "203.0.113.5:9", "", signGitHubPayload("hunter2", []byte(body2)), "forge-2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); code != http.StatusTooManyRequests {
		t.Fatalf("second valid webhook from another IP = %d, want 429 on the shared forge bucket", code)
	}
}

// TestWebhookTrustedProxySeparatesClients: behind a trusted proxy the
// canonical client IP separates clients, while an untrusted peer's spoofed
// X-Forwarded-For is ignored.
func TestWebhookTrustedProxySeparatesClients(t *testing.T) {
	s, _ := newGitHubHookServer(t, "hunter2")
	m := ratelimit.NewMiddleware(map[string]float64{ratelimit.ClassWebhooks: 0.000001}, 1)
	m.WebhookForge = ratelimit.New(1000, 100)
	_, trustedNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	m.TrustedProxies = []*net.IPNet{trustedNet}
	s.RateLimiter = m
	h := s.Handler()

	post := func(remote, xff, delivery, sha string) int {
		body := pushPayload(sha)
		return webhookClient(t, h, remote, xff, signGitHubPayload("hunter2", []byte(body)), delivery, sha)
	}
	if code := post("10.0.0.7:1", "203.0.113.9", "proxy-1", "9049f1265b7d61be4a8904a9a27120d2064dab3b"); code != http.StatusAccepted {
		t.Fatalf("client A first = %d, want 202", code)
	}
	if code := post("10.0.0.7:1", "203.0.113.9", "proxy-2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); code != http.StatusTooManyRequests {
		t.Fatalf("client A second = %d, want 429 on its canonical bucket", code)
	}
	// A different client through the SAME trusted proxy has a fresh bucket.
	if code := post("10.0.0.7:1", "203.0.113.10", "proxy-3", "cccccccccccccccccccccccccccccccccccccccc"); code != http.StatusAccepted {
		t.Fatalf("client B via trusted proxy = %d, want 202", code)
	}
	// An untrusted peer spoofing client A's XFF is keyed by its real address.
	if code := post("198.51.100.7:1", "203.0.113.9", "spoof-1", "dddddddddddddddddddddddddddddddddddddddd"); code != http.StatusAccepted {
		t.Fatalf("untrusted peer ignoring XFF = %d, want 202", code)
	}
}
