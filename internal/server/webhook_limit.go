package server

import (
	"net/http"
	"strconv"
)

// webhookPostHMACKey derives the POST-HMAC limiter key from the VERIFIED
// webhook identity: the forge and the canonical repository identity resolved
// from the authenticated payload. It is never derived from request data
// before the HMAC/token verification, so an unauthenticated caller cannot
// mint, consume or poison a forge bucket.
func webhookPostHMACKey(forge, repoID string) string {
	if repoID == "" {
		repoID = "unknown"
	}
	return "hook:" + forge + ":" + repoID
}

// allowAuthenticatedWebhook enforces the POST-HMAC webhook rate limit for an
// HMAC/token-verified delivery. It is a SEPARATE limiter from the coarse
// pre-authentication ClassWebhooks bucket: invalid-signature floods consume
// only the attacker's per-client-IP pre-auth budget, while valid deliveries
// share the per-forge/per-repository budget independent of their source IPs.
// Returns false after writing the 429 (matching the pre-auth middleware's
// response shape, including Retry-After).
func (s *Server) allowAuthenticatedWebhook(w http.ResponseWriter, r *http.Request, forge, repoID string) bool {
	if s.RateLimiter == nil || s.RateLimiter.WebhookForge == nil {
		return true
	}
	key := webhookPostHMACKey(forge, repoID)
	if s.RateLimiter.WebhookForge.Allow(key) {
		return true
	}
	wait := s.RateLimiter.WebhookForge.RetryAfter(key)
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	return false
}
