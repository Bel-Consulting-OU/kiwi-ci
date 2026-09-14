// Package ratelimit provides token-bucket request rate limiting for the
// kiwi control plane. A Limiter enforces one token budget per key
// (principal, runner, or client IP); a Middleware classifies HTTP requests
// into endpoint classes and enforces a per-class budget chain.
package ratelimit

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// Endpoint classes for rate-limit classification. Each class gets its own
// budget so a chatty runner heartbeat cannot starve webhook intake.
const (
	ClassEnroll         = "enroll"
	ClassRegister       = "register"
	ClassNext           = "next"
	ClassHeartbeat      = "heartbeat"
	ClassOIDC           = "oidc"
	ClassSecrets        = "secrets"
	ClassLogs           = "logs"
	ClassArtifactUpload = "artifact_upload"
	ClassCacheUpload    = "cache_upload"
	ClassDispatch       = "dispatch"
	ClassWebhooks       = "webhooks"
	ClassLogin          = "login"
	ClassDefault        = "default"
)

// maxBuckets bounds the per-key bucket map: when it grows past this the
// oldest idle buckets are swept so a flood of distinct keys cannot exhaust
// memory.
const maxBuckets = 10000

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a token bucket keyed by an arbitrary string. It is safe for
// concurrent use.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	buckets map[string]*bucket
}

// New returns a Limiter allowing rate tokens per second with a burst of at
// most burst tokens.
func New(rate float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: rate, burst: float64(burst), buckets: map[string]*bucket{}}
}

// Allow consumes one token for key if available, returning whether the
// request is admitted. Denied requests consume nothing.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked()
	b := l.buckets[key]
	now := time.Now()
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += l.rate * now.Sub(b.last).Seconds()
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RetryAfter reports how long key must wait before a token becomes
// available again, without consuming anything. It is 0 when the key is
// immediately admissible.
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	now := time.Now()
	if b == nil {
		return 0
	}
	tokens := b.tokens + l.rate*now.Sub(b.last).Seconds()
	if tokens >= 1 {
		return 0
	}
	if l.rate <= 0 {
		return time.Hour
	}
	return time.Duration((1 - tokens) / l.rate * float64(time.Second))
}

// sweepLocked drops buckets that are back at full capacity and idle, once
// the map exceeds maxBuckets. Must be called with l.mu held.
func (l *Limiter) sweepLocked() {
	if len(l.buckets) <= maxBuckets {
		return
	}
	now := time.Now()
	for k, b := range l.buckets {
		if b.tokens >= l.burst && now.Sub(b.last) > time.Minute {
			delete(l.buckets, k)
		}
	}
}

// Middleware enforces per-class rate limits. Classes without an explicit
// limiter fall back to the ClassDefault limiter; if neither exists the
// request passes unthrottled.
type Middleware struct {
	ByClass map[string]*Limiter
}

// NewMiddleware builds a Middleware from per-class rates (tokens/second)
// sharing one burst size. Classes whose rate is <= 0 are left unlimited
// unless a ClassDefault rate is configured.
func NewMiddleware(rates map[string]float64, burst int) *Middleware {
	m := &Middleware{ByClass: map[string]*Limiter{}}
	for class, rate := range rates {
		if rate > 0 {
			m.ByClass[class] = New(rate, burst)
		}
	}
	return m
}

// Wrap chains the middleware around next: requests over their class budget
// receive 429 with a Retry-After header and never reach the handler.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		class := Classify(r)
		l := m.ByClass[class]
		if l == nil {
			l = m.ByClass[ClassDefault]
		}
		if l == nil {
			next.ServeHTTP(w, r)
			return
		}
		key := Key(r)
		if l.Allow(key) {
			next.ServeHTTP(w, r)
			return
		}
		wait := l.RetryAfter(key)
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	})
}

// Classify maps a request to one of the Class* constants by path and
// method. The classification is ordered so more specific routes win.
func Classify(r *http.Request) string {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/hooks/"):
		return ClassWebhooks
	case strings.HasPrefix(p, "/login"):
		return ClassLogin
	case p == "/api/v1/runners/enroll":
		return ClassEnroll
	case p == "/api/v1/runners/register":
		return ClassRegister
	case strings.HasSuffix(p, "/next"):
		return ClassNext
	case strings.HasSuffix(p, "/heartbeat"):
		return ClassHeartbeat
	case strings.HasSuffix(p, "/oidc"):
		return ClassOIDC
	case strings.HasSuffix(p, "/secrets"):
		return ClassSecrets
	case strings.HasSuffix(p, "/logs") || strings.HasSuffix(p, "/log"):
		return ClassLogs
	case r.Method == http.MethodPut && strings.Contains(p, "/artifacts/"):
		return ClassArtifactUpload
	case r.Method == http.MethodPut && strings.HasPrefix(p, "/api/v1/cache/"):
		return ClassCacheUpload
	case r.Method == http.MethodPost && p == "/api/v1/runs":
		return ClassDispatch
	}
	return ClassDefault
}

// Key derives the rate-limit identity for a request: the authenticated
// principal's subject when present, otherwise the runner ID extracted from
// the path, otherwise the client IP from RemoteAddr. Distinct identities
// get independent token budgets.
func Key(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r); ok && p.Subject != "" {
		return "principal:" + p.Subject
	}
	if id := RunnerIDFromPath(r.URL.Path); id != "" {
		return "runner:" + id
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		host = "unknown"
	}
	return "ip:" + host
}

// RunnerIDFromPath extracts the runner ID from paths of the form
// /api/v1/runners/{id}/... . Sub-route names (register, enroll, list
// positions) are not IDs.
func RunnerIDFromPath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] != "runners" {
			continue
		}
		id := parts[i+1]
		if id == "" || id == "register" || id == "enroll" {
			return ""
		}
		return id
	}
	return ""
}
