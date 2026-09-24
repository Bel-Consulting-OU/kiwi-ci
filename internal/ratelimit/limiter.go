// Package ratelimit provides token-bucket request rate limiting for the
// kiwi control plane. A Limiter enforces one token budget per key
// (principal, runner, or client IP); a Middleware classifies HTTP requests
// into endpoint classes and enforces a per-class budget chain.
package ratelimit

import (
	"container/list"
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

// maxBuckets is the HARD cap on the per-key bucket map. A flood of distinct
// keys cannot grow the map past it: each insert over the cap unconditionally
// evicts the least-recently-used bucket in O(1), so the map length is bounded
// and every Allow call is O(1) — there is no full-map sweep per call (the
// previous design only evicted full, idle buckets, so fresh distinct keys
// accumulated without bound and each Allow scanned the whole map).
const maxBuckets = 10000

type bucket struct {
	tokens float64
	last   time.Time
	key    string
	// el is this bucket's position in l.lru (front = most recently seen).
	el *list.Element
}

// Limiter is a token bucket keyed by an arbitrary string. It is safe for
// concurrent use.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	buckets map[string]*bucket
	// lru orders buckets by last use (front = most recent). The tail is the
	// eviction victim when the map is at maxBuckets.
	lru *list.List
}

// New returns a Limiter allowing rate tokens per second with a burst of at
// most burst tokens.
func New(rate float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: rate, burst: float64(burst), buckets: map[string]*bucket{}, lru: list.New()}
}

// Len reports the number of live keyed buckets. It is bounded by maxBuckets.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Allow consumes one token for key if available, returning whether the
// request is admitted. Denied requests consume nothing. The per-call cost is
// O(1): map lookup plus (only on insert) an unconditional LRU eviction, never
// a scan of the map.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now, key: key}
		l.buckets[key] = b
		b.el = l.lru.PushFront(b)
		l.evictOverCapLocked()
	} else {
		l.touchLocked(b)
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

// touchLocked moves a bucket to the front of the LRU list. A bucket with no
// list position (only reachable from a package-internal test crafting map
// entries directly) is linked lazily.
func (l *Limiter) touchLocked(b *bucket) {
	if b.el == nil {
		b.el = l.lru.PushFront(b)
		return
	}
	l.lru.MoveToFront(b.el)
}

// evictOverCapLocked drops least-recently-used buckets until the map is at or
// below maxBuckets. It is O(over-cap) and over-cap is zero on every steady
// state call, so it never scans the map.
func (l *Limiter) evictOverCapLocked() {
	for len(l.buckets) > maxBuckets {
		back := l.lru.Back()
		if back == nil {
			// Defensive: an unlinked bucket (test-crafted map entry) must
			// still be evictable so the cap cannot be bypassed.
			for k := range l.buckets {
				delete(l.buckets, k)
				break
			}
			continue
		}
		victim := back.Value.(*bucket)
		l.lru.Remove(back)
		if victim.el == back {
			victim.el = nil
		}
		if cur, ok := l.buckets[victim.key]; ok && cur == victim {
			delete(l.buckets, victim.key)
		}
	}
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
// method. The table is matched against the REAL registered routes (see
// internal/server/server.go) rather than loose prefixes, so the login, logs
// and cache_upload buckets actually engage:
//
//   - POST /api/v1/login                      -> ClassLogin
//   - POST /api/v1/jobs/{id}/log               -> ClassLogs
//   - POST /api/v1/jobs/{id}/log/batch         -> ClassLogs
//   - GET  /api/v1/runs/{id}/logs[/stream]     -> ClassLogs
//   - PUT  /api/v1/jobs/{id}/cache/{key}       -> ClassCacheUpload
//
// The classification is ordered so more specific routes win.
func Classify(r *http.Request) string {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/hooks/"):
		return ClassWebhooks
	case p == "/api/v1/login" || p == "/login":
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
	case strings.HasSuffix(p, "/log") || strings.HasSuffix(p, "/log/batch") ||
		strings.HasSuffix(p, "/logs") || strings.HasSuffix(p, "/logs/stream"):
		return ClassLogs
	case r.Method == http.MethodPut && strings.Contains(p, "/artifacts/"):
		return ClassArtifactUpload
	case r.Method == http.MethodPut && strings.Contains(p, "/cache/"):
		return ClassCacheUpload
	case r.Method == http.MethodPost && p == "/api/v1/runs":
		return ClassDispatch
	}
	return ClassDefault
}

// Key derives the rate-limit identity for a request: the authenticated
// principal's subject when present, otherwise — for the runner tier whose
// credentials are authenticated by the server's tier gate before this
// middleware runs — the authenticated bearer CREDENTIAL, otherwise the client
// IP from RemoteAddr.
//
// The runner identity is deliberately never derived from the request path:
// the path segment is attacker-controlled, so a caller could mint an
// unlimited number of distinct buckets (and unbounded budgets) by varying
// it. The bearer digest is one identity per credential, independent of the
// path. Requests without a credential fall back to the client IP.
func Key(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r); ok && p.Subject != "" {
		return "principal:" + p.Subject
	}
	if runnerTierPath(r.Method, r.URL.Path) {
		if tok := bearerToken(r); tok != "" {
			return "credential:" + auth.TokenDigest(tok)
		}
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

// bearerToken extracts the raw bearer token from the Authorization header,
// tolerating the case-insensitive scheme spelling.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// runnerTierPath mirrors internal/server's runnerPath classifier: it reports
// whether a route is authenticated by the runner credential (or mTLS) before
// the limiter runs. Credential keying is restricted to this tier so a bearer
// on a public route can never mint buckets either.
func runnerTierPath(method, path string) bool {
	if method == http.MethodPost && path == "/api/v1/runners/register" {
		return true
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) < 4 || segs[0] != "api" || segs[1] != "v1" {
		return false
	}
	switch {
	case len(segs) == 5 && segs[2] == "runners" && method == http.MethodPost && segs[4] == "next":
		return true
	case segs[2] == "jobs":
		if len(segs) == 5 && method == http.MethodPost {
			switch segs[4] {
			case "heartbeat", "log", "complete", "generated", "secrets", "tests", "snapshots":
				return true
			}
		}
		if len(segs) == 5 && segs[4] == "test-shards" && method == http.MethodGet {
			return true
		}
		if len(segs) == 6 && segs[4] == "log" && segs[5] == "batch" && method == http.MethodPost {
			return true
		}
		if len(segs) == 6 && segs[4] == "artifacts" && method == http.MethodPut {
			return true
		}
		if len(segs) == 7 && segs[4] == "dependencies" && method == http.MethodGet {
			return true
		}
		if len(segs) == 6 && segs[4] == "cache" && (method == http.MethodGet || method == http.MethodPut) {
			return true
		}
	}
	return false
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
