package auth

import (
	"context"
	"net"
	"net/http"
)

// runnerIdentityContextKey carries the runner identity PROVEN by the
// server's runner tier gate (a per-runner bearer token and/or a TLS peer
// certificate verified against the runner CA). It is deliberately separate
// from the store principal: the limiter must be able to key authenticated
// mTLS-only runners without a bearer credential, and the identity must never
// be derivable from attacker-controlled request data such as the path.
type runnerIdentityContextKey struct{}

// WithRunnerIdentity binds a server-proven runner identity to ctx.
func WithRunnerIdentity(ctx context.Context, runnerID string) context.Context {
	if runnerID == "" {
		return ctx
	}
	return context.WithValue(ctx, runnerIdentityContextKey{}, runnerID)
}

// RunnerIdentityFrom returns the proven runner identity of the request, if
// the runner tier gate authenticated one.
func RunnerIdentityFrom(r *http.Request) (string, bool) {
	id, ok := r.Context().Value(runnerIdentityContextKey{}).(string)
	return id, ok && id != ""
}

// ClientIPInfo is the canonical client address resolved for a request by the
// rate-limit middleware's trusted-proxy handling. Recording the DECISION
// (whether the direct peer was trusted, and whether the address came from
// X-Forwarded-For) lets the limiter and audit consumers use the same
// canonical client identity instead of re-deriving it inconsistently.
type ClientIPInfo struct {
	// IP is the canonical client address without a port.
	IP string
	// TrustedPeer reports whether the direct peer address was inside one of
	// the configured trusted-proxy ranges. When false, X-Forwarded-For was
	// ignored entirely.
	TrustedPeer bool
	// Forwarded reports whether IP came from the X-Forwarded-For chain (a
	// trusted peer supplied it) instead of the direct peer address.
	Forwarded bool
}

type clientIPInfoContextKey struct{}

// WithClientIPInfo binds the canonical client-IP decision to ctx.
func WithClientIPInfo(ctx context.Context, info ClientIPInfo) context.Context {
	return context.WithValue(ctx, clientIPInfoContextKey{}, info)
}

// ClientIPInfoFrom returns the canonical client-IP decision recorded by the
// rate-limit middleware, if any.
func ClientIPInfoFrom(r *http.Request) (ClientIPInfo, bool) {
	info, ok := r.Context().Value(clientIPInfoContextKey{}).(ClientIPInfo)
	return info, ok && info.IP != ""
}

// ClientIP returns the canonical client address of the request: the
// trusted-proxy-resolved address when the rate-limit middleware recorded one,
// otherwise the direct peer extracted from RemoteAddr. It is the single
// accessor the rate limiter and audit consumers use.
func ClientIP(r *http.Request) string {
	if info, ok := ClientIPInfoFrom(r); ok {
		return info.IP
	}
	return DirectClientIP(r)
}

// DirectClientIP extracts the peer address from RemoteAddr without applying
// any forwarding rules.
func DirectClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		host = "unknown"
	}
	return host
}
