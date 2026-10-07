package ratelimit

import (
	"net"
	"net/http"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// CanonicalClientIP resolves the client address a request should be
// attributed to when it arrives through a reverse proxy.
//
// The trust decision is explicit and fail closed:
//
//   - The DIRECT peer address (from RemoteAddr) must be inside one of the
//     configured trusted-proxy ranges. When it is not, X-Forwarded-For is
//     IGNORED entirely and the direct peer is returned: a client cannot mint
//     its own source address by sending a spoofed header.
//   - When the direct peer IS trusted, the X-Forwarded-For chain is walked
//     from the RIGHT (nearest hop first), skipping every address that is
//     itself a trusted proxy, and the first untrusted address is the client.
//     Appending spoofed entries on the LEFT of the chain therefore cannot
//     move the resolved client: the rightmost untrusted hop is the one the
//     last trusted proxy actually observed.
//   - A malformed chain (an entry that is not a valid IP) or a chain whose
//     addresses are all trusted (the client is unknown) falls back to the
//     direct peer.
//
// xff is the flattened, ordered X-Forwarded-For address list.
func CanonicalClientIP(remoteAddr string, xff []string, trusted []*net.IPNet) auth.ClientIPInfo {
	direct := hostWithoutPort(remoteAddr)
	info := auth.ClientIPInfo{IP: direct}
	if len(trusted) == 0 || !ipInAny(direct, trusted) {
		return info
	}
	info.TrustedPeer = true
	for i := len(xff) - 1; i >= 0; i-- {
		raw := strings.TrimSpace(xff[i])
		if raw == "" {
			// Malformed chain (empty hop): the chain cannot be trusted to
			// identify the client, so use what the socket proved.
			return info
		}
		ip := parseForwardedIP(raw)
		if ip == nil {
			return info
		}
		if ipInAny(ip.String(), trusted) {
			continue
		}
		info.IP = ip.String()
		info.Forwarded = true
		return info
	}
	// No untrusted hop: the whole chain is trusted proxies (or the header was
	// absent), so the direct peer is the best-known client.
	return info
}

// ForwardedFor returns the ordered X-Forwarded-For addresses of a request,
// flattening repeated headers and comma-separated values.
func ForwardedFor(r *http.Request) []string {
	out := []string{}
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(header, ",") {
			out = append(out, strings.TrimSpace(part))
		}
	}
	return out
}

// hostWithoutPort strips a port from a RemoteAddr-style address, tolerating
// bracketed IPv6 literals.
func hostWithoutPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// A bare address (no port), possibly a bracketed IPv6 literal.
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	}
	return addr
}

// parseForwardedIP parses one X-Forwarded-For hop: a bare IP, or an IP with a
// port ("203.0.113.7:4711", "[2001:db8::1]:4711").
func parseForwardedIP(raw string) net.IP {
	if ip := net.ParseIP(raw); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// ipInAny reports whether the textual address is inside one of the ranges.
func ipInAny(addr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
