package auth

import (
	"strconv"
	"strings"
)

// CanonicalHost normalizes a forge host spelling onto ONE canonical form so
// equivalent spellings of the same forge resolve to the same repository
// identity instead of silently becoming different keys:
//
//   - the hostname is lowercased and ONE trailing dot is stripped
//     (GITHUB.COM. and github.com are the same host);
//   - userinfo is stripped (credentials never belong in a host key);
//   - the default port of the detected scheme is dropped (443 https, 80
//     http, 22 ssh); with no scheme prefix the well-known default ports
//     443, 80 and 22 are dropped as well, so "github.com:443" is the same
//     host as "github.com";
//   - a NON-default port stays part of the identity: github.com:8443 is a
//     different host from github.com.
//
// A URL-shaped input ("https://GitHub.com/x") contributes only its host; an
// scp-like input ("git@github.com:acme/repo.git") contributes only its host.
// An empty or host-less input yields "".
func CanonicalHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Scheme-prefixed URL (or bare host with a scheme-like prefix).
	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(strings.TrimSpace(s[:i]))
		rest := s[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		return canonHostPort(scheme, rest)
	}
	// scp-like user@host:path (the colon separates host from path).
	if at := strings.LastIndex(s, "@"); at >= 0 {
		rest := s[at+1:]
		if colon := scpHostColon(rest); colon >= 0 {
			tail := rest[colon+1:]
			if tail == "" || strings.Contains(tail, "/") {
				return canonHostPort("ssh", rest[:colon])
			}
		}
		return canonHostPort("", rest)
	}
	if j := strings.IndexAny(s, "/?#"); j >= 0 {
		s = s[:j]
	}
	// A bracketed IPv6 literal is host material, never the legacy
	// "host:path" spelling: its internal colons must not split it (the
	// legacy rule below would otherwise canonicalize "[::1]:8443" to the
	// bare "[" and collapse every distinct literal onto one identity key).
	// canonHostPort's bracket parser handles both well-formed and truncated
	// literals; a truncated one is preserved verbatim rather than mangled.
	if strings.HasPrefix(s, "[") {
		return canonHostPort("", s)
	}
	// The legacy "host:port"/"host:path" split only applies to a spelling with
	// EXACTLY ONE colon. Several colons name an UNBRACKETED IPv6 literal
	// ("2001:db8::1"), which must be treated as one host: splitting it on the
	// first colon would truncate the literal to "2001" and collapse distinct
	// forges onto one identity. A literal's canonical form (brackets stripped
	// by canonHostPort) is therefore stable under re-canonicalization, so an
	// r1:-serialized IPv6 host round-trips.
	if colon := strings.Index(s, ":"); colon > 0 && strings.Count(s, ":") == 1 {
		if _, err := strconv.Atoi(s[colon+1:]); err != nil {
			// Legacy "host:path" spelling with no scp user and no numeric
			// port: the colon separates the host from a path, not a port.
			s = s[:colon]
		}
	}
	return canonHostPort("", s)
}

// scpHostColon returns the index of the colon separating an scp-like host
// from its path: the first colon AFTER a bracketed IPv6 literal's closing
// bracket, the first colon otherwise, or -1 when no colon separates a host
// from a tail. A literal's internal colons never split the host.
func scpHostColon(s string) int {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return -1
		}
		if colon := strings.Index(s[end+1:], ":"); colon >= 0 {
			return end + 1 + colon
		}
		return -1
	}
	return strings.Index(s, ":")
}

// NormalizeRepoKey canonicalizes the forge-host segment of a repository key
// ("host/owner/name") onto the same canonical host spelling CanonicalRepoID
// produces, so policy, RBAC and allowlist keys match regardless of host case,
// one trailing dot or the scheme's default port. The key is classified by the
// typed positional rule (ParseStoredRepoID), never by "does the first segment
// contain a dot": a key with three or more path segments is a canonical
// identity whose first segment is the host, so a DOTLESS host
// ("gitlab/acme/widget") is canonicalized exactly like a dotted one. A bare
// key with fewer segments is returned unchanged, because a bare name is not a
// canonical identity and has no host to canonicalize. Surrounding whitespace
// is never canonicalized away.
func NormalizeRepoKey(key string) string {
	if key == "" {
		return ""
	}
	// Surrounding whitespace is NOT canonicalized away: a key with stray
	// whitespace never matches a declared grant.
	if strings.TrimSpace(key) != key {
		return key
	}
	grant, err := ParseStoredRepoID(key)
	if err != nil || grant.IsAlias() {
		return key
	}
	id, _ := grant.Identity()
	return id.ID()
}

// canonHostPort lowercases hostPort and drops its default port for scheme.
func canonHostPort(scheme, hostPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return ""
	}
	host, port := splitHostPort(hostPort)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return ""
	}
	if port != "" && isDefaultHostPort(scheme, port) {
		port = ""
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// splitHostPort splits a host[:port], handling bracketed IPv6 literals. A
// non-numeric tail after the last colon is not a port and stays part of the
// host, so a malformed host never silently loses information.
func splitHostPort(hostPort string) (host, port string) {
	if strings.HasPrefix(hostPort, "[") {
		if end := strings.Index(hostPort, "]"); end > 0 {
			host = hostPort[1:end]
			if rest := hostPort[end+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
		return hostPort, ""
	}
	if colon := strings.LastIndex(hostPort, ":"); colon > 0 && !strings.Contains(hostPort[:colon], ":") {
		if _, err := strconv.Atoi(hostPort[colon+1:]); err == nil {
			return hostPort[:colon], hostPort[colon+1:]
		}
	}
	return hostPort, ""
}

// isDefaultHostPort reports whether port is the default port of scheme. With
// no recognized scheme every well-known default (443, 80, 22) is treated as
// default so a bare "github.com:443" collapses onto "github.com".
func isDefaultHostPort(scheme, port string) bool {
	switch scheme {
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	case "ssh":
		return port == "22"
	default:
		return port == "443" || port == "80" || port == "22"
	}
}
