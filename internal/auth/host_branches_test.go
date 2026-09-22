package auth

// Branch coverage for the canonical-host edge cases a forge spelling can
// take: the scp form without a path, the IPv6 literal form, the degenerate
// empty/host-less URLs, the unknown-scheme default-port rule and the
// dotted-first-segment key that must stay untouched.

import "testing"

// TestCanonicalHostDegenerateAndScpForms pins the forms that carry no usable
// host: an empty scp target, a scheme with no authority at all, a lone dot
// host and a host that is only a trailing dot all collapse to "" — never to a
// partial or invented host.
func TestCanonicalHostDegenerateAndScpForms(t *testing.T) {
	for _, raw := range []string{
		"https://",
		"ssh://",
		"https://.",
		".",
		"https://@",
	} {
		if got := CanonicalHost(raw); got != "" {
			t.Errorf("CanonicalHost(%q) = %q, want %q", raw, got, "")
		}
	}
	// A leading "://" with an empty scheme is still a scheme-like prefix:
	// the remainder is treated as the host.
	if got := CanonicalHost("://x"); got != "x" {
		t.Errorf("CanonicalHost(%q) = %q, want x", "://x", got)
	}
}

// TestCanonicalHostScpWithoutPath keeps the string after "@" when it carries
// no path (git@github.com, git@host:not-a-port): the host part must survive
// intact rather than being dropped or truncated at the colon.
func TestCanonicalHostScpWithoutPath(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"git@github.com", "github.com"},
		{"git@GitHub.com.", "github.com"},
		{"git@github.com:not-a-port", "github.com:not-a-port"},
		{"user@github.com:443", "github.com"},
		{"git@github.com:8443", "github.com:8443"},
	}
	for _, tc := range cases {
		if got := CanonicalHost(tc.raw); got != tc.want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestCanonicalHostBracketedIPv6Literals pins the bracketed-literal branch:
// the brackets are stripped, the port is parsed (and the default port
// dropped), a missing closing bracket is preserved verbatim (never
// mangled into a partial host that could collide with another literal), and
// an scp-like literal keeps its bracket-aware colon.
func TestCanonicalHostBracketedIPv6Literals(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://[::1]:8443/repo", "::1:8443"},
		{"https://[::1]:443/repo", "::1"},
		{"https://[::1]/repo", "::1"},
		{"[::1]:8443", "::1:8443"},
		{"[::1]:443", "::1"},
		{"[::1]", "::1"},
		{"[::1", "[::1"},
		{"[not-a-literal]:22", "not-a-literal"},
		{"git@[::1]:acme/repo.git", "::1"},
		// scp syntax has no port: the colon after the literal separates the
		// path, so "8443/..." is a path segment, not a port.
		{"git@[::1]:8443/acme/repo.git", "::1"},
		{"git@[::1]", "::1"},
	}
	for _, tc := range cases {
		if got := CanonicalHost(tc.raw); got != tc.want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	// Distinct literals must never collapse onto one canonical key (the
	// pre-fix behavior returned "[" for every bracketed host with a port).
	if a, b := CanonicalHost("[::1]:8443"), CanonicalHost("[::2]:9000"); a == b {
		t.Fatalf("distinct IPv6 literals collapsed to %q", a)
	}
}

// TestCanonicalHostUnknownSchemeKeepsWellKnownDefaultPorts: with a scheme
// that is not https/http/ssh every well-known default port (443, 80, 22) is
// treated as default, while a non-default port stays part of the identity.
func TestCanonicalHostUnknownSchemeKeepsWellKnownDefaultPorts(t *testing.T) {
	for _, raw := range []string{"git://github.com:443/x", "git://github.com:80/x", "git://github.com:22/x"} {
		if got := CanonicalHost(raw); got != "github.com" {
			t.Errorf("CanonicalHost(%q) = %q, want github.com", raw, got)
		}
	}
	if got := CanonicalHost("git://github.com:9418/x"); got != "github.com:9418" {
		t.Errorf("non-default port collapsed: %q", got)
	}
}

// TestNormalizeRepoKeyHostThatCanonicalizesAway: a key whose first segment
// carries a dot (so it is treated as a host candidate) is returned UNCHANGED
// when it canonicalizes to no host at all, and normalization never invents a
// host or drops an unknown first segment. A first segment that canonicalizes
// to a non-empty host is normalized (idempotently).
func TestNormalizeRepoKeyHostThatCanonicalizesAway(t *testing.T) {
	for _, key := range []string{"./acme/repo", ".\x00/acme/repo"} {
		if got := NormalizeRepoKey(key); got != key {
			t.Errorf("NormalizeRepoKey(%q) = %q, want unchanged", key, got)
		}
	}
	// Degenerate all-dot segments still normalize to a single stable key:
	// re-normalizing the result is a no-op, so a grant and a lookup that
	// pass through this path cannot disagree.
	for _, key := range []string{"../acme/repo", "..\\/acme/repo", "GitHub.com:443/acme/repo"} {
		once := NormalizeRepoKey(key)
		if twice := NormalizeRepoKey(once); twice != once {
			t.Errorf("NormalizeRepoKey not idempotent for %q: %q then %q", key, once, twice)
		}
	}
	// The ordinary dotted-host form still normalizes.
	if got := NormalizeRepoKey("GitHub.com:443/acme/repo"); got != "github.com/acme/repo" {
		t.Fatalf("host normalization regressed: %q", got)
	}
}
