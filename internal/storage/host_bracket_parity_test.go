package storage

// Regression pin for the bracketed-IPv6 host path shared with
// auth.CanonicalHost: a literal's internal colons must never be treated as
// the legacy "host:path" separator, because that collapsed every distinct
// literal onto the same mangled key (the repository ACL/quota identity).

import (
	"testing"

	kiwiauth "github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// TestBracketedIPv6HostIdentityParity pins storage.canonicalHost to
// auth.CanonicalHost for bracketed literals and proves distinct literals keep
// distinct identities.
func TestBracketedIPv6HostIdentityParity(t *testing.T) {
	cases := []string{
		"[::1]:8443", "[::1]:443", "[::1]", "[::1",
		"https://[::1]:8443/acme/repo", "https://[fe80::1]:443/acme/repo",
		"git@[::1]:acme/repo.git", "git@[::1]:8443/acme/repo.git", "[not-a-literal]:22",
	}
	for _, raw := range cases {
		got, want := RepoHost(raw), kiwiauth.CanonicalHost(raw)
		if got != want {
			t.Errorf("RepoHost(%q) = %q, auth.CanonicalHost = %q", raw, got, want)
		}
		if got == "[" {
			t.Errorf("RepoHost(%q) collapsed to the bare bracket %q", raw, got)
		}
	}
	if a, b := RepoHost("[::1]:8443"), RepoHost("[::2]:9000"); a == b {
		t.Fatalf("distinct literals collapsed onto one identity key: %q", a)
	}
	// The repository identity derived from two distinct literals must differ
	// too: the host is the ACL prefix.
	if a, b := CanonicalRepoID("[::1]:8443", "acme/repo"), CanonicalRepoID("[::2]:9000", "acme/repo"); a == b {
		t.Fatalf("distinct literals produced one repository identity: %q", a)
	}
}
