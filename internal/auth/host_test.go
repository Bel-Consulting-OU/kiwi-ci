package auth

import "testing"

// TestCanonicalHostNormalizationTable pins the host normalizer: case, ONE
// trailing dot, the scheme's default port and userinfo never change the
// identity, while a non-default port does.
func TestCanonicalHostNormalizationTable(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"github.com", "github.com"},
		{"GITHUB.COM", "github.com"},
		{"GitHub.com.", "github.com"},
		{"github.com..", "github.com."},
		{"github.com:443", "github.com"},
		{"github.com:80", "github.com"},
		{"github.com:8443", "github.com:8443"},
		{"github.com:acme/api", "github.com"},
		{"HTTPS://GitHub.com", "github.com"},
		{"https://GitHub.com:443/acme/repo.git", "github.com"},
		{"https://GitHub.com:8443/acme/repo.git", "github.com:8443"},
		{"https://user:pass@github.com/acme/repo.git", "github.com"},
		{"ssh://git@github.com:22/acme/repo.git", "github.com"},
		{"git@github.com:acme/repo.git", "github.com"},
		{"git@github.com:22/acme/repo.git", "github.com"},
		{"github.com/acme/repo", "github.com"},
	}
	for _, tc := range cases {
		if got := CanonicalHost(tc.raw); got != tc.want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestNormalizeRepoKeyEquivalentForgeHosts pins the RBAC/policy key
// normalization: equivalent forge-host spellings address one key, bare keys
// and dotted GitLab groups are untouched.
func TestNormalizeRepoKeyEquivalentForgeHosts(t *testing.T) {
	want := "github.com/o/r"
	for _, key := range []string{"github.com/o/r", "GITHUB.COM/o/r", "github.com./o/r", "github.com:443/o/r"} {
		if got := NormalizeRepoKey(key); got != want {
			t.Errorf("NormalizeRepoKey(%q) = %q, want %q", key, got, want)
		}
	}
	for _, bare := range []string{"o/r", "acme.co/service", "", "  ", "o/r "} {
		if got := NormalizeRepoKey(bare); got != bare {
			t.Errorf("NormalizeRepoKey(%q) = %q, want unchanged", bare, got)
		}
	}
}

// TestCanonicalRepoIDHostProperty: every equivalent forge-host spelling
// produces the SAME canonical repository identity, and a non-default port
// stays distinct.
func TestCanonicalRepoIDHostProperty(t *testing.T) {
	for _, host := range []string{"github.com", "GITHUB.COM", "github.com.", "github.com:443", "https://GitHub.com"} {
		if got := CanonicalRepoID(host, "acme/repo"); got != "github.com/acme/repo" {
			t.Errorf("CanonicalRepoID(%q, acme/repo) = %q, want github.com/acme/repo", host, got)
		}
	}
	if got := CanonicalRepoID("github.com:8443", "acme/repo"); got != "github.com:8443/acme/repo" {
		t.Errorf("non-default port collapsed: %q", got)
	}
	// Idempotence: re-canonicalizing a canonical identity is a no-op, and an
	// equivalent host prefix stored inside the name collapses onto one form.
	if got := CanonicalRepoID("github.com", "github.com/acme/repo"); got != "github.com/acme/repo" {
		t.Errorf("idempotence broken: %q", got)
	}
	if got := CanonicalRepoID("github.com", "GitHub.com./acme/repo"); got != "github.com/acme/repo" {
		t.Errorf("equivalent stored prefix not collapsed: %q", got)
	}
}

// TestAuthorizeMatchesEquivalentForgeHostKeys: a grant declared with an
// equivalent host spelling authorizes the canonical identity and vice versa,
// while a different port stays a different forge.
func TestAuthorizeMatchesEquivalentForgeHostKeys(t *testing.T) {
	p := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"GitHub.com:443/o/r": {Run: true},
	}}
	if !Authorize(p, ActionRun, "github.com/o/r", false) {
		t.Fatal("equivalent declared host spelling must authorize the canonical identity")
	}
	storedCanonical := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/o/r": {Run: true},
	}}
	if !Authorize(storedCanonical, ActionRun, "GITHUB.COM./o/r", false) {
		t.Fatal("equivalent lookup host spelling must match the canonical grant")
	}
	if Authorize(storedCanonical, ActionRun, "github.com:8443/o/r", false) {
		t.Fatal("a non-default port is a different forge and must not match")
	}
	// Equivalent keys with CONFLICTING grants fail closed.
	conflict := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/o/r":     {Run: true},
		"GITHUB.COM./o/r":    {},
		"github.com:443/o/r": {},
	}}
	if Authorize(conflict, ActionRun, "github.com/o/r", false) {
		t.Fatal("ambiguous equivalent keys must fail closed")
	}
}
