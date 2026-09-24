package policy

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// r1 renders a canonical policy key in the explicit ACL spelling
// "r1:<base64url(host)>:<base64url(full_name)>". Repository policy keys are
// validated with the strict ACL configuration schema, so a canonical entry
// MUST use this form: an untagged "host/owner/name" key is ambiguous and is
// rejected by Config.Validate (see TestValidateRejectsAmbiguousRepoKey).
func r1(host, fullName string) string {
	return auth.RepoIdentity{Host: host, FullName: fullName}.Serialized()
}

// a1 renders a nested bare-alias policy key in the explicit ACL spelling
// "a1:<base64url(full_name)>".
func a1(fullName string) string {
	return auth.RepoAlias{FullName: fullName}.Serialized()
}

// TestRepoPolicyKeysMatchEquivalentForgeHosts: configured repository keys are
// canonicalized on both sides, so equivalent forge-host spellings address the
// same policy entry regardless of which spelling the file uses.
func TestRepoPolicyKeysMatchEquivalentForgeHosts(t *testing.T) {
	enabled := true
	cfg := &Config{Repositories: map[string]RepoPolicy{
		r1("GitHub.com:443", "acme/backend"): {RequireDigestPins: &enabled, CrossRepoTrigger: &enabled},
	}}
	for _, lookup := range []string{
		"github.com/acme/backend",
		"GITHUB.COM/acme/backend",
		"github.com./acme/backend",
		"github.com:443/acme/backend",
	} {
		rp, ok := cfg.RepoPolicyFor(lookup)
		if !ok || rp.RequireDigestPins == nil || !*rp.RequireDigestPins {
			t.Fatalf("lookup %q did not resolve the equivalent configured key: %+v ok=%v", lookup, rp, ok)
		}
	}
	if g := cfg.GrantsFor("GITHUB.COM./acme/backend"); !g.CrossRepoTrigger {
		t.Fatalf("equivalent lookup lost the grants: %+v", g)
	}
	// A non-default port is a different forge and never matches.
	if _, ok := cfg.RepoPolicyFor("github.com:8443/acme/backend"); ok {
		t.Fatal("a non-default port must not resolve the github.com entry")
	}
}

// TestRepoPolicyEquivalentKeysConflictFailsClosed: two keys that canonicalize
// onto the same identity with DIFFERENT policies DENY the repository (a
// restrictive entry is returned) instead of depending on map iteration order
// or silently falling back to org-only policy.
func TestRepoPolicyEquivalentKeysConflictFailsClosed(t *testing.T) {
	enabled := true
	cfg := &Config{Repositories: map[string]RepoPolicy{
		r1("github.com", "acme/backend"):     {RequireDigestPins: &enabled},
		r1("GITHUB.COM.", "acme/backend"):    {},
		r1("github.com:443", "acme/backend"): {},
	}}
	rp, ok := cfg.RepoPolicyFor("github.com/acme/backend")
	if !ok || rp.Network != "none" {
		t.Fatalf("ambiguous equivalent keys must deny (not fall back to org-only): %+v ok=%v", rp, ok)
	}
	// Equal policies on equivalent keys still resolve.
	cfg.Repositories[r1("GITHUB.COM.", "acme/backend")] = RepoPolicy{RequireDigestPins: &enabled}
	delete(cfg.Repositories, r1("github.com:443", "acme/backend"))
	rp, ok = cfg.RepoPolicyFor("github.com/acme/backend")
	if !ok || rp.RequireDigestPins == nil || !*rp.RequireDigestPins {
		t.Fatalf("equal equivalent keys must resolve: %+v ok=%v", rp, ok)
	}
}

// TestCloneHostAllowlistCanonicalEntries: allowlist entries and the queried
// host are canonicalized on both sides, and AllowedCloneHostsFor returns the
// canonical spelling.
func TestCloneHostAllowlistCanonicalEntries(t *testing.T) {
	cfg := &Config{AllowedCloneHosts: []string{"GITHUB.COM", "https://GitLab.company.com", "github.com:8443"}}
	for _, host := range []string{"github.com", "GitHub.com.", "github.com:443", "HTTPS://GitHub.com"} {
		if !cfg.CloneHostAllowed("org/app", host) {
			t.Fatalf("host %q must match the canonicalized allowlist entry", host)
		}
	}
	for _, host := range []string{"gitlab.company.com", "GitLab.Company.com:443"} {
		if !cfg.CloneHostAllowed("org/app", host) {
			t.Fatalf("host %q must match the URL-shaped allowlist entry", host)
		}
	}
	for _, host := range []string{"github.com:8443"} {
		if !cfg.CloneHostAllowed("org/app", host) {
			t.Fatalf("explicit non-default port entry %q must be admitted", host)
		}
	}
	for _, host := range []string{"github.com.evil.example", "", "gitlab.company.com:8443"} {
		if cfg.CloneHostAllowed("org/app", host) {
			t.Fatalf("host %q must not be admitted", host)
		}
	}
	hosts := cfg.AllowedCloneHostsFor("org/app")
	want := []string{"github.com", "gitlab.company.com", "github.com:8443"}
	if len(hosts) != len(want) {
		t.Fatalf("AllowedCloneHostsFor = %v", hosts)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("AllowedCloneHostsFor = %v, want %v", hosts, want)
		}
	}
}
