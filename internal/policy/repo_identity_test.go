package policy

import (
	"reflect"
	"testing"
)

// TestCanonicalRepoLookupSeparatesForges: repository policy keys are
// canonical repository identities. A github.com/acme/backend entry applies
// to that identity only — never to the same bare name on another forge — and
// a bare key is honored as an explicit alias.
func TestCanonicalRepoLookupSeparatesForges(t *testing.T) {
	enabled := true
	cfg := &Config{Repositories: map[string]RepoPolicy{
		"github.com/acme/backend": {
			RequireDigestPins:  &enabled,
			CrossRepoTrigger:   &enabled,
			AllowedCloneHosts:  []string{"github.com"},
			AllowedRegions:     []string{"eu-west-1"},
			GenerateChildGraph: &enabled,
			RequireRootless:    &enabled,
			SecretAllowlist:    []string{"DEPLOY_KEY"},
			OIDCAudiences:      []string{"https://github.com"},
			AllowedRunnerPools: []string{"linux"},
			Network:            "none",
		},
	}}
	if g := cfg.GrantsFor("github.com/acme/backend"); !g.CrossRepoTrigger || !g.GenerateChildGraph {
		t.Fatalf("canonical grants = %+v", g)
	}
	if g := cfg.GrantsFor("gitlab.company.com/acme/backend"); g.CrossRepoTrigger || g.GenerateChildGraph {
		t.Fatalf("grants leaked across forges: %+v", g)
	}
	if hosts := cfg.AllowedCloneHostsFor("gitlab.company.com/acme/backend"); hosts != nil {
		t.Fatalf("clone-host restriction leaked across forges: %v", hosts)
	}
	if regions := cfg.AllowedRegionsFor("gitlab.company.com/acme/backend"); regions != nil {
		t.Fatalf("region restriction leaked across forges: %v", regions)
	}
	if !cfg.CloneHostAllowed("github.com/acme/backend", "github.com") {
		t.Fatal("canonical clone host must be allowed")
	}
	if cfg.CloneHostAllowed("github.com/acme/backend", "evil.example") {
		t.Fatal("canonical clone-host restriction must reject undeclared hosts")
	}
	caps := cfg.CapabilitiesFor("github.com/acme/backend")
	if caps.Network == 0 || caps.RequireRootless == false {
		t.Fatalf("canonical capabilities = %+v", caps)
	}
	other := cfg.CapabilitiesFor("gitlab.company.com/acme/backend")
	if other.RequireRootless || other.Secrets != nil || other.OIDC != nil || other.RunnerLabels != nil {
		t.Fatalf("restrictions leaked across forges: %+v", other)
	}
}

// TestBareRepoKeyIsExplicitAlias: a bare "owner/name" policy key applies to
// every forge presenting that name (an explicitly configured alias), and a
// bare lookup key still resolves exact entries.
func TestBareRepoKeyIsExplicitAlias(t *testing.T) {
	enabled := true
	cfg := &Config{Repositories: map[string]RepoPolicy{
		"acme/backend": {RequireDigestPins: &enabled},
	}}
	if _, ok := cfg.RepoPolicyFor("github.com/acme/backend"); !ok {
		t.Fatal("explicit bare alias must resolve for a canonical identity")
	}
	if _, ok := cfg.RepoPolicyFor("gitlab.company.com/acme/backend"); !ok {
		t.Fatal("explicit bare alias must resolve for every forge")
	}
	if rp, ok := cfg.RepoPolicyFor("acme/backend"); !ok || rp.RequireDigestPins == nil || !*rp.RequireDigestPins {
		t.Fatal("bare lookup key must resolve its exact entry")
	}
}

// TestBareLookupAmbiguousCanonicalKeysFailClosed: a bare lookup key with
// several DIFFERENT canonical entries (same owner/name on different forges)
// resolves to no entry instead of depending on map iteration order. One
// unambiguous canonical entry still resolves.
func TestBareLookupAmbiguousCanonicalKeysFailClosed(t *testing.T) {
	enabled := true
	disabled := false
	cfg := &Config{Repositories: map[string]RepoPolicy{
		"github.com/acme/backend":         {RequireDigestPins: &enabled},
		"gitlab.company.com/acme/backend": {RequireDigestPins: &disabled},
	}}
	if _, ok := cfg.RepoPolicyFor("acme/backend"); ok {
		t.Fatal("ambiguous bare lookup must fail closed")
	}
	single := &Config{Repositories: map[string]RepoPolicy{
		"github.com/acme/backend": {RequireDigestPins: &enabled},
	}}
	rp, ok := single.RepoPolicyFor("acme/backend")
	if !ok || rp.RequireDigestPins == nil || !*rp.RequireDigestPins {
		t.Fatalf("unambiguous canonical entry not resolved: %+v ok=%v", rp, ok)
	}
}

// TestRepoPolicyLookupTables pins the exact/bare/ambiguity resolution matrix.
func TestRepoPolicyLookupTables(t *testing.T) {
	inv := RepoPolicy{AllowedRegions: []string{"eu"}}
	cases := []struct {
		name   string
		repos  map[string]RepoPolicy
		lookup string
		want   RepoPolicy
		wantOK bool
	}{
		{"exact canonical", map[string]RepoPolicy{"github.com/o/r": inv}, "github.com/o/r", inv, true},
		{"other forge", map[string]RepoPolicy{"github.com/o/r": inv}, "gitlab.example/o/r", RepoPolicy{}, false},
		{"canonical via bare alias", map[string]RepoPolicy{"o/r": inv}, "github.com/o/r", inv, true},
		{"bare exact", map[string]RepoPolicy{"o/r": inv}, "o/r", inv, true},
		{"bare canonical host-less", map[string]RepoPolicy{"github.com/o/r": inv}, "o/r", inv, true},
		{"unrelated", map[string]RepoPolicy{"github.com/o/r": inv}, "github.com/o/x", RepoPolicy{}, false},
		{"gitlab group with dot", map[string]RepoPolicy{"acme.co/service": inv}, "gitlab.example/acme.co/service", inv, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Repositories: tc.repos}
			got, ok := cfg.RepoPolicyFor(tc.lookup)
			if ok != tc.wantOK || (ok && !reflect.DeepEqual(got, tc.want)) {
				t.Fatalf("RepoPolicyFor(%q) = %+v ok=%v, want %+v ok=%v", tc.lookup, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestDotlessCanonicalPolicyHostSeparatesForge is the typed-identity
// regression for the dot heuristic: a policy entry scoped to the dotless
// canonical host "gitlab" (key "gitlab/acme/widget") applies to that host's
// repository — including equivalent host spellings — and never to another
// forge presenting the same name ("forge.example/gitlab/acme/widget"), whose
// full name merely embeds the dotless string. The reverse direction is also
// pinned: a canonical entry for the other forge must not scope the dotless
// repository.
func TestDotlessCanonicalPolicyHostSeparatesForge(t *testing.T) {
	inv := RepoPolicy{AllowedRegions: []string{"eu"}}
	cfg := &Config{Repositories: map[string]RepoPolicy{"gitlab/acme/widget": inv}}
	if got, ok := cfg.RepoPolicyFor("gitlab/acme/widget"); !ok || !reflect.DeepEqual(got, inv) {
		t.Fatalf("dotless canonical entry must resolve its own repository: %+v ok=%v", got, ok)
	}
	if _, ok := cfg.RepoPolicyFor("GitLab/acme/widget"); !ok {
		t.Fatal("equivalent spelling of the dotless host must resolve the entry")
	}
	if _, ok := cfg.RepoPolicyFor("forge.example/gitlab/acme/widget"); ok {
		t.Fatal("dotless canonical policy leaked to another forge with the same name")
	}
	rev := &Config{Repositories: map[string]RepoPolicy{"forge.example/gitlab/acme/widget": inv}}
	if _, ok := rev.RepoPolicyFor("gitlab/acme/widget"); ok {
		t.Fatal("another forge's canonical entry scoped the dotless repository")
	}
	if got, ok := rev.RepoPolicyFor("forge.example/gitlab/acme/widget"); !ok || !reflect.DeepEqual(got, inv) {
		t.Fatalf("other-forge canonical entry must resolve its own repository: %+v ok=%v", got, ok)
	}
}
