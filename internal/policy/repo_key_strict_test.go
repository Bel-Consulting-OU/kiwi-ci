package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

func policyBoolPtr(b bool) *bool { return &b }

// TestValidateRejectsAmbiguousRepoKey is the R2-A regression: a normal nested
// GitLab key like "group/sub/project", intended as a bare alias, is AMBIGUOUS
// under the typed positional rule (it could be the dotless host "group" plus
// full name "sub/project"). Config.Validate must reject it through the strict
// ACL configuration parser (auth.ParseRepoGrantConfig) with an error naming
// the accepted r1:/a1: forms, instead of silently reading it as host/full-name
// and letting the intended policy never apply (fail open).
func TestValidateRejectsAmbiguousRepoKey(t *testing.T) {
	const ambiguous = "group/sub/project"
	cfg := &Config{Repositories: map[string]RepoPolicy{
		ambiguous: {RequireDigestPins: policyBoolPtr(true)},
	}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Config.Validate accepted an ambiguous untagged nested repository key")
	}
	if !errors.Is(err, auth.ErrRepoGrantAmbiguous) {
		t.Fatalf("Config.Validate error = %v, want auth.ErrRepoGrantAmbiguous", err)
	}
	for _, want := range []string{ambiguous, auth.RepoIdentityPrefix, auth.RepoAliasPrefix} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Config.Validate error %q must name %q", err.Error(), want)
		}
	}
}

// TestLoadRejectsAmbiguousRepoKey pins the same rule through the YAML file
// path: a policy file using the ambiguous key fails to load.
func TestLoadRejectsAmbiguousRepoKey(t *testing.T) {
	p := writePolicy(t, "repositories:\n  group/sub/project:\n    require_rootless: true\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("Load accepted a policy file with an ambiguous repository key")
	}
	if !errors.Is(err, auth.ErrRepoGrantAmbiguous) {
		t.Fatalf("Load error = %v, want auth.ErrRepoGrantAmbiguous", err)
	}
}

// TestExplicitRepoPolicyKeysApply is the R2-A positive case: the canonical
// r1:<base64url(host)>:<base64url(full_name)> form scopes a DOTLESS host with
// a nested full name, and the a1:<base64url(full_name)> form is a nested bare
// alias applying to every forge presenting that name. Both are accepted by
// Validate.
func TestExplicitRepoPolicyKeysApply(t *testing.T) {
	dotless := RepoPolicy{AllowedRegions: []string{"eu"}}
	nested := RepoPolicy{RequireRootless: policyBoolPtr(true)}
	cfg := &Config{Repositories: map[string]RepoPolicy{
		r1("gitlab", "team/sub/project"): dotless,
		a1("group/sub/project"):          nested,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit r1:/a1: keys must validate: %v", err)
	}
	got, ok := cfg.RepoPolicyFor("gitlab/team/sub/project")
	if !ok || !reflect.DeepEqual(got, dotless) {
		t.Fatalf("dotless canonical lookup = %+v ok=%v, want %+v", got, ok, dotless)
	}
	if _, ok := cfg.RepoPolicyFor("GitLab/team/sub/project"); !ok {
		t.Fatal("equivalent spelling of the dotless host must resolve the r1: entry")
	}
	// The nested alias applies to the same-named repository on every forge.
	got, ok = cfg.RepoPolicyFor("gitlab.example/group/sub/project")
	if !ok || !reflect.DeepEqual(got, nested) {
		t.Fatalf("nested alias lookup = %+v ok=%v, want %+v", got, ok, nested)
	}
	if _, ok := cfg.RepoPolicyFor("github.com/group/sub/project"); !ok {
		t.Fatal("nested bare alias must apply to every forge presenting the name")
	}
	// It never scopes a different nested name, and the dotless r1: entry never
	// leaks to another forge.
	if _, ok := cfg.RepoPolicyFor("gitlab/group/sub/other"); ok {
		t.Fatal("nested alias leaked to a different full name")
	}
	if _, ok := cfg.RepoPolicyFor("forge.example/gitlab/team/sub/project"); ok {
		t.Fatal("dotless canonical r1: entry leaked to another forge")
	}
}

// TestProgrammaticConfigAmbiguousKeysIgnored is the R2-A fail-closed lookup
// case: a programmatically constructed Config can bypass Config.Validate, so
// the LOOKUP must also use the strict configuration parser. An ambiguous
// untagged nested key matches NOTHING (neither its bare-nested reading nor its
// dotless-host reading), so it can never silently scope a repository.
func TestProgrammaticConfigAmbiguousKeysIgnored(t *testing.T) {
	enabled := policyBoolPtr(true)
	cfg := &Config{Repositories: map[string]RepoPolicy{
		"group/sub/project": {RequireDigestPins: enabled},
	}}
	for _, lookup := range []string{
		"group/sub/project",               // the bare-nested reading
		"forge.example/group/sub/project", // the same name on another forge
		"example.com/group/sub/project",   // a canonical full-name reading
	} {
		if rp, ok := cfg.RepoPolicyFor(lookup); ok {
			t.Fatalf("ambiguous programmatic key resolved %q to %+v", lookup, rp)
		}
	}
	// The load path rejects the same Config outright.
	if err := cfg.Validate(); !errors.Is(err, auth.ErrRepoGrantAmbiguous) {
		t.Fatalf("Config.Validate = %v, want ErrRepoGrantAmbiguous", err)
	}
}
