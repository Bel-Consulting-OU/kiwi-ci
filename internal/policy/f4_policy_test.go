package policy

// F4-B/F4-C regressions: canonical-equivalent repository keys with DIFFERENT
// policies must fail closed at validation, and an explicitly configured but
// empty OPA source must be a configuration error (never "no OPA").

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

func TestConfigValidateRejectsEquivalentKeysWithDifferentPolicies(t *testing.T) {
	enabled := true
	conflict := &Config{Repositories: map[string]RepoPolicy{
		r1("github.com", "acme/backend"):     {RequireDigestPins: &enabled},
		r1("GITHUB.COM.", "acme/backend"):    {},
		r1("github.com:443", "acme/backend"): {},
	}}
	if err := conflict.Validate(); err == nil {
		t.Fatal("canonically equivalent keys with different policies accepted")
	}

	// Equivalent ALIAS spellings that differ are equally rejected: the plain
	// owner/name and its explicit a1: spelling address the same alias.
	a1 := auth.RepoAliasPrefix + base64.RawURLEncoding.EncodeToString([]byte("acme/backend"))
	aliasConflict := &Config{Repositories: map[string]RepoPolicy{
		"acme/backend": {RequireDigestPins: &enabled},
		a1:             {},
	}}
	if err := aliasConflict.Validate(); err == nil {
		t.Fatal("equivalent alias keys with different policies accepted")
	}

	// Identical policies on equivalent keys are accepted.
	equal := &Config{Repositories: map[string]RepoPolicy{
		r1("github.com", "acme/backend"):  {RequireDigestPins: &enabled},
		r1("GITHUB.COM.", "acme/backend"): {RequireDigestPins: &enabled},
	}}
	if err := equal.Validate(); err != nil {
		t.Fatalf("identical equivalent keys rejected: %v", err)
	}
}

func TestOPAConfiguredButEmptyIsError(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.rego")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{OPAFile: empty}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty opa_file accepted")
	}
	if gate, err := cfg.CompileOPA(); err == nil || gate != nil {
		t.Fatalf("empty opa_file compiled to (%v,%v), want a configuration error", gate, err)
	}

	// Only NEITHER-set means no OPA.
	none := &Config{}
	if err := none.Validate(); err != nil {
		t.Fatalf("absent OPA must be valid: %v", err)
	}
	if gate, err := none.CompileOPA(); err != nil || gate != nil {
		t.Fatalf("absent OPA = (%v,%v), want (nil,nil)", gate, err)
	}
}

func TestOPAExplicitlyEmptyKeysRejectedByLoad(t *testing.T) {
	for _, body := range []string{"opa_file: \"\"\n", "opa_rules: \"\"\n"} {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("policy with %q accepted (an empty OPA source disables the gate)", body)
		}
	}
}
