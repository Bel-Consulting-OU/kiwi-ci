package pipeline

import (
	"strings"
	"testing"
)

// TestCanonicalServiceAliasPinsRuntimeNormalization pins the single shared
// canonicalization: lowercasing plus the docker name sanitizer the executor
// applies before attaching --network-alias, so admission and execution agree
// on exactly one form per declared alias.
func TestCanonicalServiceAliasPinsRuntimeNormalization(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"", ""},
		{"postgres", "postgres"},
		{"Postgres", "postgres"},
		{"REDIS", "redis"},
		{"My DB!", "my-db-"},
		{"My.DB", "my.db"},
		{"a_b.c-d", "a_b.c-d"},
		{"!!!", "---"},
	}
	for _, tc := range cases {
		if got := CanonicalServiceAlias(tc.name); got != tc.want {
			t.Fatalf("CanonicalServiceAlias(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// aliasSpec builds a one-job container spec with the given service aliases.
func aliasSpec(names ...string) *Spec {
	services := make([]Service, len(names))
	for i, n := range names {
		services[i] = Service{Name: n, Image: "postgres:16"}
	}
	return &Spec{Version: 1, Jobs: map[string]Job{
		"build": {Runtime: "container", Image: "alpine:3.19", Services: services, Steps: []Step{{Run: "echo hi"}}},
	}}
}

// TestValidateRejectsCanonicalServiceAliasCollisions is the E3-E fix pin:
// aliases that differ only in case (docker resolves network aliases
// case-insensitively and the executor lowercases them) are rejected at
// validation time instead of colliding at runtime, where the second service
// would silently steal the first one's DNS name.
func TestValidateRejectsCanonicalServiceAliasCollisions(t *testing.T) {
	cases := []struct {
		name    string
		aliases []string
	}{
		{"mixed case", []string{"Redis", "redis"}},
		{"all caps", []string{"DB", "db"}},
		{"case-folded across three", []string{"Cache", "cache", "CACHE"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(aliasSpec(tc.aliases...))
			if err == nil {
				t.Fatalf("aliases %v accepted", tc.aliases)
			}
			for _, want := range []string{"declares service alias", tc.aliases[0], tc.aliases[1]} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not name %q", err, want)
				}
			}
			// Compile validates through the same path, so an engine that
			// compiles without a separate Validate call is covered too.
			if _, cerr := Compile(aliasSpec(tc.aliases...)); cerr == nil {
				t.Fatalf("compile accepted aliases %v", tc.aliases)
			}
		})
	}
	// Exactly-equal duplicates keep the historical error text.
	err := Validate(aliasSpec("db", "db"))
	if err == nil || !strings.Contains(err.Error(), `declares service alias "db" more than once`) {
		t.Fatalf("exact duplicate = %v", err)
	}
}

// TestValidateAcceptsDistinctCanonicalAliases proves the canonical rule does
// not over-reject: aliases with distinct canonical forms (including
// case-different ones with different spellings) stay legal.
func TestValidateAcceptsDistinctCanonicalAliases(t *testing.T) {
	if err := Validate(aliasSpec("postgres", "Redis", "cache-db")); err != nil {
		t.Fatalf("distinct aliases rejected: %v", err)
	}
	// A single alias keeps its canonicalization (admission must not rewrite
	// the declared name, only detect collisions).
	spec := aliasSpec("Redis")
	if err := Validate(spec); err != nil {
		t.Fatalf("single mixed-case alias rejected: %v", err)
	}
	if got := spec.Jobs["build"].Services[0].Name; got != "Redis" {
		t.Fatalf("validation rewrote the declared alias to %q", got)
	}
}
