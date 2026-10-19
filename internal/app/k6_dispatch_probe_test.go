package app

import (
	"strings"
	"testing"
)

// TestDispatchHasTrustedFlag: K6 — the deny message advertises
// dispatch --trusted; the flag must exist (was "flag provided but not
// defined").
func TestDispatchHasTrustedFlag(t *testing.T) {
	err := Dispatch(t.Context(), []string{"--trusted", "--repo", "acme/widget"})
	// Without a server this fails later, but NEVER with an undefined-flag
	// error — that is the regression the deny message pointed at.
	if err != nil && strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("dispatch --trusted missing: %v", err)
	}
}

// TestPolicyCheckHasConfigFlag: K6 — policy check must accept --config so
// a trusted preview can load the same policy file the server uses.
func TestPolicyCheckHasConfigFlag(t *testing.T) {
	err := opsPolicy(t.Context(), []string{"check", "--config", "nope.toml", "-f", "nope.yaml"})
	if err != nil && strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("policy check --config missing: %v", err)
	}
}
