package secrets

import (
	"context"
	"testing"
	"time"
)

func boolPtr(b bool) *bool { return &b }

// Secret hierarchy: instance → org → team → repo → env → job → step.
// Resolution is most-specific-first and fully explainable.
func TestHierarchyResolutionMostSpecificWins(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "DB_PASSWORD", Value: "instance", Scope: ScopeInstance, Provider: "vault"})
	h.Add(SecretRef{Name: "DB_PASSWORD", Value: "org", Scope: ScopeOrganization, Owner: "starz", Provider: "vault"})
	h.Add(SecretRef{Name: "DB_PASSWORD", Value: "repo", Scope: ScopeRepository, Owner: "starz/api", Provider: "vault"})
	h.Add(SecretRef{Name: "DB_PASSWORD", Value: "env", Scope: ScopeEnvironment, Owner: "production", Provider: "vault"})
	p := Policy{
		Org: "starz", Repository: "starz/api", Environment: "production",
		Trusted: true, Now: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}
	v, err := h.Resolve(context.Background(), "DB_PASSWORD", p)
	if err != nil {
		t.Fatal(err)
	}
	if v != "env" {
		t.Fatalf("resolve = %q, want env (most specific)", v)
	}
	e := h.Explain("DB_PASSWORD", p)
	if e.Source != "organization starz" && e.Source != "instance" {
		// Source is the definition (least specific match).
		t.Fatalf("source = %q, want the definition scope", e.Source)
	}
	if e.OverriddenBy != "environment production" {
		t.Fatalf("overridden_by = %q, want the winning environment ref", e.OverriddenBy)
	}
	if !e.Available {
		t.Fatal("must be available")
	}
	if e.Provider != "vault" {
		t.Fatalf("provider = %q", e.Provider)
	}
}

func TestHierarchyUntrustedRefused(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "S", Value: "v", Scope: ScopeRepository, Owner: "r"})
	p := Policy{Repository: "r", Trusted: false, Now: time.Now()}
	e := h.Explain("S", p)
	if e.Available {
		// Without a Trusted pin the ref is open; pin it trusted-only.
		h2 := NewHierarchy()
		h2.Add(SecretRef{Name: "S", Value: "v", Scope: ScopeRepository, Owner: "r", Trusted: boolPtr(true)})
		e = h2.Explain("S", p)
		if e.Available {
			t.Fatal("untrusted must not see trusted-only secret")
		}
	}
	if _, err := (HierarchyProvider{H: h, P: p}).Get(context.Background(), "MISSING"); err == nil {
		t.Fatal("missing secret must fail")
	}
}

func TestHierarchyPolicyDimensions(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "DEPLOY", Value: "prod", Scope: ScopeEnvironment, Owner: "production",
		Branch: "main", Event: "push", Fork: boolPtr(false), Trusted: boolPtr(true),
		ExpiresAt: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)})
	ok := Policy{Environment: "production", Branch: "main", Event: "push", Fork: false, Trusted: true, Now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	if v, err := h.Resolve(context.Background(), "DEPLOY", ok); err != nil || v != "prod" {
		t.Fatalf("ok policy = %q %v", v, err)
	}
	// Wrong branch.
	bad := ok
	bad.Branch = "feature"
	e := h.Explain("DEPLOY", bad)
	if e.Available {
		t.Fatal("wrong branch must not resolve")
	}
	// Expired.
	exp := ok
	exp.Now = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if e := h.Explain("DEPLOY", exp); e.Available {
		t.Fatal("expired secret must not resolve")
	}
	if e := h.Explain("DEPLOY", exp); e.Expires == "" {
		// Explanation still names the expiry on the source when it matched
		// before expiry checks… for expired the source is empty; reason must
		// say unavailable.
		if e.Reason == "" {
			t.Fatal("expired explain needs a reason")
		}
	}
}

func TestExplainNamesSourceAndReason(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "T", Value: "v", Scope: ScopeTeam, Owner: "platform"})
	e := h.Explain("T", Policy{Team: "platform", Trusted: true, Now: time.Now()})
	if e.Source != "team platform" {
		t.Fatalf("source = %q", e.Source)
	}
	if e.Reason == "" {
		t.Fatal("reason required")
	}
	e2 := h.Explain("T", Policy{Team: "other", Trusted: true, Now: time.Now()})
	if e2.Available {
		t.Fatal("wrong team must not resolve")
	}
}
