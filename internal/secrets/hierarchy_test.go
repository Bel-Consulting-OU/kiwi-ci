package secrets

import (
	"context"
	"strings"
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

// Trust floor: a nil Trusted on the ref means "trusted only". Untrusted
// execution must never see it, even when no explicit pin exists.
func TestHierarchyTrustFloorDefaultsClosed(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "S", Value: "v", Scope: ScopeRepository, Owner: "r"})
	p := Policy{Repository: "r", Trusted: false, Now: time.Now()}
	if e := h.Explain("S", p); e.Available {
		t.Fatal("untrusted must not see an unpinned secret (nil Trusted = trusted only)")
	}
	// Explicit untrusted-allowed ref (Trusted=false) is visible to untrusted.
	untrustedAllowed := false
	h.Add(SecretRef{Name: "U", Value: "v", Scope: ScopeRepository, Owner: "r", Trusted: &untrustedAllowed})
	e := h.Explain("U", p)
	if !e.Available {
		t.Fatalf("explicitly untrusted-allowed secret must resolve: %+v", e)
	}
}

// Expiry must not fail open when Policy.Now is zero.
func TestHierarchyExpiryDoesNotFailOpen(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "E", Value: "v", Scope: ScopeInstance, ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)})
	// Now omitted (zero): treated as time.Now(), so a 2020 expiry is past.
	e := h.Explain("E", Policy{Trusted: true})
	if e.Available {
		t.Fatal("expiry must apply even when Policy.Now is zero")
	}
}

// Two matching refs at the same scope are ambiguous — fail closed.
func TestHierarchyAmbiguousScopeFailsClosed(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "A", Value: "one", Scope: ScopeRepository, Owner: "r"})
	h.Add(SecretRef{Name: "A", Value: "two", Scope: ScopeRepository, Owner: "r"})
	_, err := h.Resolve(context.Background(), "A", Policy{Repository: "r", Trusted: true, Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous scope = %v, want fail-closed", err)
	}
}

// A job/step-scoped ref with no owner matches every job/step — that is a
// cross-execution leak. Require the owner.
func TestHierarchyJobStepRequireOwner(t *testing.T) {
	h := NewHierarchy()
	h.Add(SecretRef{Name: "J", Value: "v", Scope: ScopeJob}) // no owner
	p := Policy{Job: "job-a", Trusted: true, Now: time.Now()}
	if e := h.Explain("J", p); e.Available {
		t.Fatal("job-scoped ref without owner must not match any job")
	}
	h.Add(SecretRef{Name: "K", Value: "v", Scope: ScopeJob, Owner: "job-a"})
	if e := h.Explain("K", p); !e.Available {
		t.Fatalf("job-scoped ref with matching owner must resolve: %+v", e)
	}
	p2 := Policy{Job: "job-b", Trusted: true, Now: time.Now()}
	if e := h.Explain("K", p2); e.Available {
		t.Fatal("job-scoped ref must not leak to another job")
	}
	s := Policy{Step: "s1", Trusted: true, Now: time.Now()}
	h.Add(SecretRef{Name: "S", Value: "v", Scope: ScopeStep}) // no owner
	if e := h.Explain("S", s); e.Available {
		t.Fatal("step-scoped ref without owner must not match any step")
	}
}
