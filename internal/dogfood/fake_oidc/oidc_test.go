package fake_oidc

import (
	"testing"
	"time"
)

// TestRPValidateClaimsAndExpiry: the fake relying party accepts a correct
// claim set, refuses wrong audience/issuer/stale runner, and refuses an
// expired token.
func TestRPValidateClaimsAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	rp := New(func() time.Time { return now })
	tok := rp.Issue(Claims{
		Subject: "repo:df/app", Audience: "https://oidc.dogfood.invalid/df-1",
		Issuer: "https://oidc.dogfood.invalid", RunnerID: "runner-1", JobID: "job-1",
		IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour),
	})
	if tok.ID == "" {
		t.Fatal("issued token must carry an id")
	}
	want := Expectation{
		Audience: "https://oidc.dogfood.invalid/df-1",
		Issuer:   "https://oidc.dogfood.invalid",
		RunnerID: "runner-1",
		JobID:    "job-1",
	}
	if err := rp.Validate(tok, want); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	bad := want
	bad.Audience = "https://oidc.dogfood.invalid/other"
	if err := rp.Validate(tok, bad); err == nil {
		t.Fatal("wrong audience must be refused")
	}
	stale := want
	stale.RunnerID = "runner-2"
	if err := rp.Validate(tok, stale); err == nil {
		t.Fatal("stale/foreign runner must be refused")
	}
	now = now.Add(2 * time.Hour)
	if err := rp.Validate(tok, want); err == nil {
		t.Fatal("expired token must be refused")
	}
	if rp.IssuedCount() != 1 {
		t.Fatalf("issued count = %d", rp.IssuedCount())
	}
}
