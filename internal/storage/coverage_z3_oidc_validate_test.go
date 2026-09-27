package storage

import (
	"errors"
	"testing"
	"time"
)

// TestValidateOIDCIssuanceRequestShapeBranches pins the shape contract edges
// the PG commit relies on before it opens a transaction: an unaddressable job,
// a non-positive token lifetime and missing claims are all typed invalid, and
// a complete request passes.
func TestValidateOIDCIssuanceRequestShapeBranches(t *testing.T) {
	now := time.Now().UTC()
	good := OIDCIssuance{
		JobID: "job-1", RunnerID: "runner-1", LeaseGeneration: 1,
		LeaseTokenHash: []byte("hash"), Audience: "https://aud.example.com",
		KID: "kid", JTI: "jti", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Claims: map[string]string{},
	}
	if err := ValidateOIDCIssuanceRequest(good); err != nil {
		t.Fatalf("complete request rejected: %v", err)
	}

	bad := []struct {
		name   string
		mutate func(*OIDCIssuance)
	}{
		{"empty job id", func(r *OIDCIssuance) { r.JobID = "  " }},
		{"zero issued at", func(r *OIDCIssuance) { r.IssuedAt = time.Time{} }},
		{"lifetime not positive", func(r *OIDCIssuance) { r.ExpiresAt = r.IssuedAt }},
		{"missing claims", func(r *OIDCIssuance) { r.Claims = nil }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.mutate(&r)
			if err := ValidateOIDCIssuanceRequest(r); !errors.Is(err, ErrOIDCIssuanceInvalid) {
				t.Fatalf("request = %v, want ErrOIDCIssuanceInvalid", err)
			}
		})
	}
}

// TestValidateOIDCIssuanceAtClockBoundary pins the two commit-clock
// conditions directly, with the strict After boundary: a lease expiring at
// the commit instant and a lifetime expiring at the commit instant are both
// refused, while an issuance whose lease and lifetime strictly outlive the
// commit clock passes.
func TestValidateOIDCIssuanceAtClockBoundary(t *testing.T) {
	j := oidcIssueTestJob()
	locked := LockedOIDCIdentityForJob(j)
	req := oidcIssueTestRequest(j)
	commitNow := time.Now().UTC()
	if err := ValidateOIDCIssuanceAt(locked, req, commitNow); err != nil {
		t.Fatalf("live issuance at the commit clock = %v", err)
	}
	if err := ValidateOIDCIssuanceAt(locked, req, *j.LeaseExpiresAt); !errors.Is(err, ErrOIDCIssuanceExpired) {
		t.Fatalf("commit exactly at the lease expiry = %v, want ErrOIDCIssuanceExpired", err)
	}

	elapsed := req
	elapsed.ExpiresAt = commitNow
	if err := ValidateOIDCIssuanceAt(locked, elapsed, commitNow); !errors.Is(err, ErrOIDCIssuanceExpired) {
		t.Fatalf("commit exactly at the lifetime expiry = %v, want ErrOIDCIssuanceExpired", err)
	}

	// A zero lease expiry is the same typed refusal (no lease at all).
	noLease := locked
	noLease.LeaseExpiresAt = time.Time{}
	if err := ValidateOIDCIssuanceAt(noLease, req, commitNow); !errors.Is(err, ErrOIDCIssuanceExpired) {
		t.Fatalf("missing lease at the commit clock = %v, want ErrOIDCIssuanceExpired", err)
	}
}
