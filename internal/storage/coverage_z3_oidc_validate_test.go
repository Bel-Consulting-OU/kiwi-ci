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
	good := OIDCIssuance{
		JobID: "job-1", RunnerID: "runner-1", LeaseGeneration: 1,
		LeaseTokenHash: []byte("hash"), Audience: "https://aud.example.com",
		KID: "kid", JTI: "jti", TTL: 5 * time.Minute,
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
		{"non-positive ttl", func(r *OIDCIssuance) { r.TTL = 0 }},
		{"negative ttl", func(r *OIDCIssuance) { r.TTL = -time.Minute }},
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

// TestValidateOIDCIssuanceAtClockBoundary pins the commit-clock conditions
// directly, with the strict After boundary: a lease expiring at the commit
// instant is refused, an issuance whose lease strictly outlives the commit
// clock passes, and a non-positive TTL is a shape refusal (the absolute
// window is derived from the commit clock by the caller).
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

	// The lifetime is a TTL: a non-positive one is invalid, never a way to
	// backdate or extend the window.
	elapsed := req
	elapsed.TTL = 0
	if err := ValidateOIDCIssuanceAt(locked, elapsed, commitNow); !errors.Is(err, ErrOIDCIssuanceInvalid) {
		t.Fatalf("zero token ttl = %v, want ErrOIDCIssuanceInvalid", err)
	}

	// A zero lease expiry is the same typed refusal (no lease at all).
	noLease := locked
	noLease.LeaseExpiresAt = time.Time{}
	if err := ValidateOIDCIssuanceAt(noLease, req, commitNow); !errors.Is(err, ErrOIDCIssuanceExpired) {
		t.Fatalf("missing lease at the commit clock = %v, want ErrOIDCIssuanceExpired", err)
	}
}
