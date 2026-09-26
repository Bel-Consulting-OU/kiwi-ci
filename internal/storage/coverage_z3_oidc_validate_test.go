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
