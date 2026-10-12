package verifystore

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// TestVerificationContentDigestIdentity proves the idempotency digests: one
// submission hashes one way, Measured facts never participate, and Equal
// instants in different locations are the same claim identity.
func TestVerificationContentDigestIdentity(t *testing.T) {
	ob := verifyapi.VerificationObligation{
		ObligationID:               "ob-1",
		Subject:                    "svc",
		ImmutableCandidateDigest:   testDigest(t, "candidate"),
		SourceSnapshotDigest:       testDigest(t, "snapshot"),
		VerificationContractDigest: testDigest(t, "contract"),
		RequiredChecks:             []string{"sig"},
		RequiredAssurance:          "attested-v1",
		Freshness:                  verifyapi.FreshnessPolicy{MaxAgeSeconds: 3600},
		IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	d1, err := ObligationContentDigest(ob)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ObligationContentDigest(ob)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("obligation digest unstable: %q vs %q", d1, d2)
	}
	other := ob
	other.Subject = "other"
	d3, err := ObligationContentDigest(other)
	if err != nil {
		t.Fatal(err)
	}
	if d3 == d1 {
		t.Fatal("different obligation content produced the same digest")
	}

	loc := time.FixedZone("UTC+2", 2*3600)
	obLoc := ob
	obLoc.IssuedAt = ob.IssuedAt.In(loc)
	d4, err := ObligationContentDigest(obLoc)
	if err != nil {
		t.Fatal(err)
	}
	if d4 != d1 {
		t.Fatalf("Equal instant in another location changed the digest: %q vs %q", d4, d1)
	}

	v := verifyapi.VerificationOutcome{
		VerificationID:   "ver-1",
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          verifyapi.OutcomePass,
		AssuranceProfile: ob.RequiredAssurance,
		CompletedChecks:  []string{"sig"},
		EvidenceRoot:     testDigest(t, "evidence"),
		StartedAt:        ob.IssuedAt.Add(time.Second),
		CompletedAt:      ob.IssuedAt.Add(10 * time.Second),
	}
	c1, err := ClaimContentDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	withMeasured := v
	withMeasured.Resources.Measured = &verifyapi.MeasuredResourceFacts{DurationNS: 9}
	c2, err := ClaimContentDigest(withMeasured)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 {
		t.Fatal("Measured facts changed the claim content digest")
	}
	v2 := v
	v2.Outcome = verifyapi.OutcomeFail
	c3, err := ClaimContentDigest(v2)
	if err != nil {
		t.Fatal(err)
	}
	if c3 == c1 {
		t.Fatal("different claim content produced the same digest")
	}
}

// TestVerificationContentDigestGroupMapOrder: JSON map-key sorting makes the
// group digest independent of Go map iteration order.
func TestVerificationContentDigestGroupMapOrder(t *testing.T) {
	base := testDigest(t, "snap")
	g1 := verifyapi.SpeculativeGroup{
		VerificationGroupID: "g",
		BaseSnapshotDigest:  base,
		CandidateDigests:    map[string]verifyapi.Digest{"a": testDigest(t, "a"), "b": testDigest(t, "b")},
	}
	g2 := verifyapi.SpeculativeGroup{
		VerificationGroupID: "g",
		BaseSnapshotDigest:  base,
		CandidateDigests:    map[string]verifyapi.Digest{"b": testDigest(t, "b"), "a": testDigest(t, "a")},
	}
	d1, err := GroupContentDigest(g1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := GroupContentDigest(g2)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("group digest depends on map order: %q vs %q", d1, d2)
	}
}

// TestIsUniqueViolationMapping pins SQLSTATE 23505 → true and everything
// else → false, the gate that turns a lost insert race into an idempotent
// replay check instead of a hard error.
func TestIsUniqueViolationMapping(t *testing.T) {
	if !isUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("23505 must map as a unique violation")
	}
	if isUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Fatal("foreign-key violation must not map as unique")
	}
	if isUniqueViolation(errors.New("boom")) {
		t.Fatal("generic error must not map as unique")
	}
	wrapped := errors.Join(errors.New("wrap"), &pgconn.PgError{Code: "23505"})
	if !isUniqueViolation(wrapped) {
		t.Fatal("wrapped 23505 must map as a unique violation")
	}
}

// testDigest builds a valid 64-hex digest from a seed (mirrors the verifyapi
// test helper without exporting it).
func testDigest(t *testing.T, seed string) verifyapi.Digest {
	t.Helper()
	const hexDigits = "0123456789abcdef"
	d := make([]byte, 64)
	for i := range d {
		d[i] = hexDigits[(int(seed[i%len(seed)])+i)%16]
	}
	return verifyapi.Digest(d)
}
