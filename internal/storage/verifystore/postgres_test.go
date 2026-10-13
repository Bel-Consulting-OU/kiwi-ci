package verifystore

import (
	"context"
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

	// Model A: execution-id order and duplicates are not claim identity —
	// retries that reorder or repeat the same raw claim ids hash equal.
	vOrdered := v
	vOrdered.ExecutionIDs = []string{"exec-b", "exec-a"}
	vDup := v
	vDup.ExecutionIDs = []string{"exec-a", "exec-b", "exec-a"}
	vSorted := v
	vSorted.ExecutionIDs = []string{"exec-a", "exec-b"}
	base, err := ClaimContentDigest(vSorted)
	if err != nil {
		t.Fatal(err)
	}
	for name, cand := range map[string]verifyapi.VerificationOutcome{
		"reordered":  vOrdered,
		"duplicates": vDup,
	} {
		d, err := ClaimContentDigest(cand)
		if err != nil {
			t.Fatal(err)
		}
		if d != base {
			t.Fatalf("%s exec ids changed the claim content digest: %q vs %q", name, d, base)
		}
	}
	// A different id set is still a different claim identity.
	vOther := v
	vOther.ExecutionIDs = []string{"exec-c"}
	dOther, err := ClaimContentDigest(vOther)
	if err != nil {
		t.Fatal(err)
	}
	if dOther == base {
		t.Fatal("different exec id set produced the same digest")
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

// TestAcceptanceIntegrityRejectsTamperedPayload is the P1-B unit half of the
// restore path: the database row is not authority. A tampered outcome
// payload, an unsigned acceptance record, a flipped "verified" shape with no
// acceptance, or a wrong MAC all refuse to restore a seal — ProvenPass can
// never be recreated from a bare row.
func TestAcceptanceIntegrityRejectsTamperedPayload(t *testing.T) {
	ob := verifyapi.VerificationObligation{
		ObligationID:               "ob-1",
		Subject:                    "svc",
		ImmutableCandidateDigest:   testDigest(t, "candidate"),
		SourceSnapshotDigest:       testDigest(t, "snapshot"),
		VerificationContractDigest: testDigest(t, "contract"),
		RequiredChecks:             []string{"digest-match", "signature"},
		RequiredAssurance:          "uncontrolled",
		Freshness:                  verifyapi.FreshnessPolicy{MaxAgeSeconds: 3600},
		IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	claim := verifyapi.VerificationOutcome{
		VerificationID:   "ver-1",
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          verifyapi.OutcomePass,
		AssuranceProfile: ob.RequiredAssurance,
		CompletedChecks:  []string{"digest-match", "signature"},
		EvidenceRoot:     testDigest(t, "evidence"),
		ProvenanceRefs:   []string{"att-1"},
		Resources:        verifyapi.ResourceFacts{RunnerClass: "standard"},
		StartedAt:        ob.IssuedAt.Add(time.Second),
		CompletedAt:      ob.IssuedAt.Add(10 * time.Second),
	}
	derived := claim
	derived.CompletedChecks = []string{"digest-match", "signature", "job-status-success", "evidence-root"}
	evidence := verifyapi.VerifiedEvidence{
		ExecutionIDs:       []string{"exec-1"},
		EvidenceRoot:       testDigest(t, "evidence"),
		AttestationDigests: []verifyapi.Digest{testDigest(t, "att")},
		JobStatus:          "success",
		CompletedChecks:    derived.CompletedChecks,
		VerifierIdentity:   "verifystore-acceptance-test/v1",
		VerifiedAt:         ob.IssuedAt.Add(30 * time.Second),
	}
	// Seal through the real verifier so Accept sees a sealed record.
	f := &verifyapi.FuncEvidenceVerifier{
		Identity: "verifystore-acceptance-test/v1",
		Resolve: func(context.Context, string) (verifyapi.ResolvedAttestation, error) {
			return verifyapi.ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      testDigest(t, "evidence"),
				AttestationDigest: testDigest(t, "att"),
				Status:            "success",
				Attested: &verifyapi.AttestedResourceFacts{
					StartedAt:  ob.IssuedAt.Add(time.Second),
					FinishedAt: ob.IssuedAt.Add(10 * time.Second),
				},
				Checks: []verifyapi.VerifiedCheck{
					{Name: "digest-match", Outcome: verifyapi.CheckOutcomePass, EvidenceDigest: testDigest(t, "att"), ExecutionID: "exec-1"},
					{Name: "signature", Outcome: verifyapi.CheckOutcomePass, EvidenceDigest: testDigest(t, "att"), ExecutionID: "exec-1"},
				},
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if !sealed.ProvenPass() {
		t.Fatal("want sealed proven pass before persistence")
	}
	key, err := verifyapi.NewHMACAcceptanceKey("acc-1", []byte("verifystore-test-secret-32-b!!"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := verifyapi.Accept(ob, sealed, key, ob.IssuedAt.Add(30*time.Second))
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	persisted := verifyapi.PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       sealed.Evidence(),
		Acceptance:     rec,
	}

	// The intact row restores as a proven pass.
	restored, err := verifyapi.RestoreVerifiedOutcome(persisted, key)
	if err != nil {
		t.Fatalf("RestoreVerifiedOutcome intact = %v", err)
	}
	if !restored.ProvenPass() {
		t.Fatal("intact row must restore as a proven pass")
	}

	// Tampered DB payload: someone edits the outcome JSON after write.
	tampered := persisted
	tampered.Outcome = persisted.Outcome
	tampered.Outcome.Outcome = verifyapi.OutcomePass
	tampered.Outcome.CompletedChecks = []string{"digest-match", "signature"} // drop derived checks
	if _, err := verifyapi.RestoreVerifiedOutcome(tampered, key); err == nil {
		t.Fatal("tampered outcome payload must not restore")
	} else if !errors.Is(err, verifyapi.ErrAcceptance) {
		t.Fatalf("tampered outcome error = %v, want ErrAcceptance", err)
	}

	// Tampered evidence payload.
	tamperedEv := persisted
	tamperedEv.Evidence = persisted.Evidence
	tamperedEv.Evidence.VerifierIdentity = "forged-verifier"
	if _, err := verifyapi.RestoreVerifiedOutcome(tamperedEv, key); err == nil {
		t.Fatal("tampered evidence payload must not restore")
	}

	// Flipped verified flag shape: a claim-only row with no acceptance
	// record cannot produce a seal.
	unsigned := persisted
	unsigned.Acceptance = verifyapi.AcceptanceRecord{}
	if _, err := verifyapi.RestoreVerifiedOutcome(unsigned, key); err == nil {
		t.Fatal("unsigned acceptance record must not restore")
	} else if !errors.Is(err, verifyapi.ErrAcceptance) {
		t.Fatalf("unsigned error = %v, want ErrAcceptance", err)
	}

	// Wrong MAC (wrong key, or a corrupted MAC under the right key).
	other, err := verifyapi.NewHMACAcceptanceKey("acc-2", []byte("a-different-secret-32-bytes!!!"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyapi.RestoreVerifiedOutcome(persisted, other); err == nil {
		t.Fatal("restore under a foreign acceptance key must fail")
	}
	badMAC := persisted
	badMAC.Acceptance = persisted.Acceptance
	badMAC.Acceptance.MAC = "deadbeef"
	if _, err := verifyapi.RestoreVerifiedOutcome(badMAC, key); err == nil {
		t.Fatal("corrupted MAC must not restore")
	} else if !errors.Is(err, verifyapi.ErrAcceptance) {
		t.Fatalf("corrupted MAC error = %v, want ErrAcceptance", err)
	}

	// Key-id / algorithm mismatch in the record itself.
	badKeyID := persisted
	badKeyID.Acceptance = persisted.Acceptance
	badKeyID.Acceptance.KeyID = "someone-else"
	if _, err := verifyapi.RestoreVerifiedOutcome(badKeyID, key); err == nil {
		t.Fatal("key-id mismatch must not restore")
	}
	_ = evidence
}
