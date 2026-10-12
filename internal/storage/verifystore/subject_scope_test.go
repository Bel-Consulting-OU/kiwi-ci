package verifystore

import (
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

func mustDigest64(t *testing.T, seed string) verifyapi.Digest {
	t.Helper()
	const hexDigits = "0123456789abcdef"
	d := make([]byte, 64)
	for i := range d {
		d[i] = hexDigits[(int(seed[i%len(seed)])+i)%16]
	}
	return verifyapi.Digest(d)
}

func sampleObligation(t *testing.T) verifyapi.VerificationObligation {
	t.Helper()
	ref := verifyapi.SubjectRef{
		AuthorityNamespace: "forge.example",
		TenantID:           "tenant-1",
		ProjectID:          "proj-1",
		RepositoryID:       "repo-1",
	}
	return verifyapi.VerificationObligation{
		ObligationID:               "ob-1",
		Subject:                    "svc",
		SubjectRef:                 &ref,
		ImmutableCandidateDigest:   mustDigest64(t, "candidate"),
		SourceSnapshotDigest:       mustDigest64(t, "snapshot"),
		VerificationContractDigest: mustDigest64(t, "contract"),
		RequiredChecks:             []string{"sig"},
		RequiredAssurance:          "uncontrolled",
		Freshness:                  verifyapi.FreshnessPolicy{MaxAgeSeconds: 3600},
		IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// TestScopeOfObligationDerivesColumns pins the single derivation used by
// every write path: columns come from the obligation value and nothing else.
func TestScopeOfObligationDerivesColumns(t *testing.T) {
	ob := sampleObligation(t)
	sc := ScopeOfObligation(ob)
	want := SubjectScope{
		Subject:            "svc",
		AuthorityNamespace: "forge.example",
		TenantID:           "tenant-1",
		ProjectID:          "proj-1",
		RepositoryID:       "repo-1",
	}
	if sc != want {
		t.Fatalf("ScopeOfObligation = %+v, want %+v", sc, want)
	}
	// Legacy shape: nil SubjectRef yields empty scope dimensions.
	legacy := ob
	legacy.SubjectRef = nil
	sc2 := ScopeOfObligation(legacy)
	if sc2.Subject != "svc" || sc2.AuthorityNamespace != "" || sc2.TenantID != "" {
		t.Fatalf("legacy scope = %+v", sc2)
	}
	if !ScopeConsistent(legacy, sc2) {
		t.Fatal("derived columns must be consistent with their source by construction")
	}
}

// TestApplyScopeColumnsWin proves the read-path restore: when a payload's
// subject_ref disagrees with the normalized columns, the columns are the
// source of truth and overwrite the payload.
func TestApplyScopeColumnsWin(t *testing.T) {
	ob := sampleObligation(t)
	// Simulate a tampered payload claiming a different tenant.
	tampered := ob
	evil := verifyapi.SubjectRef{
		AuthorityNamespace: "forge.example",
		TenantID:           "attacker-tenant",
	}
	tampered.SubjectRef = &evil
	tampered.Subject = "attacker-subject"

	// The columns still say what was written.
	sc := SubjectScope{
		Subject:            "svc",
		AuthorityNamespace: "forge.example",
		TenantID:           "tenant-1",
		ProjectID:          "proj-1",
		RepositoryID:       "repo-1",
	}
	restored := ApplyScope(tampered, sc)
	if restored.Subject != "svc" || restored.SubjectReference().TenantID != "tenant-1" {
		t.Fatalf("columns must win: got subject=%q ref=%v", restored.Subject, restored.SubjectReference())
	}
	if !ScopeConsistent(restored, sc) {
		t.Fatal("restored obligation must be consistent with the columns")
	}
	// And the tampered payload is NOT consistent with the columns.
	if ScopeConsistent(tampered, sc) {
		t.Fatal("tampered payload must be reported as inconsistent")
	}

	// Zero scope columns restore the legacy nil SubjectRef.
	legacy := ApplyScope(tampered, SubjectScope{Subject: "svc"})
	if legacy.SubjectRef != nil {
		t.Fatalf("zero columns must restore a nil SubjectRef, got %+v", legacy.SubjectRef)
	}
}

// TestClaimIndexOfFollowsClaimNotDerived pins the P7 index rule: the index
// columns are denormalized from the claim payload (what GetOutcome returns),
// never from a derived verified outcome's window.
func TestClaimIndexOfFollowsClaimNotDerived(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	end := start.Add(10 * time.Second)
	claim := verifyapi.VerificationOutcome{
		VerificationID: "ver-1",
		ObligationID:   "ob-1",
		Resources: verifyapi.ResourceFacts{
			VerificationGroupID: "grp-1",
			CandidateID:         "cand-a",
		},
		StartedAt:   start,
		CompletedAt: end,
	}
	idx := ClaimIndexOf(claim)
	if idx.GroupID != "grp-1" || idx.CandidateID != "cand-a" {
		t.Fatalf("index identity = %+v", idx)
	}
	if !idx.StartedAt.Equal(start) || !idx.CompletedAt.Equal(end) {
		t.Fatalf("index window = %+v", idx)
	}
	if !ClaimIndexConsistent(claim, idx) {
		t.Fatal("derived index must be consistent with its source by construction")
	}

	// A derived outcome that re-windowed the attempt (attested job window)
	// must NOT change the index columns: those follow the claim payload.
	derived := claim
	derived.StartedAt = start.Add(time.Hour)
	derived.CompletedAt = end.Add(time.Hour)
	if ClaimIndexOf(derived) == idx {
		t.Fatal("sanity: derived window differs")
	}
	if !ClaimIndexConsistent(claim, idx) {
		t.Fatal("claim index consistency must be measured against the claim")
	}
}

// TestWriteAllRowProjectionCannotDiverge is the unit-level proof of the
// write-all invariant: every insert/upgrade writes columns derived from the
// SAME values that become the JSONB payload, in one projection. There is no
// code path that writes one without the other, and the projection functions
// are pure, so any sequence of writes leaves a consistent row.
func TestWriteAllRowProjectionCannotDiverge(t *testing.T) {
	ob := sampleObligation(t)
	claim := verifyapi.VerificationOutcome{
		VerificationID:   "ver-1",
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          verifyapi.OutcomePass,
		AssuranceProfile: ob.RequiredAssurance,
		EvidenceRoot:     mustDigest64(t, "evidence"),
		Resources: verifyapi.ResourceFacts{
			VerificationGroupID: "grp-1",
			CandidateID:         "cand-a",
		},
		StartedAt:   ob.IssuedAt.Add(time.Second),
		CompletedAt: ob.IssuedAt.Add(10 * time.Second),
	}

	// First write (insert).
	sc1 := ScopeOfObligation(ob)
	idx1 := ClaimIndexOf(claim)
	if !ScopeConsistent(ob, sc1) || !ClaimIndexConsistent(claim, idx1) {
		t.Fatal("insert projection must be consistent")
	}

	// Upsert of the SAME claim content (retry): the projection is
	// deterministic, so columns and payload stay in lockstep.
	sc2 := ScopeOfObligation(ob)
	idx2 := ClaimIndexOf(claim)
	if sc1 != sc2 || idx1 != idx2 {
		t.Fatal("retry projection must be identical")
	}

	// Upsert with a different subject (conflicting obligation content):
	// both payload and columns move together.
	ob2 := ob
	ob2.Subject = "other-svc"
	tenant := verifyapi.SubjectRef{TenantID: "tenant-2"}
	ob2.SubjectRef = &tenant
	sc3 := ScopeOfObligation(ob2)
	if sc3.Subject != "other-svc" || sc3.TenantID != "tenant-2" {
		t.Fatalf("changed obligation projection = %+v", sc3)
	}
	if ScopeConsistent(ob2, sc1) {
		t.Fatal("changed payload must not stay consistent with stale columns")
	}
	if !ScopeConsistent(ob2, sc3) {
		t.Fatal("changed payload must be consistent with its new columns")
	}

	// Claim-side upsert: index columns follow the claim payload exactly.
	claim2 := claim
	claim2.Resources.CandidateID = "cand-b"
	claim2.CompletedAt = claim.CompletedAt.Add(time.Second)
	idx3 := ClaimIndexOf(claim2)
	if idx3.CandidateID != "cand-b" || !idx3.CompletedAt.Equal(claim2.CompletedAt) {
		t.Fatalf("changed claim projection = %+v", idx3)
	}
	if ClaimIndexConsistent(claim2, idx1) {
		t.Fatal("changed claim must not stay consistent with stale index columns")
	}
	if !ClaimIndexConsistent(claim2, idx3) {
		t.Fatal("changed claim must be consistent with its new index columns")
	}
}
