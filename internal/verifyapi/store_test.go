package verifyapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestMemoryStoreSatisfiesVerificationStore is the compile-time + runtime
// proof that MemoryStore implements the durable contract.
func TestMemoryStoreSatisfiesVerificationStore(t *testing.T) {
	var _ VerificationStore = NewMemoryStore(nil)
}

// TestMemoryStoreSubmitObligationIdempotent proves ObligationID is the
// submit idempotency key: an identical resubmit is a no-op success, and a
// conflicting resubmit under the same key is refused.
func TestMemoryStoreSubmitObligationIdempotent(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore(nil)
	ob := baseObligation(t)

	if err := st.SubmitObligation(ctx, ob); err != nil {
		t.Fatalf("first SubmitObligation = %v", err)
	}
	if err := st.SubmitObligation(ctx, ob); err != nil {
		t.Fatalf("idempotent resubmit = %v, want nil", err)
	}

	conflict := ob
	conflict.Subject = "other-subject"
	if err := st.SubmitObligation(ctx, conflict); !errors.Is(err, ErrExists) {
		t.Fatalf("conflicting resubmit = %v, want ErrExists", err)
	}

	got, err := st.GetObligation(ctx, ob.ObligationID)
	if err != nil {
		t.Fatalf("GetObligation = %v", err)
	}
	if got.Subject != ob.Subject {
		t.Fatalf("stored subject = %q, want %q", got.Subject, ob.Subject)
	}
}

// TestMemoryStoreClaimIsNotProvenPass: RecordOutcome keeps the claim, and
// QueryOutcome never returns it as a proven pass.
func TestMemoryStoreClaimIsNotProvenPass(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore(func() time.Time { return time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC) })
	ob := baseObligation(t)
	if err := st.SubmitObligation(ctx, ob); err != nil {
		t.Fatal(err)
	}
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "fake-evidence")
	if err := st.RecordOutcome(ctx, v); err != nil {
		t.Fatalf("RecordOutcome = %v", err)
	}
	// Idempotent retry of the same claim.
	if err := st.RecordOutcome(ctx, v); err != nil {
		t.Fatalf("idempotent RecordOutcome = %v, want nil", err)
	}
	if _, err := st.QueryOutcome(ctx, v.VerificationID); !errors.Is(err, ErrUnverified) {
		t.Fatalf("QueryOutcome claim = %v, want ErrUnverified", err)
	}
	got, err := st.GetOutcome(ctx, v.VerificationID)
	if err != nil {
		t.Fatalf("GetOutcome = %v", err)
	}
	if got.Outcome != OutcomePass {
		t.Fatalf("claim kept with outcome %v", got.Outcome)
	}
}

// TestMemoryStoreVerifiedOutcomeIsAuthoritative: the verifier-produced record
// discharges the obligation and survives an idempotent retry.
func TestMemoryStoreVerifiedOutcomeIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	fx := newSignedAttestationFixture(t)
	ob := provenanceFixtureObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	st := NewMemoryStore(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := st.SubmitObligation(ctx, ob); err != nil {
		t.Fatal(err)
	}

	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}

	vo, err := fixtureVerifier(fx, "attestation-1").Verify(ctx, ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if err := st.RecordVerifiedOutcome(ctx, vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	if err := st.RecordVerifiedOutcome(ctx, vo); err != nil {
		t.Fatalf("idempotent RecordVerifiedOutcome = %v, want nil", err)
	}

	got, err := st.QueryOutcome(ctx, v.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome = %v", err)
	}
	if !got.ProvenPass() {
		t.Fatal("want proven pass from store")
	}
	list, err := st.OutcomesForObligation(ctx, ob.ObligationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("OutcomesForObligation = %d rows, want 1", len(list))
	}
}

// TestMemoryStoreCompareGroup exercises the group half of the store contract.
func TestMemoryStoreCompareGroup(t *testing.T) {
	ctx := context.Background()
	base := mustDigest(t, "snapshot")
	candA, candB := mustDigest(t, "cand-a"), mustDigest(t, "cand-b")
	g := SpeculativeGroup{
		VerificationGroupID: "grp-1",
		BaseSnapshotDigest:  base,
		CandidateDigests:    map[string]Digest{"a": candA, "b": candB},
	}
	st := NewMemoryStore(nil)
	if err := st.RegisterGroup(ctx, g); err != nil {
		t.Fatalf("RegisterGroup = %v", err)
	}
	if err := st.RegisterGroup(ctx, g); err != nil {
		t.Fatalf("idempotent RegisterGroup = %v, want nil", err)
	}
	cmp, err := st.CompareGroup(ctx, g.VerificationGroupID)
	if err != nil {
		t.Fatalf("CompareGroup = %v", err)
	}
	if len(cmp.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(cmp.Candidates))
	}
	if _, err := st.CompareGroup(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CompareGroup unknown = %v, want ErrNotFound", err)
	}
}

// TestMemoryStoreHonorsCancelledContext: durable methods observe cancellation
// even in the in-memory reference implementation.
func TestMemoryStoreHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := NewMemoryStore(nil)
	if err := st.SubmitObligation(ctx, baseObligation(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("SubmitObligation cancelled = %v, want context.Canceled", err)
	}
	if _, err := st.GetObligation(ctx, "ob-1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetObligation cancelled = %v, want context.Canceled", err)
	}
}
