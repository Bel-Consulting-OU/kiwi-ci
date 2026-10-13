package verifyapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Model A: the submitted claim's ExecutionIDs and the derived evidence's
// ExecutionIDs stay DISTINCT forever. These adversarial tests pin that
// evidence-derived id upgrades are never claim conflicts, while a claimed id
// the attestations do not bind is kept only as a proposal (SubmittedClaim)
// and never becomes authority.

// claimEvidenceVerifier returns a FuncEvidenceVerifier whose resolver maps
// each ref to one execution id under a shared evidence root. The attestations
// bind the obligation's required checks explicitly (structured signed check
// results) and report a successful job status, so a covered obligation can
// derive a pass.
func claimEvidenceVerifier(t *testing.T, root Digest, refToExec map[string]string) *FuncEvidenceVerifier {
	t.Helper()
	return &FuncEvidenceVerifier{
		Identity: "claim-vs-evidence-verifier/v1",
		Resolve: func(_ context.Context, ref string) (ResolvedAttestation, error) {
			exec, ok := refToExec[ref]
			if !ok {
				return ResolvedAttestation{}, errors.New("unknown evidence ref")
			}
			return ResolvedAttestation{
				ExecutionID:       exec,
				EvidenceRoot:      root,
				AttestationDigest: mustDigest(t, "att-"+ref),
				Status:            "success",
				Attested:          trustedWindow(),
				Checks:            passChecks(exec, "digest-match", "signature"),
			}, nil
		},
	}
}

// runClaimUpgrade submits the claim, verifies it and records the verified
// outcome. It returns the verify error (nil on success) and the store.
func runClaimUpgrade(t *testing.T, ob VerificationObligation, claim VerificationOutcome, verifier *FuncEvidenceVerifier) (*MemoryStore, error) {
	t.Helper()
	st := NewMemoryStore(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := st.SubmitObligation(context.Background(), ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}
	if err := st.RecordOutcome(context.Background(), claim); err != nil {
		t.Fatalf("RecordOutcome claim = %v", err)
	}
	vo, err := verifier.Verify(context.Background(), ob, claim)
	if err != nil {
		return st, err
	}
	if err := st.RecordVerifiedOutcome(context.Background(), vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	// Idempotent replay of the verified record must never fork or fail.
	if err := st.RecordVerifiedOutcome(context.Background(), vo); err != nil {
		t.Fatalf("idempotent RecordVerifiedOutcome = %v", err)
	}
	return st, nil
}

// sealRaw builds a sealed record whose SubmittedClaim is the given claim and
// whose derived evidence binds the given execution ids under root. It is the
// test factory for sealed shapes a caller cannot post (the acceptance
// boundary is the only seal source). When the claim already cites evidence
// references they are preserved; otherwise one ref per execution is invented.
func sealRaw(t *testing.T, ob VerificationObligation, claim VerificationOutcome, root Digest, execIDs []string) DerivedVerifiedOutcome {
	t.Helper()
	refs := claim.ProvenanceRefs
	if len(refs) != len(execIDs) {
		refs = make([]string, len(execIDs))
		for i, id := range execIDs {
			refs[i] = "att-" + id
		}
	}
	refToExec := make(map[string]string, len(refs))
	for i, ref := range refs {
		refToExec[ref] = execIDs[i]
	}
	claim.ProvenanceRefs = refs
	claim.EvidenceRoot = root
	f := claimEvidenceVerifier(t, root, refToExec)
	vo, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("sealRaw Verify = %v", err)
	}
	return vo
}

// TestModelAClaimEvidenceIDUpgradesAreNotConflicts is the adversarial matrix:
// empty→one exec, subset→full, duplicates, reordered, same evidence twice
// all upgrade cleanly and keep the submitted claim as-is; an unknown exec in
// the claim is a proposal only and never becomes authority.
func TestModelAClaimEvidenceIDUpgradesAreNotConflicts(t *testing.T) {
	root := mustDigest(t, "model-a-root")

	t.Run("empty→one exec", func(t *testing.T) {
		ob := baseObligation(t)
		claim := baseOutcome(t, ob)
		claim.EvidenceRoot = root
		claim.ProvenanceRefs = []string{"att-1"}
		claim.ExecutionIDs = nil // raw claim names no executions

		st, err := runClaimUpgrade(t, ob, claim, claimEvidenceVerifier(t, root, map[string]string{"att-1": "exec-1"}))
		if err != nil {
			t.Fatalf("upgrade with empty claim exec ids = %v, want success", err)
		}
		assertClaimAndEvidenceIDs(t, st, claim.VerificationID, nil, []string{"exec-1"})
	})

	t.Run("subset→full", func(t *testing.T) {
		ob := baseObligation(t)
		claim := baseOutcome(t, ob)
		claim.EvidenceRoot = root
		claim.ProvenanceRefs = []string{"att-1", "att-2"}
		claim.ExecutionIDs = []string{"exec-1"} // subset of the resolved set

		st, err := runClaimUpgrade(t, ob, claim, claimEvidenceVerifier(t, root, map[string]string{
			"att-1": "exec-1",
			"att-2": "exec-2",
		}))
		if err != nil {
			t.Fatalf("upgrade with subset claim exec ids = %v, want success", err)
		}
		assertClaimAndEvidenceIDs(t, st, claim.VerificationID, []string{"exec-1"}, []string{"exec-1", "exec-2"})
	})

	t.Run("duplicates", func(t *testing.T) {
		ob := baseObligation(t)
		claim := baseOutcome(t, ob)
		claim.EvidenceRoot = root
		claim.ProvenanceRefs = []string{"att-1"}
		claim.ExecutionIDs = []string{"exec-1", "exec-1"}

		st, err := runClaimUpgrade(t, ob, claim, claimEvidenceVerifier(t, root, map[string]string{"att-1": "exec-1"}))
		if err != nil {
			t.Fatalf("upgrade with duplicate claim exec ids = %v, want success", err)
		}
		assertClaimAndEvidenceIDs(t, st, claim.VerificationID, []string{"exec-1", "exec-1"}, []string{"exec-1"})
	})

	t.Run("reordered", func(t *testing.T) {
		ob := baseObligation(t)
		claim := baseOutcome(t, ob)
		claim.EvidenceRoot = root
		claim.ProvenanceRefs = []string{"att-1", "att-2"}
		claim.ExecutionIDs = []string{"exec-2", "exec-1"} // order differs from resolution

		st, err := runClaimUpgrade(t, ob, claim, claimEvidenceVerifier(t, root, map[string]string{
			"att-1": "exec-1",
			"att-2": "exec-2",
		}))
		if err != nil {
			t.Fatalf("upgrade with reordered claim exec ids = %v, want success", err)
		}
		assertClaimAndEvidenceIDs(t, st, claim.VerificationID, []string{"exec-2", "exec-1"}, []string{"exec-1", "exec-2"})
	})

	t.Run("unknown exec stays a proposal", func(t *testing.T) {
		ob := baseObligation(t)
		claim := baseOutcome(t, ob)
		claim.EvidenceRoot = root
		claim.ProvenanceRefs = []string{"att-1"}
		claim.ExecutionIDs = []string{"exec-1", "forged-exec"}

		st, err := runClaimUpgrade(t, ob, claim, claimEvidenceVerifier(t, root, map[string]string{"att-1": "exec-1"}))
		if err != nil {
			t.Fatalf("upgrade with unknown claimed exec id = %v, want success (Model A keeps the proposal)", err)
		}
		// The forged id survives only on the proposal side; the derived
		// authority carries only what the attestations bind.
		assertClaimAndEvidenceIDs(t, st, claim.VerificationID, []string{"exec-1", "forged-exec"}, []string{"exec-1"})
		vo, qerr := st.QueryOutcome(context.Background(), claim.VerificationID)
		if qerr != nil {
			t.Fatalf("QueryOutcome = %v", qerr)
		}
		if !vo.ProvenPass() {
			t.Fatal("want proven pass on the derived record")
		}
	})

	t.Run("same evidence twice", func(t *testing.T) {
		ob := baseObligation(t)
		claim := baseOutcome(t, ob)
		claim.EvidenceRoot = root
		claim.ProvenanceRefs = []string{"att-1", "att-1"}
		claim.ExecutionIDs = []string{"exec-1"}

		// P1f: two references to the same signed statement are one piece of
		// evidence, never two — duplicate attestation digests are refused
		// during verification rather than counted twice.
		_, err := runClaimUpgrade(t, ob, claim, claimEvidenceVerifier(t, root, map[string]string{"att-1": "exec-1"}))
		if err == nil {
			t.Fatal("duplicate attestation digest must be refused during verification")
		}
	})
}

// TestModelAVerifiedRecordWithDerivedClaimIDsStillUpgrades covers the
// robustness half: even when a sealed record's SubmittedClaim carries the
// evidence-derived id set (a subset→full upgrade), the stored raw claim is
// not a claim conflict and idempotency does not fail.
func TestModelAVerifiedRecordWithDerivedClaimIDsStillUpgrades(t *testing.T) {
	ob := baseObligation(t)
	root := mustDigest(t, "model-a-derived-root")
	st := NewMemoryStore(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := st.SubmitObligation(context.Background(), ob); err != nil {
		t.Fatal(err)
	}

	claim := baseOutcome(t, ob)
	claim.EvidenceRoot = root
	// Use the same evidence refs sealRaw will generate ("att-<exec-id>") so
	// the submitted-claim identity matches after the derived upgrade.
	claim.ProvenanceRefs = []string{"att-exec-1", "att-exec-2"}
	claim.ExecutionIDs = []string{"exec-1"} // raw claim: subset
	if err := st.RecordOutcome(context.Background(), claim); err != nil {
		t.Fatalf("RecordOutcome = %v", err)
	}

	// A sealed record whose claim side already carries the evidence-derived
	// id set (the pre-Model-A shape): execution ids supersede the raw claim
	// list, evidence carries the full set.
	upgraded := claim
	upgraded.ExecutionIDs = []string{"exec-1", "exec-2"}
	vo := sealRaw(t, ob, upgraded, root, []string{"exec-1", "exec-2"})
	if err := st.RecordVerifiedOutcome(context.Background(), vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome with derived claim ids = %v, want success (not a claim conflict)", err)
	}
	if err := st.RecordVerifiedOutcome(context.Background(), vo); err != nil {
		t.Fatalf("idempotent RecordVerifiedOutcome = %v", err)
	}

	// The verified record must be authoritative and the evidence set intact.
	got, err := st.QueryOutcome(context.Background(), claim.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome = %v", err)
	}
	if !got.ProvenPass() {
		t.Fatal("want proven pass")
	}
	if len(got.Evidence().ExecutionIDs) != 2 {
		t.Fatalf("evidence exec ids = %v, want both", got.Evidence().ExecutionIDs)
	}
}

// TestModelADisjointExecIDsRemainAClaimConflict: two submissions whose exec
// id sets merely overlap or are disjoint are different claims — the subset
// tolerance never launders a mismatched pair.
func TestModelADisjointExecIDsRemainAClaimConflict(t *testing.T) {
	ob := baseObligation(t)
	root := mustDigest(t, "model-a-disjoint-root")
	st := NewMemoryStore(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := st.SubmitObligation(context.Background(), ob); err != nil {
		t.Fatal(err)
	}

	claim := baseOutcome(t, ob)
	claim.EvidenceRoot = root
	claim.ProvenanceRefs = []string{"att-1"}
	claim.ExecutionIDs = []string{"exec-1", "exec-other"}
	if err := st.RecordOutcome(context.Background(), claim); err != nil {
		t.Fatalf("RecordOutcome = %v", err)
	}

	// A sealed record whose ids only partially overlap the stored claim.
	partial := claim
	partial.ExecutionIDs = []string{"exec-1", "exec-2"}
	vo := sealRaw(t, ob, partial, root, []string{"exec-1", "exec-2"})
	if err := st.RecordVerifiedOutcome(context.Background(), vo); !errors.Is(err, ErrExists) {
		t.Fatalf("RecordVerifiedOutcome with partially-overlapping ids = %v, want ErrExists", err)
	}

	// Disjoint sets are also a conflict.
	disjoint := claim
	disjoint.ExecutionIDs = []string{"exec-z"}
	vo2 := sealRaw(t, ob, disjoint, root, []string{"exec-z"})
	if err := st.RecordVerifiedOutcome(context.Background(), vo2); !errors.Is(err, ErrExists) {
		t.Fatalf("RecordVerifiedOutcome with disjoint ids = %v, want ErrExists", err)
	}
}

// assertClaimAndEvidenceIDs pins Model A: the stored claim keeps the
// submitted ExecutionIDs as-is, SubmittedClaim preserves the proposal, and
// the DERIVED authoritative outcome plus the evidence carry the resolved set.
func assertClaimAndEvidenceIDs(t *testing.T, st *MemoryStore, id string, wantClaim, wantEvidence []string) {
	t.Helper()
	claim, err := st.GetOutcome(context.Background(), id)
	if err != nil {
		t.Fatalf("GetOutcome = %v", err)
	}
	if !equalStringSlices(claim.ExecutionIDs, wantClaim) {
		t.Fatalf("stored claim exec ids = %v, want %v (claim stored as-is)", claim.ExecutionIDs, wantClaim)
	}
	vo, err := st.QueryOutcome(context.Background(), id)
	if err != nil {
		t.Fatalf("QueryOutcome = %v", err)
	}
	if !equalStringSlices(vo.SubmittedClaim().ExecutionIDs, wantClaim) {
		t.Fatalf("submitted claim exec ids = %v, want %v (proposal preserved)", vo.SubmittedClaim().ExecutionIDs, wantClaim)
	}
	if !equalStringSlices(vo.Evidence().ExecutionIDs, wantEvidence) {
		t.Fatalf("evidence exec ids = %v, want %v", vo.Evidence().ExecutionIDs, wantEvidence)
	}
	if !equalStringSlices(vo.Outcome().ExecutionIDs, wantEvidence) {
		t.Fatalf("derived outcome exec ids = %v, want %v (derived is authority)", vo.Outcome().ExecutionIDs, wantEvidence)
	}
}
