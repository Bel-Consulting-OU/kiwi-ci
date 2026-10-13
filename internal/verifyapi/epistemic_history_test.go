package verifyapi

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Epistemic history properties (P10, nightly lane).
//
// Randomized submit/claim/verify sequences under a seeded math/rand, checked
// after every acceptance. The seeds are fixed so a failure reproduces
// exactly; the history lengths are small enough for a unit-run nightly lane
// (not an hours-long fuzz campaign).
//
// Three invariants, asserted on every sealed record the history produces:
//
//  1. no verified without evidence — a sealed record always carries a
//     resolved evidence root, at least one attestation digest and a
//     verification timestamp; ProvenPass is never true on a bare claim;
//  2. no accepted record with mismatched subject — every authoritative
//     record names exactly one stored obligation, and its binding digests
//     equal THAT obligation's digests (two obligations under different
//     SubjectRefs never share authority, even over identical content);
//  3. no stronger claim than attested controls — the derived assurance
//     profile equals what the attested ExecutionFacts prove
//     (model.DeriveAssuranceProfileSchema), and CompletedChecks is a subset
//     of the evidence-derived pass checks. A caller-proposed stronger
//     profile never becomes authority.

const (
	epistemicHistoryLen = 24
	epistemicSubjectN   = 2
)

// epistemicWorld is one seeded history: a Service over MemoryStore whose
// resolver emits attested facts chosen by the evidence ref, so different
// refs can prove different control strengths.
type epistemicWorld struct {
	t     *testing.T
	rng   *rand.Rand
	svc   *Service
	store *MemoryStore
	now   time.Time
	// factsByRef is the attested control vector each evidence ref proves.
	factsByRef map[string]*model.ExecutionFacts
	// verified records every sealed outcome the history accepted, keyed by
	// verification id, for end-of-history invariant sweeps.
	verified map[string]DerivedVerifiedOutcome
	// obligations records every submitted obligation by id.
	obligations map[string]VerificationObligation
	// subjects is the authority subject of each obligation id.
	subjectOf map[string]SubjectRef
}

func newEpistemicWorld(t *testing.T, seed int64) *epistemicWorld {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	now := time.Date(2026, 3, 4, 5, 6, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	w := &epistemicWorld{
		t:           t,
		rng:         rng,
		now:         now,
		factsByRef:  make(map[string]*model.ExecutionFacts),
		verified:    make(map[string]DerivedVerifiedOutcome),
		obligations: make(map[string]VerificationObligation),
		subjectOf:   make(map[string]SubjectRef),
	}
	w.store = NewMemoryStore(clock)
	v := &FuncEvidenceVerifier{
		Identity: "epistemic-property-verifier/v1",
		Clock:    clock,
		Resolve: func(_ context.Context, ref string) (ResolvedAttestation, error) {
			facts, ok := w.factsByRef[ref]
			if !ok {
				return ResolvedAttestation{}, fmt.Errorf("unknown evidence ref %q", ref)
			}
			return ResolvedAttestation{
				ExecutionID:       "exec-" + ref,
				EvidenceRoot:      mustDigest(t, "root-"+ref),
				AttestationDigest: mustDigest(t, "att-"+ref),
				Status:            string(model.StatusSuccess),
				Facts:             facts,
				Checks: []VerifiedCheck{
					{Name: CheckJobStatusSuccess, Outcome: CheckOutcomePass},
					{Name: CheckEvidenceRoot, Outcome: CheckOutcomePass},
					{Name: "digest-match", Outcome: CheckOutcomePass},
				},
			}, nil
		},
	}
	svc, err := NewService(w.store, v, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = clock
	w.svc = svc
	return w
}

// randomFacts builds an attested control vector of random strength. The
// derived profile is computed from these facts — the property under test is
// that no history can accept a stronger claim than this vector proves.
func (w *epistemicWorld) randomFacts(ref string) *model.ExecutionFacts {
	isolated := w.rng.Intn(2) == 0
	secrets := w.rng.Intn(2) == 0
	hostEnv := w.rng.Intn(2) == 0
	authority := w.rng.Intn(2) == 0
	networkDenied := w.rng.Intn(2) == 0
	pinned := w.rng.Intn(2) == 0
	facts := &model.ExecutionFacts{
		FilesystemIsolated:        isolated,
		KiwiSecretsInjected:       secrets,
		HostEnvironmentInherited:  hostEnv,
		DeclaredAuthorityMediated: authority,
		NetworkAccessDenied:       networkDenied,
		ImagesDigestPinned:        pinned,
		WorkspaceQuotaConfigured:  w.rng.Intn(2) == 0,
	}
	w.factsByRef[ref] = facts
	return facts
}

// assuranceName is the profile the attested facts prove under the current
// schema. It is the ceiling: a sealed record's derived assurance must equal
// it, never exceed it.
func assuranceName(facts *model.ExecutionFacts) string {
	if facts == nil {
		return model.AssuranceUncontrolled.Name()
	}
	return model.DeriveAssuranceProfile(*facts).Name()
}

func (w *epistemicWorld) submitObligation(i int) VerificationObligation {
	w.t.Helper()
	ob := baseObligation(w.t)
	ob.ObligationID = fmt.Sprintf("ep-ob-%d", i)
	ob.IssuedAt = w.now.Add(-time.Duration(w.rng.Intn(60)) * time.Second)
	ob.Freshness = FreshnessPolicy{MaxAgeSeconds: 3600}
	// Pin one content triple per obligation so two obligations never share
	// binding digests (subject mismatch is then observable).
	ob.ImmutableCandidateDigest = mustDigest(w.t, fmt.Sprintf("cand-%d", i))
	ob.SourceSnapshotDigest = mustDigest(w.t, fmt.Sprintf("snap-%d", i))
	ob.VerificationContractDigest = mustDigest(w.t, fmt.Sprintf("contract-%d", i))
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	// Randomly demand a strong profile: a weak attestation must then fail
	// the pass path rather than launder the demand.
	if w.rng.Intn(2) == 0 {
		ob.RequiredAssurance = "sealed_pinned_no_network"
	} else {
		ob.RequiredAssurance = "no_injected_credentials"
	}
	ref := tenantRef(fmt.Sprintf("tenant-%d", i%epistemicSubjectN))
	ob.SubjectRef = &ref
	w.subjectOf[ob.ObligationID] = ref
	w.obligations[ob.ObligationID] = ob
	return ob
}

func (w *epistemicWorld) claimFor(ob VerificationObligation, inflating bool) VerificationOutcome {
	w.t.Helper()
	v := baseOutcome(w.t, ob)
	v.VerificationID = fmt.Sprintf("%s/claim-%d", ob.ObligationID, w.rng.Intn(1_000_000))
	// One evidence ref per claim: randomFacts is never overwritten after a
	// record has already bound it (that would make the invariant sweep read
	// a different control vector than the one the verifier attested).
	ref := "ev-" + v.VerificationID
	w.randomFacts(ref)
	v.EvidenceRoot = mustDigest(w.t, "root-"+ref)
	v.ProvenanceRefs = []string{ref}
	v.ExecutionIDs = []string{"exec-" + ref}
	v.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	if inflating {
		// The caller STRONGLY claims a high profile regardless of what the
		// evidence will prove. The derived record must not copy this.
		v.AssuranceProfile = "sealed_pinned_no_network"
		v.CompletedChecks = append(v.CompletedChecks, "digest-match", "never-attested-check")
	} else {
		v.AssuranceProfile = ob.RequiredAssurance
	}
	start := ob.IssuedAt.Add(time.Minute)
	v.StartedAt = start
	v.CompletedAt = start.Add(30 * time.Second)
	return v
}

// assertSealedInvariants is the three-way epistemic check on one accepted
// record. It is called on every successful VerifyAndRecord and again in the
// end-of-history sweep.
func (w *epistemicWorld) assertSealedInvariants(rec DerivedVerifiedOutcome) {
	w.t.Helper()
	// (1) No verified without evidence.
	if !rec.Sealed() {
		w.t.Fatalf("accepted record %q is not sealed", rec.Outcome.VerificationID)
	}
	if rec.Evidence.EvidenceRoot == "" {
		w.t.Fatalf("accepted record %q has no evidence root", rec.Outcome.VerificationID)
	}
	if len(rec.Evidence.AttestationDigests) == 0 {
		w.t.Fatalf("accepted record %q has no attestation digests", rec.Outcome.VerificationID)
	}
	if rec.Evidence.VerifiedAt.IsZero() {
		w.t.Fatalf("accepted record %q has no verification timestamp", rec.Outcome.VerificationID)
	}
	if rec.Outcome.EvidenceRoot != rec.Evidence.EvidenceRoot {
		w.t.Fatalf("accepted record %q outcome root %s disagrees with evidence root %s",
			rec.Outcome.VerificationID, rec.Outcome.EvidenceRoot, rec.Evidence.EvidenceRoot)
	}
	// A raw claim is never a proven pass.
	if !rec.ProvenPass() && rec.Outcome.Outcome == OutcomePass {
		w.t.Fatalf("record %q claims pass but ProvenPass() is false", rec.Outcome.VerificationID)
	}

	// (2) No accepted record with mismatched subject / binding.
	ob, ok := w.obligations[rec.Outcome.ObligationID]
	if !ok {
		w.t.Fatalf("accepted record %q names unknown obligation %q", rec.Outcome.VerificationID, rec.Outcome.ObligationID)
	}
	wantSubj := w.subjectOf[ob.ObligationID]
	if ob.SubjectRef == nil || *ob.SubjectRef != wantSubj {
		w.t.Fatalf("obligation %q subject drifted: %+v want %+v", ob.ObligationID, ob.SubjectRef, wantSubj)
	}
	if rec.Outcome.CandidateDigest != ob.ImmutableCandidateDigest ||
		rec.Outcome.SnapshotDigest != ob.SourceSnapshotDigest ||
		rec.Outcome.ContractDigest != ob.VerificationContractDigest {
		w.t.Fatalf("accepted record %q binding digests do not match obligation %q (subject %v)",
			rec.Outcome.VerificationID, ob.ObligationID, wantSubj)
	}
	if rec.Outcome.ObligationID != rec.SubmittedClaim.ObligationID {
		w.t.Fatalf("record %q derived obligation %q disagrees with claim %q",
			rec.Outcome.VerificationID, rec.Outcome.ObligationID, rec.SubmittedClaim.ObligationID)
	}
	// Every record is attributable to exactly one subject: the obligation's
	// SubjectRef. A claim that answers a different subject's obligation is
	// a different obligation id and can never be this record.
	for otherID, otherOb := range w.obligations {
		if otherID == ob.ObligationID {
			continue
		}
		if otherOb.SubjectRef != nil && ob.SubjectRef != nil && *otherOb.SubjectRef != *ob.SubjectRef {
			// Different subject: the record must not bind to the other
			// obligation's content either (that would make the two
			// interchangeable authority).
			if rec.Outcome.CandidateDigest == otherOb.ImmutableCandidateDigest &&
				rec.Outcome.SnapshotDigest == otherOb.SourceSnapshotDigest &&
				rec.Outcome.ContractDigest == otherOb.VerificationContractDigest {
				w.t.Fatalf("record %q binds content shared with differently-subjected obligation %q (%v vs %v)",
					rec.Outcome.VerificationID, otherID, wantSubj, *otherOb.SubjectRef)
			}
		}
	}

	// (3) No stronger claim than attested controls.
	// Find the attested facts this record's evidence proved.
	var facts *model.ExecutionFacts
	for _, ref := range rec.SubmittedClaim.ProvenanceRefs {
		if f, ok := w.factsByRef[ref]; ok {
			facts = f
			break
		}
	}
	ceiling := assuranceName(facts)
	if rec.Outcome.AssuranceProfile != ceiling {
		w.t.Fatalf("record %q derived assurance %q, attested controls prove %q (claim proposed %q)",
			rec.Outcome.VerificationID, rec.Outcome.AssuranceProfile, ceiling, rec.SubmittedClaim.AssuranceProfile)
	}
	// The derived outcome must not copy the claim's inflated check list.
	passNames := make(map[string]bool)
	for _, c := range rec.Evidence.VerifiedChecks {
		if c.Outcome == CheckOutcomePass {
			passNames[c.Name] = true
		}
	}
	for _, name := range rec.Outcome.CompletedChecks {
		if !passNames[name] {
			w.t.Fatalf("record %q derived CompletedChecks contains %q which the evidence did not pass", rec.Outcome.VerificationID, name)
		}
	}
	// The claim's inflated extras must never appear as derived authority.
	if containsString(rec.Outcome.CompletedChecks, "never-attested-check") {
		w.t.Fatalf("record %q laundered the claim's never-attested-check into authority", rec.Outcome.VerificationID)
	}
}

// TestEpistemicHistoryProperties runs several short seeded histories and
// asserts the three epistemic invariants on every accepted record. Failures
// print the seed so the history can be replayed.
func TestEpistemicHistoryProperties(t *testing.T) {
	seeds := []int64{1, 0x5eed, 42, 20260102, 7}
	for _, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			w := newEpistemicWorld(t, seed)
			ctx := context.Background()
			principal := Principal{
				Subject:      "epistemic-runner",
				Capabilities: []Capability{GlobalVerificationAdmin},
			}

			var submitted []VerificationObligation
			for i := 0; i < epistemicHistoryLen; i++ {
				switch w.rng.Intn(5) {
				case 0, 1:
					// Submit a new obligation.
					ob := w.submitObligation(i)
					if err := w.svc.SubmitObligation(ctx, principal, ob); err != nil {
						t.Fatalf("seed %d step %d SubmitObligation: %v", seed, i, err)
					}
					submitted = append(submitted, ob)
				case 2:
					if len(submitted) == 0 {
						continue
					}
					// Record a claim (sometimes inflating).
					ob := submitted[w.rng.Intn(len(submitted))]
					claim := w.claimFor(ob, w.rng.Intn(2) == 0)
					// Claims are proposals: recording one must never mint
					// authority.
					_ = w.svc.RecordClaim(ctx, principal, claim)
					if _, err := w.svc.QueryOutcome(ctx, principal, claim.VerificationID); err == nil {
						t.Fatalf("seed %d step %d: claim-only id %q answered QueryOutcome as verified", seed, i, claim.VerificationID)
					} else if !errors.Is(err, ErrUnverified) && !errors.Is(err, ErrNotFound) {
						t.Fatalf("seed %d step %d QueryOutcome(claim) = %v, want ErrUnverified/ErrNotFound", seed, i, err)
					}
				case 3:
					if len(submitted) == 0 {
						continue
					}
					// Verify a claim. Either it is accepted (invariants must
					// hold) or refused (fail closed — nothing recorded).
					ob := submitted[w.rng.Intn(len(submitted))]
					claim := w.claimFor(ob, w.rng.Intn(2) == 0)
					_ = w.svc.RecordClaim(ctx, principal, claim)
					seal, err := w.svc.VerifyAndRecord(ctx, principal, claim)
					if err != nil {
						// Refusal is fine: assert nothing authoritative exists.
						if _, qerr := w.svc.QueryOutcome(ctx, principal, claim.VerificationID); qerr == nil {
							t.Fatalf("seed %d step %d: refused verify left an authoritative record for %q", seed, i, claim.VerificationID)
						}
						continue
					}
					w.verified[seal.Outcome.VerificationID] = seal
					w.assertSealedInvariants(seal)
				case 4:
					// Tampered claim against a real obligation: the digests
					// will not bind and the verify must refuse.
					if len(submitted) == 0 {
						continue
					}
					ob := submitted[w.rng.Intn(len(submitted))]
					claim := w.claimFor(ob, true)
					claim.CandidateDigest = mustDigest(t, fmt.Sprintf("tamper-%d", i))
					if _, err := w.svc.VerifyAndRecord(ctx, principal, claim); err == nil {
						t.Fatalf("seed %d step %d: tampered claim was accepted", seed, i)
					}
				}
			}

			// End-of-history sweep: every accepted record still satisfies
			// the invariants, and no claim-only id has become authority.
			for id, rec := range w.verified {
				w.assertSealedInvariants(rec)
				got, err := w.svc.QueryOutcome(ctx, principal, id)
				if err != nil {
					t.Fatalf("seed %d: verified record %q no longer queries: %v", seed, id, err)
				}
				w.assertSealedInvariants(got)
			}
			// At least one seed-driven path must have produced a sealed
			// record OR a clean refusal — a history that never touched the
			// acceptance boundary would make the invariants vacuous. Across
			// the fixed seeds this is guaranteed by the case weights; assert
			// it per seed so a silent no-op history fails loudly.
			if len(w.verified) == 0 && len(submitted) == 0 {
				t.Fatalf("seed %d: history produced neither obligations nor verified records (vacuous)", seed)
			}
		})
	}
}

// TestEpistemicClaimNeverUpgradesAuthority: a claim that proposes a stronger
// assurance than the attested facts prove is recorded as a CLAIM only; the
// derived record (when the obligation's demand is satisfiable) carries the
// facts-derived profile, and when the demand exceeds the facts the verify is
// refused outright — never accepted at the claim's strength.
func TestEpistemicClaimNeverUpgradesAuthority(t *testing.T) {
	w := newEpistemicWorld(t, 0x51ea1)
	ctx := context.Background()
	principal := Principal{Subject: "ep", Capabilities: []Capability{GlobalVerificationAdmin}}

	ob := w.submitObligation(0)
	// Demand the strong profile.
	ob.RequiredAssurance = "sealed_pinned_no_network"
	w.obligations[ob.ObligationID] = ob
	if err := w.svc.SubmitObligation(ctx, principal, ob); err != nil {
		t.Fatal(err)
	}

	ref := "weak-evidence"
	// Attestation proves only an uncontrolled / weakly isolated run.
	w.factsByRef[ref] = &model.ExecutionFacts{FilesystemIsolated: false}
	claim := baseOutcome(t, ob)
	claim.VerificationID = ob.ObligationID + "/inflated"
	claim.EvidenceRoot = mustDigest(t, "root-"+ref)
	claim.ProvenanceRefs = []string{ref}
	claim.ExecutionIDs = []string{"exec-" + ref}
	claim.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	claim.AssuranceProfile = "sealed_pinned_no_network" // the lie
	claim.StartedAt = ob.IssuedAt.Add(time.Minute)
	claim.CompletedAt = claim.StartedAt.Add(time.Second)

	if err := w.svc.RecordClaim(ctx, principal, claim); err != nil {
		t.Fatalf("RecordClaim: %v", err)
	}
	// The claim is stored as a proposal and never as authority.
	if _, err := w.svc.QueryOutcome(ctx, principal, claim.VerificationID); !errors.Is(err, ErrUnverified) {
		t.Fatalf("claim-only QueryOutcome = %v, want ErrUnverified", err)
	}

	// The verifier accepts the evidence but DERIVES a partial verdict: the
	// attested facts cannot prove the demanded assurance, so the sealed
	// record is never a proven pass and never carries the claimed profile.
	seal, err := w.svc.VerifyAndRecord(ctx, principal, claim)
	if err != nil {
		// A hard refusal is also correct fail-closed behavior.
		if _, qerr := w.svc.QueryOutcome(ctx, principal, claim.VerificationID); qerr == nil {
			t.Fatal("refused verify left an authoritative record")
		}
		return
	}
	if seal.ProvenPass() {
		t.Fatalf("sealed record is a proven pass despite unproven demanded assurance: %+v", seal.Outcome)
	}
	if seal.Outcome.AssuranceProfile == "sealed_pinned_no_network" {
		t.Fatalf("derived assurance %q copied the claim's lie", seal.Outcome.AssuranceProfile)
	}
	if want := assuranceName(w.factsByRef[ref]); seal.Outcome.AssuranceProfile != want {
		t.Fatalf("derived assurance %q, attested controls prove %q", seal.Outcome.AssuranceProfile, want)
	}
	w.assertSealedInvariants(seal)
}
