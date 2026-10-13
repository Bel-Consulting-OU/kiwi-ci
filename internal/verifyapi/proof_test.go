package verifyapi

import (
	"errors"
	"testing"
	"time"
)

func testProof(t *testing.T) ProofSummary {
	t.Helper()
	return ProofSummary{
		ProofID:            "proof-1",
		VerificationID:     "ver-1",
		ObligationID:       "ob-1",
		RecipeDigest:       mustDigest(t, "recipe"),
		CandidateDigest:    mustDigest(t, "candidate"),
		SnapshotDigest:     mustDigest(t, "snapshot"),
		ContractDigest:     mustDigest(t, "contract"),
		EvidenceRoot:       mustDigest(t, "evidence"),
		Terminal:           TerminalPassed,
		Assurance:          "uncontrolled",
		AttestationDigests: []Digest{mustDigest(t, "att")},
		AcceptanceKeyID:    "acc-1",
		CompletedAt:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestProofValidityIsHistorical(t *testing.T) {
	p := testProof(t)
	if err := p.Valid(); err != nil {
		t.Fatalf("Valid = %v", err)
	}
	if !p.ProvenPass() {
		t.Fatal("TerminalPassed must be a proven pass")
	}
	// The same proof object is valid regardless of any policy context: a
	// historical statement does not re-evaluate.
	for name, mut := range map[string]func(*ProofSummary){
		"no proof id":     func(c *ProofSummary) { c.ProofID = "" },
		"no verification": func(c *ProofSummary) { c.VerificationID = "" },
		"bad candidate":   func(c *ProofSummary) { c.CandidateDigest = "nope" },
		"bad terminal":    func(c *ProofSummary) { c.Terminal = "nope" },
		"no assurance":    func(c *ProofSummary) { c.Assurance = "" },
		"no key":          func(c *ProofSummary) { c.AcceptanceKeyID = "" },
		"no completed":    func(c *ProofSummary) { c.CompletedAt = time.Time{} },
		"bad recipe":      func(c *ProofSummary) { c.RecipeDigest = "nope" },
		"bad att":         func(c *ProofSummary) { c.AttestationDigests = []Digest{"nope"} },
	} {
		bad := p
		mut(&bad)
		if err := bad.Valid(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: Valid = %v, want ErrInvalid", name, err)
		}
	}
	failed := p
	failed.Terminal = TerminalFailed
	if failed.ProvenPass() {
		t.Fatal("failed proof must not be a proven pass")
	}
}

func TestEvaluatePolicyIsCurrentAcceptability(t *testing.T) {
	p := testProof(t)
	now := p.CompletedAt.Add(time.Hour)
	live := PolicyContext{Now: now}

	// A valid, passed proof is acceptable under a live world.
	ev, err := EvaluatePolicy(testVerifiedProof(t, p), live)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Acceptable || len(ev.Denials) != 0 {
		t.Fatalf("live evaluation = %+v, want acceptable", ev)
	}

	// Withdrawn recipe: the proof stays historically valid but is no
	// longer acceptable. The proof object itself is unchanged.
	withdrawn := PolicyContext{
		Now:              now,
		WithdrawnRecipes: map[Digest]bool{p.RecipeDigest: true},
	}
	ev2, err := EvaluatePolicy(testVerifiedProof(t, p), withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	if ev2.Acceptable {
		t.Fatal("withdrawn recipe must make the proof unacceptable")
	}
	if len(ev2.Denials) != 1 || ev2.Denials[0].Reason != DenialRecipeWithdrawn {
		t.Fatalf("denials = %+v", ev2.Denials)
	}
	if p.Terminal != TerminalPassed || p.Valid() != nil {
		t.Fatal("policy evaluation must not mutate the proof")
	}

	// Compromised acceptance key.
	compromised := PolicyContext{
		Now:             now,
		CompromisedKeys: map[string]bool{p.AcceptanceKeyID: true},
	}
	ev3, err := EvaluatePolicy(testVerifiedProof(t, p), compromised)
	if err != nil {
		t.Fatal(err)
	}
	if ev3.Acceptable || ev3.Denials[0].Reason != DenialKeyCompromised {
		t.Fatalf("compromised key evaluation = %+v", ev3)
	}

	// Revoked attestation.
	revoked := PolicyContext{
		Now:                 now,
		RevokedAttestations: map[Digest]bool{p.AttestationDigests[0]: true},
	}
	ev4, err := EvaluatePolicy(testVerifiedProof(t, p), revoked)
	if err != nil {
		t.Fatal(err)
	}
	if ev4.Acceptable || ev4.Denials[0].Reason != DenialAttestationRevoked {
		t.Fatalf("revoked attestation evaluation = %+v", ev4)
	}

	// Freshness floor.
	stale := PolicyContext{Now: now, MaxAgeSeconds: 60}
	ev5, err := EvaluatePolicy(testVerifiedProof(t, p), stale)
	if err != nil {
		t.Fatal(err)
	}
	if ev5.Acceptable || ev5.Denials[0].Reason != DenialExpired {
		t.Fatalf("stale evaluation = %+v", ev5)
	}

	// A proof that never passed is never acceptable as a pass.
	notPassed := p
	notPassed.Terminal = TerminalFailed
	ev6, err := EvaluatePolicy(testVerifiedProof(t, notPassed), live)
	if err != nil {
		t.Fatal(err)
	}
	if ev6.Acceptable || ev6.Denials[0].Reason != DenialNeverPassed {
		t.Fatalf("failed proof evaluation = %+v", ev6)
	}

	// Several denials fire together; the list is complete.
	everything := PolicyContext{
		Now:                 now,
		WithdrawnRecipes:    map[Digest]bool{p.RecipeDigest: true},
		CompromisedKeys:     map[string]bool{p.AcceptanceKeyID: true},
		RevokedAttestations: map[Digest]bool{p.AttestationDigests[0]: true},
		MaxAgeSeconds:       1,
	}
	ev7, err := EvaluatePolicy(testVerifiedProof(t, p), everything)
	if err != nil {
		t.Fatal(err)
	}
	if ev7.Acceptable || len(ev7.Denials) != 4 {
		t.Fatalf("combined evaluation = %+v, want 4 denials", ev7)
	}
}

func TestEvaluatePolicyTimeAndInvalid(t *testing.T) {
	p := testProof(t)
	// Zero Now falls back to the wall clock and still evaluates.
	ev, err := EvaluatePolicy(testVerifiedProof(t, p), PolicyContext{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.EvaluatedAt.IsZero() {
		t.Fatal("EvaluatedAt must be stamped")
	}
	// An invalid summary is refused at mint time: sealVerifiedProof is the
	// only constructor and it never mints an unvalidatable proof, so
	// EvaluatePolicy can only ever see a sealed, structurally sound one.
	bad := p
	bad.ProofID = ""
	if _, err := sealVerifiedProof(bad, VerificationProof{}, DerivedVerifiedOutcome{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid summary mint = %v, want ErrInvalid", err)
	}
	// Unknown terminal state is invalid at mint time too.
	bad2 := p
	bad2.Terminal = "weird"
	if _, err := sealVerifiedProof(bad2, VerificationProof{}, DerivedVerifiedOutcome{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown terminal mint = %v, want ErrInvalid", err)
	}
	// An unsealed VerifiedProof is refused by EvaluatePolicy.
	if _, err := EvaluatePolicy(VerifiedProof{}, PolicyContext{}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("unsealed proof = %v, want ErrUnverified", err)
	}
}

// testVerifiedProof mints a sealed VerifiedProof from a summary for policy
// evaluation tests (same package may call sealVerifiedProof).
func testVerifiedProof(t *testing.T, summary ProofSummary) VerifiedProof {
	t.Helper()
	iv := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	id := VerificationOutcome{
		VerificationID:   summary.VerificationID,
		ObligationID:     summary.ObligationID,
		CandidateDigest:  summary.CandidateDigest,
		SnapshotDigest:   summary.SnapshotDigest,
		ContractDigest:   summary.ContractDigest,
		Outcome:          OutcomePass,
		AssuranceProfile: summary.Assurance,
		CompletedChecks:  []string{"digest-match"},
		ExecutionIDs:     []string{"exec-1"},
		EvidenceRoot:     summary.EvidenceRoot,
		Resources:        ResourceFacts{RunnerClass: "standard"},
		StartedAt:        iv,
		CompletedAt:      iv.Add(time.Second),
	}
	ev := VerifiedEvidence{
		ExecutionIDs:       []string{"exec-1"},
		EvidenceRoot:       summary.EvidenceRoot,
		AttestationDigests: summary.AttestationDigests,
		JobStatus:          "success",
		CompletedChecks:    []string{"digest-match"},
		VerifierIdentity:   "proof-test-verifier/v1",
		VerifiedAt:         iv,
	}
	out, err := sealDerivedOutcome(id, id, ev)
	if err != nil {
		t.Fatalf("sealDerivedOutcome = %v", err)
	}
	doc := VerificationProof{
		Obligation: VerificationObligation{
			ObligationID:               summary.ObligationID,
			Subject:                    "s",
			ImmutableCandidateDigest:   summary.CandidateDigest,
			SourceSnapshotDigest:       summary.SnapshotDigest,
			VerificationContractDigest: summary.ContractDigest,
			RequiredChecks:             []string{"digest-match"},
			RequiredAssurance:          summary.Assurance,
			IssuedAt:                   iv,
		},
		SubmittedClaim: id,
		Outcome:        id,
		Evidence:       ev,
		Acceptance: AcceptanceRecord{
			AcceptanceVersion: AcceptanceVersionCurrent,
			Algorithm:         AcceptanceAlgorithmHMACSHA256,
			VerifiedAt:        iv,
			KeyID:             summary.AcceptanceKeyID,
		},
	}
	vp, err := sealVerifiedProof(summary, doc, out)
	if err != nil {
		t.Fatalf("sealVerifiedProof = %v", err)
	}
	return vp
}
