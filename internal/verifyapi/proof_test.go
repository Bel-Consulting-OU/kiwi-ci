package verifyapi

import (
	"errors"
	"testing"
	"time"
)

func testProof(t *testing.T) Proof {
	t.Helper()
	return Proof{
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
	for name, mut := range map[string]func(*Proof){
		"no proof id":     func(c *Proof) { c.ProofID = "" },
		"no verification": func(c *Proof) { c.VerificationID = "" },
		"bad candidate":   func(c *Proof) { c.CandidateDigest = "nope" },
		"bad terminal":    func(c *Proof) { c.Terminal = "nope" },
		"no assurance":    func(c *Proof) { c.Assurance = "" },
		"no key":          func(c *Proof) { c.AcceptanceKeyID = "" },
		"no completed":    func(c *Proof) { c.CompletedAt = time.Time{} },
		"bad recipe":      func(c *Proof) { c.RecipeDigest = "nope" },
		"bad att":         func(c *Proof) { c.AttestationDigests = []Digest{"nope"} },
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
	ev, err := EvaluatePolicy(p, live)
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
	ev2, err := EvaluatePolicy(p, withdrawn)
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
	ev3, err := EvaluatePolicy(p, compromised)
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
	ev4, err := EvaluatePolicy(p, revoked)
	if err != nil {
		t.Fatal(err)
	}
	if ev4.Acceptable || ev4.Denials[0].Reason != DenialAttestationRevoked {
		t.Fatalf("revoked attestation evaluation = %+v", ev4)
	}

	// Freshness floor.
	stale := PolicyContext{Now: now, MaxAgeSeconds: 60}
	ev5, err := EvaluatePolicy(p, stale)
	if err != nil {
		t.Fatal(err)
	}
	if ev5.Acceptable || ev5.Denials[0].Reason != DenialExpired {
		t.Fatalf("stale evaluation = %+v", ev5)
	}

	// A proof that never passed is never acceptable as a pass.
	notPassed := p
	notPassed.Terminal = TerminalFailed
	ev6, err := EvaluatePolicy(notPassed, live)
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
	ev7, err := EvaluatePolicy(p, everything)
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
	ev, err := EvaluatePolicy(p, PolicyContext{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.EvaluatedAt.IsZero() {
		t.Fatal("EvaluatedAt must be stamped")
	}
	// An invalid proof is refused, never evaluated.
	bad := p
	bad.ProofID = ""
	if _, err := EvaluatePolicy(bad, PolicyContext{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid proof = %v, want ErrInvalid", err)
	}
	// Unknown terminal state is invalid.
	bad2 := p
	bad2.Terminal = "weird"
	if _, err := EvaluatePolicy(bad2, PolicyContext{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown terminal = %v, want ErrInvalid", err)
	}
}
