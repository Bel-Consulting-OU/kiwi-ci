package verifyapi

import (
	"fmt"
	"time"
)

// Proof is the immutable, machine-verifiable historical statement of one
// verification: identity, the digests it was bound to, the terminal state,
// the acceptance key that sealed it and when it completed. It is a pure
// value: Valid() is context-free (a historical statement does not
// re-evaluate against live policy), and EvaluatePolicy never mutates it.
type Proof struct {
	ProofID            string        `json:"proof_id"`
	VerificationID     string        `json:"verification_id"`
	ObligationID       string        `json:"obligation_id"`
	RecipeDigest       Digest        `json:"recipe_digest"`
	CandidateDigest    Digest        `json:"candidate_digest"`
	SnapshotDigest     Digest        `json:"snapshot_digest"`
	ContractDigest     Digest        `json:"contract_digest"`
	EvidenceRoot       Digest        `json:"evidence_root"`
	Terminal           TerminalState `json:"terminal"`
	Assurance          string        `json:"assurance"`
	AttestationDigests []Digest      `json:"attestation_digests"`
	AcceptanceKeyID    string        `json:"acceptance_key_id"`
	CompletedAt        time.Time     `json:"completed_at"`
}

// Valid reports whether the proof is structurally sound. It is the
// historical check: every identity present, every digest well-formed, a
// closed terminal state, an assurance label, an acceptance key and a
// completion instant. It consults no policy context.
func (p Proof) Valid() error {
	if p.ProofID == "" {
		return fmt.Errorf("%w: proof_id is required", ErrInvalid)
	}
	if p.VerificationID == "" {
		return fmt.Errorf("%w: verification_id is required", ErrInvalid)
	}
	if p.ObligationID == "" {
		return fmt.Errorf("%w: obligation_id is required", ErrInvalid)
	}
	for _, d := range []struct {
		name string
		d    Digest
	}{
		{"recipe_digest", p.RecipeDigest},
		{"candidate_digest", p.CandidateDigest},
		{"snapshot_digest", p.SnapshotDigest},
		{"contract_digest", p.ContractDigest},
		{"evidence_root", p.EvidenceRoot},
	} {
		if err := validateDigest(d.name, d.d); err != nil {
			return err
		}
	}
	if !p.Terminal.Valid() {
		return fmt.Errorf("%w: unknown terminal state %q", ErrInvalid, p.Terminal)
	}
	if p.Assurance == "" {
		return fmt.Errorf("%w: assurance is required", ErrInvalid)
	}
	if len(p.AttestationDigests) == 0 {
		return fmt.Errorf("%w: at least one attestation digest is required", ErrInvalid)
	}
	for i, d := range p.AttestationDigests {
		if err := validateDigest(fmt.Sprintf("attestation_digests[%d]", i), d); err != nil {
			return err
		}
	}
	if p.AcceptanceKeyID == "" {
		return fmt.Errorf("%w: acceptance_key_id is required", ErrInvalid)
	}
	if p.CompletedAt.IsZero() {
		return fmt.Errorf("%w: completed_at is required", ErrInvalid)
	}
	return nil
}

// ProvenPass reports whether the historical statement is a proven pass:
// only TerminalPassed qualifies.
func (p Proof) ProvenPass() bool { return p.Terminal == TerminalPassed }

// DenialReason is why a proof is not acceptable under a live policy context.
type DenialReason string

const (
	// DenialRecipeWithdrawn: the recipe the proof was built under has been
	// withdrawn.
	DenialRecipeWithdrawn DenialReason = "recipe_withdrawn"
	// DenialKeyCompromised: the acceptance key that sealed the proof has
	// been compromised.
	DenialKeyCompromised DenialReason = "key_compromised"
	// DenialAttestationRevoked: one of the proof's attestations is revoked.
	DenialAttestationRevoked DenialReason = "attestation_revoked"
	// DenialExpired: the proof is older than the policy's freshness floor.
	DenialExpired DenialReason = "expired"
	// DenialNeverPassed: the proof never reached a passed terminal state.
	DenialNeverPassed DenialReason = "never_passed"
)

// Denial is one reason a proof is unacceptable under a live policy context.
type Denial struct {
	Reason DenialReason `json:"reason"`
}

// PolicyContext is the LIVE world a proof is evaluated against: the current
// clock and the sets of withdrawn recipes, compromised keys and revoked
// attestations. It is deliberately separate from Proof — a historical
// statement never mutates, only its current acceptability changes.
type PolicyContext struct {
	// Now is the evaluation clock. Zero falls back to time.Now().
	Now time.Time
	// WithdrawnRecipes lists recipe digests no longer acceptable.
	WithdrawnRecipes map[Digest]bool
	// CompromisedKeys lists acceptance key ids no longer trustworthy.
	CompromisedKeys map[string]bool
	// RevokedAttestations lists attestation digests that are revoked.
	RevokedAttestations map[Digest]bool
	// MaxAgeSeconds is the freshness floor: a proof completed longer than
	// this before Now is expired. Zero = no floor.
	MaxAgeSeconds int64
}

// PolicyEvaluation is the result of evaluating one proof under one live
// policy context. Denials lists every reason the proof is unacceptable
// (complete, not first-match); Acceptable is true exactly when the list is
// empty.
type PolicyEvaluation struct {
	EvaluatedAt time.Time `json:"evaluated_at"`
	Acceptable  bool      `json:"acceptable"`
	Denials     []Denial  `json:"denials"`
}

// EvaluatePolicy reports whether a historically valid proof is acceptable
// under the given live policy context. It never mutates the proof: the
// historical statement stands, only its current acceptability is computed.
// An invalid proof is refused with ErrInvalid before any evaluation.
func EvaluatePolicy(p Proof, live PolicyContext) (PolicyEvaluation, error) {
	if err := p.Valid(); err != nil {
		return PolicyEvaluation{}, err
	}
	now := live.Now
	if now.IsZero() {
		now = time.Now()
	}
	ev := PolicyEvaluation{EvaluatedAt: now}
	if p.Terminal != TerminalPassed {
		ev.Denials = append(ev.Denials, Denial{Reason: DenialNeverPassed})
	}
	if live.WithdrawnRecipes[p.RecipeDigest] {
		ev.Denials = append(ev.Denials, Denial{Reason: DenialRecipeWithdrawn})
	}
	if live.CompromisedKeys[p.AcceptanceKeyID] {
		ev.Denials = append(ev.Denials, Denial{Reason: DenialKeyCompromised})
	}
	for _, d := range p.AttestationDigests {
		if live.RevokedAttestations[d] {
			ev.Denials = append(ev.Denials, Denial{Reason: DenialAttestationRevoked})
			break
		}
	}
	if live.MaxAgeSeconds > 0 {
		age := now.Sub(p.CompletedAt)
		if age > time.Duration(live.MaxAgeSeconds)*time.Second {
			ev.Denials = append(ev.Denials, Denial{Reason: DenialExpired})
		}
	}
	ev.Acceptable = len(ev.Denials) == 0
	return ev, nil
}

// VerificationProof is an immutable, machine-verifiable bundle of one
// accepted verification: the obligation, the submitted claim, the derived
// authoritative outcome, the resolved evidence and the acceptance record
// that binds them. It is a value type — copying it copies every field — and
// Verify() re-checks the whole bundle against an acceptance keyring without
// consulting any live registry or store. That makes a proof portable: it can
// be shipped to another process, persisted in an artifact, or archived, and
// it either verifies or it does not — there is no ambient authority to trust.
type VerificationProof struct {
	// Obligation is the obligation the proof answers.
	Obligation VerificationObligation `json:"obligation"`
	// SubmittedClaim is the caller's original submission (audit only).
	SubmittedClaim VerificationOutcome `json:"submitted_claim"`
	// Outcome is the DERIVED authoritative outcome.
	Outcome VerificationOutcome `json:"outcome"`
	// Evidence is the resolved evidence backing Outcome.
	Evidence VerifiedEvidence `json:"evidence"`
	// Acceptance is the integrity record computed at persist time.
	Acceptance AcceptanceRecord `json:"acceptance"`
}

// NewVerificationProof snapshots a persisted bundle into an immutable proof
// value. The input is copied field by field so later mutation of the caller's
// slices cannot change the proof.
func NewVerificationProof(p PersistedVerified) VerificationProof {
	return VerificationProof{
		Obligation:     cloneObligation(p.Obligation),
		SubmittedClaim: cloneOutcome(p.SubmittedClaim),
		Outcome:        cloneOutcome(p.Outcome),
		Evidence:       cloneEvidence(p.Evidence),
		Acceptance:     p.Acceptance,
	}
}

// NewVerificationProofFromParts builds a proof from explicit parts. The
// result is NOT verified at construction — call Verify to re-check the
// acceptance binding and seal rules.
func NewVerificationProofFromParts(obligation VerificationObligation, submitted, outcome VerificationOutcome, evidence VerifiedEvidence, acceptance AcceptanceRecord) (VerificationProof, error) {
	return VerificationProof{
		Obligation:     cloneObligation(obligation),
		SubmittedClaim: cloneOutcome(submitted),
		Outcome:        cloneOutcome(outcome),
		Evidence:       cloneEvidence(evidence),
		Acceptance:     acceptance,
	}, nil
}

// Verify re-checks the proof against the given keyring: the acceptance MAC
// must verify under the key the record names, the committed digests must
// match the bundle, and the seal rules (including the claim-identity rule)
// must hold. It consults no registry, no store, and no ambient state — the
// proof and the keyring are the only inputs. A proof that does not verify is
// refused with ErrAcceptance / ErrUnverified; it never yields a partial
// trust signal.
func (p VerificationProof) Verify(keyring *AcceptanceKeyring) (DerivedVerifiedOutcome, error) {
	if keyring == nil {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verification proof requires an acceptance keyring", ErrAcceptance)
	}
	return RestoreVerifiedOutcomeWithKeyring(PersistedVerified{
		Obligation:     p.Obligation,
		SubmittedClaim: p.SubmittedClaim,
		Outcome:        p.Outcome,
		Evidence:       p.Evidence,
		Acceptance:     p.Acceptance,
	}, nil, keyring)
}

// cloneEvidence deep-copies the mutable slices/pointers of VerifiedEvidence.
func cloneEvidence(e VerifiedEvidence) VerifiedEvidence {
	out := e
	out.ExecutionIDs = append([]string(nil), e.ExecutionIDs...)
	out.AttestationDigests = append([]Digest(nil), e.AttestationDigests...)
	out.CompletedChecks = append([]string(nil), e.CompletedChecks...)
	out.VerifiedChecks = append([]VerifiedCheck(nil), e.VerifiedChecks...)
	if e.Attested != nil {
		a := *e.Attested
		out.Attested = &a
	}
	if e.ObservedControls != nil {
		c := *e.ObservedControls
		out.ObservedControls = &c
	}
	return out
}
