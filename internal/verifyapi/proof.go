package verifyapi

import (
	"fmt"
	"time"
)

// ProofSummary is the compact historical statement of one verification:
// identity, the digests it was bound to, the terminal state, the acceptance
// key that sealed it and when it completed. (Renamed from Proof — it is a
// summary/descriptor of a verification, not the full machine-verifiable
// bundle; that is VerificationProof / VerifiedProof.) It is a pure value:
// Valid() is context-free (a historical statement does not re-evaluate
// against live policy), and policy evaluation never mutates it.
type ProofSummary struct {
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

// Valid reports whether the summary is structurally sound. It is the
// historical check: every identity present, every digest well-formed, a
// closed terminal state, an assurance label, an acceptance key and a
// completion instant. It consults no policy context. RecipeDigest may be
// empty (the obligation was issued without a recipe); when set it must be a
// well-formed digest.
func (p ProofSummary) Valid() error {
	if p.ProofID == "" {
		return fmt.Errorf("%w: proof_id is required", ErrInvalid)
	}
	if p.VerificationID == "" {
		return fmt.Errorf("%w: verification_id is required", ErrInvalid)
	}
	if p.ObligationID == "" {
		return fmt.Errorf("%w: obligation_id is required", ErrInvalid)
	}
	if p.RecipeDigest != "" {
		if err := validateDigest("recipe_digest", p.RecipeDigest); err != nil {
			return err
		}
	}
	for _, d := range []struct {
		name string
		d    Digest
	}{
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
func (p ProofSummary) ProvenPass() bool { return p.Terminal == TerminalPassed }

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
// attestations. It is deliberately separate from the historical statement —
// a historical statement never mutates, only its current acceptability
// changes.
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

// VerifiedProof is a proof that has been verified against an acceptance
// keyring. The seal is unexported: the only constructor is
// VerificationProof.Verify (via sealVerifiedProof), so an unverified
// document can never be policy-evaluated as if it were proof. EvaluatePolicy
// accepts ONLY VerifiedProof — the constraint is compile-time.
type VerifiedProof struct {
	// Summary is the compact historical statement of the verified proof.
	Summary ProofSummary
	// Out is the sealed derived outcome the document verified to.
	Out DerivedVerifiedOutcome
	// Document is the proof bundle that was verified.
	Document VerificationProof

	sealed bool
}

// sealVerifiedProof is the only way a VerifiedProof is minted. It is called
// by VerificationProof.Verify after the acceptance MAC and every committed
// digest have been re-checked.
func sealVerifiedProof(summary ProofSummary, doc VerificationProof, out DerivedVerifiedOutcome) (VerifiedProof, error) {
	if err := summary.Valid(); err != nil {
		return VerifiedProof{}, err
	}
	if !out.Sealed() {
		return VerifiedProof{}, fmt.Errorf("%w: verified proof requires a sealed derived outcome", ErrUnverified)
	}
	return VerifiedProof{Summary: summary, Out: out, Document: doc, sealed: true}, nil
}

// Sealed reports whether this proof was produced by VerificationProof.Verify.
// An unsealed zero value is not proof.
func (p VerifiedProof) Sealed() bool { return p.sealed }

// ProvenPass reports whether the verified proof is a proven pass: sealed,
// with a TerminalPassed summary.
func (p VerifiedProof) ProvenPass() bool { return p.sealed && p.Summary.ProvenPass() }

// EvaluatePolicy reports whether a verified proof is acceptable under the
// given live policy context. It never mutates the proof: the historical
// statement stands, only its current acceptability is computed. Only a
// VerifiedProof is accepted (compile-time); an unsealed value is refused
// with ErrUnverified and an invalid summary with ErrInvalid.
func EvaluatePolicy(p VerifiedProof, live PolicyContext) (PolicyEvaluation, error) {
	if !p.sealed {
		return PolicyEvaluation{}, fmt.Errorf("%w: policy evaluation requires a verified proof", ErrUnverified)
	}
	if err := p.Summary.Valid(); err != nil {
		return PolicyEvaluation{}, err
	}
	now := live.Now
	if now.IsZero() {
		now = time.Now()
	}
	ev := PolicyEvaluation{EvaluatedAt: now}
	if p.Summary.Terminal != TerminalPassed {
		ev.Denials = append(ev.Denials, Denial{Reason: DenialNeverPassed})
	}
	// An empty RecipeDigest is an inline proof (no recipe). It is never
	// denied by the withdrawal list: a map entry for "" must not deny every
	// recipe-less proof.
	if p.Summary.RecipeDigest != "" && live.WithdrawnRecipes[p.Summary.RecipeDigest] {
		ev.Denials = append(ev.Denials, Denial{Reason: DenialRecipeWithdrawn})
	}
	if live.CompromisedKeys[p.Summary.AcceptanceKeyID] {
		ev.Denials = append(ev.Denials, Denial{Reason: DenialKeyCompromised})
	}
	for _, d := range p.Summary.AttestationDigests {
		if live.RevokedAttestations[d] {
			ev.Denials = append(ev.Denials, Denial{Reason: DenialAttestationRevoked})
			break
		}
	}
	if live.MaxAgeSeconds > 0 {
		age := now.Sub(p.Summary.CompletedAt)
		if age > time.Duration(live.MaxAgeSeconds)*time.Second {
			ev.Denials = append(ev.Denials, Denial{Reason: DenialExpired})
		}
	}
	ev.Acceptable = len(ev.Denials) == 0
	return ev, nil
}

// UnverifiedProofDocument is the honest name of a portable proof bundle that
// has not yet been verified: VerificationProof. Verify() against an
// acceptance keyring is the only way it becomes a VerifiedProof.
type UnverifiedProofDocument = VerificationProof

// VerificationProof is an immutable, machine-verifiable bundle of one
// accepted verification: the obligation, the submitted claim, the derived
// authoritative outcome, the resolved evidence and the acceptance record
// that binds them. It is a value type — copying it copies every field — and
// Verify() re-checks the whole bundle against an acceptance keyring without
// consulting any live registry or store. That makes a proof portable: it can
// be shipped to another process, persisted in an artifact, or archived, and
// it either verifies or it does not — there is no ambient authority to trust.
//
// A VerificationProof is an UnverifiedProofDocument: until Verify returns a
// sealed VerifiedProof, it is data, never authority.
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
// trust signal. On success the result is a sealed VerifiedProof — the only
// way one is ever minted — so policy evaluation and discharge can demand
// VerifiedProof at compile time.
func (p VerificationProof) Verify(keyring *AcceptanceKeyring) (VerifiedProof, error) {
	return p.VerifyWithRecipe(keyring, nil)
}

// VerifyWithRecipe is the recipe-aware verify. Recipe-bound proofs must pass
// the resolved recipe so the demand digest can be recomputed faithfully.
func (p VerificationProof) VerifyWithRecipe(keyring *AcceptanceKeyring, recipe *Recipe) (VerifiedProof, error) {
	if keyring == nil {
		return VerifiedProof{}, fmt.Errorf("%w: verification proof requires an acceptance keyring", ErrAcceptance)
	}
	if p.Obligation.RecipeDigest != "" && recipe == nil {
		return VerifiedProof{}, fmt.Errorf("%w: recipe-bound proof requires the resolved recipe", ErrBinding)
	}
	if recipe != nil {
		d, err := RecipeDigest(*recipe)
		if err != nil {
			return VerifiedProof{}, err
		}
		if d != p.Obligation.RecipeDigest {
			return VerifiedProof{}, fmt.Errorf("%w: proof recipe digest %s does not match supplied recipe %s", ErrBinding, p.Obligation.RecipeDigest, d)
		}
	}
	out, err := RestoreVerifiedOutcomeWithRecipe(PersistedVerified{
		Obligation:     p.Obligation,
		SubmittedClaim: p.SubmittedClaim,
		Outcome:        p.Outcome,
		Evidence:       p.Evidence,
		Acceptance:     p.Acceptance,
	}, nil, keyring, recipe)
	if err != nil {
		return VerifiedProof{}, err
	}
	// The recipe's evidence floor applies to the proof path too, not only
	// the service discharge: a record whose evidence does not meet the floor
	// must never verify into authority. Restore already re-derived Window
	// and Kinds, so this check sees only MAC-verified material.
	if recipe != nil {
		if err := recipe.EvidenceMin.Check(out.Evidence); err != nil {
			return VerifiedProof{}, fmt.Errorf("%w: proof fails the recipe evidence floor: %v", ErrUnverified, err)
		}
	}
	summary, err := ProofSummaryFromBundle(p, out, recipe)
	if err != nil {
		return VerifiedProof{}, err
	}
	return sealVerifiedProof(summary, p, out)
}

// ProofSummaryFromBundle derives the compact historical statement of one
// verified proof document. Every field comes from the bundle and its sealed
// derived outcome — never from a caller string. RecipeDigest is taken from
// the RESOLVED DEMAND (the rule set the discharge was measured against),
// not from the obligation's recipe pin: the two are required to agree, and
// the demand is what the acceptance record actually committed.
//
// The optional recipe argument (pass at most one) is the resolved recipe the
// proof was verified against; nil resolves the demand from the obligation
// alone.
func ProofSummaryFromBundle(p VerificationProof, out DerivedVerifiedOutcome, recipes ...*Recipe) (ProofSummary, error) {
	if !out.Sealed() {
		return ProofSummary{}, fmt.Errorf("%w: ProofSummaryFromBundle requires a sealed derived outcome", ErrUnverified)
	}
	var recipe *Recipe
	if len(recipes) > 0 {
		recipe = recipes[0]
	}
	demand, err := ResolveEffectiveDemand(p.Obligation, recipe)
	if err != nil {
		return ProofSummary{}, err
	}
	completed := out.Outcome.CompletedAt
	if completed.IsZero() {
		completed = p.Acceptance.VerifiedAt
	}
	s := ProofSummary{
		ProofID:            p.Acceptance.KeyID + "/" + out.Outcome.VerificationID,
		VerificationID:     out.Outcome.VerificationID,
		ObligationID:       out.Outcome.ObligationID,
		RecipeDigest:       demand.RecipeDigest,
		CandidateDigest:    out.Outcome.CandidateDigest,
		SnapshotDigest:     out.Outcome.SnapshotDigest,
		ContractDigest:     out.Outcome.ContractDigest,
		EvidenceRoot:       out.Evidence.EvidenceRoot,
		Terminal:           terminalOfOutcome(out.Outcome.Outcome),
		Assurance:          out.Outcome.AssuranceProfile,
		AttestationDigests: append([]Digest(nil), out.Evidence.AttestationDigests...),
		AcceptanceKeyID:    p.Acceptance.KeyID,
		CompletedAt:        completed,
	}
	return s, s.Valid()
}

// terminalOfOutcome maps a coarse derived outcome onto the rich terminal
// vocabulary for the summary.
func terminalOfOutcome(o Outcome) TerminalState {
	switch o {
	case OutcomePass:
		return TerminalPassed
	case OutcomeFail:
		return TerminalFailed
	default:
		return TerminalEvidenceIncomplete
	}
}

// cloneEvidence deep-copies the mutable slices/pointers of VerifiedEvidence.
func cloneEvidence(e VerifiedEvidence) VerifiedEvidence {
	out := e
	out.ExecutionIDs = append([]string(nil), e.ExecutionIDs...)
	out.AttestationDigests = append([]Digest(nil), e.AttestationDigests...)
	out.CompletedChecks = append([]string(nil), e.CompletedChecks...)
	out.VerifiedChecks = append([]VerifiedCheck(nil), e.VerifiedChecks...)
	out.Kinds = append([]string(nil), e.Kinds...)
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
