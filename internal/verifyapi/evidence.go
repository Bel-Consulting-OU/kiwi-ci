package verifyapi

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Evidence acceptance-boundary errors. Callers must treat every error here as
// a refusal (fail closed): no VerifiedOutcome is produced and nothing is
// stored as authoritative.
var (
	// ErrUnverified is returned when a value that claims authority was not
	// produced by an EvidenceVerifier. A raw submitted outcome is only a
	// claim; it never discharges an obligation as proven.
	ErrUnverified = errors.New("verifyapi: outcome is not evidence-verified")
	// ErrEvidence is returned when cryptographically resolved evidence is
	// missing, does not verify, or does not agree with the submitted claim.
	ErrEvidence = errors.New("verifyapi: evidence resolution failed")
)

// VerifiedEvidence is the cryptographically resolved evidence of one outcome.
// Every field is produced by the verifier from signature-checked attestation
// material — never copied from the caller's claim — so a forged evidence_root
// or execution id can never appear here.
type VerifiedEvidence struct {
	// ExecutionIDs are the execution identities the verified attestations
	// bind (canonical attempt ids), in resolution order.
	ExecutionIDs []string `json:"execution_ids"`
	// EvidenceRoot is the evidence root carried by the verified attestations.
	// Every attestation must agree on one root and the claim must name it.
	EvidenceRoot Digest `json:"evidence_root"`
	// AttestationDigests are the canonical subject digests of the verified
	// attestation statements (the digests their signatures bind).
	AttestationDigests []Digest `json:"attestation_digests"`
	// VerifierIdentity names the evidence verifier that produced this record.
	VerifierIdentity string `json:"verifier_identity"`
	// VerifiedAt is when the verifier resolved the evidence (verifier clock).
	VerifiedAt time.Time `json:"verified_at"`
}

// VerifiedOutcome is the server-created result of evidence verification: the
// submitted outcome plus the cryptographically resolved evidence behind it.
// Only a VerifiedOutcome may be stored as authoritative (see
// Registry.RecordVerifiedOutcome). The zero value is not verified — the seal
// is set exclusively by EvidenceVerifier implementations in this package, so
// a caller cannot fabricate authority outside the process boundary.
type VerifiedOutcome struct {
	// Outcome is the bound submitted claim this record answers. On a sealed
	// record its ExecutionIDs are the resolved set (the claim is only allowed
	// to name ids the attestations bind) and its EvidenceRoot equals the
	// resolved root (the claim is refused otherwise); Evidence carries the
	// full resolved facts alongside.
	Outcome VerificationOutcome `json:"outcome"`
	// Evidence is the cryptographically resolved evidence backing Outcome.
	Evidence VerifiedEvidence `json:"evidence"`

	// sealed is the server-creation seal. It is intentionally unexported:
	// values constructed outside a verifier of this package are never sealed
	// and are refused by RecordVerifiedOutcome.
	sealed bool
}

// EvidenceVerifier is the acceptance boundary between submitted claims and
// authoritative results. Verify resolves the outcome's evidence references
// cryptographically (signatures, attestation consistency, evidence roots) and
// returns a server-created VerifiedOutcome, or an error — never a partially
// trusted result. Only the returned VerifiedOutcome may be stored as
// authoritative.
type EvidenceVerifier interface {
	Verify(ctx context.Context, outcome VerificationOutcome) (VerifiedOutcome, error)
}

// Sealed reports whether this record was produced by an EvidenceVerifier.
// An unsealed zero value is a claim, not proof.
func (v VerifiedOutcome) Sealed() bool { return v.sealed }

// ProvenPass reports whether this record is an authoritative verified pass.
// This is the single discharge predicate for a proven pass claim.
func (v VerifiedOutcome) ProvenPass() bool {
	return v.sealed && v.Outcome.Outcome == OutcomePass
}

// ResolvedAttestation is one cryptographically resolved execution
// attestation: the execution identity it binds, the evidence root it commits,
// and the canonical digest its signature covers.
type ResolvedAttestation struct {
	ExecutionID       string
	EvidenceRoot      Digest
	AttestationDigest Digest
}

// AttestationResolver cryptographically resolves one opaque evidence
// reference into a verified attestation. Implementations must fail closed:
// a ref that cannot be loaded, whose signature does not verify, or whose
// attestation block is inconsistent is an error, never a partial resolution.
// It is the injection seam that keeps cryptographic dependencies out of the
// core contract: the provenance-backed adapter and test fakes both plug in
// here.
type AttestationResolver func(ctx context.Context, ref string) (ResolvedAttestation, error)

// FuncEvidenceVerifier is an EvidenceVerifier built from an injected
// attestation resolver plus a stable verifier identity. It enforces the
// claim/evidence agreement rule: the submitted evidence root must equal the
// resolved one, every submitted execution id must be among the resolved ones,
// and at least one attestation must resolve. The concrete cryptographic
// resolution (internal/provenance.VerifyWith / VerifyExecutionAttestation)
// lives behind the resolver so this contract stays free of provider imports.
type FuncEvidenceVerifier struct {
	// Identity is stamped on every VerifiedOutcome this verifier produces.
	Identity string
	// Resolve resolves one evidence reference into a verified attestation.
	Resolve AttestationResolver
	// Clock stamps VerifiedAt. Nil selects time.Now.
	Clock func() time.Time
}

// Verify resolves every evidence reference on the outcome and seals a
// VerifiedOutcome whose Evidence is entirely verifier-derived. The claim is
// accepted only when it agrees with what the signatures prove.
func (f *FuncEvidenceVerifier) Verify(ctx context.Context, outcome VerificationOutcome) (VerifiedOutcome, error) {
	if f == nil || f.Resolve == nil {
		return VerifiedOutcome{}, fmt.Errorf("%w: verifier has no attestation resolver", ErrUnverified)
	}
	if f.Identity == "" {
		return VerifiedOutcome{}, fmt.Errorf("%w: verifier identity is required", ErrUnverified)
	}
	if err := outcome.Validate(); err != nil {
		return VerifiedOutcome{}, err
	}
	if len(outcome.ProvenanceRefs) == 0 {
		return VerifiedOutcome{}, fmt.Errorf("%w: outcome %q cites no evidence references", ErrEvidence, outcome.VerificationID)
	}
	resolved := make([]ResolvedAttestation, 0, len(outcome.ProvenanceRefs))
	for _, ref := range outcome.ProvenanceRefs {
		if ref == "" {
			return VerifiedOutcome{}, fmt.Errorf("%w: empty evidence reference", ErrEvidence)
		}
		if err := ctx.Err(); err != nil {
			return VerifiedOutcome{}, err
		}
		att, err := f.Resolve(ctx, ref)
		if err != nil {
			return VerifiedOutcome{}, fmt.Errorf("%w: evidence %q: %v", ErrEvidence, ref, err)
		}
		if att.ExecutionID == "" || att.EvidenceRoot == "" || att.AttestationDigest == "" {
			return VerifiedOutcome{}, fmt.Errorf("%w: evidence %q resolved incompletely (execution id, evidence root and attestation digest are all required)", ErrEvidence, ref)
		}
		if err := validateDigest("resolved evidence_root", att.EvidenceRoot); err != nil {
			return VerifiedOutcome{}, fmt.Errorf("%w: evidence %q: %v", ErrEvidence, ref, err)
		}
		resolved = append(resolved, att)
	}
	// Every attestation must commit the same evidence root; a split root is
	// not one coherent evidence set and is refused rather than guessed.
	root := resolved[0].EvidenceRoot
	execIDs := make([]string, 0, len(resolved))
	digests := make([]Digest, 0, len(resolved))
	seenExec := make(map[string]bool, len(resolved))
	for _, att := range resolved {
		if att.EvidenceRoot != root {
			return VerifiedOutcome{}, fmt.Errorf("%w: attestations disagree on evidence root (%s vs %s)", ErrEvidence, root, att.EvidenceRoot)
		}
		if !seenExec[att.ExecutionID] {
			seenExec[att.ExecutionID] = true
			execIDs = append(execIDs, att.ExecutionID)
		}
		digests = append(digests, att.AttestationDigest)
	}
	// Claim/evidence agreement, fail closed: the caller's evidence_root must
	// be exactly the resolved one, and any claimed execution id must really
	// be bound by a verified attestation. A fake evidence_root can therefore
	// never launder a pass — Verify refuses it before anything is sealed.
	if outcome.EvidenceRoot != Digest(root) {
		return VerifiedOutcome{}, fmt.Errorf("%w: claimed evidence_root %q does not match resolved %q", ErrEvidence, outcome.EvidenceRoot, root)
	}
	for _, id := range outcome.ExecutionIDs {
		if !seenExec[id] {
			return VerifiedOutcome{}, fmt.Errorf("%w: claimed execution id %q is not bound by any verified attestation", ErrEvidence, id)
		}
	}
	now := time.Now
	if f.Clock != nil {
		now = f.Clock
	}
	return sealVerifiedOutcome(outcome, VerifiedEvidence{
		ExecutionIDs:       execIDs,
		EvidenceRoot:       root,
		AttestationDigests: digests,
		VerifierIdentity:   f.Identity,
		VerifiedAt:         now(),
	})
}

// sealVerifiedOutcome builds a sealed VerifiedOutcome. It is the only way
// authority is granted: evidence must be complete and the verifier identity
// present, otherwise nothing is sealed.
func sealVerifiedOutcome(outcome VerificationOutcome, evidence VerifiedEvidence) (VerifiedOutcome, error) {
	if err := outcome.Validate(); err != nil {
		return VerifiedOutcome{}, err
	}
	if evidence.VerifierIdentity == "" {
		return VerifiedOutcome{}, fmt.Errorf("%w: verifier identity is required", ErrUnverified)
	}
	if evidence.EvidenceRoot == "" {
		return VerifiedOutcome{}, fmt.Errorf("%w: resolved evidence root is required", ErrUnverified)
	}
	if err := validateDigest("resolved evidence_root", evidence.EvidenceRoot); err != nil {
		return VerifiedOutcome{}, err
	}
	if len(evidence.AttestationDigests) == 0 {
		return VerifiedOutcome{}, fmt.Errorf("%w: at least one attestation digest is required", ErrUnverified)
	}
	if evidence.VerifiedAt.IsZero() {
		return VerifiedOutcome{}, fmt.Errorf("%w: verified_at is required", ErrUnverified)
	}
	out := VerifiedOutcome{
		Outcome:  outcome,
		Evidence: evidence,
		sealed:   true,
	}
	out.Outcome.ExecutionIDs = append([]string(nil), evidence.ExecutionIDs...)
	return out, nil
}
