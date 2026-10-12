package verifyapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// ProvenanceEvidenceVerifier is the concrete EvidenceVerifier backed by
// internal/provenance. Each opaque evidence reference is resolved to signed
// envelope bytes by Resolve, then checked with provenance.VerifyWith (Ed25519
// DSSE signature + constraint pins) and provenance.VerifyExecutionAttestation
// (subject digests the evidence block, mirror fields agree). Only what those
// checks prove is stamped into the VerifiedOutcome.
//
// The verifier is a thin adapter: all cryptographic meaning stays in
// provenance, and this package only maps the verified statements onto the
// verifyapi acceptance boundary.
type ProvenanceEvidenceVerifier struct {
	// Identity is stamped on every VerifiedOutcome this verifier produces.
	Identity string
	// Resolve loads the signed envelope bytes for one evidence reference.
	// It is typically wired to a blob/CAS lookup at the mounting call site.
	Resolve func(ctx context.Context, ref string) ([]byte, error)
	// Keys resolves signature key ids to trusted Ed25519 public keys. It is
	// consulted only when TrustedKey is unset.
	Keys func(kid string) (ed25519.PublicKey, bool)
	// TrustedKey, when set, is the only accepted verification key.
	TrustedKey ed25519.PublicKey
	// VerifyOpts are optional non-empty pins every statement must match
	// (repository, commit, capsule digests, …).
	VerifyOpts provenance.VerifyOptions
	// Clock stamps VerifiedAt. Nil selects time.Now.
	Clock func() time.Time
}

// Verify implements EvidenceVerifier over real provenance envelopes.
func (p *ProvenanceEvidenceVerifier) Verify(ctx context.Context, obligation VerificationObligation, submittedClaim VerificationOutcome) (DerivedVerifiedOutcome, error) {
	if p == nil || p.Resolve == nil {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verifier has no evidence loader", ErrUnverified)
	}
	f := &FuncEvidenceVerifier{
		Identity: p.Identity,
		Clock:    p.Clock,
		Resolve: func(ctx context.Context, ref string) (ResolvedAttestation, error) {
			return resolveProvenanceAttestation(ctx, ref, p)
		},
	}
	return f.Verify(ctx, obligation, submittedClaim)
}

// resolveProvenanceAttestation loads one signed envelope and cryptographically
// resolves it: signature verification via provenance.VerifyWith, then the
// execution-attestation consistency rule via provenance.VerifyExecutionAttestation.
func resolveProvenanceAttestation(ctx context.Context, ref string, p *ProvenanceEvidenceVerifier) (ResolvedAttestation, error) {
	if err := ctx.Err(); err != nil {
		return ResolvedAttestation{}, err
	}
	raw, err := p.Resolve(ctx, ref)
	if err != nil {
		return ResolvedAttestation{}, fmt.Errorf("load evidence envelope: %w", err)
	}
	opts := p.VerifyOpts
	if len(p.TrustedKey) > 0 {
		opts.TrustedKey = p.TrustedKey
	}
	st, err := provenance.VerifyWith(raw, p.Keys, opts)
	if err != nil {
		return ResolvedAttestation{}, fmt.Errorf("verify envelope: %w", err)
	}
	if err := provenance.VerifyExecutionAttestation(st); err != nil {
		return ResolvedAttestation{}, fmt.Errorf("verify execution attestation: %w", err)
	}
	att := st.Attestation
	if att == nil {
		return ResolvedAttestation{}, fmt.Errorf("statement carries no execution attestation")
	}
	digest := ""
	if len(st.Subject) > 0 {
		digest = st.Subject[0].Digest["sha256"]
	}
	if digest == "" {
		return ResolvedAttestation{}, fmt.Errorf("attestation statement has no subject digest")
	}
	execID := att.AttemptID
	if execID == "" {
		execID = st.AttemptID
	}
	res := ResolvedAttestation{
		ExecutionID:       execID,
		EvidenceRoot:      Digest(att.EvidenceRootSHA256),
		AttestationDigest: Digest(digest),
		// Job status and assurance facts come from the SIGNED attestation
		// block only — never from the caller's claim. The verifier derives
		// Result and AssuranceProfile from these.
		Status:          att.Status,
		AssuranceSchema: att.SchemaVersion,
	}
	if att.ExecutionAssurance.Facts != nil {
		f := *att.ExecutionAssurance.Facts
		res.Facts = &f
	}
	// Durable job facts come from the SIGNED attestation block only (job
	// started_at/finished_at), never from the caller's claim. A statement
	// that carries no window — or an inverted one — resolves without
	// attested facts so Measured.WallTimeNS stays unfilled instead of
	// guessed.
	if att.StartedAt != nil && att.FinishedAt != nil && !att.FinishedAt.Before(*att.StartedAt) {
		res.Attested = &AttestedResourceFacts{
			StartedAt:  *att.StartedAt,
			FinishedAt: *att.FinishedAt,
		}
	}
	// Named checks are bound by structured signed result evidence: each
	// test-report suite the attestation commits (its suite digest covers the
	// ordered cases) binds its report name as a completed check. Caller
	// strings never enter here.
	for _, rep := range att.TestReports {
		if rep.Name != "" {
			res.Checks = append(res.Checks, rep.Name)
		}
	}
	return res, nil
}

// EvidenceEnvelopeJSON marshals a provenance.Envelope the way evidence
// references are expected to carry it (the canonical loader input). Kept here
// so call sites and tests share one encoding.
func EvidenceEnvelopeJSON(env provenance.Envelope) ([]byte, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("verifyapi: encode evidence envelope: %w", err)
	}
	return raw, nil
}
