package verifyapi

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Evidence acceptance-boundary errors. Callers must treat every error here as
// a refusal (fail closed): no DerivedVerifiedOutcome is produced and nothing
// is stored as authoritative.
var (
	// ErrUnverified is returned when a value that claims authority was not
	// produced by an EvidenceVerifier, or when a persisted record cannot be
	// restored through the acceptance integrity path. A raw submitted
	// outcome is only a claim; it never discharges an obligation as proven.
	ErrUnverified = errors.New("verifyapi: outcome is not evidence-verified")
	// ErrEvidence is returned when cryptographically resolved evidence is
	// missing, does not verify, or is internally inconsistent.
	ErrEvidence = errors.New("verifyapi: evidence resolution failed")
	// ErrAcceptance is returned when a durable acceptance record is absent,
	// malformed, or fails its MAC/signature integrity check. A row whose
	// acceptance record does not verify can never be restored as sealed.
	ErrAcceptance = errors.New("verifyapi: acceptance integrity check failed")
)

// Derived check identities bound by structured signed result evidence. These
// are the only names the verifier derives from attestation FACTS themselves;
// named checks additionally surface from signed test-report suites and
// explicit signed check results (see ResolvedAttestation.Checks). A caller's
// CompletedChecks string list is NEVER authority for any of these names.
const (
	// CheckJobStatusSuccess counts as completed only when every resolved
	// attestation's signed job status is success.
	CheckJobStatusSuccess = "job-status-success"
	// CheckEvidenceRoot counts as completed only when the resolved evidence
	// commits a well-formed evidence root.
	CheckEvidenceRoot = "evidence-root"
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
	// Every attestation must agree on one root.
	EvidenceRoot Digest `json:"evidence_root"`
	// AttestationDigests are the canonical subject digests of the verified
	// attestation statements (the digests their signatures bind).
	AttestationDigests []Digest `json:"attestation_digests"`
	// Attested holds the durable execution facts the verified attestations
	// carry (job started_at/finished_at), when any of them do. Nil when the
	// attestations carry no job window — e.g. older statements — in which
	// case Measured.WallTimeNS stays unfilled rather than guessed. Filled
	// exclusively from signature-checked attestation material.
	Attested *AttestedResourceFacts `json:"attested,omitempty"`
	// JobStatus is the consensus signed job status derived from the
	// attestations: "success" only when every attestation reports success,
	// "failure" when any reports failure, otherwise "incomplete".
	JobStatus string `json:"job_status"`
	// CompletedChecks are the check identities bound by structured signed
	// result evidence (attestation facts, test-report suites, explicit
	// signed check results). Never caller strings.
	CompletedChecks []string `json:"completed_checks"`
	// Assurance is the profile derived from the signed assurance facts with
	// model.DeriveAssuranceProfileSchema (weakest profile across
	// attestations). Never the caller's string.
	Assurance model.ExecutionAssurance `json:"assurance"`
	// ObservedControls is the executor-observed enforcement receipt carried
	// by the signed attestations, when they unanimously agree on one. Nil
	// when no attestation carries a receipt or the receipts disagree.
	ObservedControls *model.ExecutionControlReceipt `json:"observed_controls,omitempty"`
	// VerifierIdentity names the evidence verifier that produced this record.
	VerifierIdentity string `json:"verifier_identity"`
	// VerifiedAt is when the verifier resolved the evidence (verifier clock).
	VerifiedAt time.Time `json:"verified_at"`
}

// DerivedVerifiedOutcome is the server-created authoritative record of one
// verification (Model A of the acceptance boundary): the caller's submission
// is preserved verbatim as a PROPOSAL for audit, and every authority-bearing
// value on Outcome is DERIVED from cryptographically resolved evidence —
// never copied from the proposal. Only a DerivedVerifiedOutcome may be stored
// as authoritative (see Registry.RecordVerifiedOutcome). The zero value is
// not verified — the seal is set exclusively by EvidenceVerifier
// implementations in this package, so a caller cannot fabricate authority
// outside the process boundary.
type DerivedVerifiedOutcome struct {
	// SubmittedClaim is the caller's proposal, preserved for audit. It
	// authorizes nothing: when its Result, AssuranceProfile, CompletedChecks,
	// ExecutionIDs or EvidenceRoot disagree with the derived values, the
	// derived values win and the claim stays here as the submission record.
	SubmittedClaim VerificationOutcome `json:"submitted_claim"`
	// Outcome is the DERIVED authoritative outcome: Result, CompletedChecks,
	// AssuranceProfile, ExecutionIDs and EvidenceRoot all come from the
	// signed evidence (see VerifiedEvidence), and the execution window and
	// Measured resource facts follow the attested job window when one exists.
	Outcome VerificationOutcome `json:"outcome"`
	// Evidence is the cryptographically resolved evidence backing Outcome.
	Evidence VerifiedEvidence `json:"evidence"`

	// sealed is the server-creation seal. It is intentionally unexported:
	// values constructed outside a verifier of this package are never sealed
	// and are refused by RecordVerifiedOutcome.
	sealed bool
}

// EvidenceVerifier is the acceptance boundary between submitted claims and
// authoritative results. Verify resolves the claim's evidence references
// cryptographically (signatures, attestation consistency, evidence roots),
// DERIVES every authority-bearing outcome value from what those signatures
// prove (job status, assurance facts, observed controls, bound checks), and
// returns a server-created DerivedVerifiedOutcome — or an error, never a
// partially trusted result. The caller's claim is a proposal only: its
// Result / AssuranceProfile / CompletedChecks / ExecutionIDs / EvidenceRoot
// are never trusted as authority.
type EvidenceVerifier interface {
	Verify(ctx context.Context, obligation VerificationObligation, submittedClaim VerificationOutcome) (DerivedVerifiedOutcome, error)
}

// Sealed reports whether this record was produced by an EvidenceVerifier (or
// restored through the acceptance integrity path). An unsealed zero value is
// a claim, not proof.
func (v DerivedVerifiedOutcome) Sealed() bool { return v.sealed }

// ProvenPass reports whether this record is an authoritative verified pass:
// sealed, with a DERIVED pass result. This is the single discharge predicate
// for a proven pass claim — and since the derived result is pass only when
// the signed job status is success and every obligation check is bound by
// signed result evidence, a caller-claimed pass can never satisfy it alone.
func (v DerivedVerifiedOutcome) ProvenPass() bool {
	return v.sealed && v.Outcome.Outcome == OutcomePass
}

// ResolvedAttestation is one cryptographically resolved execution
// attestation: the execution identity it binds, the evidence root it commits,
// the canonical digest its signature covers, and the signed facts the
// verifier derives authority from (job status, assurance facts, bound
// checks). A resolver must copy these from the signed attestation only —
// never from the caller's claim.
type ResolvedAttestation struct {
	ExecutionID       string
	EvidenceRoot      Digest
	AttestationDigest Digest
	// Status is the signed job status of the attested execution
	// (model.Status vocabulary: "success", "failure", "cancelled", …).
	Status string
	// Facts is the signed assurance fact vector (model.ExecutionFacts) the
	// attestation carries. Nil when the statement carries none (legacy
	// schema); the verifier then derives the conservative unproven profile.
	Facts *model.ExecutionFacts
	// AssuranceSchema is the attestation schema version the facts were
	// signed under (frozen v5 vs current v6 derivation semantics). Zero is
	// treated as the current schema.
	AssuranceSchema int
	// Attested carries the durable job facts the signature covers (job
	// started_at/finished_at). Optional: nil when the statement carries no
	// window; the verifier then records no attested wall time instead of
	// inventing one.
	Attested *AttestedResourceFacts
	// Checks are the named checks this attestation binds through structured
	// signed result evidence: test-report suite names and explicit signed
	// check results. Only these names become CompletedChecks authority —
	// caller strings never enter.
	Checks []string
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
// attestation resolver plus a stable verifier identity. It derives every
// authority-bearing outcome value from the resolved attestations (Model A):
// the claim supplies identity and proposed window only, and any disagreement
// is recorded on SubmittedClaim rather than trusted.
type FuncEvidenceVerifier struct {
	// Identity is stamped on every DerivedVerifiedOutcome this verifier produces.
	Identity string
	// Resolve resolves one evidence reference into a verified attestation.
	Resolve AttestationResolver
	// Clock stamps VerifiedAt. Nil selects time.Now.
	Clock func() time.Time
}

// Verify resolves every evidence reference on the claim and seals a
// DerivedVerifiedOutcome whose Outcome is entirely verifier-derived.
func (f *FuncEvidenceVerifier) Verify(ctx context.Context, obligation VerificationObligation, submittedClaim VerificationOutcome) (DerivedVerifiedOutcome, error) {
	if f == nil || f.Resolve == nil {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verifier has no attestation resolver", ErrUnverified)
	}
	if f.Identity == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verifier identity is required", ErrUnverified)
	}
	if err := obligation.Validate(); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if err := submittedClaim.Validate(); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	// Addressing is not a proposal: a claim that answers a different
	// obligation (or names a different candidate / snapshot / contract) is a
	// different claim and is refused before any evidence is resolved.
	if err := bindIdentity(obligation, submittedClaim); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if len(submittedClaim.ProvenanceRefs) == 0 {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: claim %q cites no evidence references", ErrEvidence, submittedClaim.VerificationID)
	}
	resolved := make([]ResolvedAttestation, 0, len(submittedClaim.ProvenanceRefs))
	for _, ref := range submittedClaim.ProvenanceRefs {
		if ref == "" {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: empty evidence reference", ErrEvidence)
		}
		if err := ctx.Err(); err != nil {
			return DerivedVerifiedOutcome{}, err
		}
		att, err := f.Resolve(ctx, ref)
		if err != nil {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: evidence %q: %v", ErrEvidence, ref, err)
		}
		if att.ExecutionID == "" || att.EvidenceRoot == "" || att.AttestationDigest == "" {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: evidence %q resolved incompletely (execution id, evidence root and attestation digest are all required)", ErrEvidence, ref)
		}
		if err := validateDigest("resolved evidence_root", att.EvidenceRoot); err != nil {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: evidence %q: %v", ErrEvidence, ref, err)
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
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: attestations disagree on evidence root (%s vs %s)", ErrEvidence, root, att.EvidenceRoot)
		}
		if !seenExec[att.ExecutionID] {
			seenExec[att.ExecutionID] = true
			execIDs = append(execIDs, att.ExecutionID)
		}
		digests = append(digests, att.AttestationDigest)
	}

	// ---- derivation: authority comes only from what the signatures prove ----
	jobStatus := deriveJobStatus(resolved)
	completed := deriveCompletedChecks(resolved, root)
	assurance := deriveAssurance(resolved)
	observed := mergeObserved(resolved)
	attested := mergeAttested(resolved)
	start, end := deriveWindow(submittedClaim, attested)

	derived := VerificationOutcome{
		VerificationID:   submittedClaim.VerificationID,
		ObligationID:     obligation.ObligationID,
		CandidateDigest:  obligation.ImmutableCandidateDigest,
		SnapshotDigest:   obligation.SourceSnapshotDigest,
		ContractDigest:   obligation.VerificationContractDigest,
		Outcome:          deriveResult(obligation, jobStatus, completed, assurance),
		AssuranceProfile: assurance.Name(),
		CompletedChecks:  completed,
		ExecutionIDs:     append([]string(nil), execIDs...),
		EvidenceRoot:     root,
		// Reported resource facts stay the caller's REPORTED assertions
		// (never authority); Measured is substrate-derived below. The
		// claim's proposed economics are preserved on SubmittedClaim.
		Resources: ResourceFacts{
			QueueLatencyNS:      submittedClaim.Resources.QueueLatencyNS,
			ExecutionLatencyNS:  submittedClaim.Resources.ExecutionLatencyNS,
			WallTimeNS:          submittedClaim.Resources.WallTimeNS,
			CPUTimeNS:           submittedClaim.Resources.CPUTimeNS,
			PeakMemoryBytes:     submittedClaim.Resources.PeakMemoryBytes,
			IOBytes:             submittedClaim.Resources.IOBytes,
			CacheHits:           submittedClaim.Resources.CacheHits,
			CacheMisses:         submittedClaim.Resources.CacheMisses,
			RunnerClass:         submittedClaim.Resources.RunnerClass,
			RetryCount:          submittedClaim.Resources.RetryCount,
			Cancelled:           submittedClaim.Resources.Cancelled,
			DuplicateAvoided:    submittedClaim.Resources.DuplicateAvoided,
			Speculative:         submittedClaim.Resources.Speculative,
			VerificationGroupID: submittedClaim.Resources.VerificationGroupID,
			CandidateID:         submittedClaim.Resources.CandidateID,
		},
		StartedAt:      start,
		CompletedAt:    end,
		ProvenanceRefs: append([]string(nil), submittedClaim.ProvenanceRefs...),
	}
	derived.Resources.Measured = DeriveMeasuredFacts(derived, attested)

	now := time.Now
	if f.Clock != nil {
		now = f.Clock
	}
	return sealDerivedOutcome(submittedClaim, derived, VerifiedEvidence{
		ExecutionIDs:       execIDs,
		EvidenceRoot:       root,
		AttestationDigests: digests,
		Attested:           attested,
		JobStatus:          jobStatus,
		CompletedChecks:    completed,
		Assurance:          assurance,
		ObservedControls:   observed,
		VerifierIdentity:   f.Identity,
		VerifiedAt:         now(),
	})
}

// bindIdentity enforces the claim-addressing rule: the submission must answer
// THIS obligation about THIS candidate under THIS source state under THIS
// contract. Unlike the derived values (Model A proposals), a mis-addressed
// claim is a different obligation's answer and is refused — there is no
// rebinding.
func bindIdentity(obligation VerificationObligation, claim VerificationOutcome) error {
	if claim.ObligationID != obligation.ObligationID {
		return fmt.Errorf("%w: claim names obligation %q, expected %q", ErrBinding, claim.ObligationID, obligation.ObligationID)
	}
	if claim.CandidateDigest != obligation.ImmutableCandidateDigest {
		return fmt.Errorf("%w: candidate digest %s does not match obligation %s", ErrBinding, claim.CandidateDigest, obligation.ImmutableCandidateDigest)
	}
	if claim.SnapshotDigest != obligation.SourceSnapshotDigest {
		return fmt.Errorf("%w: snapshot digest %s does not match obligation %s", ErrBinding, claim.SnapshotDigest, obligation.SourceSnapshotDigest)
	}
	if claim.ContractDigest != obligation.VerificationContractDigest {
		return fmt.Errorf("%w: contract digest %s does not match obligation %s", ErrBinding, claim.ContractDigest, obligation.VerificationContractDigest)
	}
	return nil
}

// deriveJobStatus folds the signed job statuses of every attestation into one
// consensus value. "success" requires unanimous success; any failure wins as
// failure; anything else (cancelled, skipped, empty, mixed) is "incomplete".
func deriveJobStatus(resolved []ResolvedAttestation) string {
	if len(resolved) == 0 {
		return "incomplete"
	}
	allSame := true
	for _, att := range resolved {
		if att.Status != resolved[0].Status {
			allSame = false
			break
		}
	}
	if allSame && resolved[0].Status == string(model.StatusSuccess) {
		return string(model.StatusSuccess)
	}
	for _, att := range resolved {
		if att.Status == string(model.StatusFailure) {
			return string(model.StatusFailure)
		}
	}
	if allSame && resolved[0].Status != "" {
		return resolved[0].Status
	}
	return "incomplete"
}

// deriveCompletedChecks builds the authoritative completed-check set from
// structured signed result evidence only:
//
//   - attestation facts: CheckJobStatusSuccess (unanimous signed success) and
//     CheckEvidenceRoot (a committed, well-formed root);
//   - test-report suites / explicit signed check results: the names the
//     resolver surfaced on ResolvedAttestation.Checks.
//
// A caller's CompletedChecks string list is never consulted. The result is
// deterministic: structural names first, then named checks sorted.
func deriveCompletedChecks(resolved []ResolvedAttestation, root Digest) []string {
	out := make([]string, 0, 4)
	if deriveJobStatus(resolved) == string(model.StatusSuccess) {
		out = append(out, CheckJobStatusSuccess)
	}
	if root != "" {
		if err := validateDigest("resolved evidence_root", root); err == nil {
			out = append(out, CheckEvidenceRoot)
		}
	}
	seen := make(map[string]bool, len(out))
	for _, c := range out {
		seen[c] = true
	}
	named := make([]string, 0, len(resolved))
	seenNamed := make(map[string]bool)
	for _, att := range resolved {
		for _, c := range att.Checks {
			if c == "" || seen[c] || seenNamed[c] {
				continue
			}
			seenNamed[c] = true
			named = append(named, c)
		}
	}
	sort.Strings(named)
	return append(out, named...)
}

// deriveAssurance derives the profile label from the signed assurance facts
// with model.DeriveAssuranceProfileSchema — never from the caller's string.
// When several attestations carry facts, the weakest (numerically lowest)
// derived profile wins so one uncontrolled execution cannot be laundered by
// a stronger sibling. An attestation without facts derives the conservative
// unproven profile (model.UnprovenExecutionFacts → uncontrolled).
func deriveAssurance(resolved []ResolvedAttestation) model.ExecutionAssurance {
	weakest := model.AssuranceSealedPinnedNoNetwork
	for _, att := range resolved {
		facts := model.UnprovenExecutionFacts()
		if att.Facts != nil {
			facts = *att.Facts
		}
		schema := att.AssuranceSchema
		if schema == 0 {
			schema = provenanceCurrentAssuranceSchema
		}
		p := model.DeriveAssuranceProfileSchema(schema, facts)
		if p < weakest {
			weakest = p
		}
	}
	return weakest
}

// provenanceCurrentAssuranceSchema is the schema version assumed when a
// resolver does not pin one: the current attestation schema (v6 semantics).
const provenanceCurrentAssuranceSchema = 6

// deriveResult computes the authoritative verdict. Pass requires BOTH the
// signed job status success AND full obligation check coverage by derived
// completed checks (and the derived assurance meeting the required profile);
// a failure status yields fail; anything else (including a missing or
// partial check set, or an assurance shortfall) yields partial and therefore
// can never satisfy ProvenPass.
func deriveResult(obligation VerificationObligation, jobStatus string, completed []string, assurance model.ExecutionAssurance) Outcome {
	if jobStatus == string(model.StatusFailure) {
		return OutcomeFail
	}
	if jobStatus != string(model.StatusSuccess) {
		return OutcomePartial
	}
	covered := make(map[string]bool, len(completed))
	for _, c := range completed {
		covered[c] = true
	}
	for _, need := range obligation.RequiredChecks {
		if !covered[need] {
			return OutcomePartial
		}
	}
	if assurance.Name() != obligation.RequiredAssurance {
		return OutcomePartial
	}
	return OutcomePass
}

// deriveWindow picks the authoritative execution window: the attested job
// window when the evidence carries one (so freshness cannot be satisfied by a
// caller-typed interval), else the claim's proposed window.
func deriveWindow(claim VerificationOutcome, attested *AttestedResourceFacts) (start, end time.Time) {
	if attested != nil && !attested.StartedAt.IsZero() && !attested.FinishedAt.IsZero() {
		return attested.StartedAt, attested.FinishedAt
	}
	return claim.StartedAt, claim.CompletedAt
}

// mergeAttested folds the attested job facts of every resolved attestation
// into one window. Fail closed on a partial set: if some attestations carry a
// job window and others do not, or any window is inverted, the merged facts
// are dropped entirely (nil) rather than reported as attested from a subset —
// a half-attested window would overstate what the signatures prove. When
// every attestation carries a window, the merged facts are the envelope
// (earliest start, latest finish) of the attested executions.
func mergeAttested(resolved []ResolvedAttestation) *AttestedResourceFacts {
	if len(resolved) == 0 {
		return nil
	}
	var merged *AttestedResourceFacts
	for _, att := range resolved {
		if att.Attested == nil {
			return nil
		}
		a := *att.Attested
		if a.StartedAt.IsZero() || a.FinishedAt.IsZero() || a.FinishedAt.Before(a.StartedAt) {
			return nil
		}
		if merged == nil {
			m := a
			merged = &m
			continue
		}
		if a.StartedAt.Before(merged.StartedAt) {
			merged.StartedAt = a.StartedAt
		}
		if a.FinishedAt.After(merged.FinishedAt) {
			merged.FinishedAt = a.FinishedAt
		}
	}
	return merged
}

// mergeObserved folds the executor-observed control receipts of the resolved
// attestations into the derived ObservedControls. Fail closed: when any
// attestation lacks a receipt or the receipts disagree, the derived value is
// nil — there is no single proven observation. When all receipts are present
// and equal, that receipt is the derived one.
func mergeObserved(resolved []ResolvedAttestation) *model.ExecutionControlReceipt {
	if len(resolved) == 0 {
		return nil
	}
	var got *model.ExecutionControlReceipt
	for _, att := range resolved {
		var r *model.ExecutionControlReceipt
		if att.Observed() != nil {
			r = att.Observed()
		}
		if r == nil {
			return nil
		}
		if got == nil {
			c := *r
			got = &c
			continue
		}
		if *got != *r {
			return nil
		}
	}
	return got
}

// Observed returns the executor-observed control receipt the signed
// attestation carries (on the assurance facts), or nil when it carries none.
func (a ResolvedAttestation) Observed() *model.ExecutionControlReceipt {
	if a.Facts == nil {
		return nil
	}
	return a.Facts.Observed
}

// sealDerivedOutcome builds a sealed DerivedVerifiedOutcome. It is the only
// way authority is granted: evidence must be complete and the verifier
// identity present, otherwise nothing is sealed. The derived outcome is
// checked for structural soundness here; obligation binding (including
// freshness) is applied at record time by the registry/store.
func sealDerivedOutcome(submitted, derived VerificationOutcome, evidence VerifiedEvidence) (DerivedVerifiedOutcome, error) {
	if err := derived.Validate(); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if evidence.VerifierIdentity == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verifier identity is required", ErrUnverified)
	}
	if evidence.EvidenceRoot == "" {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: resolved evidence root is required", ErrUnverified)
	}
	if err := validateDigest("resolved evidence_root", evidence.EvidenceRoot); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if len(evidence.AttestationDigests) == 0 {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: at least one attestation digest is required", ErrUnverified)
	}
	if evidence.VerifiedAt.IsZero() {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verified_at is required", ErrUnverified)
	}
	// The derived record must agree with the evidence side: these are the
	// same derivation, restated as a seal invariant so a future edit cannot
	// silently split them.
	if derived.EvidenceRoot != evidence.EvidenceRoot {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: derived evidence root %q disagrees with resolved %q", ErrUnverified, derived.EvidenceRoot, evidence.EvidenceRoot)
	}
	if !equalStringSlices(derived.ExecutionIDs, evidence.ExecutionIDs) {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: derived execution ids %v disagree with resolved %v", ErrUnverified, derived.ExecutionIDs, evidence.ExecutionIDs)
	}
	if !equalStringSlices(derived.CompletedChecks, evidence.CompletedChecks) {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: derived completed checks %v disagree with evidence %v", ErrUnverified, derived.CompletedChecks, evidence.CompletedChecks)
	}
	if derived.AssuranceProfile != evidence.Assurance.Name() {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: derived assurance %q disagrees with evidence %q", ErrUnverified, derived.AssuranceProfile, evidence.Assurance.Name())
	}
	out := DerivedVerifiedOutcome{
		SubmittedClaim: submitted,
		Outcome:        derived,
		Evidence:       evidence,
		sealed:         true,
	}
	return out, nil
}
