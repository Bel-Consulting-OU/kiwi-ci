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

// CheckOutcome is the evidence-derived verdict of one verified check. It is
// computed from signed result material (report cases, attestation facts) —
// never copied from a caller's claim.
type CheckOutcome string

const (
	// CheckOutcomePass: the check's evidence proves every case passed.
	CheckOutcomePass CheckOutcome = "pass"
	// CheckOutcomeFail: the check's evidence proves at least one failure.
	CheckOutcomeFail CheckOutcome = "fail"
	// CheckOutcomeError: the check's evidence proves an execution error.
	CheckOutcomeError CheckOutcome = "error"
	// CheckOutcomeIncomplete: the evidence does not prove a terminal
	// pass/fail/error (empty suite, all skipped, or no resolvable report).
	// Incomplete never satisfies an obligation requirement.
	CheckOutcomeIncomplete CheckOutcome = "incomplete"
	// CheckOutcomeConflict: the same-named check carries contradictory
	// evidence-derived outcomes across attestations (e.g. one pass and one
	// fail). The conflict is NOT resolved first-wins; the check is invalid
	// and the attempt's terminal state is evidence_invalid (P3g).
	CheckOutcomeConflict CheckOutcome = "conflict"
)

// Valid reports whether o is one of the closed check-outcome vocabulary values.
func (o CheckOutcome) Valid() bool {
	switch o {
	case CheckOutcomePass, CheckOutcomeFail, CheckOutcomeError, CheckOutcomeIncomplete, CheckOutcomeConflict:
		return true
	}
	return false
}

// VerifiedCheck is one evidence-derived required-check result. Name is the
// check identity the obligation demands; Outcome is derived from the signed
// report cases (or structural attestation facts); EvidenceDigest commits the
// material the outcome was derived from (the signed suite digest for a
// test-report check, the evidence root for a structural check); ExecutionID
// names the execution the evidence binds.
//
// Obligation satisfaction requires Outcome == CheckOutcomePass — a check
// that merely ran (or merely appears by name in a caller's list) never
// discharges a requirement.
type VerifiedCheck struct {
	// Name is the check identity (matches VerificationObligation.RequiredChecks).
	Name string `json:"name"`
	// Outcome is the evidence-derived verdict (pass/fail/error/incomplete).
	Outcome CheckOutcome `json:"outcome"`
	// EvidenceDigest commits the signed material the verdict was derived
	// from (the test-report suite digest, or the evidence root).
	EvidenceDigest Digest `json:"evidence_digest"`
	// ExecutionID is the execution whose evidence produced this check.
	ExecutionID string `json:"execution_id"`
}

// Passed reports whether this check satisfies an obligation requirement.
// A conflicted check never passes.
func (c VerifiedCheck) Passed() bool { return c.Outcome == CheckOutcomePass }

// hasCheckConflicts reports whether any check carries the conflict marker
// (P3g): same-name evidence-derived outcomes that disagree across
// attestations. A conflicted evidence set is invalid — never first-wins.
func hasCheckConflicts(checks []VerifiedCheck) bool {
	for _, c := range checks {
		if c.Outcome == CheckOutcomeConflict {
			return true
		}
	}
	return false
}

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
	// Window is the authoritative execution window derived from the
	// resolved evidence, tagged with the source that established it. A
	// caller-typed claim window is never a source: when the attestations
	// carry no window the source is WindowSourceUnknown and freshness is
	// UNKNOWN (never satisfied). See ExecutionWindow.
	Window ExecutionWindow `json:"window"`
	// Kinds lists the evidence kinds the verifier derived as present
	// (EvidenceKindExecutionAttestation, EvidenceKindTestReport, …). It is
	// computed from the resolved material, never caller-asserted, and is
	// what Recipe.EvidenceMinimum.RequiredKinds is matched against.
	Kinds []string `json:"kinds,omitempty"`
	// JobStatus is the consensus signed job status derived from the
	// attestations: "success" only when every attestation reports success,
	// "failure" when any reports failure, otherwise "incomplete".
	JobStatus string `json:"job_status"`
	// CompletedChecks lists the names of the verified checks whose
	// evidence-derived Outcome is pass. It is derived from VerifiedChecks
	// and is the wire-facing subset an obligation requirement is matched
	// against. Never caller strings.
	CompletedChecks []string `json:"completed_checks"`
	// VerifiedChecks is the full evidence-derived check set with outcomes.
	// This is the authority: a name appears in CompletedChecks only when its
	// VerifiedCheck.Outcome is pass.
	VerifiedChecks []VerifiedCheck `json:"verified_checks,omitempty"`
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
	// ObserverWindow is the observer-reported execution window the signed
	// statement carries (a verified observer report), when it is not the
	// job's own attested window. It is weaker authority than Attested:
	// a freshness demand of RequireAttestedWindow is never satisfied by
	// it alone. Nil when the statement carries no observer window.
	ObserverWindow *AttestedResourceFacts
	// Checks are the evidence-derived check results this attestation binds.
	// Each entry carries a Name plus an Outcome derived from signed result
	// material (test-report cases, explicit signed check results) — never a
	// caller string and never a bare name that implies pass. Only a
	// VerifiedCheck whose Outcome is CheckOutcomePass becomes CompletedChecks
	// authority.
	Checks []VerifiedCheck
}

// TestReportLookup resolves a signed suite digest to the stored test report
// it commits. Implementations must fail closed: a digest with no matching
// stored report yields (nil, false), and the check is then derived as
// incomplete — never as pass. The lookup is the seam that turns a signed
// SuiteDigest into report cases whose pass/fail/error/incomplete verdict the
// verifier derives itself (rather than trusting a caller-named check list).
type TestReportLookup func(ctx context.Context, suiteDigest string) (*model.TestReport, bool)

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
	verifiedChecks := deriveVerifiedChecks(resolved, root)
	completed := completedCheckNames(verifiedChecks)
	assurance := deriveAssurance(resolved)
	observed := mergeObserved(resolved)
	attested := mergeAttested(resolved)
	observer := mergeObserver(resolved)
	window := deriveWindow(submittedClaim, attested, observer)
	kinds := deriveEvidenceKinds(resolved, verifiedChecks)
	// Freshness authority: a caller-typed window is never a source, so an
	// Unknown window leaves freshness UNKNOWN (NOT satisfied). A pass claim
	// without a trusted execution window is downgraded — it can never
	// discharge as a proven pass.
	result := deriveResult(obligation, jobStatus, verifiedChecks, assurance)
	if result == OutcomePass && !window.SatisfiesFreshness(MinWindowForRequireAttested(false)) {
		result = OutcomePartial
	}

	derived := VerificationOutcome{
		VerificationID:   submittedClaim.VerificationID,
		ObligationID:     obligation.ObligationID,
		CandidateDigest:  obligation.ImmutableCandidateDigest,
		SnapshotDigest:   obligation.SourceSnapshotDigest,
		ContractDigest:   obligation.VerificationContractDigest,
		Outcome:          result,
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
		StartedAt:      window.StartedAt,
		CompletedAt:    window.CompletedAt,
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
		Window:             window,
		Kinds:              kinds,
		JobStatus:          jobStatus,
		CompletedChecks:    completed,
		VerifiedChecks:     verifiedChecks,
		Assurance:          assurance,
		ObservedControls:   observed,
		VerifierIdentity:   f.Identity,
		VerifiedAt:         now(),
	})
}

// rederiveEvidenceWindowKinds returns e with its policy-facing Window and
// Kinds recomputed exclusively from MAC-verified material: the window from
// the attested job facts (attested exactly when those facts exist) and the
// kinds from the attestation digests and verified checks. The persisted
// Window / Kinds fields are never consulted — a database writer cannot forge
// an attested window or inject an evidence kind, and a signed-but-inconsistent
// record can never feed policy a window or kind set the material does not
// prove. The claim supplies only the structural bracket of an Unknown
// window (the same role it plays in deriveWindow) and is itself digest-bound.
func rederiveEvidenceWindowKinds(e VerifiedEvidence, claim VerificationOutcome) VerifiedEvidence {
	e.Window = deriveWindow(claim, e.Attested, nil)
	e.Kinds = rederiveKinds(e)
	return e
}

// rederiveKinds recomputes the evidence-kind set from MAC-verified material
// only: an execution-attestation kind is present exactly when attestation
// digests were resolved, and a test-report kind exactly when some verified
// check's verdict was derived from a suite digest other than the shared
// evidence root. Same rule as deriveEvidenceKinds, restated over the
// persisted primitives instead of the resolver's view.
func rederiveKinds(e VerifiedEvidence) []string {
	var kinds []string
	if len(e.AttestationDigests) > 0 {
		kinds = append(kinds, EvidenceKindExecutionAttestation)
	}
	for _, c := range e.VerifiedChecks {
		if c.EvidenceDigest != "" && c.EvidenceDigest != e.EvidenceRoot {
			kinds = append(kinds, EvidenceKindTestReport)
			break
		}
	}
	return kinds
}

// deriveEvidenceKinds computes the verifier-derived evidence-kind set: a
// resolved execution attestation is always "execution-attestation", and a
// check whose verdict was derived from signed test-report material (its
// EvidenceDigest is a suite digest, not the shared evidence root) is
// "test-report". Never caller strings.
func deriveEvidenceKinds(resolved []ResolvedAttestation, checks []VerifiedCheck) []string {
	seen := map[string]bool{}
	var kinds []string
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	if len(resolved) > 0 {
		add(EvidenceKindExecutionAttestation)
	}
	var root Digest
	if len(resolved) > 0 {
		root = resolved[0].EvidenceRoot
	}
	for _, c := range checks {
		if c.EvidenceDigest != "" && c.EvidenceDigest != root {
			add(EvidenceKindTestReport)
			break
		}
	}
	return kinds
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

// deriveVerifiedChecks builds the authoritative evidence-derived check set.
// Every entry's Outcome is computed from signed result material — never from
// a caller's string list:
//
//   - attestation facts: CheckJobStatusSuccess (unanimous signed success) and
//     CheckEvidenceRoot (a committed, well-formed root);
//   - test-report suites / explicit signed check results: the VerifiedCheck
//     values the resolver surfaced on ResolvedAttestation.Checks, whose
//     outcomes were derived from the signed report cases (pass / fail /
//     error / incomplete) or from the explicit signed check result.
//
// A caller's CompletedChecks string list is never consulted. The result is
// deterministic: structural names first, then named checks sorted by name.
func deriveVerifiedChecks(resolved []ResolvedAttestation, root Digest) []VerifiedCheck {
	out := make([]VerifiedCheck, 0, 4)
	status := deriveJobStatus(resolved)
	if status == string(model.StatusSuccess) {
		out = append(out, VerifiedCheck{
			Name:           CheckJobStatusSuccess,
			Outcome:        CheckOutcomePass,
			EvidenceDigest: root,
		})
	} else if status == string(model.StatusFailure) {
		out = append(out, VerifiedCheck{
			Name:           CheckJobStatusSuccess,
			Outcome:        CheckOutcomeFail,
			EvidenceDigest: root,
		})
	} else {
		out = append(out, VerifiedCheck{
			Name:           CheckJobStatusSuccess,
			Outcome:        CheckOutcomeIncomplete,
			EvidenceDigest: root,
		})
	}
	if root != "" && validateDigest("resolved evidence_root", root) == nil {
		out = append(out, VerifiedCheck{
			Name:           CheckEvidenceRoot,
			Outcome:        CheckOutcomePass,
			EvidenceDigest: root,
		})
	} else {
		out = append(out, VerifiedCheck{
			Name:           CheckEvidenceRoot,
			Outcome:        CheckOutcomeIncomplete,
			EvidenceDigest: root,
		})
	}
	// Aggregate every attestation's result per name instead of first-wins
	// (P3g): a same-name pass+fail (or pass+error) disagreement is a
	// conflict and the check is evidence_invalid — never silently resolved
	// to whichever attestation happened to arrive first. Structural names
	// are already emitted above and are not re-derived here.
	type agg struct {
		pass, fail, error, incomplete bool
		first                         VerifiedCheck
	}
	buckets := map[string]*agg{}
	order := make([]string, 0, len(resolved))
	for _, att := range resolved {
		for _, c := range att.Checks {
			if c.Name == "" || c.Name == CheckJobStatusSuccess || c.Name == CheckEvidenceRoot {
				continue
			}
			a, ok := buckets[c.Name]
			if !ok {
				vc := c
				if vc.ExecutionID == "" {
					vc.ExecutionID = att.ExecutionID
				}
				if vc.EvidenceDigest == "" {
					vc.EvidenceDigest = att.EvidenceRoot
				}
				a = &agg{first: vc}
				buckets[c.Name] = a
				order = append(order, c.Name)
			}
			switch c.Outcome {
			case CheckOutcomePass:
				a.pass = true
			case CheckOutcomeFail:
				a.fail = true
			case CheckOutcomeError:
				a.error = true
			default:
				a.incomplete = true
			}
		}
	}
	named := make([]VerifiedCheck, 0, len(order))
	for _, name := range order {
		a := buckets[name]
		vc := a.first
		switch {
		case a.pass && a.fail, a.pass && a.error:
			// Contradictory evidence for one name: conflict, not first-wins.
			vc.Outcome = CheckOutcomeConflict
		case a.pass:
			vc.Outcome = CheckOutcomePass
		case a.fail:
			vc.Outcome = CheckOutcomeFail
		case a.error:
			vc.Outcome = CheckOutcomeError
		default:
			vc.Outcome = CheckOutcomeIncomplete
		}
		named = append(named, vc)
	}
	sort.SliceStable(named, func(i, j int) bool { return named[i].Name < named[j].Name })
	return append(out, named...)
}

// completedCheckNames returns the names of the verified checks whose
// evidence-derived outcome is pass. Only these names enter CompletedChecks,
// so obligation satisfaction transitively requires VerifiedCheck.Outcome ==
// pass.
func completedCheckNames(checks []VerifiedCheck) []string {
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		if c.Passed() {
			out = append(out, c.Name)
		}
	}
	return out
}

// DeriveCheckOutcomeFromCases computes the evidence-derived verdict of one
// test-report suite from its cases (and its report-level error/failure
// counts). The caller never supplies a verdict — it is derived here:
//
//   - error  when the report carries errors, or any case reports an error
//     message without having passed;
//   - fail   when any non-skipped case did not pass;
//   - incomplete when the suite is empty or every case is skipped (nothing
//     was proven either way);
//   - pass   only when at least one case ran and every non-skipped case passed.
func DeriveCheckOutcomeFromCases(rep model.TestReport) CheckOutcome {
	if rep.Errors > 0 {
		return CheckOutcomeError
	}
	ran := false
	for _, c := range rep.Cases {
		if c.Skipped {
			continue
		}
		ran = true
		if !c.Passed {
			// A failed case with a message is still a fail (the report's
			// Errors counter is the error signal); without one it is a fail
			// too. Either way it is not a pass.
			return CheckOutcomeFail
		}
	}
	if !ran {
		return CheckOutcomeIncomplete
	}
	if rep.Failures > 0 {
		return CheckOutcomeFail
	}
	return CheckOutcomePass
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
// signed job status success AND full obligation check coverage by
// evidence-derived VerifiedChecks whose Outcome is pass (and the derived
// assurance meeting the required profile); a failure status yields fail;
// anything else (including a missing or partial check set, a check whose
// evidence-derived outcome is not pass, or an assurance shortfall) yields
// partial and therefore can never satisfy ProvenPass.
func deriveResult(obligation VerificationObligation, jobStatus string, checks []VerifiedCheck, assurance model.ExecutionAssurance) Outcome {
	if jobStatus == string(model.StatusFailure) {
		return OutcomeFail
	}
	if jobStatus != string(model.StatusSuccess) {
		return OutcomePartial
	}
	passed := make(map[string]bool, len(checks))
	for _, c := range checks {
		if c.Passed() {
			passed[c.Name] = true
		}
	}
	for _, need := range obligation.RequiredChecks {
		if !passed[need] {
			return OutcomePartial
		}
	}
	if assurance.Name() != obligation.RequiredAssurance {
		return OutcomePartial
	}
	return OutcomePass
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
//
// The submitted claim is independently checked against the accepted identity
// (VerificationID, ObligationID, CandidateDigest, SnapshotDigest,
// ContractDigest) so a claim swapped into a persisted row can never restore
// under an identity the acceptance record did not bind.
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
	// Claim-identity rule: the submitted claim must agree with the accepted
	// identity on every binding field. A claim that names a different
	// verification, obligation, candidate, snapshot or contract is a
	// different submission and must not ride along under this seal.
	if submitted.VerificationID != derived.VerificationID {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: submitted claim verification id %q disagrees with accepted %q", ErrUnverified, submitted.VerificationID, derived.VerificationID)
	}
	if submitted.ObligationID != derived.ObligationID {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: submitted claim obligation id %q disagrees with accepted %q", ErrUnverified, submitted.ObligationID, derived.ObligationID)
	}
	if submitted.CandidateDigest != derived.CandidateDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: submitted claim candidate digest %s disagrees with accepted %s", ErrUnverified, submitted.CandidateDigest, derived.CandidateDigest)
	}
	if submitted.SnapshotDigest != derived.SnapshotDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: submitted claim snapshot digest %s disagrees with accepted %s", ErrUnverified, submitted.SnapshotDigest, derived.SnapshotDigest)
	}
	if submitted.ContractDigest != derived.ContractDigest {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: submitted claim contract digest %s disagrees with accepted %s", ErrUnverified, submitted.ContractDigest, derived.ContractDigest)
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
