package verifyapi

import (
	"fmt"
	"sort"
)

// Neutral candidate comparison (P14).
//
// CandidateComparison lines up the verification facts of several candidates
// so a consumer can decide for itself. It is deliberately NEUTRAL: no model
// scores, no utility weights, no rankings, no winner. The row set carries
// only facts the verification substrate already established (terminal state,
// coarse outcome, assurance, wall/CPU/memory, artifact size). A scoring
// layer (an evidence consumer or any other external controller) applies
// its own utility on top of
// these facts; this type never carries one.

// RowAuthority marks how a comparison row became known. Every comparison
// row carries one: "verified" rows derive from a sealed
// DerivedVerifiedOutcome or a re-verified VerificationProof; "claim" rows
// are caller assertions only and are never projected into a plain pass.
type RowAuthority string

const (
	// RowAuthorityVerified: the row's facts come from a sealed,
	// verifier-produced record (or a VerificationProof that re-verified
	// through the acceptance path).
	RowAuthorityVerified RowAuthority = "verified"
	// RowAuthorityClaim: the row is a caller claim preserved for audit.
	// It authorizes nothing and never projects to OutcomePass.
	RowAuthorityClaim RowAuthority = "claim"
)

// CandidateFact is one comparable row of neutral verification facts about a
// single candidate. Every field is a recorded fact, not a judgment.
type CandidateFact struct {
	// CandidateID is the caller's candidate identity inside a comparison.
	CandidateID string `json:"candidate_id"`
	// CandidateDigest pins the exact candidate bytes these facts are
	// about.
	CandidateDigest Digest `json:"candidate_digest"`
	// VerificationID names the verification whose facts are shown (the
	// canonical attempt when several exist).
	VerificationID string `json:"verification_id"`
	// Terminal is the rich terminal state of that attempt.
	Terminal TerminalState `json:"terminal"`
	// Outcome is the coarse projection of Terminal (pass/fail/partial).
	Outcome Outcome `json:"outcome"`
	// Assurance is the profile the attempt achieved.
	Assurance string `json:"assurance"`
	// Authority is how this row became known: "verified" for sealed
	// records, "claim" for caller assertions. A claim row is never
	// projected into a plain pass regardless of its claimed outcome.
	Authority RowAuthority `json:"authority"`
	// WallTimeNS is the wall-clock cost of the attempt in nanoseconds.
	// Substrate-attested when the evidence carried a job window; otherwise
	// the recorded reported figure.
	WallTimeNS int64 `json:"wall_time_ns"`
	// CPUTimeNS is the CPU cost in nanoseconds (reported fact).
	CPUTimeNS int64 `json:"cpu_time_ns"`
	// PeakMemoryBytes is the peak memory footprint (reported fact).
	PeakMemoryBytes int64 `json:"peak_memory_bytes"`
	// ArtifactSizeBytes is the size in bytes of the candidate artifact
	// this attempt verified. Zero when the surface recorded none.
	ArtifactSizeBytes int64 `json:"artifact_size_bytes"`
}

// Validate reports whether the row is structurally sound: identity present,
// valid terminal state, and non-negative cost/size figures. The absence of
// any score field is by type shape and cannot regress.
func (f CandidateFact) Validate() error {
	if f.CandidateID == "" {
		return fmt.Errorf("%w: candidate_id is required", ErrInvalid)
	}
	if err := validateDigest("candidate_digest", f.CandidateDigest); err != nil {
		return err
	}
	if f.VerificationID == "" {
		return fmt.Errorf("%w: verification_id is required", ErrInvalid)
	}
	if !f.Terminal.Valid() {
		return fmt.Errorf("%w: terminal state %q is not a terminal state", ErrInvalid, f.Terminal)
	}
	if f.Outcome != f.Terminal.ProjectCoarse() {
		return fmt.Errorf("%w: outcome %q is not the coarse projection of terminal %q", ErrInvalid, f.Outcome, f.Terminal)
	}
	if f.Assurance == "" {
		return fmt.Errorf("%w: assurance is required", ErrInvalid)
	}
	if f.Authority != RowAuthorityVerified && f.Authority != RowAuthorityClaim {
		return fmt.Errorf("%w: authority %q must be %q or %q", ErrInvalid, f.Authority, RowAuthorityVerified, RowAuthorityClaim)
	}
	if f.Authority == RowAuthorityClaim && f.Outcome == OutcomePass {
		return fmt.Errorf("%w: a claim row is never projected into a plain pass", ErrInvalid)
	}
	for name, n := range map[string]int64{
		"wall_time_ns":        f.WallTimeNS,
		"cpu_time_ns":         f.CPUTimeNS,
		"peak_memory_bytes":   f.PeakMemoryBytes,
		"artifact_size_bytes": f.ArtifactSizeBytes,
	} {
		if n < 0 {
			return fmt.Errorf("%w: %s must be >= 0", ErrInvalid, name)
		}
	}
	return nil
}

// CandidateComparison is the lined-up neutral fact set of several
// candidates. Rows are sorted by CandidateID so the wire shape is
// deterministic. The type has no score, rank, or utility field on purpose:
// see the package comment on this file.
type CandidateComparison struct {
	// SchemaVersion is the verifyapi schema version of this document.
	SchemaVersion int `json:"schema_version"`
	// BaseSnapshotDigest, when set, names the shared source state every
	// row was verified against (the comparability precondition). Empty
	// means the rows were assembled without a shared-base assertion.
	BaseSnapshotDigest Digest `json:"base_snapshot_digest,omitempty"`
	// Candidates holds one fact row per candidate, sorted by
	// CandidateID.
	Candidates []CandidateFact `json:"candidates"`
}

// CompareCandidates assembles the neutral comparison from verified fact
// rows. Rows are validated, de-duplicated by CandidateID (a second row for
// one candidate is refused: pick the canonical attempt before comparing),
// and sorted by CandidateID. No scoring of any kind is applied.
func CompareCandidates(base Digest, rows []CandidateFact) (CandidateComparison, error) {
	if len(rows) == 0 {
		return CandidateComparison{}, fmt.Errorf("%w: comparison needs at least one candidate", ErrInvalid)
	}
	if base != "" {
		if err := validateDigest("base_snapshot_digest", base); err != nil {
			return CandidateComparison{}, err
		}
	}
	out := CandidateComparison{
		SchemaVersion:      SchemaVersion,
		BaseSnapshotDigest: base,
		Candidates:         make([]CandidateFact, 0, len(rows)),
	}
	seen := make(map[string]bool, len(rows))
	for i, r := range rows {
		if err := r.Validate(); err != nil {
			return CandidateComparison{}, fmt.Errorf("candidates[%d]: %w", i, err)
		}
		if seen[r.CandidateID] {
			return CandidateComparison{}, fmt.Errorf("%w: duplicate candidate_id %q", ErrInvalid, r.CandidateID)
		}
		seen[r.CandidateID] = true
		out.Candidates = append(out.Candidates, r)
	}
	sort.Slice(out.Candidates, func(i, j int) bool {
		return out.Candidates[i].CandidateID < out.Candidates[j].CandidateID
	})
	return out, nil
}

// FactFromOutcome derives one neutral fact row from a sealed derived outcome
// and the candidate identity it answered. The terminal state comes from
// StatusFromCompleteness (evidence completeness plus the derived coarse
// verdict), so a claimed pass without a complete evidence set never becomes
// TerminalPassed here. ArtifactSizeBytes is taken from sizeBytes (0 when
// unknown). The row is stamped RowAuthorityVerified only for sealed input:
// an unsealed record is a bare claim and is refused (see CompareClaims for
// the claim-only surface).
func FactFromOutcome(candidateID string, d DerivedVerifiedOutcome, c EvidenceCompleteness, artifactSizeBytes int64) (CandidateFact, error) {
	if !d.Sealed() {
		return CandidateFact{}, fmt.Errorf("%w: FactFromOutcome requires a sealed derived outcome, never a bare claim", ErrUnverified)
	}
	v := d.Outcome
	status := StatusFromCompleteness(c, v.Outcome)
	wall := v.Resources.WallTimeNS
	if v.Resources.Measured != nil && v.Resources.Measured.WallTimeNS > 0 {
		wall = v.Resources.Measured.WallTimeNS
	}
	return CandidateFact{
		CandidateID:       candidateID,
		CandidateDigest:   v.CandidateDigest,
		VerificationID:    v.VerificationID,
		Terminal:          status.Terminal,
		Outcome:           status.Coarse,
		Assurance:         v.AssuranceProfile,
		Authority:         RowAuthorityVerified,
		WallTimeNS:        wall,
		CPUTimeNS:         v.Resources.CPUTimeNS,
		PeakMemoryBytes:   v.Resources.PeakMemoryBytes,
		ArtifactSizeBytes: artifactSizeBytes,
	}, nil
}

// ---------------------------------------------------------------------------
// P2c — verified-only vs claim-only comparison surfaces.
// ---------------------------------------------------------------------------

// VerifiedCandidateSource is one input to CompareVerifiedCandidates: either
// a sealed DerivedVerifiedOutcome or a VerificationProof that will be
// re-verified through the acceptance path. It never holds a raw claim.
type VerifiedCandidateSource struct {
	// CandidateID is the caller's candidate identity inside the comparison.
	CandidateID string
	// ArtifactSizeBytes is the candidate artifact size (0 when unknown).
	ArtifactSizeBytes int64

	derived *DerivedVerifiedOutcome
	proof   *VerificationProof
}

// VerifiedFromDerived wraps a sealed DerivedVerifiedOutcome as a comparison
// source. An unsealed record (a claim) is refused — this constructor is the
// only way a derived record enters the verified comparison.
func VerifiedFromDerived(candidateID string, d DerivedVerifiedOutcome, artifactSizeBytes int64) (VerifiedCandidateSource, error) {
	if candidateID == "" {
		return VerifiedCandidateSource{}, fmt.Errorf("%w: candidate_id is required", ErrInvalid)
	}
	if !d.Sealed() {
		return VerifiedCandidateSource{}, fmt.Errorf("%w: verified comparison accepts only sealed records, never raw claims", ErrUnverified)
	}
	cp := d
	return VerifiedCandidateSource{CandidateID: candidateID, ArtifactSizeBytes: artifactSizeBytes, derived: &cp}, nil
}

// VerifiedFromProof wraps a VerificationProof as a comparison source. The
// proof is re-verified through the acceptance path at comparison time (its
// MAC must verify under the keyring); a proof that does not verify is
// refused rather than partially trusted.
func VerifiedFromProof(candidateID string, p VerificationProof, artifactSizeBytes int64) (VerifiedCandidateSource, error) {
	if candidateID == "" {
		return VerifiedCandidateSource{}, fmt.Errorf("%w: candidate_id is required", ErrInvalid)
	}
	cp := p
	return VerifiedCandidateSource{CandidateID: candidateID, ArtifactSizeBytes: artifactSizeBytes, proof: &cp}, nil
}

// sealed returns the sealed DerivedVerifiedOutcome behind this source,
// re-verifying a proof through the acceptance path when necessary.
func (s VerifiedCandidateSource) sealed(keyring *AcceptanceKeyring) (DerivedVerifiedOutcome, error) {
	if s.derived != nil {
		if !s.derived.Sealed() {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verified comparison accepts only sealed records, never raw claims", ErrUnverified)
		}
		return *s.derived, nil
	}
	if s.proof != nil {
		vp, err := s.proof.Verify(keyring)
		if err != nil {
			return DerivedVerifiedOutcome{}, err
		}
		return vp.Out, nil
	}
	return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verified candidate source is empty", ErrInvalid)
}

// VerifiedCandidateFact is one row of a verified-only comparison. Every field
// is derived from a sealed record; Authority is always "verified".
type VerifiedCandidateFact struct {
	CandidateID       string        `json:"candidate_id"`
	CandidateDigest   Digest        `json:"candidate_digest"`
	VerificationID    string        `json:"verification_id"`
	Terminal          TerminalState `json:"terminal"`
	Outcome           Outcome       `json:"outcome"`
	Assurance         string        `json:"assurance"`
	Authority         RowAuthority  `json:"authority"`
	WallTimeNS        int64         `json:"wall_time_ns"`
	CPUTimeNS         int64         `json:"cpu_time_ns"`
	PeakMemoryBytes   int64         `json:"peak_memory_bytes"`
	ArtifactSizeBytes int64         `json:"artifact_size_bytes"`
}

// Validate reports structural soundness: identity present, valid terminal
// state, coarse projection consistent, and authority is "verified".
func (f VerifiedCandidateFact) Validate() error {
	if f.CandidateID == "" {
		return fmt.Errorf("%w: candidate_id is required", ErrInvalid)
	}
	if err := validateDigest("candidate_digest", f.CandidateDigest); err != nil {
		return err
	}
	if f.VerificationID == "" {
		return fmt.Errorf("%w: verification_id is required", ErrInvalid)
	}
	if !f.Terminal.Valid() {
		return fmt.Errorf("%w: terminal state %q is not a terminal state", ErrInvalid, f.Terminal)
	}
	if f.Outcome != f.Terminal.ProjectCoarse() {
		return fmt.Errorf("%w: outcome %q is not the coarse projection of terminal %q", ErrInvalid, f.Outcome, f.Terminal)
	}
	if f.Assurance == "" {
		return fmt.Errorf("%w: assurance is required", ErrInvalid)
	}
	if f.Authority != RowAuthorityVerified {
		return fmt.Errorf("%w: verified fact authority must be %q", ErrInvalid, RowAuthorityVerified)
	}
	for name, n := range map[string]int64{
		"wall_time_ns":        f.WallTimeNS,
		"cpu_time_ns":         f.CPUTimeNS,
		"peak_memory_bytes":   f.PeakMemoryBytes,
		"artifact_size_bytes": f.ArtifactSizeBytes,
	} {
		if n < 0 {
			return fmt.Errorf("%w: %s must be >= 0", ErrInvalid, name)
		}
	}
	return nil
}

// VerifiedCandidateComparison is the lined-up fact set of several candidates
// built ONLY from sealed DerivedVerifiedOutcome values or re-verified
// VerificationProof values. It never accepts a raw claim, and every row
// carries Authority = "verified".
type VerifiedCandidateComparison struct {
	SchemaVersion      int                     `json:"schema_version"`
	BaseSnapshotDigest Digest                  `json:"base_snapshot_digest,omitempty"`
	Candidates         []VerifiedCandidateFact `json:"candidates"`
}

// CompareVerifiedCandidates assembles the verified-only comparison. Each
// source must yield a sealed DerivedVerifiedOutcome (directly or by
// re-verifying a VerificationProof under keyring); any unsealed or
// unverifiable source is refused. Rows are de-duplicated by CandidateID and
// sorted for a deterministic wire shape. No scoring of any kind is applied.
func CompareVerifiedCandidates(base Digest, sources []VerifiedCandidateSource, keyring *AcceptanceKeyring) (VerifiedCandidateComparison, error) {
	if len(sources) == 0 {
		return VerifiedCandidateComparison{}, fmt.Errorf("%w: comparison needs at least one candidate", ErrInvalid)
	}
	if base != "" {
		if err := validateDigest("base_snapshot_digest", base); err != nil {
			return VerifiedCandidateComparison{}, err
		}
	}
	out := VerifiedCandidateComparison{
		SchemaVersion:      SchemaVersion,
		BaseSnapshotDigest: base,
		Candidates:         make([]VerifiedCandidateFact, 0, len(sources)),
	}
	seen := make(map[string]bool, len(sources))
	for i, s := range sources {
		sealed, err := s.sealed(keyring)
		if err != nil {
			return VerifiedCandidateComparison{}, fmt.Errorf("candidates[%d]: %w", i, err)
		}
		fact := verifiedFactFromDerived(s.CandidateID, s.ArtifactSizeBytes, sealed)
		if err := fact.Validate(); err != nil {
			return VerifiedCandidateComparison{}, fmt.Errorf("candidates[%d]: %w", i, err)
		}
		if seen[fact.CandidateID] {
			return VerifiedCandidateComparison{}, fmt.Errorf("%w: duplicate candidate_id %q", ErrInvalid, fact.CandidateID)
		}
		seen[fact.CandidateID] = true
		out.Candidates = append(out.Candidates, fact)
	}
	sort.Slice(out.Candidates, func(i, j int) bool {
		return out.Candidates[i].CandidateID < out.Candidates[j].CandidateID
	})
	return out, nil
}

// verifiedFactFromDerived projects a sealed record onto one comparison row.
// The terminal state is computed from the derived verdict plus the
// evidence-derived check set: a check conflict (P3g) is evidence_invalid,
// a proven pass is TerminalPassed, a derived fail is TerminalFailed, and
// anything else is evidence_incomplete. The row is never built from a claim.
func verifiedFactFromDerived(candidateID string, artifactSizeBytes int64, d DerivedVerifiedOutcome) VerifiedCandidateFact {
	term, coarse := verifiedTerminal(d)
	wall := d.Outcome.Resources.WallTimeNS
	if d.Outcome.Resources.Measured != nil && d.Outcome.Resources.Measured.WallTimeNS > 0 {
		wall = d.Outcome.Resources.Measured.WallTimeNS
	}
	return VerifiedCandidateFact{
		CandidateID:       candidateID,
		CandidateDigest:   d.Outcome.CandidateDigest,
		VerificationID:    d.Outcome.VerificationID,
		Terminal:          term,
		Outcome:           coarse,
		Assurance:         d.Outcome.AssuranceProfile,
		Authority:         RowAuthorityVerified,
		WallTimeNS:        wall,
		CPUTimeNS:         d.Outcome.Resources.CPUTimeNS,
		PeakMemoryBytes:   d.Outcome.Resources.PeakMemoryBytes,
		ArtifactSizeBytes: artifactSizeBytes,
	}
}

// verifiedTerminal maps a sealed record onto its rich terminal state.
// Check-conflict evidence is invalid (P3g) regardless of the derived
// verdict; a proven pass is the only TerminalPassed.
func verifiedTerminal(d DerivedVerifiedOutcome) (TerminalState, Outcome) {
	if hasCheckConflicts(d.Evidence.VerifiedChecks) {
		return TerminalEvidenceInvalid, TerminalEvidenceInvalid.ProjectCoarse()
	}
	if d.ProvenPass() {
		return TerminalPassed, OutcomePass
	}
	switch d.Outcome.Outcome {
	case OutcomeFail:
		return TerminalFailed, OutcomeFail
	default:
		return TerminalEvidenceIncomplete, TerminalEvidenceIncomplete.ProjectCoarse()
	}
}

// ClaimFact is one row of a claim-only comparison: the caller's assertion,
// preserved for audit. It is NEVER authoritative. The claimed outcome is
// recorded as ClaimedOutcome (never as a projected pass); Authority is
// always "claim".
type ClaimFact struct {
	CandidateID      string       `json:"candidate_id"`
	CandidateDigest  Digest       `json:"candidate_digest"`
	ClaimedOutcome   Outcome      `json:"claimed_outcome"`
	ClaimedAssurance string       `json:"claimed_assurance"`
	Authority        RowAuthority `json:"authority"`
}

// Validate reports structural soundness. A claim row is never projected
// into a plain pass: even a ClaimedOutcome of pass stays a claim.
func (f ClaimFact) Validate() error {
	if f.CandidateID == "" {
		return fmt.Errorf("%w: candidate_id is required", ErrInvalid)
	}
	if err := validateDigest("candidate_digest", f.CandidateDigest); err != nil {
		return err
	}
	if !f.ClaimedOutcome.Valid() {
		return fmt.Errorf("%w: claimed outcome %q is not a valid outcome", ErrInvalid, f.ClaimedOutcome)
	}
	if f.ClaimedAssurance == "" {
		return fmt.Errorf("%w: claimed assurance is required", ErrInvalid)
	}
	if f.Authority != RowAuthorityClaim {
		return fmt.Errorf("%w: claim fact authority must be %q", ErrInvalid, RowAuthorityClaim)
	}
	return nil
}

// AuthoritativeOutcome is the only outcome a consumer may treat as the
// row's standing: a claim never projects to plain pass, regardless of
// ClaimedOutcome. A claimed pass becomes OutcomePartial (unproven).
func (f ClaimFact) AuthoritativeOutcome() Outcome {
	if f.ClaimedOutcome == OutcomePass {
		return OutcomePartial
	}
	return f.ClaimedOutcome
}

// ClaimComparison is the lined-up claim set of several candidates. It is a
// separate type from VerifiedCandidateComparison precisely so a claim can
// never ride along into a verified projection: every row's Authority is
// "claim" and AuthoritativeOutcome never returns pass.
type ClaimComparison struct {
	SchemaVersion      int         `json:"schema_version"`
	BaseSnapshotDigest Digest      `json:"base_snapshot_digest,omitempty"`
	Candidates         []ClaimFact `json:"candidates"`
}

// CompareClaims assembles the claim-only comparison. Rows are validated,
// de-duplicated by CandidateID, and sorted by CandidateID. No scoring and
// no authority projection: a claimed pass stays a claim.
func CompareClaims(base Digest, rows []ClaimFact) (ClaimComparison, error) {
	if len(rows) == 0 {
		return ClaimComparison{}, fmt.Errorf("%w: comparison needs at least one candidate", ErrInvalid)
	}
	if base != "" {
		if err := validateDigest("base_snapshot_digest", base); err != nil {
			return ClaimComparison{}, err
		}
	}
	out := ClaimComparison{
		SchemaVersion:      SchemaVersion,
		BaseSnapshotDigest: base,
		Candidates:         make([]ClaimFact, 0, len(rows)),
	}
	seen := make(map[string]bool, len(rows))
	for i, r := range rows {
		if err := r.Validate(); err != nil {
			return ClaimComparison{}, fmt.Errorf("candidates[%d]: %w", i, err)
		}
		if seen[r.CandidateID] {
			return ClaimComparison{}, fmt.Errorf("%w: duplicate candidate_id %q", ErrInvalid, r.CandidateID)
		}
		seen[r.CandidateID] = true
		out.Candidates = append(out.Candidates, r)
	}
	sort.Slice(out.Candidates, func(i, j int) bool {
		return out.Candidates[i].CandidateID < out.Candidates[j].CandidateID
	})
	return out, nil
}
