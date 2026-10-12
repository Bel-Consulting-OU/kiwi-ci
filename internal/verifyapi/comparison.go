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

// FactFromOutcome derives one neutral fact row from a recorded outcome and
// the candidate identity it answered. The terminal state comes from
// StatusFromCompleteness (evidence completeness plus the derived coarse
// verdict), so a claimed pass without a complete evidence set never becomes
// TerminalPassed here. ArtifactSizeBytes is taken from sizeBytes (0 when
// unknown).
func FactFromOutcome(candidateID string, v VerificationOutcome, c EvidenceCompleteness, artifactSizeBytes int64) CandidateFact {
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
		WallTimeNS:        wall,
		CPUTimeNS:         v.Resources.CPUTimeNS,
		PeakMemoryBytes:   v.Resources.PeakMemoryBytes,
		ArtifactSizeBytes: artifactSizeBytes,
	}
}
