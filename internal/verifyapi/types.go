package verifyapi

import "time"

// SchemaVersion identifies the verifyapi wire schema. v1 is the first stable
// contract shape; any incompatible change bumps the value and the decoder
// refuses unknown versions rather than guessing.
const SchemaVersion = 1

// Digest is a lowercase hex SHA-256 content digest. Digests are the binding
// atoms of the contract: an outcome is valid only for the exact digests the
// obligation named.
type Digest string

// Outcome is the verdict of one bound verification.
type Outcome string

const (
	// OutcomePass: every required check passed under the claimed profile.
	OutcomePass Outcome = "pass"
	// OutcomeFail: at least one required check failed.
	OutcomeFail Outcome = "fail"
	// OutcomePartial: the verification ran but did not cover the full
	// obligation (interrupted, cancelled mid-flight, or a strict subset of
	// checks completed). Partial never satisfies a pass claim.
	OutcomePartial Outcome = "partial"
)

// Valid reports whether o is one of the closed verdict vocabulary values.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomePass, OutcomeFail, OutcomePartial:
		return true
	}
	return false
}

// FreshnessPolicy is the expiry/freshness contract of one obligation. Zero
// values mean "no constraint on that dimension"; at least one dimension must
// be set so an obligation cannot live forever by omission.
type FreshnessPolicy struct {
	// MaxAgeSeconds bounds the age of the verification relative to the
	// obligation's issued_at: an outcome whose completed_at is further than
	// MaxAgeSeconds after issued_at is stale and refused. Zero = no max age.
	MaxAgeSeconds int64 `json:"max_age_seconds,omitempty"`
	// NotAfter is the hard expiry of the obligation itself: once the clock
	// passes it (or an outcome claims a completed_at past it) the obligation
	// accepts no further outcomes. Zero value = no hard expiry.
	NotAfter *time.Time `json:"not_after,omitempty"`
}

// VerificationObligation is the claim-bound demand for verification. It names
// the subject being verified, pins the immutable candidate, the source
// snapshot and the verification contract by digest, and declares which checks
// and which assurance profile the outcome must carry. Opaque correlation
// metadata travels with the obligation for caller-side joins and is never
// interpreted by the verification substrate.
type VerificationObligation struct {
	// ObligationID is the caller-chosen stable identity of this claim.
	ObligationID string `json:"obligation_id"`
	// Subject names what is being verified (artifact name, service id, …).
	// Opaque to the substrate.
	Subject string `json:"subject"`
	// ImmutableCandidateDigest pins the exact candidate under verification.
	// Any different digest is a different obligation.
	ImmutableCandidateDigest Digest `json:"immutable_candidate_digest"`
	// SourceSnapshotDigest pins the exact source state the candidate was
	// produced from. Any different digest is a different obligation.
	SourceSnapshotDigest Digest `json:"source_snapshot_digest"`
	// VerificationContractDigest pins the contract defining the checks and
	// assurance. Any different digest is a different obligation.
	VerificationContractDigest Digest `json:"verification_contract_digest"`
	// RequiredChecks is the non-empty set of check identities the outcome
	// must have covered to claim pass.
	RequiredChecks []string `json:"required_checks"`
	// RequiredAssurance is the assurance profile the outcome must claim.
	// Opaque string defined by the verification contract.
	RequiredAssurance string `json:"required_assurance"`
	// Freshness is the expiry/freshness policy enforced at record time.
	Freshness FreshnessPolicy `json:"freshness"`
	// OpaqueCorrelationMetadata is free-form caller correlation state. It is
	// preserved and echoed, never interpreted, and never participates in the
	// binding decision.
	OpaqueCorrelationMetadata map[string]string `json:"opaque_correlation_metadata,omitempty"`
	// IssuedAt is when the obligation was issued. Freshness is measured
	// against it.
	IssuedAt time.Time `json:"issued_at"`
}

// ResourceFacts are the neutral economic facts of one verification execution.
// They describe cost and behavior, never money: there are no prices, billing
// dimensions or vendor concepts here. All durations are nanoseconds and all
// sizes are bytes so serialization is unit-stable.
type ResourceFacts struct {
	QueueLatencyNS      int64  `json:"queue_latency_ns"`
	ExecutionLatencyNS  int64  `json:"execution_latency_ns"`
	WallTimeNS          int64  `json:"wall_time_ns"`
	CPUTimeNS           int64  `json:"cpu_time_ns"`
	PeakMemoryBytes     int64  `json:"peak_memory_bytes"`
	IOBytes             int64  `json:"io_bytes"`
	CacheHits           int64  `json:"cache_hits"`
	CacheMisses         int64  `json:"cache_misses"`
	RunnerClass         string `json:"runner_class"`
	RetryCount          int    `json:"retry_count"`
	Cancelled           bool   `json:"cancelled"`
	DuplicateAvoided    bool   `json:"duplicate_avoided"`
	Speculative         bool   `json:"speculative"`
	VerificationGroupID string `json:"verification_group_id,omitempty"`
	CandidateID         string `json:"candidate_id,omitempty"`
}

// VerificationOutcome is the bound result of one verification. It is valid
// only for the exact (obligation, candidate digest, snapshot digest, contract
// digest) tuple it names, plus the evidence root it cites: change any of those
// and the outcome no longer discharges the obligation (see BindingError).
type VerificationOutcome struct {
	// VerificationID is the stable identity of this outcome record.
	VerificationID string `json:"verification_id"`
	// ObligationID is the obligation this outcome answers.
	ObligationID string `json:"obligation_id"`
	// CandidateDigest / SnapshotDigest / ContractDigest must equal the
	// obligation's corresponding digests exactly.
	CandidateDigest Digest `json:"candidate_digest"`
	SnapshotDigest  Digest `json:"snapshot_digest"`
	ContractDigest  Digest `json:"contract_digest"`
	// Outcome is the verdict (pass/fail/partial).
	Outcome Outcome `json:"outcome"`
	// AssuranceProfile is the profile the verification actually achieved.
	// Must equal the obligation's RequiredAssurance on a pass.
	AssuranceProfile string `json:"assurance_profile"`
	// CompletedChecks lists the checks this execution covered. A pass
	// requires RequiredChecks ⊆ CompletedChecks.
	CompletedChecks []string `json:"completed_checks"`
	// ExecutionIDs references the executions that produced this outcome
	// (integration with the execution/provenance surface: the ids are
	// foreign keys the caller can resolve against its own execution store).
	ExecutionIDs []string `json:"execution_ids,omitempty"`
	// EvidenceRoot is the root of the evidence produced (e.g. a provenance
	// root digest). Required: an outcome without evidence cannot discharge a
	// claim.
	EvidenceRoot string `json:"evidence_root"`
	// Resources are the neutral resource facts of the execution.
	Resources ResourceFacts `json:"resources"`
	// StartedAt / CompletedAt bracket the verification window. Freshness is
	// enforced against both.
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	// ProvenanceRefs are opaque provenance references (capsule digests,
	// attestation ids) attached to the outcome. Never interpreted.
	ProvenanceRefs []string `json:"provenance_refs,omitempty"`
}

// SpeculativeGroup ties the outcomes of several candidates that were verified
// against one shared base snapshot, so their ResourceFacts are comparable
// without re-deriving measurements. Group membership is recorded on each
// ResourceFacts row (verification_group_id, candidate_id).
type SpeculativeGroup struct {
	// VerificationGroupID is the stable identity of the group.
	VerificationGroupID string `json:"verification_group_id"`
	// BaseSnapshotDigest is the shared source state every member outcome
	// must name as its SnapshotDigest. A member bound to a different base is
	// not comparable and is refused.
	BaseSnapshotDigest Digest `json:"base_snapshot_digest"`
	// CandidateDigests pins the candidate set of the group, keyed by
	// candidate id. Only these candidates may join the group.
	CandidateDigests map[string]Digest `json:"candidate_digests"`
}

// CandidateFacts is one comparable row of a speculative-group comparison:
// the candidate identity and the resource facts of its outcome.
type CandidateFacts struct {
	CandidateID     string        `json:"candidate_id"`
	CandidateDigest Digest        `json:"candidate_digest"`
	VerificationID  string        `json:"verification_id"`
	Outcome         Outcome       `json:"outcome"`
	Resources       ResourceFacts `json:"resources"`
}

// GroupComparison is the lined-up resource facts of every recorded outcome in
// a speculative group. Rows are ordered by candidate id so the wire shape is
// deterministic.
type GroupComparison struct {
	VerificationGroupID string           `json:"verification_group_id"`
	BaseSnapshotDigest  Digest           `json:"base_snapshot_digest"`
	SchemaVersion       int              `json:"schema_version"`
	Candidates          []CandidateFacts `json:"candidates"`
}
