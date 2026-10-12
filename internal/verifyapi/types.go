package verifyapi

import "time"

// SchemaVersion identifies the verifyapi wire schema. v1 is the first stable
// contract shape; any incompatible change bumps the value and the decoder
// refuses unknown versions rather than guessing.
const SchemaVersion = 1

// Digest is a lowercase hex SHA-256 content digest (exactly 64 hex chars).
// Digests are the binding atoms of the contract: an outcome is valid only for
// the exact digests the obligation named. Fields documented as digests are
// validated fail-closed at construction, bind and decode.
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
	// NotBefore, when set, delays the earliest acceptable execution start
	// to this instant. The ENTIRE outcome window [started_at, completed_at]
	// must begin at or after max(issued_at, not_before): work that started
	// before the obligation (or before the policy's own window) can never
	// satisfy it. Zero value = no extra delay beyond issued_at.
	NotBefore *time.Time `json:"not_before,omitempty"`
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
	// against it, and the outcome execution interval must begin at or after
	// max(issued_at, freshness.not_before).
	IssuedAt time.Time `json:"issued_at"`
}

// MeasuredResourceFacts are substrate-derived facts of one verification
// execution. They are never caller-asserted: the registry fills them at
// record time from the outcome's own execution interval (and, later, from
// execution evidence), so a resource comparison cannot be gamed by a
// dishonest reporter. Extend this type only with quantities the substrate
// itself can derive or verify.
type MeasuredResourceFacts struct {
	// DurationNS is the execution window in nanoseconds
	// (completed_at - started_at), derived by the registry at record time.
	DurationNS int64 `json:"duration_ns"`
}

// ResourceFacts are the neutral economic facts of one verification execution.
// They describe cost and behavior, never money: there are no prices, billing
// dimensions or vendor concepts here. All durations are nanoseconds and all
// sizes are bytes so serialization is unit-stable.
//
// Every field of ResourceFacts is a REPORTED fact: a caller assertion about
// the execution. CPU time, memory, I/O and cache counters are reported until
// they are tied to execution evidence (an attested runner measurement or an
// equivalent provenance binding); treat them as trustworthy only as far as
// the reporter is. Substrate-derived quantities live in Measured and are
// filled by the registry at record time.
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
	// Measured holds substrate-derived facts (currently the execution
	// duration from started_at/completed_at). Optional on the wire; the
	// registry fills it at record time and overwrites any caller-supplied
	// value. Callers should leave it nil.
	Measured *MeasuredResourceFacts `json:"measured,omitempty"`
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
	// EvidenceRoot is the SHA-256 root of the evidence produced (e.g. a
	// provenance root digest). Required: an outcome without evidence cannot
	// discharge a claim.
	EvidenceRoot Digest `json:"evidence_root"`
	// Resources are the neutral resource facts of the execution. Reported
	// fields are caller assertions; Resources.Measured is filled by the
	// registry at record time.
	Resources ResourceFacts `json:"resources"`
	// StartedAt / CompletedAt bracket the verification window. The entire
	// window must lie inside the obligation's freshness interval: started_at
	// is at or after max(issued_at, freshness.not_before), completed_at is
	// at or before not_after (when set) and within max_age, and
	// started_at <= completed_at.
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
// the candidate identity and the resource facts of its canonical outcome
// attempt. When a candidate has several recorded attempts, CompareGroup
// selects one deterministically (latest completed_at, ties broken by
// ascending verification_id); the row carries that attempt and only it.
type CandidateFacts struct {
	CandidateID     string        `json:"candidate_id"`
	CandidateDigest Digest        `json:"candidate_digest"`
	VerificationID  string        `json:"verification_id"`
	Outcome         Outcome       `json:"outcome"`
	Resources       ResourceFacts `json:"resources"`
}

// GroupComparison is the lined-up resource facts of every recorded outcome in
// a speculative group. Rows are ordered by candidate id so the wire shape is
// deterministic; within each candidate the canonical attempt is selected by
// the rule documented on CompareGroup.
type GroupComparison struct {
	VerificationGroupID string           `json:"verification_group_id"`
	BaseSnapshotDigest  Digest           `json:"base_snapshot_digest"`
	SchemaVersion       int              `json:"schema_version"`
	Candidates          []CandidateFacts `json:"candidates"`
}
