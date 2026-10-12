package verifyapi

import (
	"errors"
	"fmt"
	"time"
)

// Validation and binding errors. Callers must treat every error here as a
// refusal (fail closed): no outcome is recorded and no claim is discharged.
var (
	// ErrInvalid is returned when a domain value fails structural validation.
	ErrInvalid = errors.New("verifyapi: invalid value")
	// ErrNotFound is returned when an id has no record.
	ErrNotFound = errors.New("verifyapi: not found")
	// ErrExists is returned when an id is submitted twice.
	ErrExists = errors.New("verifyapi: already exists")
	// ErrBinding is returned when an outcome does not bind to the obligation
	// it names (wrong candidate, snapshot or contract digest, or wrong
	// assurance / check coverage). The binding rule is absolute: any change
	// to those dimensions is a different obligation.
	ErrBinding = errors.New("verifyapi: binding mismatch")
	// ErrFreshness is returned when an obligation is expired or the outcome
	// is stale relative to the obligation's freshness policy.
	ErrFreshness = errors.New("verifyapi: freshness violation")
	// ErrGroupBinding is returned when an outcome claims a speculative group
	// but is not comparable to it (unknown group/candidate, or a base
	// snapshot other than the group's shared base).
	ErrGroupBinding = errors.New("verifyapi: speculative group mismatch")
)

// validDigest reports whether s is a plausible content digest: non-empty and
// consisting only of lowercase hex characters. Length is not pinned so
// truncated or extended digest algorithms remain representable; the binding
// rule itself is exact string equality, not algorithm identity.
func validDigest(d Digest) bool {
	s := string(d)
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Validate reports whether the obligation is structurally sound. It fails
// closed: missing ids, unpinned digests, an empty check set, an empty
// assurance profile, or a freshness policy that constrains nothing are all
// refusals.
func (o VerificationObligation) Validate() error {
	if o.ObligationID == "" {
		return fmt.Errorf("%w: obligation_id is required", ErrInvalid)
	}
	if o.Subject == "" {
		return fmt.Errorf("%w: subject is required", ErrInvalid)
	}
	if !validDigest(o.ImmutableCandidateDigest) {
		return fmt.Errorf("%w: immutable_candidate_digest is not a digest", ErrInvalid)
	}
	if !validDigest(o.SourceSnapshotDigest) {
		return fmt.Errorf("%w: source_snapshot_digest is not a digest", ErrInvalid)
	}
	if !validDigest(o.VerificationContractDigest) {
		return fmt.Errorf("%w: verification_contract_digest is not a digest", ErrInvalid)
	}
	if len(o.RequiredChecks) == 0 {
		return fmt.Errorf("%w: required_checks must be non-empty", ErrInvalid)
	}
	seen := make(map[string]bool, len(o.RequiredChecks))
	for _, c := range o.RequiredChecks {
		if c == "" {
			return fmt.Errorf("%w: required_checks contains an empty check", ErrInvalid)
		}
		if seen[c] {
			return fmt.Errorf("%w: required_checks contains duplicate %q", ErrInvalid, c)
		}
		seen[c] = true
	}
	if o.RequiredAssurance == "" {
		return fmt.Errorf("%w: required_assurance is required", ErrInvalid)
	}
	if err := o.Freshness.validate(o.IssuedAt); err != nil {
		return err
	}
	if o.IssuedAt.IsZero() {
		return fmt.Errorf("%w: issued_at is required", ErrInvalid)
	}
	return nil
}

// validate reports whether the freshness policy is well-formed and
// constrains at least one dimension. A policy that constrains nothing would
// let an obligation live forever, which the contract forbids.
func (p FreshnessPolicy) validate(issuedAt time.Time) error {
	if p.MaxAgeSeconds == 0 && p.NotAfter == nil {
		return fmt.Errorf("%w: freshness policy must set max_age_seconds or not_after", ErrInvalid)
	}
	if p.MaxAgeSeconds < 0 {
		return fmt.Errorf("%w: freshness max_age_seconds must be >= 0", ErrInvalid)
	}
	if p.MaxAgeSeconds > 0 && issuedAt.IsZero() {
		return fmt.Errorf("%w: freshness max_age_seconds requires issued_at", ErrInvalid)
	}
	if p.NotAfter != nil && !issuedAt.IsZero() && p.NotAfter.Before(issuedAt) {
		return fmt.Errorf("%w: freshness not_after precedes issued_at", ErrInvalid)
	}
	return nil
}

// CheckFreshness enforces the obligation's expiry/freshness policy at the
// given instant against an outcome window of [startedAt, completedAt]. It is
// the single freshness rule both the registry and direct callers share:
//
//   - hard expiry: now must not be past not_after, and neither must the
//     outcome's completed_at (a completion claimed after expiry cannot
//     launder the claim);
//   - max age: completed_at must fall within max_age_seconds of issued_at.
//
// A zero completed_at is treated as "not yet completed" and checked against
// now, so an in-flight recording still cannot outrun expiry.
func (o VerificationObligation) CheckFreshness(now, startedAt, completedAt time.Time) error {
	end := completedAt
	if end.IsZero() {
		end = now
	}
	if o.Freshness.NotAfter != nil {
		if now.After(*o.Freshness.NotAfter) {
			return fmt.Errorf("%w: obligation expired at %s", ErrFreshness, o.Freshness.NotAfter.UTC().Format(time.RFC3339))
		}
		if end.After(*o.Freshness.NotAfter) {
			return fmt.Errorf("%w: outcome completed_at %s is past expiry %s", ErrFreshness, end.UTC().Format(time.RFC3339), o.Freshness.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if o.Freshness.MaxAgeSeconds > 0 {
		maxAge := time.Duration(o.Freshness.MaxAgeSeconds) * time.Second
		if end.Before(o.IssuedAt) {
			return fmt.Errorf("%w: outcome completed_at precedes issued_at", ErrFreshness)
		}
		if end.Sub(o.IssuedAt) > maxAge {
			return fmt.Errorf("%w: outcome is stale (age %s exceeds max_age %s)", ErrFreshness, end.Sub(o.IssuedAt), maxAge)
		}
	}
	return nil
}

// Validate reports whether the outcome is structurally sound. Binding to a
// specific obligation is a separate step (Bind); this check only looks at the
// outcome in isolation.
func (v VerificationOutcome) Validate() error {
	if v.VerificationID == "" {
		return fmt.Errorf("%w: verification_id is required", ErrInvalid)
	}
	if v.ObligationID == "" {
		return fmt.Errorf("%w: obligation_id is required", ErrInvalid)
	}
	if !validDigest(v.CandidateDigest) {
		return fmt.Errorf("%w: candidate_digest is not a digest", ErrInvalid)
	}
	if !validDigest(v.SnapshotDigest) {
		return fmt.Errorf("%w: snapshot_digest is not a digest", ErrInvalid)
	}
	if !validDigest(v.ContractDigest) {
		return fmt.Errorf("%w: contract_digest is not a digest", ErrInvalid)
	}
	if !v.Outcome.Valid() {
		return fmt.Errorf("%w: outcome %q is not pass/fail/partial", ErrInvalid, v.Outcome)
	}
	if v.AssuranceProfile == "" {
		return fmt.Errorf("%w: assurance_profile is required", ErrInvalid)
	}
	if v.EvidenceRoot == "" {
		return fmt.Errorf("%w: evidence_root is required", ErrInvalid)
	}
	if v.StartedAt.IsZero() {
		return fmt.Errorf("%w: started_at is required", ErrInvalid)
	}
	if v.CompletedAt.IsZero() {
		return fmt.Errorf("%w: completed_at is required", ErrInvalid)
	}
	if v.CompletedAt.Before(v.StartedAt) {
		return fmt.Errorf("%w: completed_at precedes started_at", ErrInvalid)
	}
	for i, id := range v.ExecutionIDs {
		if id == "" {
			return fmt.Errorf("%w: execution_ids[%d] is empty", ErrInvalid, i)
		}
	}
	if err := v.Resources.validate(); err != nil {
		return err
	}
	return nil
}

// validate reports whether the resource facts are structurally sound: no
// negative measurements, and a non-empty runner class so rows stay
// comparable. Durations are nanoseconds and sizes are bytes by contract.
func (r ResourceFacts) validate() error {
	if r.QueueLatencyNS < 0 {
		return fmt.Errorf("%w: queue_latency_ns must be >= 0", ErrInvalid)
	}
	if r.ExecutionLatencyNS < 0 {
		return fmt.Errorf("%w: execution_latency_ns must be >= 0", ErrInvalid)
	}
	if r.WallTimeNS < 0 {
		return fmt.Errorf("%w: wall_time_ns must be >= 0", ErrInvalid)
	}
	if r.CPUTimeNS < 0 {
		return fmt.Errorf("%w: cpu_time_ns must be >= 0", ErrInvalid)
	}
	if r.PeakMemoryBytes < 0 {
		return fmt.Errorf("%w: peak_memory_bytes must be >= 0", ErrInvalid)
	}
	if r.IOBytes < 0 {
		return fmt.Errorf("%w: io_bytes must be >= 0", ErrInvalid)
	}
	if r.CacheHits < 0 {
		return fmt.Errorf("%w: cache_hits must be >= 0", ErrInvalid)
	}
	if r.CacheMisses < 0 {
		return fmt.Errorf("%w: cache_misses must be >= 0", ErrInvalid)
	}
	if r.RunnerClass == "" {
		return fmt.Errorf("%w: runner_class is required", ErrInvalid)
	}
	if r.RetryCount < 0 {
		return fmt.Errorf("%w: retry_count must be >= 0", ErrInvalid)
	}
	if r.Speculative {
		if r.VerificationGroupID == "" {
			return fmt.Errorf("%w: speculative resources require verification_group_id", ErrInvalid)
		}
		if r.CandidateID == "" {
			return fmt.Errorf("%w: speculative resources require candidate_id", ErrInvalid)
		}
	}
	return nil
}

// Validate reports whether the speculative group is structurally sound: a
// pinned shared base, and a non-empty candidate set with valid digests.
func (g SpeculativeGroup) Validate() error {
	if g.VerificationGroupID == "" {
		return fmt.Errorf("%w: verification_group_id is required", ErrInvalid)
	}
	if !validDigest(g.BaseSnapshotDigest) {
		return fmt.Errorf("%w: base_snapshot_digest is not a digest", ErrInvalid)
	}
	if len(g.CandidateDigests) == 0 {
		return fmt.Errorf("%w: candidate_digests must be non-empty", ErrInvalid)
	}
	for id, d := range g.CandidateDigests {
		if id == "" {
			return fmt.Errorf("%w: candidate_digests contains an empty candidate id", ErrInvalid)
		}
		if !validDigest(d) {
			return fmt.Errorf("%w: candidate_digests[%s] is not a digest", ErrInvalid, id)
		}
	}
	return nil
}

// Bind enforces the binding rule: the outcome is accepted for the obligation
// only when it answers THAT obligation about THAT candidate under THAT source
// state under THAT contract, and the claim itself is coherent. Any mismatch is
// refused (ErrBinding / ErrFreshness / ErrInvalid); there is no rebinding and
// no partial acceptance.
//
// Exact checks:
//
//   - the outcome names the obligation;
//   - candidate, snapshot and contract digests equal the obligation's;
//   - the claimed assurance profile equals the required one;
//   - a pass claim covers every required check and is not cancelled;
//   - the freshness policy holds at now for the outcome's window;
//   - the outcome itself is structurally valid.
func Bind(obligation VerificationObligation, outcome VerificationOutcome, now time.Time) error {
	if err := obligation.Validate(); err != nil {
		return err
	}
	if err := outcome.Validate(); err != nil {
		return err
	}
	if outcome.ObligationID != obligation.ObligationID {
		return fmt.Errorf("%w: outcome names obligation %q, expected %q", ErrBinding, outcome.ObligationID, obligation.ObligationID)
	}
	if outcome.CandidateDigest != obligation.ImmutableCandidateDigest {
		return fmt.Errorf("%w: candidate digest %s does not match obligation %s", ErrBinding, outcome.CandidateDigest, obligation.ImmutableCandidateDigest)
	}
	if outcome.SnapshotDigest != obligation.SourceSnapshotDigest {
		return fmt.Errorf("%w: snapshot digest %s does not match obligation %s", ErrBinding, outcome.SnapshotDigest, obligation.SourceSnapshotDigest)
	}
	if outcome.ContractDigest != obligation.VerificationContractDigest {
		return fmt.Errorf("%w: contract digest %s does not match obligation %s", ErrBinding, outcome.ContractDigest, obligation.VerificationContractDigest)
	}
	if outcome.AssuranceProfile != obligation.RequiredAssurance {
		return fmt.Errorf("%w: assurance profile %q does not match required %q", ErrBinding, outcome.AssuranceProfile, obligation.RequiredAssurance)
	}
	if outcome.Outcome == OutcomePass {
		if outcome.Resources.Cancelled {
			return fmt.Errorf("%w: cancelled execution cannot claim pass", ErrBinding)
		}
		covered := make(map[string]bool, len(outcome.CompletedChecks))
		for _, c := range outcome.CompletedChecks {
			covered[c] = true
		}
		for _, need := range obligation.RequiredChecks {
			if !covered[need] {
				return fmt.Errorf("%w: pass claim is missing required check %q", ErrBinding, need)
			}
		}
	}
	return obligation.CheckFreshness(now, outcome.StartedAt, outcome.CompletedAt)
}

// BindGroup enforces speculative-group comparability: the outcome must be a
// member of the named group, under the candidate id it claims, and must bind
// to the group's shared base snapshot. Anything else is refused — a resource
// comparison across different base states is meaningless.
func BindGroup(group SpeculativeGroup, outcome VerificationOutcome) error {
	if err := group.Validate(); err != nil {
		return err
	}
	rf := outcome.Resources
	if !rf.Speculative {
		return fmt.Errorf("%w: outcome resources are not marked speculative", ErrGroupBinding)
	}
	if rf.VerificationGroupID != group.VerificationGroupID {
		return fmt.Errorf("%w: outcome names group %q, expected %q", ErrGroupBinding, rf.VerificationGroupID, group.VerificationGroupID)
	}
	digest, ok := group.CandidateDigests[rf.CandidateID]
	if !ok {
		return fmt.Errorf("%w: candidate %q is not a member of group %q", ErrGroupBinding, rf.CandidateID, group.VerificationGroupID)
	}
	if outcome.CandidateDigest != digest {
		return fmt.Errorf("%w: candidate digest %s does not match group member %q (%s)", ErrGroupBinding, outcome.CandidateDigest, rf.CandidateID, digest)
	}
	if outcome.SnapshotDigest != group.BaseSnapshotDigest {
		return fmt.Errorf("%w: snapshot digest %s does not match group base %s", ErrGroupBinding, outcome.SnapshotDigest, group.BaseSnapshotDigest)
	}
	return nil
}
