package verifyapi

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Registry is the in-process verification substrate: it stores obligations,
// records bound outcomes, and holds speculative groups for comparable
// resource facts. It is safe for concurrent use and it is the authoritative
// API of this package — the HTTP facade is a thin mapping over it.
//
// Storage is intentionally in-memory: persisting verification state is the
// host application's concern (see VerificationStore / MemoryStore; the
// production durable implementation is PostgresStore in
// internal/storage/verifystore).
// The registry never invents executions or evidence: outcome.ExecutionIDs and
// outcome.EvidenceRoot are caller-supplied references into the
// execution/provenance surfaces until an EvidenceVerifier cryptographically
// resolves them into a DerivedVerifiedOutcome.
//
// # Acceptance boundary
//
// RecordOutcome stores a CLAIM: the outcome is validated and bound, but it is
// never proof. Only RecordVerifiedOutcome stores an authoritative result, and
// it accepts only sealed DerivedVerifiedOutcome values (server-created by an
// EvidenceVerifier, with every authority-bearing value DERIVED from the
// signed evidence — the caller's submission is a proposal preserved on
// SubmittedClaim). QueryOutcome returns authoritative records only — a raw
// claim never satisfies it as a proven pass (ErrUnverified).
type Registry struct {
	mu          sync.RWMutex
	clock       func() time.Time
	obligations map[string]VerificationObligation
	// outcomes holds every recorded claim (and the outcome side of verified
	// records) keyed by verification id.
	outcomes map[string]VerificationOutcome
	// verified holds ONLY sealed DerivedVerifiedOutcome records. Membership
	// here is what makes a result authoritative.
	verified     map[string]DerivedVerifiedOutcome
	groups       map[string]SpeculativeGroup
	capabilities map[string]VerifierCapability
}

// NewRegistry returns an empty registry reading wall time from the given
// clock. A nil clock selects time.Now.
func NewRegistry(clock func() time.Time) *Registry {
	if clock == nil {
		clock = time.Now
	}
	return &Registry{
		clock:        clock,
		obligations:  make(map[string]VerificationObligation),
		outcomes:     make(map[string]VerificationOutcome),
		verified:     make(map[string]DerivedVerifiedOutcome),
		groups:       make(map[string]SpeculativeGroup),
		capabilities: make(map[string]VerifierCapability),
	}
}

// SubmitObligation validates and stores a new obligation. Duplicate ids are
// refused: an obligation is an immutable claim and is never replaced in
// place (a changed candidate/source/contract is a different obligation).
func (r *Registry) SubmitObligation(o VerificationObligation) error {
	if err := o.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.obligations[o.ObligationID]; exists {
		return fmt.Errorf("%w: obligation %q", ErrExists, o.ObligationID)
	}
	r.obligations[o.ObligationID] = cloneObligation(o)
	return nil
}

// Obligation fetches a stored obligation by id.
func (r *Registry) Obligation(id string) (VerificationObligation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	o, ok := r.obligations[id]
	if !ok {
		return VerificationObligation{}, fmt.Errorf("%w: obligation %q", ErrNotFound, id)
	}
	return cloneObligation(o), nil
}

// RecordOutcome validates the outcome, binds it to its obligation under the
// binding rule and freshness policy at the registry clock, optionally binds
// it to a speculative group, fills the substrate-derived Measured resource
// facts from the execution interval, and stores it as a CLAIM. Every failure
// is a refusal: the record is not stored and no claim is discharged. A
// recorded claim is never authoritative — it must be evidence-verified and
// stored via RecordVerifiedOutcome to discharge an obligation as proven.
func (r *Registry) RecordOutcome(v VerificationOutcome) error {
	if err := v.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.outcomes[v.VerificationID]; exists {
		return fmt.Errorf("%w: outcome %q", ErrExists, v.VerificationID)
	}
	ob, ok := r.obligations[v.ObligationID]
	if !ok {
		return fmt.Errorf("%w: obligation %q", ErrNotFound, v.ObligationID)
	}
	if err := Bind(ob, v, r.clock()); err != nil {
		return err
	}
	if v.Resources.Speculative {
		g, ok := r.groups[v.Resources.VerificationGroupID]
		if !ok {
			return fmt.Errorf("%w: group %q", ErrGroupBinding, v.Resources.VerificationGroupID)
		}
		if err := BindGroup(g, v); err != nil {
			return err
		}
	}
	// Measured facts are substrate-derived/attested, never caller-asserted:
	// overwrite any supplied value so a dishonest reporter cannot inflate a
	// comparison. A claim has no resolved evidence, so it gets derived facts
	// only (no attested wall time).
	v.Resources.Measured = DeriveMeasuredFacts(v, nil)
	r.outcomes[v.VerificationID] = cloneOutcome(v)
	return nil
}

// RecordVerifiedOutcome stores a sealed DerivedVerifiedOutcome as the
// AUTHORITATIVE result of its verification. Only records produced by an
// EvidenceVerifier (or restored through the acceptance integrity path) are
// accepted: an unsealed value (including a raw submitted outcome) is refused
// with ErrUnverified, so a forged evidence_root can never become a proven
// pass. The derived Outcome inside is validated and bound exactly like a
// claim (including the substrate-derived Measured facts).
//
// Model A split: the caller's submission is kept AS-IS as the stored claim
// (GetOutcome / OutcomesForObligation), and the derived Outcome is stored as
// the authoritative record (QueryOutcome). A claim already stored under the
// same verification id is upgraded only when it is the same submission as the
// record's SubmittedClaim — the derived outcome itself is allowed (and
// expected) to differ from the claim, because the claim is a proposal and the
// derived values are authority.
func (r *Registry) RecordVerifiedOutcome(v DerivedVerifiedOutcome) error {
	if !v.Sealed() {
		return fmt.Errorf("%w: RecordVerifiedOutcome requires a verifier-produced record", ErrUnverified)
	}
	out := v.Outcome
	if err := out.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, exists := r.verified[out.VerificationID]; exists {
		if claimEquivalent(existing.Outcome, out) {
			return nil
		}
		return fmt.Errorf("%w: outcome %q", ErrExists, out.VerificationID)
	}
	ob, ok := r.obligations[out.ObligationID]
	if !ok {
		return fmt.Errorf("%w: obligation %q", ErrNotFound, out.ObligationID)
	}
	if err := Bind(ob, out, r.clock()); err != nil {
		return err
	}
	if out.Resources.Speculative {
		g, ok := r.groups[out.Resources.VerificationGroupID]
		if !ok {
			return fmt.Errorf("%w: group %q", ErrGroupBinding, out.Resources.VerificationGroupID)
		}
		if err := BindGroup(g, out); err != nil {
			return err
		}
	}
	// Measured facts are substrate-derived/attested, never caller-asserted.
	// DurationNS is derived from the outcome window; WallTimeNS is filled
	// only from the sealed evidence's attested job facts (nil on a record
	// whose attestations carry no window).
	out.Resources.Measured = DeriveMeasuredFacts(out, v.Evidence.Attested)
	// Model A: the claim side is stored as submitted, never overwritten by
	// the derived outcome.
	claim := cloneOutcome(v.SubmittedClaim)
	claim.Resources.Measured = DeriveMeasuredFacts(claim, nil)
	if stored, exists := r.outcomes[out.VerificationID]; exists {
		if !claimCompatible(stored, claim) {
			return fmt.Errorf("%w: outcome %q already recorded as a different claim", ErrExists, out.VerificationID)
		}
	} else {
		r.outcomes[out.VerificationID] = claim
	}
	seal := v
	seal.Outcome = cloneOutcome(out)
	r.verified[out.VerificationID] = cloneDerived(seal)
	return nil
}

// claimEquivalent reports whether a stored claim and a verified record's
// outcome are the same submission. Binding-relevant fields, the evidence
// root and the reported resource facts are compared exactly (the
// substrate-derived Measured subset is excluded — it is filled at record
// time) so two different runs cannot share one verification id.
//
// ExecutionIDs use Model A canonicalization instead of strict list equality:
// the submitted claim and the verified evidence keep their id sets DISTINCT
// forever, so evidence-derived id upgrades (empty→one, subset→full,
// duplicates, reordering) must never be treated as claim conflicts. The two
// sets are therefore compared set-wise and a subset relation in either
// direction is accepted; disjoint or partially-overlapping sets remain a
// conflict (a claim naming an id the other side does not is a different
// submission — Verify already refuses any claimed id the attestations do
// not bind).
func claimEquivalent(a, b VerificationOutcome) bool {
	if !(a.VerificationID == b.VerificationID &&
		a.ObligationID == b.ObligationID &&
		a.CandidateDigest == b.CandidateDigest &&
		a.SnapshotDigest == b.SnapshotDigest &&
		a.ContractDigest == b.ContractDigest &&
		a.Outcome == b.Outcome &&
		a.AssuranceProfile == b.AssuranceProfile &&
		a.EvidenceRoot == b.EvidenceRoot &&
		equalStringSlices(a.CompletedChecks, b.CompletedChecks) &&
		equalStringSlices(a.ProvenanceRefs, b.ProvenanceRefs) &&
		a.StartedAt.Equal(b.StartedAt) &&
		a.CompletedAt.Equal(b.CompletedAt)) {
		return false
	}
	if !executionIDsCompatible(a.ExecutionIDs, b.ExecutionIDs) {
		return false
	}
	ra, rb := a.Resources, b.Resources
	ra.Measured, rb.Measured = nil, nil
	return ra == rb
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// claimCompatible reports whether a stored claim and a sealed record's
// SubmittedClaim are the same submission. It is claimEquivalent on every
// dimension except ExecutionIDs, where a subset/superset relationship is
// tolerated: a pre-Model-A sealed record carries the evidence-derived id set
// on its claim side, which is an upgrade of the raw claim (not a different
// claim). Partially-overlapping or disjoint id sets remain a conflict.
func claimCompatible(a, b VerificationOutcome) bool {
	aa, bb := a, b
	aa.ExecutionIDs, bb.ExecutionIDs = nil, nil
	if !claimEquivalent(aa, bb) {
		return false
	}
	return executionIDsCompatible(a.ExecutionIDs, b.ExecutionIDs)
}

// executionIDsCompatible reports whether two execution-id lists may belong to
// the same claim under Model A. Duplicates and ordering are canonicalized
// away; one side being a subset of the other is an evidence-derived id
// upgrade (or a raw claim naming fewer ids than the evidence resolved) and
// is compatible. Disjoint or partially-overlapping sets are not.
func executionIDsCompatible(a, b []string) bool {
	sa, sb := stringSet(a), stringSet(b)
	return isSubset(sa, sb) || isSubset(sb, sa)
}

func stringSet(ids []string) map[string]struct{} {
	s := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		s[id] = struct{}{}
	}
	return s
}

func isSubset(sub, super map[string]struct{}) bool {
	if len(sub) > len(super) {
		return false
	}
	for id := range sub {
		if _, ok := super[id]; !ok {
			return false
		}
	}
	return true
}

// QueryOutcome fetches the authoritative verified record for a verification
// id. A raw submitted outcome kept as a claim never satisfies this query as a
// proven pass: a claim-only id returns ErrUnverified and an unknown id
// returns ErrNotFound. Callers that accept claims may read them via Outcome /
// OutcomesForObligation; callers that need proof must use QueryOutcome (see
// DerivedVerifiedOutcome.ProvenPass).
func (r *Registry) QueryOutcome(id string) (DerivedVerifiedOutcome, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if v, ok := r.verified[id]; ok {
		return cloneDerived(v), nil
	}
	if _, ok := r.outcomes[id]; ok {
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: outcome %q is an unverified claim", ErrUnverified, id)
	}
	return DerivedVerifiedOutcome{}, fmt.Errorf("%w: outcome %q", ErrNotFound, id)
}

// Outcome fetches a stored outcome by id. This returns claims as well as the
// outcome side of verified records; it is NOT proof of verification — use
// QueryOutcome for the authoritative record.
func (r *Registry) Outcome(id string) (VerificationOutcome, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.outcomes[id]
	if !ok {
		return VerificationOutcome{}, fmt.Errorf("%w: outcome %q", ErrNotFound, id)
	}
	return cloneOutcome(v), nil
}

// OutcomesForObligation returns the stored outcomes answering the given
// obligation, ordered by verification id for deterministic iteration.
func (r *Registry) OutcomesForObligation(obligationID string) []VerificationOutcome {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []VerificationOutcome
	for _, v := range r.outcomes {
		if v.ObligationID == obligationID {
			out = append(out, cloneOutcome(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VerificationID < out[j].VerificationID })
	return out
}

// RegisterGroup validates and stores a speculative group. Duplicate ids are
// refused; the candidate set of a stored group is immutable.
func (r *Registry) RegisterGroup(g SpeculativeGroup) error {
	if err := g.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.groups[g.VerificationGroupID]; exists {
		return fmt.Errorf("%w: group %q", ErrExists, g.VerificationGroupID)
	}
	r.groups[g.VerificationGroupID] = cloneGroup(g)
	return nil
}

// Group fetches a stored speculative group by id.
func (r *Registry) Group(id string) (SpeculativeGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.groups[id]
	if !ok {
		return SpeculativeGroup{}, fmt.Errorf("%w: group %q", ErrNotFound, id)
	}
	return cloneGroup(g), nil
}

// betterAttempt reports whether a is the canonical attempt over b when both
// answer the same candidate in a speculative group. The rule is a total order
// over distinct outcomes (verification ids are unique), so map iteration order
// cannot change the winner: latest completed_at wins; ties break by ascending
// verification_id.
func betterAttempt(a, b VerificationOutcome) bool {
	if !a.CompletedAt.Equal(b.CompletedAt) {
		return a.CompletedAt.After(b.CompletedAt)
	}
	return a.VerificationID < b.VerificationID
}

// CompareGroup lines up the resource facts of every recorded outcome in a
// speculative group into comparable rows ordered by candidate id. When a
// candidate has several recorded outcomes, exactly one canonical attempt is
// selected deterministically: the outcome with the latest completed_at wins,
// ties broken by ascending verification_id. Two CompareGroup calls over the
// same stored records therefore always return identical rows and the same
// winner. Outcomes whose base snapshot does not match the group (which
// BindGroup prevents from being recorded) can never appear; the check is
// repeated at comparison time so a caller that reads across surfaces still
// gets fail-closed behavior.
func (r *Registry) CompareGroup(groupID string) (GroupComparison, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.groups[groupID]
	if !ok {
		return GroupComparison{}, fmt.Errorf("%w: group %q", ErrNotFound, groupID)
	}
	byCandidate := make(map[string]VerificationOutcome)
	for _, v := range r.outcomes {
		rf := v.Resources
		if !rf.Speculative || rf.VerificationGroupID != groupID {
			continue
		}
		// Prefer the DERIVED authoritative outcome when one exists: its
		// Measured facts are substrate-filled from evidence. The claim is
		// the fallback for claim-only members.
		if seal, ok := r.verified[v.VerificationID]; ok {
			v = seal.Outcome
		}
		if err := BindGroup(g, v); err != nil {
			return GroupComparison{}, err
		}
		prev, exists := byCandidate[rf.CandidateID]
		if !exists || betterAttempt(v, prev) {
			byCandidate[rf.CandidateID] = v
		}
	}
	ids := make([]string, 0, len(g.CandidateDigests))
	for id := range g.CandidateDigests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := make([]CandidateFacts, 0, len(ids))
	for _, id := range ids {
		row := CandidateFacts{
			CandidateID:     id,
			CandidateDigest: g.CandidateDigests[id],
		}
		if v, ok := byCandidate[id]; ok {
			row.VerificationID = v.VerificationID
			row.Outcome = v.Outcome
			row.Resources = cloneResources(v.Resources)
		}
		rows = append(rows, row)
	}
	return GroupComparison{
		VerificationGroupID: g.VerificationGroupID,
		BaseSnapshotDigest:  g.BaseSnapshotDigest,
		SchemaVersion:       SchemaVersion,
		Candidates:          rows,
	}, nil
}

// RegisterCapability validates and stores a verifier capability row.
// (kind, version) is the identity: a duplicate is refused rather than
// silently replaced, so capability advertising cannot be overwritten by a
// later registrant.
func (r *Registry) RegisterCapability(c VerifierCapability) error {
	if err := c.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := capabilityKey(c)
	if _, exists := r.capabilities[key]; exists {
		return fmt.Errorf("%w: capability %s/%s", ErrExists, c.Kind, c.Version)
	}
	r.capabilities[key] = cloneCapability(c)
	return nil
}

// QueryCapabilities returns the registered capabilities matching every
// non-empty query dimension, ordered by (kind, version) for deterministic
// iteration. A zero query lists them all.
func (r *Registry) QueryCapabilities(q CapabilityQuery) []VerifierCapability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []VerifierCapability
	for _, c := range r.capabilities {
		if q.matches(c) {
			out = append(out, cloneCapability(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func cloneCapability(c VerifierCapability) VerifierCapability {
	out := c
	out.ClaimClasses = append([]string(nil), c.ClaimClasses...)
	out.AssuranceLevels = append([]string(nil), c.AssuranceLevels...)
	out.Platforms = append([]string(nil), c.Platforms...)
	out.EvidenceTypes = append([]string(nil), c.EvidenceTypes...)
	return out
}

func cloneObligation(o VerificationObligation) VerificationObligation {
	out := o
	out.RequiredChecks = append([]string(nil), o.RequiredChecks...)
	if o.SubjectRef != nil {
		s := *o.SubjectRef
		out.SubjectRef = &s
	}
	if o.OpaqueCorrelationMetadata != nil {
		out.OpaqueCorrelationMetadata = make(map[string]string, len(o.OpaqueCorrelationMetadata))
		for k, v := range o.OpaqueCorrelationMetadata {
			out.OpaqueCorrelationMetadata[k] = v
		}
	}
	if o.Freshness.NotAfter != nil {
		t := *o.Freshness.NotAfter
		out.Freshness.NotAfter = &t
	}
	if o.Freshness.NotBefore != nil {
		t := *o.Freshness.NotBefore
		out.Freshness.NotBefore = &t
	}
	return out
}

func cloneOutcome(v VerificationOutcome) VerificationOutcome {
	out := v
	out.CompletedChecks = append([]string(nil), v.CompletedChecks...)
	out.ExecutionIDs = append([]string(nil), v.ExecutionIDs...)
	out.ProvenanceRefs = append([]string(nil), v.ProvenanceRefs...)
	out.Resources = cloneResources(v.Resources)
	return out
}

func cloneResources(r ResourceFacts) ResourceFacts {
	if r.Measured != nil {
		m := *r.Measured
		r.Measured = &m
	}
	return r
}

func cloneDerived(v DerivedVerifiedOutcome) DerivedVerifiedOutcome {
	out := v
	out.SubmittedClaim = cloneOutcome(v.SubmittedClaim)
	out.Outcome = cloneOutcome(v.Outcome)
	out.Evidence.ExecutionIDs = append([]string(nil), v.Evidence.ExecutionIDs...)
	out.Evidence.AttestationDigests = append([]Digest(nil), v.Evidence.AttestationDigests...)
	out.Evidence.CompletedChecks = append([]string(nil), v.Evidence.CompletedChecks...)
	if v.Evidence.Attested != nil {
		a := *v.Evidence.Attested
		out.Evidence.Attested = &a
	}
	if v.Evidence.ObservedControls != nil {
		c := *v.Evidence.ObservedControls
		out.Evidence.ObservedControls = &c
	}
	return out
}

func cloneGroup(g SpeculativeGroup) SpeculativeGroup {
	out := g
	if g.CandidateDigests != nil {
		out.CandidateDigests = make(map[string]Digest, len(g.CandidateDigests))
		for k, v := range g.CandidateDigests {
			out.CandidateDigests[k] = v
		}
	}
	return out
}
