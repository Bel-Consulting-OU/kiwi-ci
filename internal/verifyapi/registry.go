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
// host application's concern (callers that need durability wrap the registry
// or copy its records into their own stores). The registry never invents
// executions or evidence: outcome.ExecutionIDs and outcome.EvidenceRoot are
// caller-supplied references into the execution/provenance surfaces.
type Registry struct {
	mu          sync.RWMutex
	clock       func() time.Time
	obligations map[string]VerificationObligation
	outcomes    map[string]VerificationOutcome
	groups      map[string]SpeculativeGroup
}

// NewRegistry returns an empty registry reading wall time from the given
// clock. A nil clock selects time.Now.
func NewRegistry(clock func() time.Time) *Registry {
	if clock == nil {
		clock = time.Now
	}
	return &Registry{
		clock:       clock,
		obligations: make(map[string]VerificationObligation),
		outcomes:    make(map[string]VerificationOutcome),
		groups:      make(map[string]SpeculativeGroup),
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
// it to a speculative group, and stores it. Every failure is a refusal: the
// record is not stored and no claim is discharged.
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
	r.outcomes[v.VerificationID] = cloneOutcome(v)
	return nil
}

// Outcome fetches a stored outcome by id.
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

// CompareGroup lines up the resource facts of every recorded outcome in a
// speculative group into comparable rows ordered by candidate id. Outcomes
// whose base snapshot does not match the group (which BindGroup prevents from
// being recorded) can never appear; the check is repeated at comparison time
// so a caller that reads across surfaces still gets fail-closed behavior.
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
		if err := BindGroup(g, v); err != nil {
			return GroupComparison{}, err
		}
		byCandidate[rf.CandidateID] = v
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

func cloneObligation(o VerificationObligation) VerificationObligation {
	out := o
	out.RequiredChecks = append([]string(nil), o.RequiredChecks...)
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
	return r
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
