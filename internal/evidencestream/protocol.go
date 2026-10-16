// Package evidencestream is the VERSIONED protocol external evidence
// consumers use to integrate with Kiwi. It is a protocol, not shared
// internal code: consumers talk to these contracts over HTTP/JSON and never
// import Kiwi internals. Kiwi remains the execution and evidence authority;
// a consumer may propose, inspect and replay, but Kiwi independently
// validates policy and decides.
//
// Neutral vocabulary only. Consumer products must not leak into Kiwi's
// domain model — see surfacecheck.TestNoVendorSemanticsInProductionCode.
package evidencestream

import (
	"context"
	"time"
)

// ProtocolVersion is the version of this wire contract. Additive changes
// bump the minor semantics via SchemaVersion on each message; breaking
// changes bump this constant and old endpoints are retired, never mutated.
const ProtocolVersion = 1

// EventType is one immutable fact in the execution stream. Types are the
// same vocabulary as model.ExecutionEvent: consumers read facts, they never
// scrape logs.
type EventType string

const (
	// Lifecycle facts (the stream a consumer plans against).
	EventRunAccepted    EventType = "run.accepted"
	EventRunQueued      EventType = "run.queued"
	EventJobQueued      EventType = "job.queued"
	EventJobLeased      EventType = "job.leased"
	EventStepStarted    EventType = "step.started"
	EventStepFinished   EventType = "step.finished"
	EventDiagnostic     EventType = "diagnostic.produced"
	EventTestFailed     EventType = "test.failed"
	EventArtifact       EventType = "artifact.produced"
	EventLogLine        EventType = "log.produced"
	EventEvidenceSealed EventType = "evidence.sealed"
	EventJobVerified    EventType = "job.verified"
	EventJobSucceeded   EventType = "job.succeeded"
	EventJobFailed      EventType = "job.failed"
	EventRunCompleted   EventType = "run.completed"
)

// Fact is one immutable execution fact. It is append-only: a consumer may
// cache it, index it and plan against it, but never treat it as a mutable
// resource. Seq is the durable cursor from the control plane.
type Fact struct {
	Seq           int64     `json:"seq"`
	SchemaVersion int       `json:"schema_version"`
	Protocol      int       `json:"protocol"`
	Type          EventType `json:"type"`
	RunID         string    `json:"run_id,omitempty"`
	JobID         string    `json:"job_id,omitempty"`
	RepoID        string    `json:"repo_id,omitempty"`
	Attempt       int64     `json:"attempt,omitempty"`
	Actor         string    `json:"actor,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	// Payload is small and non-secret by contract: ids, names, digests,
	// claim KEY names. Never a secret value or plaintext claim.
	Payload map[string]string `json:"payload,omitempty"`
}

// Proposal is a consumer-submitted plan that Kiwi may accept, constrain or
// reject. The consumer is an ADVISOR: Kiwi validates policy, trust floors
// and quotas independently and executes only what it admits.
type Proposal struct {
	// ID is the consumer's correlation id (idempotency key).
	ID string `json:"id"`
	// Kind names the proposal: job-ordering, test-selection, sharding,
	// cache-strategy, runner-placement.
	Kind string `json:"kind"`
	// TargetRun is the run the proposal is about (may be empty for a
	// pre-run planning proposal).
	TargetRun string `json:"target_run,omitempty"`
	// Suggested carries the consumer's recommendation as opaque JSON the
	// consumer owns. Kiwi never interprets consumer semantics — it only
	// validates the execution surface it maps onto (jobs, labels, cache
	// keys) and records what it accepted.
	Suggested jsonRaw `json:"suggested"`
	// Constraints the consumer asks Kiwi to respect (e.g. max_parallel,
	// budget). Advisory; Kiwi may tighten, never loosen, policy.
	Constraints map[string]string `json:"constraints,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// ProposalDecision is Kiwi's verdict on one Proposal. It is the single
// authority record: the same decision is served to the consumer, recorded
// for audit, and applied at execution.
type ProposalDecision struct {
	ProposalID string `json:"proposal_id"`
	// Accepted means Kiwi will execute the (possibly constrained) plan.
	Accepted bool `json:"accepted"`
	// Constrained is the plan Kiwi actually will run. It is never weaker
	// than policy and never weaker than the consumer's constraints.
	Constrained jsonRaw `json:"constrained,omitempty"`
	// Reason is the operator-readable explanation.
	Reason string `json:"reason"`
	// Stage names the authority gate that decided (policy, quota, trust,
	// capacity, syntax).
	Stage string `json:"stage"`
	// AuditID links the durable audit row for this decision.
	AuditID   string    `json:"audit_id,omitempty"`
	DecidedAt time.Time `json:"decided_at"`
}

// ReplayRequest asks Kiwi to replay an exact snapshot or to evaluate a
// counterfactual. Kiwi PRESERVES the distinction between original and
// experimental evidence: a counterfactual run never overwrites or shadows
// the original facts.
type ReplayRequest struct {
	ID string `json:"id"`
	// Mode is "exact" (byte-identical snapshot replay) or "counterfactual"
	// (a modified run derived from the snapshot).
	Mode string `json:"mode"`
	// SnapshotRef names the sealed snapshot to replay from.
	SnapshotRef string `json:"snapshot_ref"`
	// Modifications is the consumer's proposed delta for counterfactual
	// mode. Opaque to Kiwi; it maps onto the execution surface only.
	Modifications jsonRaw `json:"modifications,omitempty"`
	// DistinguishEvidence forces experimental facts to carry the
	// experimental marker so they can never be confused with originals.
	DistinguishEvidence bool `json:"distinguish_evidence"`
}

// ReplayResult is the outcome of one ReplayRequest.
type ReplayResult struct {
	RequestID string `json:"request_id"`
	// OriginalRun is the run the snapshot came from.
	OriginalRun string `json:"original_run"`
	// ReplayRun is the new run (exact or counterfactual).
	ReplayRun string `json:"replay_run"`
	// Experimental is true when the replay facts are marked experimental.
	Experimental bool `json:"experimental"`
	// Status of the replay run.
	Status string `json:"status"`
	// ProvenanceDigest seals the replay's input identity.
	ProvenanceDigest string `json:"provenance_digest,omitempty"`
}

// Diagnostic is a typed analyzer output (compiler/tooling diagnostics,
// dependency graphs, source mappings). Kiwi stores it as typed evidence
// WITHOUT treating the analyzer as verification authority unless policy
// explicitly trusts it.
type Diagnostic struct {
	SchemaVersion int `json:"schema_version"`
	// Producer names the analyzer (a tool identity, not a product brand).
	Producer string `json:"producer"`
	// ProducerTrusted records whether policy admitted this producer as a
	// verification authority. Default false: diagnostics are evidence,
	// not proof.
	ProducerTrusted bool   `json:"producer_trusted"`
	Kind            string `json:"kind"`
	// Subject is the run/job/step the diagnostic is about.
	Subject DiagnosticSubject `json:"subject"`
	// Findings are typed analyzer outputs.
	Findings []DiagnosticFinding `json:"findings,omitempty"`
	// Graph is an optional dependency/source graph (opaque to Kiwi).
	Graph      jsonRaw   `json:"graph,omitempty"`
	ProducedAt time.Time `json:"produced_at"`
}

// DiagnosticSubject locates the diagnostic.
type DiagnosticSubject struct {
	RunID  string `json:"run_id,omitempty"`
	JobID  string `json:"job_id,omitempty"`
	StepID string `json:"step_id,omitempty"`
	// SourceRef is a path:line:col locator when applicable.
	SourceRef string `json:"source_ref,omitempty"`
}

// DiagnosticFinding is one typed analyzer finding.
type DiagnosticFinding struct {
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Code      string `json:"code,omitempty"`
	SourceRef string `json:"source_ref,omitempty"`
}

// FactStream is the read side of the evidence stream. A consumer follows
// facts from a durable cursor; the control plane is the only writer.
type FactStream interface {
	// Follow returns facts after the given Seq, in cursor order. The
	// context ends the subscription.
	Follow(ctx context.Context, afterSeq int64) (<-chan Fact, error)
	// Replay returns a bounded historical window of facts.
	Replay(ctx context.Context, afterSeq int64, limit int) ([]Fact, error)
}

// ProposalSink is the write side of the proposal API.
type ProposalSink interface {
	// Submit posts one proposal and returns Kiwi's decision. Idempotent
	// on Proposal.ID.
	Submit(ctx context.Context, p Proposal) (ProposalDecision, error)
}

// ReplayEngine is the counterfactual/exact-replay side.
type ReplayEngine interface {
	// Replay evaluates one ReplayRequest. Exact replays must be
	// byte-identical in inputs; counterfactuals produce a NEW run whose
	// facts are marked experimental when DistinguishEvidence is set.
	Replay(ctx context.Context, r ReplayRequest) (ReplayResult, error)
}

// DiagnosticSink stores typed analyzer output as evidence.
type DiagnosticSink interface {
	// Ingest records one Diagnostic. A non-trusted producer's output is
	// stored as evidence only and never upgrades a verification result.
	Ingest(ctx context.Context, d Diagnostic) error
}

// jsonRaw is opaque consumer-owned JSON. Kiwi stores and forwards it; it
// never interprets consumer semantics.
type jsonRaw = RawMessage

// RawMessage is opaque JSON carried through the protocol.
type RawMessage []byte
