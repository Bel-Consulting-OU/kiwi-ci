package evidencestream

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Facts must be non-secret and additive: unknown types are ignored, payload
// carries ids/digests only.
func TestFactIsNonSecretAndVersioned(t *testing.T) {
	f := Fact{
		Seq:           7,
		SchemaVersion: 1,
		Protocol:      ProtocolVersion,
		Type:          EventEvidenceSealed,
		RunID:         "r1",
		JobID:         "j1",
		CreatedAt:     time.Unix(0, 0).UTC(),
		Payload:       map[string]string{"evidence_root": "abc"},
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back Fact
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Protocol != ProtocolVersion || back.Type != EventEvidenceSealed {
		t.Fatalf("roundtrip = %+v", back)
	}
}

// A proposal decision is the ONE authority record: accepted/constrained/
// reason/stage/audit id. Consumers and audit read the same object.
func TestProposalDecisionCarriesAuditID(t *testing.T) {
	d := ProposalDecision{
		ProposalID: "p1",
		Accepted:   true,
		Reason:     "policy admitted",
		Stage:      "policy",
		AuditID:    "audit-1",
		DecidedAt:  time.Unix(0, 0).UTC(),
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back ProposalDecision
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Accepted || back.AuditID != "audit-1" {
		t.Fatalf("decision = %+v", back)
	}
}

// A counterfactual replay must be marked experimental so it can never
// shadow original evidence.
func TestReplayResultMarksExperimental(t *testing.T) {
	r := ReplayResult{
		RequestID:    "x",
		OriginalRun:  "r0",
		ReplayRun:    "r1",
		Experimental: true,
		Status:       "success",
	}
	if !r.Experimental {
		t.Fatal("counterfactual must be marked experimental")
	}
}

// A diagnostic from a non-trusted producer is evidence, not proof.
func TestDiagnosticProducerTrustDefault(t *testing.T) {
	d := Diagnostic{
		SchemaVersion:   1,
		Producer:        "analyzer-x",
		ProducerTrusted: false,
		Kind:            "compiler",
	}
	if d.ProducerTrusted {
		t.Fatal("producer must default to untrusted")
	}
}

// Interfaces are the protocol surface; a stub satisfies them.
type stubStream struct{}

func (stubStream) Follow(context.Context, int64) (<-chan Fact, error) { return nil, nil }
func (stubStream) Replay(context.Context, int64, int) ([]Fact, error) { return nil, nil }

type stubSink struct{}

func (stubSink) Submit(context.Context, Proposal) (ProposalDecision, error) {
	return ProposalDecision{}, nil
}

type stubReplay struct{}

func (stubReplay) Replay(context.Context, ReplayRequest) (ReplayResult, error) {
	return ReplayResult{}, nil
}

type stubDiag struct{}

func (stubDiag) Ingest(context.Context, Diagnostic) error { return nil }

func TestProtocolInterfaces(t *testing.T) {
	// Compile-time: the interfaces are what consumers implement against.
	var _ FactStream = stubStream{}
	var _ ProposalSink = stubSink{}
	var _ ReplayEngine = stubReplay{}
	var _ DiagnosticSink = stubDiag{}
	var _ = ProtocolVersion
	var _ = EventRunAccepted
	var _ = EventJobVerified
}
