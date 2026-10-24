package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRunnerProtocolConstants pins the wire-semantic protocol version and its
// task requirement. Changing either without bumping RunnerProtocolVersion (or
// letting JobRequiresProtocol lag/lead it silently) is a protocol break, not
// a refactor: every v2 semantic requirement enumerated on the constant must
// be implemented by both sides before the versions may move.
func TestRunnerProtocolConstants(t *testing.T) {
	if RunnerProtocolVersion != 2 {
		t.Fatalf("RunnerProtocolVersion = %d, want 2 (bump deliberately and document the new semantics)", RunnerProtocolVersion)
	}
	if JobRequiresProtocol != RunnerProtocolVersion {
		t.Fatalf("JobRequiresProtocol = %d, want RunnerProtocolVersion %d", JobRequiresProtocol, RunnerProtocolVersion)
	}
}

// TestRunnerProtocolVersionAdditiveJSON pins the additive persistence
// contract: a runner payload persisted before the field exists decodes as 0
// (legacy v1), and an unset version is omitted from the wire so legacy rows
// round-trip unchanged.
func TestRunnerProtocolVersionAdditiveJSON(t *testing.T) {
	var legacy Runner
	if err := json.Unmarshal([]byte(`{"id":"r1","name":"legacy"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ProtocolVersion != 0 {
		t.Fatalf("legacy payload protocol version = %d, want 0", legacy.ProtocolVersion)
	}
	encoded, err := json.Marshal(Runner{ID: "r1", ProtocolVersion: RunnerProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"protocol_version":2`) {
		t.Fatalf("negotiated version not encoded: %s", encoded)
	}
	omitted, err := json.Marshal(Runner{ID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(omitted), "protocol_version") {
		t.Fatalf("unset protocol version must stay omitted (legacy shape): %s", omitted)
	}
}

// TestExecutionSemanticsConstants pins the SEMANTIC execution-engine version.
// It is deliberately separate from RunnerProtocolVersion: the wire schema and
// the engine semantics move independently, and a change to how durable state
// or compiled jobs are interpreted must bump this constant deliberately (and
// update the reproducibility-boundary documentation).
func TestExecutionSemanticsConstants(t *testing.T) {
	if ExecutionSemanticsVersion != "kiwi.execution.v3" {
		t.Fatalf("ExecutionSemanticsVersion = %q, want %q (bump deliberately, document the new semantics, and expect exact replay to refuse old records)", ExecutionSemanticsVersion, "kiwi.execution.v3")
	}
}

// TestExecutionSemanticsAdditiveJSON pins the additive persistence contract:
// a run/job/snapshot payload persisted before the field existed decodes with
// the empty string (legacy: predates semantics stamping), a stamped record
// round-trips, and an absent stamp stays omitted from the wire so legacy rows
// serialize unchanged.
func TestExecutionSemanticsAdditiveJSON(t *testing.T) {
	var legacyRun Run
	if err := json.Unmarshal([]byte(`{"id":"r1","status":"queued"}`), &legacyRun); err != nil {
		t.Fatal(err)
	}
	if legacyRun.ExecutionSemantics != "" {
		t.Fatalf("legacy run semantics = %q, want empty", legacyRun.ExecutionSemantics)
	}
	var legacyJob Job
	if err := json.Unmarshal([]byte(`{"id":"j1","run_id":"r1"}`), &legacyJob); err != nil {
		t.Fatal(err)
	}
	if legacyJob.ExecutionSemantics != "" {
		t.Fatalf("legacy job semantics = %q, want empty", legacyJob.ExecutionSemantics)
	}
	var legacySnap SnapshotRecord
	if err := json.Unmarshal([]byte(`{"id":"s1","run_id":"r1"}`), &legacySnap); err != nil {
		t.Fatal(err)
	}
	if legacySnap.ExecutionSemantics != "" {
		t.Fatalf("legacy snapshot semantics = %q, want empty", legacySnap.ExecutionSemantics)
	}

	stampedRun, err := json.Marshal(Run{ID: "r1", ExecutionSemantics: ExecutionSemanticsVersion})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stampedRun), `"execution_semantics":"`+ExecutionSemanticsVersion+`"`) {
		t.Fatalf("run semantics not encoded: %s", stampedRun)
	}
	stampedJob, err := json.Marshal(Job{ID: "j1", RunID: "r1", ExecutionSemantics: ExecutionSemanticsVersion})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stampedJob), `"execution_semantics":"`+ExecutionSemanticsVersion+`"`) {
		t.Fatalf("job semantics not encoded: %s", stampedJob)
	}
	stampedSnap, err := json.Marshal(SnapshotRecord{ID: "s1", RunID: "r1", ExecutionSemantics: ExecutionSemanticsVersion})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stampedSnap), `"execution_semantics":"`+ExecutionSemanticsVersion+`"`) {
		t.Fatalf("snapshot semantics not encoded: %s", stampedSnap)
	}

	for name, v := range map[string]any{"run": Run{ID: "r1"}, "job": Job{ID: "j1"}, "snapshot": SnapshotRecord{ID: "s1"}} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "execution_semantics") {
			t.Fatalf("unset %s semantics must stay omitted (legacy shape): %s", name, raw)
		}
	}
}
