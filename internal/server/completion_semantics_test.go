package server

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCheckCompletionSemantics pins requested == observed before a
// completion is accepted.
//
//   - Stamped job + explicit equal stamp → accepted.
//   - Stamped job + explicit mismatch → refused (never inferred).
//   - v3 stamped job + omission → refused (the pre-gate false-v3 hole).
//   - v2 stamped job + omission → accepted ONLY as the pre-field drain
//     bridge when LeaseInterpreter is also v2 (or empty: lease predates
//     the field and could only have been granted under the legacy contract).
//   - Unstamped job → whatever the runner reports, including nothing.
func TestCheckCompletionSemantics(t *testing.T) {
	v3 := model.Job{ID: "j3", ExecutionSemantics: model.ExecutionSemanticsVersion, LeaseInterpreter: model.ExecutionSemanticsVersion}
	// Match.
	if got, ok := checkCompletionSemantics(v3, Complete{ExecutionSemantics: model.ExecutionSemanticsVersion}); !ok || got != model.ExecutionSemanticsVersion {
		t.Fatalf("v3 match: got %q ok=%v", got, ok)
	}
	// Mismatch.
	if _, ok := checkCompletionSemantics(v3, Complete{ExecutionSemantics: model.LegacyExecutionSemanticsVersion}); ok {
		t.Fatal("v3 mismatch must be refused")
	}
	// Omission on v3: NEVER inferred (the false-v3 certification hole).
	if _, ok := checkCompletionSemantics(v3, Complete{}); ok {
		t.Fatal("v3 stamped job + omitted execution_semantics must be refused")
	}
	// Omission on v3 with empty LeaseInterpreter: still refused.
	if _, ok := checkCompletionSemantics(model.Job{ID: "j3b", ExecutionSemantics: model.ExecutionSemanticsVersion}, Complete{}); ok {
		t.Fatal("v3 omission without lease interpreter must be refused")
	}

	// v2 drain bridge: explicit match.
	v2 := model.Job{ID: "j2", ExecutionSemantics: model.LegacyExecutionSemanticsVersion, LeaseInterpreter: model.LegacyExecutionSemanticsVersion}
	if got, ok := checkCompletionSemantics(v2, Complete{ExecutionSemantics: model.LegacyExecutionSemanticsVersion}); !ok || got != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("v2 match: got %q ok=%v", got, ok)
	}
	// v2 + explicit v3 → refused.
	if _, ok := checkCompletionSemantics(v2, Complete{ExecutionSemantics: model.ExecutionSemanticsVersion}); ok {
		t.Fatal("v2 job + v3 stamp must be refused")
	}
	// v2 + omission + legacy lease → bridge accepts.
	if got, ok := checkCompletionSemantics(v2, Complete{}); !ok || got != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("v2 drain bridge: got %q ok=%v", got, ok)
	}
	// v2 + omission + empty LeaseInterpreter (lease predates the field) → accepted.
	v2Old := model.Job{ID: "j2o", ExecutionSemantics: model.LegacyExecutionSemanticsVersion}
	if got, ok := checkCompletionSemantics(v2Old, Complete{}); !ok || got != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("v2 pre-field lease: got %q ok=%v", got, ok)
	}
	// v2 + omission but LeaseInterpreter recorded as v3 → refused.
	v2Bad := model.Job{ID: "j2x", ExecutionSemantics: model.LegacyExecutionSemanticsVersion, LeaseInterpreter: model.ExecutionSemanticsVersion}
	if _, ok := checkCompletionSemantics(v2Bad, Complete{}); ok {
		t.Fatal("v2 omission with v3 lease interpreter must be refused")
	}

	// Unstamped job: accept whatever the runner reports, including nothing.
	if got, ok := checkCompletionSemantics(model.Job{}, Complete{ExecutionSemantics: model.ExecutionSemanticsVersion}); !ok || got != model.ExecutionSemanticsVersion {
		t.Fatalf("unstamped: got %q ok=%v", got, ok)
	}
	if got, ok := checkCompletionSemantics(model.Job{}, Complete{}); !ok || got != "" {
		t.Fatalf("unstamped empty: got %q ok=%v", got, ok)
	}
}
