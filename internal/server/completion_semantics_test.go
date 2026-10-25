package server

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCheckCompletionSemantics pins requested == observed before a
// completion is accepted. A STAMPED job requires an explicit equal stamp —
// omission is refused so a pre-gate lease (8a6d34f era) cannot have its
// v2 execution certified as v3 by inference. An UNSTAMPED legacy job still
// accepts whatever the runner reports.
func TestCheckCompletionSemantics(t *testing.T) {
	j := model.Job{ID: "j", ExecutionSemantics: model.ExecutionSemanticsVersion}
	// Match: accepted, observed is the stamp.
	if got, ok := checkCompletionSemantics(j, Complete{ExecutionSemantics: model.ExecutionSemanticsVersion}); !ok || got != model.ExecutionSemanticsVersion {
		t.Fatalf("match: got %q ok=%v", got, ok)
	}
	// Runner omits on a stamped job: refused (no inference).
	if _, ok := checkCompletionSemantics(j, Complete{}); ok {
		t.Fatal("stamped job + omitted execution_semantics must be refused")
	}
	// Mismatch: refused.
	if _, ok := checkCompletionSemantics(j, Complete{ExecutionSemantics: model.LegacyExecutionSemanticsVersion}); ok {
		t.Fatal("mismatch must be refused")
	}
	// Unstamped job: accept whatever the runner reports (legacy path).
	if got, ok := checkCompletionSemantics(model.Job{}, Complete{ExecutionSemantics: model.ExecutionSemanticsVersion}); !ok || got != model.ExecutionSemanticsVersion {
		t.Fatalf("unstamped: got %q ok=%v", got, ok)
	}
	// Unstamped job + empty: also accepted (nothing to contradict).
	if got, ok := checkCompletionSemantics(model.Job{}, Complete{}); !ok || got != "" {
		t.Fatalf("unstamped empty: got %q ok=%v", got, ok)
	}
}
