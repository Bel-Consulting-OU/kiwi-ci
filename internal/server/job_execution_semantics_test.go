package server

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestJobExecutionSemanticsPrefersObserved: evidence (attestation, snapshot,
// provenance) must read the COMPLETION's observed interpreter stamp when the
// attempt recorded one, not only the requested stamp — that is the durable
// proof of requested == observed.
func TestJobExecutionSemanticsPrefersObserved(t *testing.T) {
	run := model.Run{ID: "r1", ExecutionSemantics: model.ExecutionSemanticsVersion}
	// Completed under equality: both stamps set → observed wins (same value).
	j := model.Job{
		ID:                         "j1",
		ExecutionSemantics:         model.ExecutionSemanticsVersion,
		ObservedExecutionSemantics: model.ExecutionSemanticsVersion,
	}
	if got := jobExecutionSemantics(j, run); got != model.ExecutionSemanticsVersion {
		t.Fatalf("completed job semantics = %q", got)
	}
	// Observed-only (legacy requested empty, runner reported v3).
	j = model.Job{ID: "j2", ObservedExecutionSemantics: model.ExecutionSemanticsVersion}
	if got := jobExecutionSemantics(j, run); got != model.ExecutionSemanticsVersion {
		t.Fatalf("observed-only semantics = %q", got)
	}
	// Requested only (still running / completed before observed field).
	j = model.Job{ID: "j3", ExecutionSemantics: model.ExecutionSemanticsVersion}
	if got := jobExecutionSemantics(j, run); got != model.ExecutionSemanticsVersion {
		t.Fatalf("requested-only semantics = %q", got)
	}
	// Unstamped job falls back to the run.
	j = model.Job{ID: "j4"}
	if got := jobExecutionSemantics(j, run); got != model.ExecutionSemanticsVersion {
		t.Fatalf("run fallback semantics = %q", got)
	}
	// Fully legacy: empty everywhere stays empty (never guessed).
	j = model.Job{ID: "j5"}
	if got := jobExecutionSemantics(j, model.Run{}); got != "" {
		t.Fatalf("legacy semantics = %q, want empty", got)
	}
}
