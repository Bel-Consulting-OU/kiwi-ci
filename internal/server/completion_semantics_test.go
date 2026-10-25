package server

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCheckCompletionSemantics pins requested == observed before a
// completion is accepted (and may fill the observed stamp from the job).
func TestCheckCompletionSemantics(t *testing.T) {
	j := model.Job{ID: "j", ExecutionSemantics: model.ExecutionSemanticsVersion}
	// Match: accepted, observed is the stamp.
	if got, ok := checkCompletionSemantics(j, Complete{ExecutionSemantics: model.ExecutionSemanticsVersion}); !ok || got != model.ExecutionSemanticsVersion {
		t.Fatalf("match: got %q ok=%v", got, ok)
	}
	// Runner omits: fill from job stamp (lease already proved support).
	if got, ok := checkCompletionSemantics(j, Complete{}); !ok || got != model.ExecutionSemanticsVersion {
		t.Fatalf("fill: got %q ok=%v", got, ok)
	}
	// Mismatch: refused.
	if _, ok := checkCompletionSemantics(j, Complete{ExecutionSemantics: model.LegacyExecutionSemanticsVersion}); ok {
		t.Fatal("mismatch must be refused")
	}
	// Unstamped job: accept whatever the runner reports (legacy path).
	if got, ok := checkCompletionSemantics(model.Job{}, Complete{ExecutionSemantics: model.ExecutionSemanticsVersion}); !ok || got != model.ExecutionSemanticsVersion {
		t.Fatalf("unstamped: got %q ok=%v", got, ok)
	}
}
