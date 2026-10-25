package storage

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestClaimAllowsRunnerExecutionSemantics: the claim-path predicate refuses
// a job whose stamped interpreter the runner never advertised.
func TestClaimAllowsRunnerExecutionSemantics(t *testing.T) {
	r := model.Runner{
		ID: "r", Capacity: 1,
		SupportedExecutionSemantics: []string{model.LegacyExecutionSemanticsVersion},
	}
	c := LeaseClaim{
		JobID: "j", RunnerID: "r", Generation: 1,
		ExecutionSemantics: model.ExecutionSemanticsVersion,
	}
	if ClaimAllowsRunner(r, c) {
		t.Fatal("legacy runner must not claim a v3 job")
	}
	r.SupportedExecutionSemantics = []string{model.ExecutionSemanticsVersion}
	if !ClaimAllowsRunner(r, c) {
		t.Fatal("v3 runner must claim a v3 job")
	}
	// Empty advertisement = legacy only.
	r.SupportedExecutionSemantics = nil
	if ClaimAllowsRunner(r, c) {
		t.Fatal("runner that never advertised must not claim a stamped v3 job")
	}
	// Empty job stamp (pre-stamp legacy) is always admitted.
	c.ExecutionSemantics = ""
	if !ClaimAllowsRunner(r, c) {
		t.Fatal("empty job stamp must be admitted")
	}
}
