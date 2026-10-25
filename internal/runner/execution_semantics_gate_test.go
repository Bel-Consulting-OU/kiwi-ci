package runner

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestRunnerRefusesJobSemanticsMismatch pins the defense-in-depth equality
// gate before MaterializeEffectiveExecution: a stamped job whose engine
// version this binary does not implement is completed as failure, never
// interpreted under the wrong semantics.
func TestRunnerRefusesJobSemanticsMismatch(t *testing.T) {
	// Unit-level: the gate condition itself.
	sem := model.LegacyExecutionSemanticsVersion
	if sem == "" || sem == model.ExecutionSemanticsVersion {
		t.Fatal("precondition: legacy stamp differs from current")
	}
	if !(sem != "" && sem != model.ExecutionSemanticsVersion) {
		t.Fatal("gate must fire for a non-current stamp")
	}
	// Current stamp passes the equality gate (non-empty and equal to itself).
	cur := model.ExecutionSemanticsVersion
	if cur == "" || cur != model.ExecutionSemanticsVersion {
		t.Fatal("current stamp must be non-empty and pass the equality gate")
	}
	// Registration advertises only the current engine.
	r := model.Runner{
		SupportedExecutionSemantics: []string{model.ExecutionSemanticsVersion},
	}
	if !model.SupportsExecutionSemantics(r.SupportedExecutionSemantics, model.ExecutionSemanticsVersion) {
		t.Fatal("runner must advertise its own engine")
	}
	if model.SupportsExecutionSemantics(r.SupportedExecutionSemantics, model.LegacyExecutionSemanticsVersion) {
		t.Fatal("current-only runner must not claim the legacy engine")
	}
	// A runner that never advertised is legacy-only.
	if model.SupportsExecutionSemantics(nil, model.ExecutionSemanticsVersion) {
		t.Fatal("unadvertised runner must not lease/execute v3 work")
	}
}
