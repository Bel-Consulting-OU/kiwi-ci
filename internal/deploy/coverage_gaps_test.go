package deploy

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestEffectiveStepsZeroDefaultRollbackCondition(t *testing.T) {
	n := NormalizedDeployment{
		Rollback:                 []pipeline.Step{{Run: "rollback"}},
		DefaultRollbackCondition: "",
	}
	steps := n.EffectiveSteps()
	if len(steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(steps))
	}
	if steps[0].If != DefaultRollbackCondition {
		t.Fatalf("rollback condition = %q, want %q", steps[0].If, DefaultRollbackCondition)
	}
}
