package storage

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestLeasePredicateExecutionSemanticsGate(t *testing.T) {
	base := LeasePredicate{
		Runner: model.Runner{
			ID: "r", Capacity: 1,
			SupportedExecutionSemantics: []string{model.LegacyExecutionSemanticsVersion},
		},
		Job: model.Job{ID: "j"},
	}
	// v3 job → denied for legacy runner
	p := base
	p.Job.ExecutionSemantics = model.ExecutionSemanticsVersion
	if p.Allows() {
		t.Fatal("legacy runner must not lease a v3 job")
	}
	// v2 job → allowed
	p.Job.ExecutionSemantics = model.LegacyExecutionSemanticsVersion
	if !p.Allows() {
		t.Fatal("legacy runner must lease a v2 job")
	}
	// Current runner advertising v3
	p.Runner.SupportedExecutionSemantics = []string{model.ExecutionSemanticsVersion}
	p.Job.ExecutionSemantics = model.ExecutionSemanticsVersion
	if !p.Allows() {
		t.Fatal("v3 runner must lease a v3 job")
	}
	p.Job.ExecutionSemantics = model.LegacyExecutionSemanticsVersion
	if p.Allows() {
		t.Fatal("v3-only runner must not lease a v2 job")
	}
}
