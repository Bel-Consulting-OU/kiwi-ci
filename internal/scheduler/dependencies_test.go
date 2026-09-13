package scheduler

import (
	"testing"

	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/pipeline"
)

// evalOracle evaluates expr through pipeline.ConditionAllows exactly the way
// ConditionAllows must, so parity assertions stay honest.
func evalOracle(t *testing.T, expr string, status model.Status) (bool, error) {
	t.Helper()
	if expr == "" {
		expr = "success()"
	}
	return pipeline.Eval(expr, pipeline.EvalContext{Status: status})
}

func TestConditionAllowsParityWithPipelineEval(t *testing.T) {
	exprs := []string{
		"always()",
		"failure()",
		"cancelled()",
		"success()",
		"true",
		"always() && branch == 'main'",
		"always() && branch != 'main'",
		"failure() || cancelled()",
		"(always())",
		"!failure()",
		"garbage()",
		"",
	}
	statuses := []model.Status{
		model.StatusSuccess,
		model.StatusFailure,
		model.StatusCancelled,
		model.StatusBlocked,
		model.StatusSkipped,
	}
	for _, expr := range exprs {
		for _, st := range statuses {
			want, wantErr := evalOracle(t, expr, st)
			got := ConditionAllows(expr, st)
			// Eval errors must map to false.
			if wantErr != nil {
				want = false
			}
			if got != want {
				t.Errorf("ConditionAllows(%q, %q) = %v, want %v (pipeline.Eval parity)", expr, st, got, want)
			}
		}
	}
}

func TestConditionAllowsExact(t *testing.T) {
	cases := []struct {
		expr   string
		status model.Status
		want   bool
	}{
		{"always()", model.StatusFailure, true},
		{"always()", model.StatusSuccess, true},
		{"failure()", model.StatusFailure, true},
		{"failure()", model.StatusBlocked, true},
		{"failure()", model.StatusSuccess, false},
		{"failure()", model.StatusCancelled, false},
		{"cancelled()", model.StatusCancelled, true},
		{"cancelled()", model.StatusFailure, false},
		{"cancelled()", model.StatusSuccess, false},
		{"success()", model.StatusSuccess, true},
		{"success()", model.StatusFailure, false},
	}
	for _, c := range cases {
		if got := ConditionAllows(c.expr, c.status); got != c.want {
			t.Errorf("ConditionAllows(%q, %q) = %v, want %v", c.expr, c.status, got, c.want)
		}
	}
}

func TestConditionAllowsCompositeWithBranch(t *testing.T) {
	// The unified evaluator sees the same context shape the executor uses;
	// with no branch in the scheduler context, the branch clause is false and
	// only always() is satisfied. Parity is asserted against pipeline.Eval.
	expr := "always() && branch == 'main'"
	for _, st := range []model.Status{model.StatusSuccess, model.StatusFailure, model.StatusCancelled} {
		want, err := pipeline.Eval(expr, pipeline.EvalContext{Status: st})
		if err != nil {
			t.Fatalf("oracle eval: %v", err)
		}
		if got := ConditionAllows(expr, st); got != want {
			t.Errorf("ConditionAllows(%q, %q) = %v, want %v", expr, st, got, want)
		}
	}
}

func TestDependencyOutcome(t *testing.T) {
	mk := func(statuses map[string]model.Status) func(id string) (model.Status, bool) {
		return func(id string) (model.Status, bool) {
			st, ok := statuses[id]
			return st, ok
		}
	}
	cases := []struct {
		name     string
		statuses map[string]model.Status
		deps     []string
		ready    bool
		outcome  model.Status
	}{
		{"no deps", nil, nil, true, model.StatusSuccess},
		{"all success", map[string]model.Status{"a": model.StatusSuccess}, []string{"a"}, true, model.StatusSuccess},
		{"pending dep not ready", map[string]model.Status{"a": model.StatusQueued}, []string{"a"}, false, model.StatusPending},
		{"running dep not ready", map[string]model.Status{"a": model.StatusRunning}, []string{"a"}, false, model.StatusPending},
		{"failure dep", map[string]model.Status{"a": model.StatusFailure}, []string{"a"}, true, model.StatusFailure},
		{"blocked dep is failure", map[string]model.Status{"a": model.StatusBlocked}, []string{"a"}, true, model.StatusFailure},
		{"cancelled dep", map[string]model.Status{"a": model.StatusCancelled}, []string{"a"}, true, model.StatusCancelled},
		{"failure dominates cancelled", map[string]model.Status{"a": model.StatusCancelled, "b": model.StatusFailure}, []string{"a", "b"}, true, model.StatusFailure},
		{"missing dep is failure", map[string]model.Status{"a": model.StatusSuccess}, []string{"a", "zz"}, true, model.StatusFailure},
		{"skipped dep is success", map[string]model.Status{"a": model.StatusSkipped}, []string{"a"}, true, model.StatusSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ready, outcome := DependencyOutcome(c.deps, c.statuses, mk(c.statuses))
			if ready != c.ready || outcome != c.outcome {
				t.Errorf("DependencyOutcome(%v) = (%v, %q), want (%v, %q)", c.deps, ready, outcome, c.ready, c.outcome)
			}
		})
	}
}

func TestDependencyOutcomeNilGet(t *testing.T) {
	ready, outcome := DependencyOutcome([]string{"a"}, nil, nil)
	if !ready || outcome != model.StatusFailure {
		t.Errorf("missing dep with nil get = (%v, %q), want (true, failure)", ready, outcome)
	}
	ready, outcome = DependencyOutcome(nil, nil, nil)
	if !ready || outcome != model.StatusSuccess {
		t.Errorf("no deps = (%v, %q), want (true, success)", ready, outcome)
	}
}

func TestDependencyOutcomeFailureWithConditionAllows(t *testing.T) {
	statuses := map[string]model.Status{"a": model.StatusFailure}
	ready, outcome := DependencyOutcome([]string{"a"}, statuses, nil)
	if !ready || outcome != model.StatusFailure {
		t.Fatalf("unexpected outcome (%v, %q)", ready, outcome)
	}
	// The scheduler gate: a job with failure() proceeds on failed deps, a
	// job with cancelled() or no condition does not.
	if !ConditionAllows("failure()", outcome) {
		t.Error("failure() must allow a failed dependency outcome")
	}
	if ConditionAllows("cancelled()", outcome) {
		t.Error("cancelled() must not allow a failed dependency outcome")
	}
}
