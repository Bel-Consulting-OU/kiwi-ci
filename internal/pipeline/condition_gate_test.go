package pipeline

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Regression: the server used to resolve `if` against an EMPTY Branch/Event
// and then block the job on that wrong answer. Branch/event conditions must
// see the job's real context.
func TestConditionAllowsSeesBranchAndEvent(t *testing.T) {
	cases := []struct {
		expr   string
		ctx    EvalContext
		want   bool
		reason string
	}{
		{
			expr:   "branch == 'main'",
			ctx:    EvalContext{Status: model.StatusSuccess, Branch: "main", Event: "push"},
			want:   true,
			reason: "matching branch must allow",
		},
		{
			expr:   "branch == 'main'",
			ctx:    EvalContext{Status: model.StatusSuccess, Branch: "feature", Event: "push"},
			want:   false,
			reason: "non-matching branch must refuse even on success",
		},
		{
			expr:   "always() && branch == 'main'",
			ctx:    EvalContext{Status: model.StatusFailure, Branch: "main", Event: "push"},
			want:   true,
			reason: "always() && branch must survive a failed dependency",
		},
		{
			expr:   "event == 'pull_request'",
			ctx:    EvalContext{Status: model.StatusSuccess, Branch: "main", Event: "pull_request"},
			want:   true,
			reason: "matching event must allow",
		},
		{
			expr:   "event == 'pull_request'",
			ctx:    EvalContext{Status: model.StatusSuccess, Branch: "main", Event: "push"},
			want:   false,
			reason: "non-matching event must refuse even on success",
		},
		{
			expr:   "branchMatch('release/**')",
			ctx:    EvalContext{Status: model.StatusSuccess, Branch: "release/1.2"},
			want:   true,
			reason: "branchMatch must see the real branch",
		},
	}
	for _, c := range cases {
		if got := ConditionAllows(c.expr, c.ctx); got != c.want {
			t.Fatalf("ConditionAllows(%q, %+v) = %v, want %v (%s)", c.expr, c.ctx, got, c.want, c.reason)
		}
	}
}

// Regression: the gate used to be `status == success || ConditionAllows(...)`,
// which skipped the condition entirely on green deps. `if: failure()` and
// `if: false` must NOT run when dependencies succeeded.
func TestConditionAllowsHonorsFalseOnSuccess(t *testing.T) {
	green := EvalContext{Status: model.StatusSuccess, Branch: "main", Event: "push"}
	for _, expr := range []string{"failure()", "false", "cancelled()", "branch == 'nope'"} {
		if ConditionAllows(expr, green) {
			t.Fatalf("ConditionAllows(%q) on success must be false — the old success-short-circuit leaked through", expr)
		}
	}
	// success() and always() still pass on green deps.
	for _, expr := range []string{"", "success()", "always()", "true", "branch == 'main'"} {
		if !ConditionAllows(expr, green) {
			t.Fatalf("ConditionAllows(%q) on success must be true", expr)
		}
	}
}

// JobConditionContext derives Branch from the persisted ref exactly the way
// the runner and expandConcurrency do.
func TestJobConditionContextBranchFromRef(t *testing.T) {
	cases := map[string]string{
		"refs/heads/main":    "main",
		"refs/heads/feat/x":  "feat/x",
		"main":               "main",
		"refs/tags/v1.0.0":   "",
		"refs/pull/12/merge": "",
	}
	for ref, want := range cases {
		got := ConditionBranchFromRef(ref)
		if got != want {
			t.Fatalf("ConditionBranchFromRef(%q) = %q, want %q", ref, got, want)
		}
	}
	ctx := JobConditionContext(model.StatusFailure, "refs/heads/main", "push", nil)
	if ctx.Branch != "main" || ctx.Event != "push" || ctx.Status != model.StatusFailure {
		t.Fatalf("JobConditionContext = %+v", ctx)
	}
}
