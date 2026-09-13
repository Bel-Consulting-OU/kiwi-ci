package scheduler

import (
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// DependencyOutcome evaluates a job's dependency set: whether every upstream
// job has reached a terminal state and, if so, the aggregate outcome.
// statuses may preload upstream states; get resolves any id missing from it.
// A missing upstream job is treated as a failure (ready, outcome failure) so
// a corrupt dependency edge can never wedge the queue silently.
func DependencyOutcome(deps []string, statuses map[string]model.Status, get func(id string) (model.Status, bool)) (ready bool, outcome model.Status) {
	outcome = model.StatusSuccess
	for _, depID := range deps {
		st, ok := statuses[depID]
		if !ok && get != nil {
			st, ok = get(depID)
		}
		if !ok {
			return true, model.StatusFailure
		}
		if !st.Terminal() {
			return false, model.StatusPending
		}
		switch st {
		case model.StatusFailure, model.StatusBlocked:
			outcome = model.StatusFailure
		case model.StatusCancelled:
			if outcome != model.StatusFailure {
				outcome = model.StatusCancelled
			}
		}
	}
	return true, outcome
}

// ConditionAllows evaluates a job's condition expression against a dependency
// outcome using the shared pipeline evaluator. This is the unified condition
// path (audit item 7): the control plane, the SQL scheduler, and the executor
// evaluate the exact same expression with the exact same semantics, so a
// composite condition like `always() && branch == 'main'` can no longer
// diverge between server and local execution. An empty condition defaults to
// success() (failed dependencies block downstream jobs); evaluation errors
// yield false.
func ConditionAllows(expr string, status model.Status) bool {
	return pipeline.ConditionAllows(expr, status)
}
