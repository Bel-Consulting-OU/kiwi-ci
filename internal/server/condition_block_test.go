package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Regression: "server resolves wrong before blocks".
// The gate used to (1) skip the condition when deps were green and
// (2) evaluate `branch == ...` with an empty Branch, then mark the job
// blocked on that wrong answer. Both must be gone.
func TestServerConditionGateSeesBranchAndDoesNotShortCircuit(t *testing.T) {
	s := New("secret")
	now := time.Now().UTC()

	// Job A fails. Job B is `if: always() && branch == 'main'` on main.
	// The old status-only evaluator saw Branch="" → false → B blocked.
	// With the real branch it must be allowed.
	s.jobs["a"] = model.Job{ID: "a", RunID: "r1", Key: "a", Status: model.StatusFailure, FinishedAt: &now}
	s.jobs["b"] = model.Job{
		ID: "b", RunID: "r1", Key: "b", Status: model.StatusQueued,
		Condition: "always() && branch == 'main'",
		Ref:       "refs/heads/main", Event: "push",
		Needs: []string{"a"},
	}

	ready, dep := dependencyOutcomeLocked(s.jobs["b"], s.jobs)
	if !ready || dep != model.StatusFailure {
		t.Fatalf("b dep outcome = ready=%v dep=%v, want ready+failure", ready, dep)
	}
	if !depsReadyLocked(s.jobs["b"], s.jobs) {
		t.Fatal("b must be ready: always() && branch == 'main' on main, even after a failed dep")
	}

	// Green deps + if: failure() must NOT be ready (old short-circuit
	// treated success as an automatic pass).
	s.jobs["c"] = model.Job{ID: "c", RunID: "r2", Key: "c", Status: model.StatusSuccess, FinishedAt: &now}
	s.jobs["d"] = model.Job{
		ID: "d", RunID: "r2", Key: "d", Status: model.StatusQueued,
		Condition: "failure()", Ref: "refs/heads/main", Event: "push",
		Needs: []string{"c"},
	}
	if depsReadyLocked(s.jobs["d"], s.jobs) {
		t.Fatal("if: failure() after green deps must not be ready")
	}

	// Green deps + if: false must not be ready either.
	s.jobs["e"] = model.Job{
		ID: "e", RunID: "r2", Key: "e", Status: model.StatusQueued,
		Condition: "false", Ref: "refs/heads/main", Event: "push",
		Needs: []string{"c"},
	}
	if depsReadyLocked(s.jobs["e"], s.jobs) {
		t.Fatal("if: false must not be ready")
	}

	// scheduleStateLocked must skip (not block) d: deps were green.
	s.runs["r2"] = model.Run{ID: "r2", Ref: "refs/heads/main"}
	s.scheduleStateLocked()
	if s.jobs["d"].Status != model.StatusSkipped {
		t.Fatalf("d status = %q, want skipped (condition not satisfied on green deps)", s.jobs["d"].Status)
	}
	if s.jobs["e"].Status != model.StatusSkipped {
		t.Fatalf("e status = %q, want skipped", s.jobs["e"].Status)
	}
	// b has a failed dep and a condition that admits it — still queued.
	if s.jobs["b"].Status != model.StatusQueued {
		t.Fatalf("b status = %q, want queued", s.jobs["b"].Status)
	}
}

// A failed dep + default condition (success()) stays blocked — that
// contract must not regress while fixing the short-circuit.
func TestServerConditionGateStillBlocksOnFailedDeps(t *testing.T) {
	s := New("secret")
	now := time.Now().UTC()
	s.jobs["a"] = model.Job{ID: "a", RunID: "r1", Key: "a", Status: model.StatusFailure, FinishedAt: &now}
	s.jobs["b"] = model.Job{
		ID: "b", RunID: "r1", Key: "b", Status: model.StatusQueued,
		Condition: "", Ref: "refs/heads/main", Event: "push",
		Needs: []string{"a"},
	}
	s.runs["r1"] = model.Run{ID: "r1", Ref: "refs/heads/main"}
	s.scheduleStateLocked()
	if s.jobs["b"].Status != model.StatusBlocked {
		t.Fatalf("b status = %q, want blocked", s.jobs["b"].Status)
	}
	if !strings.Contains(s.jobs["b"].Error, "dependency failed") {
		t.Fatalf("b error = %q", s.jobs["b"].Error)
	}
	_ = context.Background()
}
