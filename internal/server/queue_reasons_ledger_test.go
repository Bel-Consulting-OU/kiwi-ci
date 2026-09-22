package server

// K4-B: the fs/dev reservation ledger must be folded from the RUNNING jobs
// each runner holds (the per-runner ActiveJobs index), not from the whole
// in-memory job history, and the per-poll sums must be computed ONCE and
// shared by next() admission and the fleet-global queue-reason explainer.
// The memReservationSumVisits seam counts every job reservation the poll
// folds: with H history jobs and k running ones it must be exactly k, where
// before the fix it was 2*(H+k).

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
)

func TestMemoryReservationLedgerWorkScalesWithRunningJobs(t *testing.T) {
	s := New("token")
	now := time.Now().UTC()
	const history = 2000
	const running = 3
	jobs := make(map[string]model.Job, history+running+1)
	for i := 0; i < history; i++ {
		id := fmt.Sprintf("hist-%04d", i)
		jobs[id] = model.Job{ID: id, RunID: "run-hist", Key: id, Status: model.StatusSuccess, CreatedAt: now}
	}
	runner := model.Runner{ID: "ledger-runner", Name: "ledger", Labels: []string{"container"}, Capacity: 8}
	active := make([]string, 0, running)
	expires := now.Add(time.Hour)
	for i := 0; i < running; i++ {
		id := fmt.Sprintf("live-%d", i)
		jobs[id] = model.Job{ID: id, RunID: "run-live", Key: id, Status: model.StatusRunning, LeaseRunnerID: runner.ID, LeaseExpiresAt: &expires, CPURequest: 0.5, CreatedAt: now}
		active = append(active, id)
	}
	runner.ActiveJobs = active
	// A queued job the runner cannot take (label mismatch), so the poll takes
	// the lease-miss path and runs the fleet-global explainer too.
	jobs["waiting"] = model.Job{ID: "waiting", RunID: "run-live", Key: "waiting", Status: model.StatusQueued, RequiredLabels: []string{"gpu"}, CreatedAt: now}
	s.jobs = jobs
	s.runners = map[string]model.Runner{runner.ID: runner}

	memReservationSumVisits.Store(0)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runner.ID+"/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	got := memReservationSumVisits.Load()
	t.Logf("poll folded %d reservation entries for %d running jobs and %d history jobs", got, running, history)
	if got != running {
		t.Fatalf("poll folded %d job reservations for %d running jobs and %d history jobs: the fs/dev ledger must scale with the RUNNING jobs each runner holds", got, running, history)
	}
	if reason := fsJob(t, s, "waiting").QueueReason; reason != string(queue.NoCompatibleRunner) {
		t.Fatalf("queued job reason = %q, want NO_COMPATIBLE_RUNNER", reason)
	}
}
