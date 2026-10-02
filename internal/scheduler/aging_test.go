package scheduler

// Fairness regression: bounded aging guarantees every eligible queued job
// eventually outranks (or ties and ages ahead of) a continuous stream of
// fresh high-priority work.

import (
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestOrderQueuedJobsAgingPreventsStarvation(t *testing.T) {
	now := time.Now().UTC()
	old := model.Job{ID: "old-low", Priority: 0, CreatedAt: now.Add(-3 * time.Hour)}
	var queued []model.Job
	queued = append(queued, old)
	for i := 0; i < 10; i++ {
		queued = append(queued, model.Job{ID: "fresh-high", Priority: 8, CreatedAt: now.Add(-time.Minute)})
	}
	orderQueuedJobs(queued, now)
	if queued[0].ID != "old-low" {
		t.Fatalf("old low-priority job did not win after aging: first = %s", queued[0].ID)
	}

	// Fresh low-priority work still yields to fresh high-priority work.
	fresh := []model.Job{
		{ID: "low", Priority: 0, CreatedAt: now},
		{ID: "high", Priority: 8, CreatedAt: now},
	}
	orderQueuedJobs(fresh, now)
	if fresh[0].ID != "high" {
		t.Fatalf("fresh priority order inverted: %s", fresh[0].ID)
	}

	// Within one aged class the oldest job wins.
	older := []model.Job{
		{ID: "newer", Priority: 1, CreatedAt: now.Add(-20 * time.Minute)},
		{ID: "older", Priority: 1, CreatedAt: now.Add(-25 * time.Minute)},
	}
	orderQueuedJobs(older, now)
	if older[0].ID != "older" {
		t.Fatalf("tie-break not oldest-first: %s", older[0].ID)
	}

	// The boost is UNCAPPED so it can cross any finite static-priority gap
	// (downstream depth has no small maximum): a job old enough beats even a
	// priority-100 fresh stream.
	deep := model.Job{ID: "very-old", Priority: 0, CreatedAt: now.Add(-100 * time.Hour)}
	queued = []model.Job{deep}
	for i := 0; i < 5; i++ {
		queued = append(queued, model.Job{ID: "fresh-deep", Priority: 100, CreatedAt: now})
	}
	orderQueuedJobs(queued, now)
	if queued[0].ID != "very-old" {
		t.Fatalf("uncapped aging failed against priority-100 work: first = %s", queued[0].ID)
	}
}
