package storage

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// concurrency.limit is enforced, not a schema ornament: at most Limit jobs
// of a group run at once; the rest wait. This pins the lease predicate.
func TestConcurrencyLimitGatesLease(t *testing.T) {
	j := model.Job{
		ID: "j1", ConcurrencyGroup: "deploy", ConcurrencyLimit: 1,
		Status: model.StatusQueued,
	}
	runner := model.Runner{Capacity: 10, Capabilities: []string{"native"}}
	// No other running job: allowed.
	if !(LeasePredicate{Runner: runner, Job: j}).Allows() {
		t.Fatal("limit=1 with 0 running must allow")
	}
	// One other running job of the group: at capacity, refused.
	if (LeasePredicate{Runner: runner, Job: j, GroupRunning: 1}).Allows() {
		t.Fatal("limit=1 with 1 running must refuse")
	}
	// Unlimited (limit=0) never gates on the group.
	j.ConcurrencyLimit = 0
	if !(LeasePredicate{Runner: runner, Job: j, GroupRunning: 99}).Allows() {
		t.Fatal("limit=0 must not gate")
	}
	// Environment concurrency and group limit are independent gates.
	j2 := model.Job{
		ID: "j2", Environment: "prod", EnvironmentConcurrency: 1,
		ConcurrencyGroup: "deploy", ConcurrencyLimit: 5,
	}
	if (LeasePredicate{Runner: runner, Job: j2, EnvRunning: 1}).Allows() {
		t.Fatal("env at capacity must refuse")
	}
	if !(LeasePredicate{Runner: runner, Job: j2, GroupRunning: 1}).Allows() {
		t.Fatal("group under limit must allow")
	}
}

func TestListJobsByConcurrencyGroup(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	now := time.Now()
	for i, g := range []string{"deploy", "deploy", "test"} {
		j := model.Job{
			ID: string(rune('a' + i)), ConcurrencyGroup: g,
			Status: model.StatusQueued, CreatedAt: now,
		}
		_ = m.UpdateJob(ctx, j)
	}
	got, err := m.ListJobsByConcurrencyGroup(ctx, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("deploy group = %d jobs, want 2", len(got))
	}
}
