package storage

import (
	"context"
	"fmt"
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

// TestConcurrencyLimitAtomicClaimRace: the limit is enforced inside the
// claim, not only in the scheduler prefilter. N concurrent claims against a
// limit-1 group must produce exactly one lease.
func TestConcurrencyLimitAtomicClaimRace(t *testing.T) {
	ctx := context.Background()
	const attempts = 20
	for round := 0; round < 10; round++ {
		m := newMemStore()
		now := time.Now()
		// Register one runner with room for many jobs.
		r := model.Runner{
			ID: "r1", Capacity: attempts, Capabilities: []string{"native"},
		}
		if err := m.UpsertRunner(ctx, r); err != nil {
			t.Fatal(err)
		}
		ids := make([]string, attempts)
		for i := range ids {
			ids[i] = fmt.Sprintf("job-%d-%d", round, i)
			j := model.Job{
				ID: ids[i], Status: model.StatusQueued, CreatedAt: now,
				RepoID: "example.com/o/r", RepoURL: "https://example.com/o/r.git",
				ConcurrencyGroup: "deploy", ConcurrencyLimit: 1,
				Trusted: true,
			}
			_ = m.UpdateJob(ctx, j)
		}
		// Fire concurrent claims.
		type res struct {
			ok  bool
			err error
		}
		results := make(chan res, attempts)
		for i := range ids {
			go func(id string) {
				_, err := m.AcquireLeaseAtomic(ctx, LeaseClaim{
					JobID: id, RunnerID: "r1", Generation: 1,
					RunnerCapacity:   attempts,
					Runtime:          "native",
					CanonRepoID:      "example.com/o/r",
					ConcurrencyGroup: "deploy", ConcurrencyLimit: 1,
					ExpiresAt: now.Add(time.Hour),
				})
				results <- res{ok: err == nil, err: err}
			}(ids[i])
		}
		leased := 0
		for i := 0; i < attempts; i++ {
			r := <-results
			if r.ok {
				leased++
			}
		}
		if leased != 1 {
			t.Fatalf("round %d: %d jobs leased despite limit=1 (want exactly 1)", round, leased)
		}
	}
}
