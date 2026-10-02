package storage

// Real-PostgreSQL integration tests for the idempotent DeploymentStore
// contract: a deterministic-ID replay returns the STORED canonical record
// (created=false) instead of failing on the unique key, a conflicting
// identity fails closed, and concurrent inserts converge on exactly one row.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func deploymentOnceFixture(t *testing.T) (st *PostgresStore, candidate model.Deployment) {
	t.Helper()
	st = pgITStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	candidate = model.Deployment{
		ID: pgITNewID(t), RunID: pgITNewID(t), JobID: pgITNewID(t),
		Repository: "kiwi-it/repo", Environment: "prod",
		Status: model.StatusRunning, CreatedAt: now,
	}
	return st, candidate
}

// TestIntegrationDeploymentReplayReturnsCanonicalStoredRecord pins the
// idempotent replay: the second call returns the durable record, not the
// candidate, so a replica with an empty local mirror caches what the
// database actually holds.
func TestIntegrationDeploymentReplayReturnsCanonicalStoredRecord(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()
	stored, created, err := st.InsertDeploymentOnce(ctx, candidate)
	if err != nil || !created {
		t.Fatalf("first insert = (%+v, created=%t, err=%v)", stored, created, err)
	}

	// A replay whose candidate diverges (different status, finish and
	// created instants) must still return the durable record.
	mutated := candidate
	mutated.Status = model.StatusFailure
	finished := candidate.CreatedAt.Add(time.Hour)
	mutated.FinishedAt = &finished
	later := candidate.CreatedAt.Add(2 * time.Hour)
	mutated.CreatedAt = later
	replay, created, err := st.InsertDeploymentOnce(ctx, mutated)
	if err != nil || created {
		t.Fatalf("replay = (created=%t, err=%v), want an idempotent no-op", created, err)
	}
	if replay.Status != model.StatusRunning || replay.FinishedAt != nil || !replay.CreatedAt.Equal(candidate.CreatedAt) {
		t.Fatalf("replay returned the candidate (%+v), want the stored record", replay)
	}
	if got := deploymentRowCount(t, st, candidate.ID); got != 1 {
		t.Fatalf("deployment rows = %d, want 1", got)
	}
}

// TestIntegrationDeploymentIdentityConflictFailsClosed pins the guard: the
// same deterministic ID with a different run/job/environment is refused and
// nothing is overwritten.
func TestIntegrationDeploymentIdentityConflictFailsClosed(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()
	if _, created, err := st.InsertDeploymentOnce(ctx, candidate); err != nil || !created {
		t.Fatalf("first insert = (created=%t, err=%v)", created, err)
	}
	conflict := candidate
	conflict.Environment = "staging"
	if _, _, err := st.InsertDeploymentOnce(ctx, conflict); !errors.Is(err, ErrDeploymentIdentityConflict) {
		t.Fatalf("conflicting identity = %v, want ErrDeploymentIdentityConflict", err)
	}
	recs, err := st.ListDeploymentsByRun(ctx, candidate.RunID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("deployments = %+v err=%v, want 1", recs, err)
	}
	if recs[0].Environment != "prod" || recs[0].Status != model.StatusRunning {
		t.Fatalf("conflict overwrote the stored record: %+v", recs[0])
	}
}

// TestIntegrationDeploymentConcurrentInsertsConverge races many replicas on
// the same deterministic ID: exactly one call creates, every other call gets
// the same stored record, and one durable row exists.
func TestIntegrationDeploymentConcurrentInsertsConverge(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()

	const workers = 50
	type result struct {
		stored  model.Deployment
		created bool
		err     error
	}
	results := make([]result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stored, created, err := st.InsertDeploymentOnce(ctx, candidate)
			results[i] = result{stored: stored, created: created, err: err}
		}(i)
	}
	wg.Wait()

	createdCount := 0
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("worker %d: %v", i, r.err)
		}
		if r.created {
			createdCount++
		}
		if r.stored.ID != candidate.ID || r.stored.Environment != candidate.Environment {
			t.Fatalf("worker %d returned a divergent record: %+v", i, r.stored)
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want exactly 1", createdCount)
	}
	if got := deploymentRowCount(t, st, candidate.ID); got != 1 {
		t.Fatalf("deployment rows = %d, want 1", got)
	}
}

// deploymentRowCount counts durable deployment rows for one deterministic ID.
func deploymentRowCount(t *testing.T, st *PostgresStore, id string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM deployments WHERE id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
