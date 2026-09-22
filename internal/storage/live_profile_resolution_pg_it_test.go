package storage

// Real-PostgreSQL integration tests for the shared live-profile resolution:
// the SQL claim resolves the runner-ID binding (runner_profile_links) as well
// as the certificate-serial binding, honors profile edits on the next lease
// without re-registration, and stays race-safe under concurrent claims.
// Gated on KIWI_TEST_POSTGRES_URL exactly like the other *_it_test.go files
// in this package.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func pgITLiveProfileEnqueue(t *testing.T, st *PostgresStore, runID, jobID, repoID string, labels []string) {
	t.Helper()
	job := pgITJob(runID, jobID, pgITRepo)
	job.RepoID = repoID
	job.RequiredLabels = labels
	if err := st.InsertCompiledRun(context.Background(), InsertCompiledRunRequest{
		Run:  pgITRun(runID, model.StatusQueued),
		Jobs: map[string]model.Job{jobID: job},
	}); err != nil {
		t.Fatalf("enqueue %s: %v", jobID, err)
	}
}

// TestIntegrationLeaseRunnerIDProfileLivePostgres: the SQL claim
// resolves the runner-ID binding at lease time and honors profile edits
// without re-registration.
func TestIntegrationLeaseRunnerIDProfileLivePostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 9, Labels: []string{"snapshot"}, CostPerHour: 9}); err != nil {
		t.Fatalf("runner: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "live-p", Labels: []string{"bound"}, Repositories: []string{liveProfileRepoA}, MaxCapacity: 1, CostPerHour: 3.5}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, runnerID, "live-p"); err != nil {
		t.Fatalf("link: %v", err)
	}

	run1, job1 := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, run1, job1, liveProfileRepoA, []string{"bound"})
	leased, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: job1, RunnerID: runnerID, CanonRepoID: liveProfileRepoA, RequiredLabels: []string{"bound"}, Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h")})
	if err != nil {
		t.Fatalf("bound-profile lease = %v, want the live runner-ID profile", err)
	}
	if leased.CostRate != 3.5 {
		t.Fatalf("frozen cost rate = %v, want 3.5 from the live profile", leased.CostRate)
	}

	run2, job2 := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, run2, job2, liveProfileRepoA, []string{"bound"})
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: job2, RunnerID: runnerID, CanonRepoID: liveProfileRepoA, RequiredLabels: []string{"bound"}, Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h")}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("second claim = %v, want ErrNoCapacity (live profile capacity 1)", err)
	}

	// Edit the live profile: capacity 3, label and repository ACL replaced.
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "live-p", Labels: []string{"edited"}, Repositories: []string{liveProfileRepoB}, MaxCapacity: 3}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: job2, RunnerID: runnerID, CanonRepoID: liveProfileRepoA, RequiredLabels: []string{"bound"}, Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h")}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("claim after edit = %v, want ErrNoCapacity (label/ACL edited)", err)
	}
	run3, job3 := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, run3, job3, liveProfileRepoB, []string{"edited"})
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: job3, RunnerID: runnerID, CanonRepoID: liveProfileRepoB, RequiredLabels: []string{"edited"}, Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h")}); err != nil {
		t.Fatalf("edited-profile claim = %v, want the edited live profile", err)
	}
}

// TestIntegrationLeaseRunnerIDProfileCapacityRacePostgres: concurrent
// claims against a runner-ID-bound profile of capacity 1 admit exactly one.
func TestIntegrationLeaseRunnerIDProfileCapacityRacePostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 8, Labels: []string{"snapshot"}}); err != nil {
		t.Fatalf("runner: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "race-p", MaxCapacity: 1}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, runnerID, "race-p"); err != nil {
		t.Fatalf("link: %v", err)
	}
	jobA, jobB := pgITNewID(t), pgITNewID(t)
	pgITLiveProfileEnqueue(t, st, pgITNewID(t), jobA, liveProfileRepoA, nil)
	pgITLiveProfileEnqueue(t, st, pgITNewID(t), jobB, liveProfileRepoA, nil)

	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, job := range []string{jobA, jobB} {
		wg.Add(1)
		go func(job string) {
			defer wg.Done()
			_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: job, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute), TokenHash: []byte("h")})
			results <- err
		}(job)
	}
	wg.Wait()
	close(results)
	var won, lost int
	for err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrNoCapacity):
			lost++
		default:
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("capacity-1 race winners/losers = %d/%d, want 1/1", won, lost)
	}
}
