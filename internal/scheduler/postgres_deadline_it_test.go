package scheduler

// Real-PostgreSQL regression for the durable queue-deadline claim predicate
// (Round-11 finding B): a replica whose application clock is stale must not be
// able to lease a job whose persisted queue_deadline has already elapsed at
// the DATABASE clock. The stale `now` passes the scheduler's Go deadline
// gate; only the claim's SQL predicate can reject the write. Gated on
// KIWI_TEST_POSTGRES_URL like the other scheduler integration tests.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationSchedulerLeaseRespectsDurableQueueDeadline(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)

	runnerID := pgITSchedID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}

	runID, jobID := pgITSchedID(t), pgITSchedID(t)
	realNow := time.Now().UTC()
	deadline := realNow.Add(-time.Minute) // already elapsed at the database clock
	job := pgITSchedJob(runID, jobID)
	job.CreatedAt = realNow.Add(-2 * time.Hour)
	job.QueueDeadline = &deadline
	if err := sched.Enqueue(ctx,
		model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: realNow.Add(-2 * time.Hour)},
		map[string]model.Job{jobID: job}, nil, false); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// The replica's application clock is 10 minutes behind, so the Go gate
	// still considers the deadline (1 minute ago) unelapsed. The claim must
	// re-assert the durable deadline in SQL and refuse the lease.
	staleNow := realNow.Add(-10 * time.Minute)
	if _, _, _, err := sched.Lease(ctx, runnerID, staleNow); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("stale-clock Lease = %v, want ErrNoJobs (durable deadline must reject the claim)", err)
	}

	stored, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if stored.LeaseRunnerID != "" {
		t.Fatalf("lease_runner_id = %q, want NULL after a deadline-rejected claim", stored.LeaseRunnerID)
	}
	if stored.LeaseExpiresAt != nil {
		t.Fatalf("lease_expires_at = %v, want NULL after a deadline-rejected claim", stored.LeaseExpiresAt)
	}
	if stored.Status != model.StatusQueued {
		t.Fatalf("status = %s, want queued", stored.Status)
	}
	if stored.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0 (the claim must not consume an attempt)", stored.Attempts)
	}
}
