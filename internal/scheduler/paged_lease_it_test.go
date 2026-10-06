package scheduler

// Real-PostgreSQL integration test for the bounded paged lease scan: the sole
// eligible job sits on the THIRD page (page size 5 over 12 ineligible jobs),
// so a successful lease proves the scheduler followed the store's keyset
// cursor instead of re-reading the first page. Gated on
// KIWI_TEST_POSTGRES_URL exactly like the other scheduler integration tests.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationSchedulerLeasePagedScan leases the only eligible
// job, which is placed behind seven label-ineligible jobs (priority 10) with
// a page size of 5, so it lands on page 2.
func TestPostgresIntegrationSchedulerLeasePagedScan(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)

	runnerID := pgITSchedID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 8}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	runID := pgITSchedID(t)
	base := time.Now().UTC().Add(-time.Hour)
	jobs := map[string]model.Job{}
	for i := 0; i < 7; i++ {
		id := pgITSchedID(t)
		j := pgITSchedJob(runID, id)
		j.Key = fmt.Sprintf("blocked-%02d", i)
		j.Priority = 10
		j.RequiredLabels = []string{"never"}
		j.CreatedAt = base.Add(time.Duration(i) * time.Millisecond)
		jobs[id] = j
	}
	targetID := pgITSchedID(t)
	target := pgITSchedJob(runID, targetID)
	target.Key = "target"
	target.CreatedAt = base.Add(time.Second)
	jobs[targetID] = target
	if err := sched.Enqueue(ctx, model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: base}, jobs, nil, false); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// 5-row pages, budget 50: the target is on page 2 (5+3). A scheduler
	// that ignored the cursor would refetch the first page until the budget
	// ran out and never reach it.
	sched.SetLeaseScanLimits(5, 50, 0)
	leased, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("paged Lease: %v", err)
	}
	if leased.ID != targetID {
		t.Fatalf("leased %s, want the target on page 2 (%s)", leased.ID, targetID)
	}
}
