package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITExecutionEvents reads one run's stream in seq order.
func pgITExecutionEvents(t *testing.T, st *PostgresStore, runID string) []model.ExecutionEvent {
	t.Helper()
	events, _, err := st.ListExecutionEvents(context.Background(), 0, MaxExecutionEventLimit, runID)
	if err != nil {
		t.Fatalf("list execution events: %v", err)
	}
	return events
}

// TestIntegrationExecutionEventsTransitions proves the AFTER triggers append
// exactly-once with the state change: enqueue, lease, complete and the
// recovery requeue produce ordered events with from/to, attempt = the lease
// generation and a monotonic seq.
func TestIntegrationExecutionEventsTransitions(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// Run 1: enqueue -> lease -> complete.
	run1, job1, runner1 := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, run1, job1, pgITRepo)
	pgITSeedRunner(t, st, runner1, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: job1, RunnerID: runner1, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	receipt := model.CompletionReceipt{JobID: job1, Generation: 1, RunnerID: runner1, ResultHash: "h1"}
	if err := st.CompleteJob(ctx, job1, 1, runner1, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("complete: %v", err)
	}

	events := pgITExecutionEvents(t, st, run1)
	want := []struct {
		typ, from, to string
		attempt       int64
	}{
		{"run.queued", "", "queued", 0},
		{"job.queued", "", "queued", 0},
		{"job.running", "queued", "running", 1},
		{"job.succeeded", "running", "success", 1},
		{"run.succeeded", "queued", "success", 0},
	}
	if len(events) != len(want) {
		t.Fatalf("run 1 events = %d, want %d: %+v", len(events), len(want), events)
	}
	for i, w := range want {
		e := events[i]
		if e.Type != w.typ || e.FromStatus != w.from || e.ToStatus != w.to || e.Attempt != w.attempt {
			t.Fatalf("event %d = %+v, want %+v", i, e, w)
		}
		if e.RunID != run1 || e.SchemaVersion != 1 {
			t.Fatalf("event %d identity = %+v", i, e)
		}
		if i > 0 && e.Seq <= events[i-1].Seq {
			t.Fatalf("seq not monotonic: %d after %d", e.Seq, events[i-1].Seq)
		}
	}
	running := events[2]
	if running.JobID != job1 || running.Payload["runner"] != runner1 || running.Payload["job"] == "" {
		t.Fatalf("running event payload = %+v", running)
	}
	done := events[3]
	if done.Payload["started_at"] == "" || done.Payload["finished_at"] == "" || done.Payload["duration_ms"] == "" {
		t.Fatalf("terminal event timings missing: %+v", done.Payload)
	}

	// Run 2: lease with an already-expired lease, then the recovery requeue.
	// The job keeps an infrastructure retry budget (MaxInfraRetries 2), so
	// the recovery requeues instead of terminally failing.
	run2, job2, runner2 := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	retryable := pgITJob(run2, job2, pgITRepo)
	retryable.MaxInfraRetries = 2
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: run2, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{job2: retryable},
	}); err != nil {
		t.Fatal(err)
	}
	pgITSeedRunner(t, st, runner2, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: job2, RunnerID: runner2, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(-time.Minute), RunnerCapacity: 1}); err != nil {
		t.Fatalf("expired lease seed: %v", err)
	}
	if err := st.RecoverExpiredLease(ctx, job2, 1, time.Now().UTC()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	events2 := pgITExecutionEvents(t, st, run2)
	var requeued *model.ExecutionEvent
	for i := range events2 {
		if events2[i].Type == "job.requeued" {
			requeued = &events2[i]
		}
	}
	if requeued == nil {
		t.Fatalf("no job.requeued event: %+v", events2)
	}
	if requeued.FromStatus != "running" || requeued.ToStatus != "queued" || requeued.Attempt != 1 {
		t.Fatalf("requeue event = %+v", requeued)
	}
	if !requeued.CreatedAt.After(events2[0].CreatedAt) {
		t.Fatalf("requeue created_at not ordered: %v vs %v", requeued.CreatedAt, events2[0].CreatedAt)
	}
}

// TestIntegrationExecutionEventsRollbackLeavesNothing proves the trigger
// append shares the transaction: a rolled-back transition leaves no event,
// and two inserts in one transaction keep their statement order by seq.
func TestIntegrationExecutionEventsRollbackLeavesNothing(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobA, jobB := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			jobA: pgITJob(runID, jobA, pgITRepo),
			jobB: pgITJob(runID, jobB, pgITRepo),
		},
	}); err != nil {
		t.Fatal(err)
	}
	before := len(pgITExecutionEvents(t, st, runID))

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error='rolled back' WHERE id=$1`, jobA); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if after := len(pgITExecutionEvents(t, st, runID)); after != before {
		t.Fatalf("rolled-back transition left %d new event(s)", after-before)
	}
	if j, _ := st.GetJob(ctx, jobA); j.Status != model.StatusQueued {
		t.Fatalf("rolled-back job status = %s, want queued", j.Status)
	}

	// Two status changes in ONE transaction appear in seq order (jobA first).
	tx, err = st.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error='one tx' WHERE id=$1`, jobA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error='one tx' WHERE id=$1`, jobB); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	events := pgITExecutionEvents(t, st, runID)
	var seqA, seqB int64
	for _, e := range events {
		if e.Type != "job.cancelled" {
			continue
		}
		switch e.JobID {
		case jobA:
			seqA = e.Seq
		case jobB:
			seqB = e.Seq
		}
	}
	if seqA == 0 || seqB == 0 || seqB <= seqA {
		t.Fatalf("one-transaction ordering: seq(%s)=%d seq(%s)=%d, want A then B", jobA, seqA, jobB, seqB)
	}
	if seqB-seqA != 1 {
		t.Fatalf("one-transaction events not adjacent: %d then %d", seqA, seqB)
	}
}

// TestIntegrationExecutionEventsNoOpGuard proves the triggers append nothing
// for a payload-only rewrite and for a status self-assignment.
func TestIntegrationExecutionEventsNoOpGuard(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	before := len(pgITExecutionEvents(t, st, runID))

	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = payload, error = '' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status = status WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE runs SET status = status WHERE id=$1`, runID); err != nil {
		t.Fatal(err)
	}
	if after := len(pgITExecutionEvents(t, st, runID)); after != before {
		t.Fatalf("no-op updates appended %d event(s)", after-before)
	}
	// A real transition still appends exactly one.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='blocked' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	events := pgITExecutionEvents(t, st, runID)
	if len(events) != before+1 {
		t.Fatalf("real transition events = %d, want %d", len(events), before+1)
	}
	if last := events[len(events)-1]; last.Type != "job.blocked" || last.FromStatus != "queued" || last.ToStatus != "blocked" {
		t.Fatalf("blocked event = %+v", last)
	}
}

// TestIntegrationExecutionEventsPaginationNoGaps proves cursor pagination is
// gap-free and duplicate-free under concurrent transactional appends: both
// transactions commit, then paging walks the stream and sees every event
// exactly once in seq order.
func TestIntegrationExecutionEventsPaginationNoGaps(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobs := map[string]model.Job{}
	ids := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		id := pgITNewID(t)
		jobs[id] = pgITJob(runID, id, pgITRepo)
		ids = append(ids, id)
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: jobs,
	}); err != nil {
		t.Fatal(err)
	}
	enqueued := len(pgITExecutionEvents(t, st, runID))

	// Two concurrent transactions, each flipping three jobs in one tx.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for half := 0; half < 2; half++ {
		wg.Add(1)
		go func(half int) {
			defer wg.Done()
			tx, err := st.pool.Begin(ctx)
			if err != nil {
				errs <- err
				return
			}
			for i := half * 3; i < half*3+3; i++ {
				if _, err := tx.Exec(ctx, `UPDATE jobs SET status='blocked', error='concurrent' WHERE id=$1`, ids[i]); err != nil {
					_ = tx.Rollback(ctx)
					errs <- err
					return
				}
			}
			errs <- tx.Commit(ctx)
		}(half)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}

	full := pgITExecutionEvents(t, st, runID)
	if len(full) != enqueued+6 {
		t.Fatalf("full stream = %d events, want %d", len(full), enqueued+6)
	}
	seen := map[int64]bool{}
	var walked []model.ExecutionEvent
	after := int64(0)
	for {
		page, cursor, err := st.ListExecutionEvents(ctx, after, 2, runID)
		if err != nil {
			t.Fatalf("page after %d: %v", after, err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if seen[e.Seq] {
				t.Fatalf("seq %d returned twice", e.Seq)
			}
			seen[e.Seq] = true
			walked = append(walked, e)
		}
		if cursor <= after {
			t.Fatalf("cursor did not advance: %d -> %d", after, cursor)
		}
		after = cursor
	}
	if len(walked) != len(full) {
		t.Fatalf("cursor walk = %d events, want %d", len(walked), len(full))
	}
	for i := 1; i < len(walked); i++ {
		if walked[i].Seq <= walked[i-1].Seq {
			t.Fatalf("cursor walk not ascending: %d then %d", walked[i-1].Seq, walked[i].Seq)
		}
	}
}

// TestIntegrationExecutionEventsRunFilterAndLimitBounds proves the run filter
// and the storage limit bounds over real rows.
func TestIntegrationExecutionEventsRunFilterAndLimitBounds(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runA, runB := pgITNewID(t), pgITNewID(t)
	jobA, jobB := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runA, jobA, pgITRepo)
	pgITEnqueueOne(t, st, runB, jobB, pgITRepo)

	filtered, _, err := st.ListExecutionEvents(ctx, 0, MaxExecutionEventLimit, runA)
	if err != nil || len(filtered) != 2 {
		t.Fatalf("run filter = %d err %v, want 2", len(filtered), err)
	}
	for _, e := range filtered {
		if e.RunID != runA {
			t.Fatalf("run filter leaked %q", e.RunID)
		}
	}
	// Out-of-range limits clamp to one default page instead of erroring.
	for _, limit := range []int{0, -1, MaxExecutionEventLimit + 1} {
		page, cursor, err := st.ListExecutionEvents(ctx, 0, limit, "")
		if err != nil || len(page) != 4 || cursor != page[len(page)-1].Seq {
			t.Fatalf("limit %d = %d events cursor %d err %v, want 4", limit, len(page), cursor, err)
		}
	}
	// A manual append participates in the same stream and cursor.
	if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: runA, JobID: jobA, Attempt: 7, Type: "job.succeeded", FromStatus: "running", ToStatus: "success", Payload: map[string]string{"k": "v"}}); err != nil {
		t.Fatalf("manual append: %v", err)
	}
	all, cursor, err := st.ListExecutionEvents(ctx, 0, 100, runA)
	if err != nil || len(all) != 3 || cursor != all[2].Seq {
		t.Fatalf("after manual append = %d cursor %d err %v", len(all), cursor, err)
	}
	last := all[2]
	if last.Attempt != 7 || last.Payload["k"] != "v" {
		t.Fatalf("manual append not stored: %+v", last)
	}
	// The empty cursor keeps the caller's position.
	if page, cur, err := st.ListExecutionEvents(ctx, cursor, 100, runA); err != nil || len(page) != 0 || cur != cursor {
		t.Fatalf("empty page = %d cursor %d err %v", len(page), cur, err)
	}
}
