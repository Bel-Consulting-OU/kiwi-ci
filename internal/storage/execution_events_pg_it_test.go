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
	if err := st.CompleteJob(ctx, job1, 1, runner1, model.StatusSuccess, "", nil, receipt, nil); err != nil {
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
		// The semantic companion of the claim, appended later in the SAME
		// transaction (after the status trigger): one attempt.created per
		// successful lease.
		{model.EventAttemptCreated, "", "", 1},
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
	attemptCreated := events[3]
	if attemptCreated.JobID != job1 || attemptCreated.Payload["runner"] != runner1 {
		t.Fatalf("attempt.created = %+v", attemptCreated)
	}
	done := events[4]
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

// pgITWaitForLockWait blocks until the backend pid waits on a heavyweight
// lock (the transaction-scoped cursor row lock T1 holds), so the test proves
// T2 is actually blocked instead of guessing with a sleep.
func pgITWaitForLockWait(t *testing.T, st *PostgresStore, pid int) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waitType string
		err := st.pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type, '') FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waitType)
		if err != nil {
			t.Fatalf("read pg_stat_activity for pid %d: %v", pid, err)
		}
		if waitType == "Lock" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("backend %d never waited on the cursor row lock", pid)
}

// pgITAssertExecutionEventSeqContiguous asserts the committed stream has no
// holes in its seq allocation: every committed seq from 1..max is present.
func pgITAssertExecutionEventSeqContiguous(t *testing.T, st *PostgresStore) {
	t.Helper()
	ctx := context.Background()
	rows, err := st.pool.Query(ctx, `SELECT seq FROM execution_events ORDER BY seq`)
	if err != nil {
		t.Fatalf("read seq stream: %v", err)
	}
	defer rows.Close()
	want := int64(1)
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			t.Fatalf("scan seq: %v", err)
		}
		if seq != want {
			t.Fatalf("execution event seq hole: got %d, want %d", seq, want)
		}
		want++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("seq stream rows: %v", err)
	}
	if want == 1 {
		t.Fatal("no committed execution events")
	}
}

// pgITInsertTwoJobRun seeds one queued run with two jobs and returns the
// committed baseline cursor (the enqueue events are already visible).
func pgITInsertTwoJobRun(t *testing.T, st *PostgresStore) (runID, jobA, jobB string, baseline int64) {
	t.Helper()
	ctx := context.Background()
	runID, jobA, jobB = pgITNewID(t), pgITNewID(t), pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			jobA: pgITJob(runID, jobA, pgITRepo),
			jobB: pgITJob(runID, jobB, pgITRepo),
		},
	}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	baseline, err := st.LatestExecutionEventSeq(ctx)
	if err != nil {
		t.Fatalf("baseline latest seq: %v", err)
	}
	pgITAssertExecutionEventSeqContiguous(t, st)
	return runID, jobA, jobB, baseline
}

// pgITBlockedEvent returns the run's job.blocked event for jobID.
func pgITBlockedEvent(t *testing.T, st *PostgresStore, runID, jobID string) model.ExecutionEvent {
	t.Helper()
	events := pgITExecutionEvents(t, st, runID)
	for _, e := range events {
		if e.Type == "job.blocked" && e.JobID == jobID {
			return e
		}
	}
	t.Fatalf("no job.blocked event for %s in %+v", jobID, events)
	return model.ExecutionEvent{}
}

// TestPostgresIntegrationExecutionEventsCursorCommitOrdered is the BLOCKER-1
// regression on real PostgreSQL: seq must be allocated in commit order, so a
// consumer can never observe a higher seq while a lower allocation is still
// in flight (the BIGSERIAL loss history).
//
// T1 updates job A in an open transaction (the trigger allocates the next
// cursor and holds it); T2's update of job B must BLOCK on the same cursor
// row until T1 commits. No A/B event is visible while T1 is open, and no
// consumer can see a seq above the baseline. After T1 commits, T2 proceeds
// and commits: A precedes B adjacent, the stream has no holes, and a read
// after=0 then after=A.seq returns B exactly once.
func TestPostgresIntegrationExecutionEventsCursorCommitOrdered(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobA, jobB, baseline := pgITInsertTwoJobRun(t, st)

	// T1: allocate the next seq for job A, uncommitted.
	tx1, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin T1: %v", err)
	}
	defer tx1.Rollback(ctx)
	if _, err := tx1.Exec(ctx, `UPDATE jobs SET status='blocked', error='t1' WHERE id=$1`, jobA); err != nil {
		t.Fatalf("T1 update job A: %v", err)
	}

	// T2: update job B. It must block on the cursor row T1 holds.
	t2pid := make(chan int, 1)
	t2done := make(chan error, 1)
	go func() {
		tx2, err := st.pool.Begin(ctx)
		if err != nil {
			t2done <- err
			return
		}
		defer tx2.Rollback(ctx)
		var pid int
		if err := tx2.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t2done <- err
			return
		}
		t2pid <- pid
		if _, err := tx2.Exec(ctx, `UPDATE jobs SET status='blocked', error='t2' WHERE id=$1`, jobB); err != nil {
			t2done <- err
			return
		}
		t2done <- tx2.Commit(ctx)
	}()
	pid := <-t2pid
	pgITWaitForLockWait(t, st, pid)

	// While T1 is in flight and T2 blocked: neither event is visible, the
	// latest committed cursor is still the baseline, and no higher seq can
	// be observed (T2 cannot commit before T1 releases the cursor).
	if got, err := st.LatestExecutionEventSeq(ctx); err != nil || got != baseline {
		t.Fatalf("latest seq during in-flight allocation = %d, %v; want baseline %d", got, err, baseline)
	}
	for _, e := range pgITExecutionEvents(t, st, runID) {
		if e.JobID == jobA || e.JobID == jobB {
			if e.Type == "job.blocked" {
				t.Fatalf("uncommitted blocked event visible: %+v", e)
			}
		}
	}

	// Commit T1: T2 unblocks (its UPDATE proceeds) and commits.
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit T1: %v", err)
	}
	if err := <-t2done; err != nil {
		t.Fatalf("commit T2: %v", err)
	}
	evA := pgITBlockedEvent(t, st, runID, jobA)
	evB := pgITBlockedEvent(t, st, runID, jobB)
	if evA.Seq != baseline+1 || evB.Seq != evA.Seq+1 {
		t.Fatalf("commit-ordered seqs = A:%d B:%d, want A=%d and B=A+1", evA.Seq, evB.Seq, baseline+1)
	}
	pgITAssertExecutionEventSeqContiguous(t, st)

	// Cursor walk over the committed stream: after=0 sees A (and B), then
	// after=A.seq returns B exactly once. A consumer that advanced its
	// cursor while T1 was in flight (impossible to pass baseline then) is
	// replayed the events it could have missed.
	page1, cursor1, err := st.ListExecutionEvents(ctx, 0, MaxExecutionEventLimit, runID)
	if err != nil {
		t.Fatalf("read after=0: %v", err)
	}
	if len(page1) == 0 || page1[len(page1)-1].Seq != evB.Seq || cursor1 != evB.Seq {
		t.Fatalf("after=0 page = %d events cursor %d, want through B(%d)", len(page1), cursor1, evB.Seq)
	}
	page2, cursor2, err := st.ListExecutionEvents(ctx, evA.Seq, MaxExecutionEventLimit, runID)
	if err != nil {
		t.Fatalf("read after=A: %v", err)
	}
	if len(page2) != 1 || page2[0].Seq != evB.Seq || page2[0].JobID != jobB || cursor2 != evB.Seq {
		t.Fatalf("after=A page = %+v cursor %d, want exactly B(%d)", page2, cursor2, evB.Seq)
	}
	// The same pagination from the pre-commit baseline cursor sees the two
	// events exactly once each: no lost event behind an advanced cursor.
	fromBaseline, _, err := st.ListExecutionEvents(ctx, baseline, MaxExecutionEventLimit, runID)
	if err != nil {
		t.Fatalf("read after=baseline: %v", err)
	}
	seenA, seenB := 0, 0
	for _, e := range fromBaseline {
		if e.Seq == evA.Seq {
			seenA++
		}
		if e.Seq == evB.Seq {
			seenB++
		}
	}
	if seenA != 1 || seenB != 1 {
		t.Fatalf("baseline walk saw A %d times, B %d times, want once each", seenA, seenB)
	}
}

// TestPostgresIntegrationExecutionEventsCursorRollbackNoHole proves the
// rollback half of the cursor contract: a transaction that allocated a seq
// and rolled back does not burn it, so the next committing transaction uses
// exactly the next visible seq (no hole). A separate scratch database keeps
// the assertion "starts at 1 with no gap" meaningful for the whole stream.
func TestPostgresIntegrationExecutionEventsCursorRollbackNoHole(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobA, jobB, baseline := pgITInsertTwoJobRun(t, st)

	// T1 allocates the next seq for job A, then rolls back.
	tx1, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin T1: %v", err)
	}
	if _, err := tx1.Exec(ctx, `UPDATE jobs SET status='blocked', error='t1' WHERE id=$1`, jobA); err != nil {
		t.Fatalf("T1 update job A: %v", err)
	}

	// T2 must block until the rollback releases the cursor row.
	t2pid := make(chan int, 1)
	t2done := make(chan error, 1)
	go func() {
		tx2, err := st.pool.Begin(ctx)
		if err != nil {
			t2done <- err
			return
		}
		defer tx2.Rollback(ctx)
		var pid int
		if err := tx2.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t2done <- err
			return
		}
		t2pid <- pid
		if _, err := tx2.Exec(ctx, `UPDATE jobs SET status='blocked', error='t2' WHERE id=$1`, jobB); err != nil {
			t2done <- err
			return
		}
		t2done <- tx2.Commit(ctx)
	}()
	pid := <-t2pid
	pgITWaitForLockWait(t, st, pid)

	if err := tx1.Rollback(ctx); err != nil {
		t.Fatalf("rollback T1: %v", err)
	}
	if err := <-t2done; err != nil {
		t.Fatalf("commit T2 after rollback: %v", err)
	}

	// The rolled-back allocation is NOT burned: B takes baseline+1 and the
	// stream has no gap where A's allocation was. A itself never committed.
	evB := pgITBlockedEvent(t, st, runID, jobB)
	if evB.Seq != baseline+1 {
		t.Fatalf("committed seq after rollback = %d, want %d (rolled-back allocation must not be burned)", evB.Seq, baseline+1)
	}
	for _, e := range pgITExecutionEvents(t, st, runID) {
		if e.JobID == jobA && e.Type == "job.blocked" {
			t.Fatalf("rolled-back transition left event %+v", e)
		}
	}
	if j, _ := st.GetJob(ctx, jobA); j.Status != model.StatusQueued {
		t.Fatalf("rolled-back job A status = %s, want queued", j.Status)
	}
	pgITAssertExecutionEventSeqContiguous(t, st)
}

// TestIntegrationExecutionEventsManualAppendUsesCursor proves the manual
// AppendExecutionEvent allocates through the same commit-ordered cursor as
// the triggers: it interleaves with trigger appends in strict seq order and
// leaves no holes.
func TestIntegrationExecutionEventsManualAppendUsesCursor(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobA, _, baseline := pgITInsertTwoJobRun(t, st)
	if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: runID, JobID: jobA, Attempt: 7, Type: "job.note", Payload: map[string]string{"k": "v"}}); err != nil {
		t.Fatalf("manual append: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='blocked' WHERE id=$1`, jobA); err != nil {
		t.Fatalf("trigger append: %v", err)
	}
	events := pgITExecutionEvents(t, st, runID)
	var note, blocked model.ExecutionEvent
	for _, e := range events {
		switch e.Type {
		case "job.note":
			note = e
		case "job.blocked":
			blocked = e
		}
	}
	if note.Seq != baseline+1 || blocked.Seq != note.Seq+1 {
		t.Fatalf("manual/trigger seqs = note:%d blocked:%d, want %d then %d", note.Seq, blocked.Seq, baseline+1, baseline+2)
	}
	if note.Payload["k"] != "v" || note.Attempt != 7 {
		t.Fatalf("manual append payload = %+v", note)
	}
	pgITAssertExecutionEventSeqContiguous(t, st)
}
