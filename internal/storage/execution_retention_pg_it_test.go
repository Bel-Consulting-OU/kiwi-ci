package storage

// PostgreSQL integration tests for the P1 history-omission fixes: the atomic
// execution event retention read, the commit-ordered log cursors and the
// execution bootstrap snapshot. Gated on KIWI_TEST_POSTGRES_URL like the
// other pgIT tests.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationExecutionEventsAtomicRetentionRead proves the
// single-snapshot retention read against a real prune: while a prune
// transaction holds an uncommitted prefix delete + watermark update, the read
// returns the PRE-prune page with the PRE-prune watermark (never a truncated
// page with an old watermark); after the commit it returns the post-prune
// page with the new watermark; and pruning every row never regresses the
// latest cursor (which comes from the cursor row, not MAX(seq)).
func TestPostgresIntegrationExecutionEventsAtomicRetentionRead(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	seqs := make([]int64, 0, 5)
	for i := 0; i < 5; i++ {
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{
			RunID: runID, Type: "job.queued", ToStatus: "queued",
			Payload: map[string]string{"job": "build"},
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	events := pgITExecutionEvents(t, st, runID)
	if len(events) != 5 {
		t.Fatalf("seeded events = %d, want 5", len(events))
	}
	for _, e := range events {
		seqs = append(seqs, e.Seq)
	}
	highWater, err := st.LatestExecutionEventSeq(ctx)
	if err != nil || highWater != seqs[4] {
		t.Fatalf("high-water = %d err %v, want %d", highWater, err, seqs[4])
	}

	// T1: delete the first two events and advance retained_from, uncommitted.
	tx1, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback(ctx)
	if _, err := tx1.Exec(ctx, `DELETE FROM execution_events WHERE seq = ANY($1)`, []int64{seqs[0], seqs[1]}); err != nil {
		t.Fatalf("T1 delete: %v", err)
	}
	if _, err := tx1.Exec(ctx, `UPDATE execution_event_cursor SET retained_from = $1 WHERE id = TRUE`, seqs[1]); err != nil {
		t.Fatalf("T1 watermark: %v", err)
	}

	// While T1 is uncommitted the read must see the consistent PRE state:
	// all five rows and retained_from 0 (a page missing rows 1-2 while the
	// watermark still reads 0 is exactly the silent truncation this read
	// exists to prevent).
	page, cursor, retained, latest, err := st.ReadExecutionEventsRetention(ctx, 0, 100, "")
	if err != nil || len(page) != 5 || cursor != seqs[4] || retained != 0 || latest != highWater {
		t.Fatalf("pre-prune atomic read = %d cursor %d retained %d latest %d err %v, want 5/%d/0/%d", len(page), cursor, retained, latest, err, seqs[4], highWater)
	}

	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit T1: %v", err)
	}
	page, cursor, retained, latest, err = st.ReadExecutionEventsRetention(ctx, 0, 100, "")
	if err != nil || len(page) != 3 || page[0].Seq != seqs[2] || cursor != seqs[4] || retained != seqs[1] || latest != highWater {
		t.Fatalf("post-prune atomic read = %d cursor %d retained %d latest %d err %v, want 3/%d/%d/%d", len(page), cursor, retained, latest, err, seqs[4], seqs[1], highWater)
	}
	// Expiry boundary: after == retainedFrom valid, one below expired.
	if ExecutionEventCursorExpired(retained, retained) || !ExecutionEventCursorExpired(retained-1, retained) {
		t.Fatalf("expiry boundary at retained %d disagrees", retained)
	}
	// The valid boundary cursor returns the survivors.
	page, _, _, _, err = st.ReadExecutionEventsRetention(ctx, retained, 100, runID)
	if err != nil || len(page) != 3 || page[0].Seq != seqs[2] {
		t.Fatalf("after=retainedFrom page = %+v err %v, want survivors from %d", page, err, seqs[2])
	}

	// Prune EVERYTHING through the real prune path: latest must not regress.
	pruned, retained, err := st.PruneExecutionEvents(ctx, time.Now().UTC().Add(time.Hour), 100)
	if err != nil || pruned != 3 || retained != seqs[4] {
		t.Fatalf("prune all = %d/%d err %v, want 3/%d", pruned, retained, err, seqs[4])
	}
	page, cursor, retained, latest, err = st.ReadExecutionEventsRetention(ctx, seqs[4], 100, "")
	if err != nil || len(page) != 0 || cursor != seqs[4] || retained != seqs[4] || latest != highWater {
		t.Fatalf("all-pruned atomic read = %d cursor %d retained %d latest %d err %v, want empty/%d/%d/%d", len(page), cursor, retained, latest, err, seqs[4], seqs[4], highWater)
	}
	if latest2, err := st.LatestExecutionEventSeq(ctx); err != nil || latest2 != highWater {
		t.Fatalf("LatestExecutionEventSeq after pruning every row = %d err %v, want the pre-prune high-water %d", latest2, err, highWater)
	}
}

// pgITWaitForLogCursorLockWait blocks until some backend is waiting on a lock
// whose statement touches log_cursors (the upsert AppendLog/AppendLogBatch
// run), so the test proves the second append is actually blocked on the
// commit-ordered cursor instead of guessing with a sleep.
func pgITWaitForLogCursorLockWait(t *testing.T, st *PostgresStore) int {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var pid int
		err := st.pool.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%log_cursors%' LIMIT 1`).Scan(&pid)
		if err == nil && pid != 0 {
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no backend ever waited on the log cursor row lock")
	return 0
}

// TestPostgresIntegrationLogCursorCommitOrdered proves the audit's exact log
// history on real PostgreSQL: T1 holds a lower allocated batch uncommitted,
// T2's append BLOCKS on the run's cursor row, no T1 entry is observable and
// latest is still 0 while T1 is open, and after T1 commits T2 appends at the
// next contiguous seq. A consumer that advanced to T1's last seq then reads
// T2 exactly once: nothing is skipped and the lower seqs are not lost behind
// an advanced cursor.
func TestPostgresIntegrationLogCursorCommitOrdered(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	now := time.Now().UTC()

	// T1 allocates a two-entry lower batch by hand (the same upsert the store
	// uses), uncommitted.
	tx1, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin T1: %v", err)
	}
	defer tx1.Rollback(ctx)
	var end int64
	if err := tx1.QueryRow(ctx, `
		INSERT INTO log_cursors (run_id, value) VALUES ($1, 2)
		ON CONFLICT (run_id) DO UPDATE SET value = log_cursors.value + 2
		RETURNING value`, runID).Scan(&end); err != nil {
		t.Fatalf("T1 allocate: %v", err)
	}
	start := end - 1
	for i, line := range []string{"t1-a", "t1-b"} {
		if _, err := tx1.Exec(ctx, `INSERT INTO log_entries (seq, run_id, job_id, job_key, step, line, lease_generation, created_at) VALUES ($1, $2, $3, 'build', 'run', $4, 1, $5)`,
			start+int64(i), runID, jobID, line, now); err != nil {
			t.Fatalf("T1 insert %s: %v", line, err)
		}
	}

	// T2: a real AppendLog in another connection must block on the cursor.
	t2done := make(chan error, 1)
	go func() {
		t2done <- st.AppendLog(ctx, model.LogEntry{RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "t2", LeaseGeneration: 1, CreatedAt: now})
	}()
	pgITWaitForLogCursorLockWait(t, st)

	// Nothing from T1 is observable and latest is still 0.
	logs, err := st.ReadLogs(ctx, runID, 0, 100)
	if err != nil || len(logs) != 0 {
		t.Fatalf("logs while T1 in flight = %d err %v, want none", len(logs), err)
	}
	if latest, err := st.LatestLogSeq(ctx, runID); err != nil || latest != 0 {
		t.Fatalf("latest while T1 in flight = %d err %v, want 0", latest, err)
	}

	// T1 commits: T2 unblocks and commits at the next contiguous seq.
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit T1: %v", err)
	}
	if err := <-t2done; err != nil {
		t.Fatalf("T2 append: %v", err)
	}
	logs, err = st.ReadLogs(ctx, runID, 0, 100)
	if err != nil || len(logs) != 3 {
		t.Fatalf("logs after both commits = %d err %v, want 3", len(logs), err)
	}
	if logs[0].Seq != start || logs[1].Seq != start+1 || logs[2].Seq != start+2 {
		t.Fatalf("seqs = [%d %d %d], want [%d %d %d] (T1's lower batch first)", logs[0].Seq, logs[1].Seq, logs[2].Seq, start, start+1, start+2)
	}
	if logs[2].Line != "t2" {
		t.Fatalf("T2 line = %q, want t2", logs[2].Line)
	}
	if latest, err := st.LatestLogSeq(ctx, runID); err != nil || latest != start+2 {
		t.Fatalf("latest after commits = %d err %v, want %d", latest, err, start+2)
	}
	// A consumer that advanced to T1's last seq before T2 committed reads T2
	// exactly once: no skipped entry.
	tail, err := st.ReadLogs(ctx, runID, start+1, 100)
	if err != nil || len(tail) != 1 || tail[0].Seq != start+2 {
		t.Fatalf("tail after T1's seq = %+v err %v, want exactly T2 at %d", tail, err, start+2)
	}
}

// TestPostgresIntegrationLogBatchContiguousAndRollbackFreesRange proves a
// batch allocation is one contiguous range and a rolled-back allocation is
// freed (the next append reuses it instead of leaving a hole).
func TestPostgresIntegrationLogBatchContiguousAndRollbackFreesRange(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	identity := LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: "batch-" + pgITRandomHex(t, 8)}
	now := time.Now().UTC()
	entries := []model.LogEntry{
		{RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "one", CreatedAt: now},
		{RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "two", CreatedAt: now},
		{RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "three", CreatedAt: now},
	}
	inserted, err := st.AppendLogBatch(ctx, entries, identity)
	if err != nil || !inserted {
		t.Fatalf("batch append = %v err %v", inserted, err)
	}
	got, err := st.ReadLogs(ctx, runID, 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("batch logs = %d err %v, want 3", len(got), err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Seq != got[i-1].Seq+1 {
			t.Fatalf("batch seqs not contiguous: %v", seqsOfLogs(got))
		}
	}
	if latest, err := st.LatestLogSeq(ctx, runID); err != nil || latest != got[2].Seq {
		t.Fatalf("latest after batch = %d err %v, want %d", latest, err, got[2].Seq)
	}

	// A rolled-back allocation of 2 is freed: the next append takes the very
	// next seq, no hole.
	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO log_cursors (run_id, value) VALUES ($1, 2)
		ON CONFLICT (run_id) DO UPDATE SET value = log_cursors.value + 2`, runID); err != nil {
		t.Fatalf("scratch allocate: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendLog(ctx, model.LogEntry{RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "four", CreatedAt: now}); err != nil {
		t.Fatalf("append after rollback: %v", err)
	}
	got, err = st.ReadLogs(ctx, runID, 0, 100)
	if err != nil || len(got) != 4 {
		t.Fatalf("logs after rollback = %d err %v, want 4", len(got), err)
	}
	if got[3].Seq != got[2].Seq+1 {
		t.Fatalf("rolled-back range not freed: seqs %v", seqsOfLogs(got))
	}
}

func seqsOfLogs(entries []model.LogEntry) []int64 {
	out := make([]int64, len(entries))
	for i, e := range entries {
		out[i] = e.Seq
	}
	return out
}

// TestPostgresIntegrationExecutionSnapshotAtomic proves the bootstrap
// snapshot on real PostgreSQL: cursor + state come from one transaction with
// the cursor read FIRST, so a transition committed after the snapshot has an
// event seq strictly above snapshot.Cursor (the no-gap contract). It also
// checks the bounded active-run list and the queued/running job counts.
func TestPostgresIntegrationExecutionSnapshotAtomic(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobA, jobB := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, RepoID: pgITRepoID, Ref: "refs/heads/main", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobA: pgITJob(runID, jobA, pgITRepo), jobB: pgITJob(runID, jobB, pgITRepo)},
	}); err != nil {
		t.Fatal(err)
	}

	snap, err := st.ExecutionSnapshot(ctx, DefaultExecutionSnapshotRuns)
	if err != nil || snap.Cursor == 0 || snap.GeneratedAt.IsZero() {
		t.Fatalf("snapshot = %+v err %v", snap, err)
	}
	found := false
	for _, r := range snap.Runs {
		if r.ID == runID {
			found = true
			if r.Status != model.StatusQueued || r.RepoID != pgITRepoID || r.Ref != "refs/heads/main" {
				t.Fatalf("snapshot run = %+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("snapshot omits the active run: %+v", snap.Runs)
	}
	if snap.Queued < 2 {
		t.Fatalf("snapshot queued count = %d, want at least the two seeded jobs", snap.Queued)
	}

	// Inject a transition AFTER the snapshot: its event seq must be strictly
	// above the snapshot cursor, so a consumer starting there cannot miss it.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status = 'blocked', error = 'post-snapshot' WHERE id = $1`, jobA); err != nil {
		t.Fatal(err)
	}
	latest, err := st.LatestExecutionEventSeq(ctx)
	if err != nil || latest <= snap.Cursor {
		t.Fatalf("latest after post-snapshot transition = %d err %v, want > snapshot cursor %d", latest, err, snap.Cursor)
	}
	page, _, _, _, err := st.ReadExecutionEventsRetention(ctx, snap.Cursor, MaxExecutionEventLimit, runID)
	if err != nil {
		t.Fatal(err)
	}
	sawBlocked := false
	for _, e := range page {
		if e.Type == "job.blocked" && e.JobID == jobA && e.Seq > snap.Cursor {
			sawBlocked = true
		}
	}
	if !sawBlocked {
		t.Fatalf("post-snapshot transition missing above cursor %d: %+v", snap.Cursor, page)
	}
}

// TestPostgresIntegrationRunKeyIndexRepair proves the 0048/0053 repair path:
// a database whose index is missing (the state a dirty 0048 left behind) gets
// jobs_run_key_idx re-created when the 0053 migration applies, and
// RunKeyIndexPresent reports the presence truthfully either way.
func TestPostgresIntegrationRunKeyIndexRepair(t *testing.T) {
	// Clone a database at schema version 52, BEFORE 0053 exists in its
	// migration history, so the repair migration can be applied for real.
	env := pgITSetupAtVersion(t, 52)
	st := env.open(t)
	ctx := context.Background()
	present, err := st.RunKeyIndexPresent(ctx)
	if err != nil || !present {
		t.Fatalf("database at 52 index present = %v err %v, want true", present, err)
	}
	if _, err := st.pool.Exec(ctx, `DROP INDEX IF EXISTS jobs_run_key_idx`); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	present, err = st.RunKeyIndexPresent(ctx)
	if err != nil || present {
		t.Fatalf("dropped index present = %v err %v, want false", present, err)
	}
	// Migrate applies 0053 exactly as startup would: the conditional CREATE
	// UNIQUE INDEX runs again and repairs the database.
	env.migrate(t, st)
	present, err = st.RunKeyIndexPresent(ctx)
	if err != nil || !present {
		t.Fatalf("index after 0053 = %v err %v, want true", present, err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != pgITLatestVersion(t) {
		t.Fatalf("schema version after repair = %d err %v, want %d", v, err, pgITLatestVersion(t))
	}
}

// TestPostgresIntegrationDeploymentEventAttempt proves the stored semantic
// deployment events carry the record's lease generation as Attempt.
func TestPostgresIntegrationDeploymentEventAttempt(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	d := model.Deployment{
		ID: pgITNewID(t), RunID: runID, JobID: jobID, Environment: "staging",
		Status: model.StatusRunning, LeaseGeneration: 3, CreatedAt: time.Now().UTC(),
	}
	if _, created, err := st.StartDeployment(ctx, d, model.AuditEvent{ID: pgITNewID(t), Action: "deployment.started"}); err != nil || !created {
		t.Fatalf("start = created %v err %v", created, err)
	}
	page, _, _, _, err := st.ReadExecutionEventsRetention(ctx, 0, MaxExecutionEventLimit, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page {
		if e.Type == model.EventDeploymentStarted {
			if e.Attempt != 3 {
				t.Fatalf("deployment.started attempt = %d, want 3: %+v", e.Attempt, e)
			}
			return
		}
	}
	t.Fatalf("no deployment.started event in %+v", page)
}

// TestFaultyStoreNewForwards pins the wrapper forwarding for the new reads:
// an inner store that lacks a contract fails closed, and a capable inner
// store is passed through.
func TestFaultyStoreNewForwards(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	if err := inner.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "run.queued"}); err != nil {
		t.Fatal(err)
	}
	fault := &FaultyStore{Inner: inner}
	if page, _, _, latest, err := fault.ReadExecutionEventsRetention(ctx, 0, 10, ""); err != nil || len(page) != 1 || latest != 1 {
		t.Fatalf("forwarded retention read = %d latest %d err %v", len(page), latest, err)
	}
	if latest, err := fault.LatestExecutionEventSeq(ctx); err != nil || latest != 1 {
		t.Fatalf("forwarded latest = %d err %v", latest, err)
	}
	if _, _, _, _, err := (&FaultyStore{Inner: storeOnlyInner{}}).ReadExecutionEventsRetention(ctx, 0, 10, ""); err == nil {
		t.Fatal("missing inner read contract must fail closed")
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).LatestExecutionEventSeq(ctx); err == nil {
		t.Fatal("missing inner cursor contract must fail closed")
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).ExecutionSnapshot(ctx, 0); err == nil {
		t.Fatal("missing inner snapshot contract must fail closed")
	}
}
