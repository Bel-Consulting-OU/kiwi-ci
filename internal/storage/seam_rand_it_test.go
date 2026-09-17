package storage

// Integration coverage for the Postgres store's entropy-failure branches:
// every identifier minted inside a transaction must fail closed and roll the
// surrounding transaction back (no partial state).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

type pgSeamErrReader struct{}

func (pgSeamErrReader) Read([]byte) (int, error) { return 0, errors.New("seam: entropy failed") }

func TestPostgresIntegrationEntropyFailureRollsBack(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}

	old := randReader
	randReader = pgSeamErrReader{}
	restore := func() { randReader = old }
	defer restore()

	// CompleteJob: the audit-event id cannot be minted, so the completion
	// rolls back and the job stays running.
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}); err == nil {
		t.Fatal("CompleteJob with failing entropy must fail")
	}
	if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusRunning {
		t.Fatalf("rolled-back completion job = %+v, %v; want running", j, err)
	}

	// OutboxAppend: an item without an id fails closed and leaves no row.
	if err := st.OutboxAppend(ctx, OutboxItem{Kind: "seam", CreatedAt: time.Now().UTC()}); err == nil {
		t.Fatal("OutboxAppend with failing entropy must fail")
	}
	if n, err := st.OutboxPending(ctx); err != nil || len(n) != 0 {
		t.Fatalf("outbox rows after failed append = %d, %v; want 0", len(n), err)
	}

	// InsertTestReport: the report row is inserted first, the per-case id
	// fails, and the whole transaction rolls back.
	rep := model.TestReport{ID: pgITNewID(t), RunID: runID, JobID: jobID, Path: "results.xml", Tests: 1,
		Cases: []model.TestResult{{Name: "case-1"}}, CreatedAt: time.Now().UTC()}
	if err := st.InsertTestReport(ctx, rep); err == nil {
		t.Fatal("InsertTestReport with failing entropy must fail")
	}
	if reports, err := st.ListTestReports(ctx, runID); err != nil || len(reports) != 0 {
		t.Fatalf("test reports after failed insert = %d, %v; want 0", len(reports), err)
	}

	restore()
	// cancelSupersededTx: the superseded job is cancelled inside the enqueue
	// transaction, the audit id fails there, and the enqueue rolls back
	// leaving the superseded job untouched.
	superseded := pgITNewID(t)
	pgITEnqueueOne(t, st, pgITNewID(t), superseded, pgITRepo)
	randReader = pgSeamErrReader{}
	err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:            pgITRun(pgITNewID(t), model.StatusQueued),
		CancelPrevious: []string{superseded},
	})
	if err == nil {
		t.Fatal("InsertCompiledRun with failing entropy must fail")
	}
	if j, err := st.GetJob(ctx, superseded); err != nil || j.Status != model.StatusQueued {
		t.Fatalf("superseded job after failed enqueue = %+v, %v; want queued", j, err)
	}
}
