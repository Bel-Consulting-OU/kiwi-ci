package storage

import (
	"context"
	"testing"
)

// TestPostgresIntegrationApproveJobIdempotentReplay pins docs/INVARIANTS.md I8
// on the real SQL store: ApproveJob commits the waiting_approval -> queued
// transition and exactly one approval.granted event on the first call, and a
// repeat against the approved non-terminal job returns the stored job with the
// FIRST approver preserved and NO second event.
func TestPostgresIntegrationApproveJobIdempotentReplay(t *testing.T) {
	ctx := context.Background()
	st := pgITStore(t)
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{approval_required}', 'true') WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}

	first, err := st.ApproveJob(ctx, jobID, "alice")
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if first.ApprovedBy != "alice" {
		t.Fatalf("first approval = %+v, want alice", first)
	}
	second, err := st.ApproveJob(ctx, jobID, "bob")
	if err != nil {
		t.Fatalf("replayed approval: %v", err)
	}
	if second.ApprovedBy != "alice" || second.Status != first.Status {
		t.Fatalf("replayed approval = %+v, want the first approver alice and status %q", second, first.Status)
	}

	page, _, _, _, err := st.ReadExecutionEventsRetention(ctx, 0, MaxExecutionEventLimit, ExecutionEventScope{Kind: ExecutionEventScopeRun, RunID: runID})
	if err != nil {
		t.Fatal(err)
	}
	events := 0
	for _, e := range page {
		if e.Type == "approval.granted" {
			events++
		}
	}
	if events != 1 {
		t.Fatalf("approval.granted events = %d, want exactly 1", events)
	}
}
