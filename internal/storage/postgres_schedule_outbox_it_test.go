package storage

// Real-PostgreSQL integration coverage for the two read probes the DB mode
// uses outside the hot claim path: the schedule lookup (the scheduler's
// per-tick read) and the outbox membership probe (the completion-effect
// dedupe guard). Both must distinguish "absent" from "cannot read".

import (
	"context"
	"testing"
	"time"
)

// TestPostgresIntegrationGetScheduleReadsAndErrors: a stored schedule is
// returned with its spec, an unknown ID is not-found (not an error), and a
// broken relation surfaces an error.
func TestPostgresIntegrationGetScheduleReadsAndErrors(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	sc := Schedule{ID: "sched-read-it", Repository: pgITRepo, RepoID: pgITRepo, Spec: "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n", Enabled: true, CreatedAt: time.Now().UTC().Truncate(time.Second), CreatedBy: "admin"}
	if err := st.UpsertSchedule(ctx, sc); err != nil {
		t.Fatalf("UpsertSchedule: %v", err)
	}
	got, ok, err := st.GetSchedule(ctx, sc.ID)
	if err != nil || !ok {
		t.Fatalf("GetSchedule = (ok=%v, err=%v)", ok, err)
	}
	if got.ID != sc.ID || got.Repository != sc.Repository || got.Spec != sc.Spec || !got.Enabled || got.CreatedBy != sc.CreatedBy {
		t.Fatalf("round-tripped schedule = %+v, want %+v", got, sc)
	}
	if _, ok, err := st.GetSchedule(ctx, "absent-schedule"); err != nil || ok {
		t.Fatalf("unknown schedule = (ok=%v, err=%v), want not found", ok, err)
	}
	// A mistyped column makes the read fail: not-found must not be reported
	// for a store outage.
	pgITBreakColumnToArray(t, st, "schedules", "repository")
	if _, _, err := st.GetSchedule(ctx, sc.ID); err == nil {
		t.Fatal("GetSchedule over a broken relation succeeded")
	}
}

// TestPostgresIntegrationOutboxHasProbe: the membership probe answers
// true/false from durable rows, rejects an empty ID, and reports a broken
// relation instead of a false "not present" (which would re-append a
// completion effect).
func TestPostgresIntegrationOutboxHasProbe(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	item := OutboxItem{ID: pgITNewID(t), Kind: OutboxKindCompletionReconcile, CreatedAt: time.Now().UTC()}
	item.Payload = []byte(`{"job_id":"` + pgITNewID(t) + `"}`)
	if err := st.OutboxAppend(ctx, item); err != nil {
		t.Fatalf("OutboxAppend: %v", err)
	}
	if ok, err := st.OutboxHas(ctx, item.ID); err != nil || !ok {
		t.Fatalf("OutboxHas(known) = (%v, %v)", ok, err)
	}
	if ok, err := st.OutboxHas(ctx, "absent-id"); err != nil || ok {
		t.Fatalf("OutboxHas(unknown) = (%v, %v)", ok, err)
	}
	if _, err := st.OutboxHas(ctx, ""); err == nil {
		t.Fatal("OutboxHas with an empty id succeeded")
	}
	pgITBreakColumnToArray(t, st, "outbox", "id")
	if _, err := st.OutboxHas(ctx, item.ID); err == nil {
		t.Fatal("OutboxHas over a broken relation succeeded")
	}
}

// TestPostgresIntegrationScheduleLastRunAdvanceMonotonic is a small
// cross-check of the DB-mode schedule marker: an advance is observable
// through GetSchedule and a stale nominal cannot move it backwards.
func TestPostgresIntegrationScheduleLastRunAdvanceMonotonic(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	sc := Schedule{ID: "sched-advance-it", Repository: pgITRepo, Spec: "version: 1\njobs: {}\n", Enabled: true, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	if err := st.UpsertSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}
	newer := time.Now().UTC().Truncate(time.Second)
	if err := st.AdvanceScheduleLastRun(ctx, sc.ID, newer); err != nil {
		t.Fatalf("AdvanceScheduleLastRun: %v", err)
	}
	got, _, err := st.GetSchedule(ctx, sc.ID)
	if err != nil || got.LastRun == nil || !got.LastRun.Equal(newer) {
		t.Fatalf("advanced marker = (%+v, %v)", got.LastRun, err)
	}
	if err := st.AdvanceScheduleLastRun(ctx, sc.ID, newer.Add(-time.Hour)); err != nil {
		t.Fatalf("stale advance: %v", err)
	}
	got, _, err = st.GetSchedule(ctx, sc.ID)
	if err != nil || got.LastRun == nil || !got.LastRun.Equal(newer) {
		t.Fatalf("stale advance moved the marker: (%+v, %v)", got.LastRun, err)
	}
}
