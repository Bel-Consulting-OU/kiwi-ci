package storage

// Real-PostgreSQL integration test for the metrics aggregates. It is gated on
// KIWI_TEST_POSTGRES_URL via pgITStore (skipped when the variable is unset,
// and in -short mode).
//
// The dataset is deliberately shaped so the OLD metrics path would have been
// wrong: 133 runs / 137 jobs with failures only in the runs older than the
// newest 100, and jobs in terminal runs whose statuses differ from their
// run's. The test proves the SQL aggregates report the true table-wide counts
// (not a newest-100 sample), equal the in-memory aggregates for the same
// data, and fail closed on a cancelled context.

import (
	"context"
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestIntegrationMetricsAggregatesPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// Before seeding, the fresh tables aggregate to empty families and a
	// zero slot total (SUM over zero rows is NULL — the SQL must COALESCE,
	// and an empty family is a readable empty map, not an error).
	if runs, err := st.RunStatusCounts(ctx); err != nil || runs == nil || len(runs) != 0 {
		t.Fatalf("empty RunStatusCounts = %v, %v; want non-nil empty map", runs, err)
	}
	if jobs, err := st.JobStatusCounts(ctx); err != nil || jobs == nil || len(jobs) != 0 {
		t.Fatalf("empty JobStatusCounts = %v, %v; want non-nil empty map", jobs, err)
	}
	if reasons, err := st.QueuedJobQueueReasonCounts(ctx); err != nil || reasons == nil || len(reasons) != 0 {
		t.Fatalf("empty QueuedJobQueueReasonCounts = %v, %v; want non-nil empty map", reasons, err)
	}
	if slots, err := st.RunnerSlotTotals(ctx); err != nil || slots != (RunnerSlotTotals{}) {
		t.Fatalf("empty RunnerSlotTotals = %+v, %v; want zero", slots, err)
	}

	metricsAggregateSeed(t, st)

	runs, err := st.RunStatusCounts(ctx)
	if err != nil {
		t.Fatalf("RunStatusCounts: %v", err)
	}
	jobs, err := st.JobStatusCounts(ctx)
	if err != nil {
		t.Fatalf("JobStatusCounts: %v", err)
	}
	reasons, err := st.QueuedJobQueueReasonCounts(ctx)
	if err != nil {
		t.Fatalf("QueuedJobQueueReasonCounts: %v", err)
	}
	slots, err := st.RunnerSlotTotals(ctx)
	if err != nil {
		t.Fatalf("RunnerSlotTotals: %v", err)
	}

	wantRuns, wantJobs, wantReasons, wantSlots := metricsAggregateWant()
	if !reflect.DeepEqual(runs, wantRuns) {
		t.Fatalf("runs = %v, want %v", runs, wantRuns)
	}
	if !reflect.DeepEqual(jobs, wantJobs) {
		t.Fatalf("jobs = %v, want %v (jobs of terminal runs must be counted)", jobs, wantJobs)
	}
	if !reflect.DeepEqual(reasons, wantReasons) {
		t.Fatalf("reasons = %v, want %v", reasons, wantReasons)
	}
	if slots != wantSlots {
		t.Fatalf("slots = %+v, want %+v", slots, wantSlots)
	}

	// The defect being fixed: ListRuns(100) (the old DB metrics source) sees
	// only the newest 100 runs — zero failures — while the aggregate counts
	// all 30. This pins that the aggregate is NOT that sample.
	listed, err := st.ListRuns(ctx, 100)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	sampled := map[model.Status]int{}
	for _, r := range listed {
		sampled[r.Status]++
	}
	if len(listed) != 100 {
		t.Fatalf("ListRuns(100) returned %d runs", len(listed))
	}
	if sampled[model.StatusFailure] != 0 {
		t.Fatalf("sampled failure runs = %d, want 0 (the sample is what the old path counted)", sampled[model.StatusFailure])
	}
	if runs[model.StatusFailure] != 30 {
		t.Fatalf("aggregate failure runs = %d, want 30", runs[model.StatusFailure])
	}

	// Memory/DB parity for the exact same dataset.
	mem := newMemStore()
	metricsAggregateSeed(t, mem)
	memRuns, err := mem.RunStatusCounts(ctx)
	if err != nil {
		t.Fatalf("mem RunStatusCounts: %v", err)
	}
	memJobs, err := mem.JobStatusCounts(ctx)
	if err != nil {
		t.Fatalf("mem JobStatusCounts: %v", err)
	}
	memReasons, err := mem.QueuedJobQueueReasonCounts(ctx)
	if err != nil {
		t.Fatalf("mem QueuedJobQueueReasonCounts: %v", err)
	}
	memSlots, err := mem.RunnerSlotTotals(ctx)
	if err != nil {
		t.Fatalf("mem RunnerSlotTotals: %v", err)
	}
	if !reflect.DeepEqual(runs, memRuns) || !reflect.DeepEqual(jobs, memJobs) ||
		!reflect.DeepEqual(reasons, memReasons) || slots != memSlots {
		t.Fatalf("postgres/memory parity broken:\npg runs=%v jobs=%v reasons=%v slots=%+v\nmem runs=%v jobs=%v reasons=%v slots=%+v",
			runs, jobs, reasons, slots, memRuns, memJobs, memReasons, memSlots)
	}

	// A cancelled context is an error for every aggregate: never a zero map
	// a scrape could render as wrong zeros.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if v, err := st.RunStatusCounts(canceled); err == nil || v != nil {
		t.Fatalf("RunStatusCounts on canceled ctx = %v, %v; want error and nil", v, err)
	}
	if v, err := st.JobStatusCounts(canceled); err == nil || v != nil {
		t.Fatalf("JobStatusCounts on canceled ctx = %v, %v; want error and nil", v, err)
	}
	if v, err := st.QueuedJobQueueReasonCounts(canceled); err == nil || v != nil {
		t.Fatalf("QueuedJobQueueReasonCounts on canceled ctx = %v, %v; want error and nil", v, err)
	}
	if _, err := st.RunnerSlotTotals(canceled); err == nil {
		t.Fatal("RunnerSlotTotals on canceled ctx must fail")
	}
}
