package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// metricsAggregateRun builds a canonical 32-hex run ID for the metrics
// aggregate tests.
func metricsAggregateID(base int) string { return fmt.Sprintf("%032x", base) }

// metricsAggregateSeed fills a Store with the aggregate test dataset: runs
// whose statuses are spread, jobs inside terminal runs (the status gauge
// counts them), jobs with and without queue reasons, and runners with
// clamped capacities. The same dataset is used for the memStore reference
// and, in the integration test, for the real PostgresStore, so both backends
// must produce identical aggregates.
func metricsAggregateSeed(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	statusFor := func(i int) model.Status {
		switch {
		case i < 30:
			return model.StatusFailure
		case i >= 130 && i < 132:
			return model.StatusRunning
		case i == 132:
			return model.StatusQueued
		default:
			return model.StatusSuccess
		}
	}
	for i := 0; i < 133; i++ {
		if err := st.InsertRun(ctx, model.Run{
			ID:        metricsAggregateID(i),
			Status:    statusFor(i),
			CreatedAt: time.Unix(int64(1000+i), 0).UTC(),
		}); err != nil {
			t.Fatalf("insert run %d: %v", i, err)
		}
	}
	// One job per run: failure runs hold a successful job and vice versa,
	// so a terminal-run filter could not accidentally produce the right
	// numbers.
	for i := 0; i < 133; i++ {
		jobStatus := model.StatusFailure
		if i < 30 {
			jobStatus = model.StatusSuccess
		}
		switch {
		case i >= 130 && i < 132:
			jobStatus = model.StatusRunning
		case i == 132:
			jobStatus = model.StatusQueued
		}
		j := model.Job{
			ID:        metricsAggregateID(0x1000 + i),
			RunID:     metricsAggregateID(i),
			Key:       "build",
			Status:    jobStatus,
			CreatedAt: time.Unix(int64(2000+i), 0).UTC(),
		}
		if i == 132 {
			j.QueueReason = "NO_COMPATIBLE_RUNNER"
		}
		if err := st.InsertJob(ctx, j); err != nil {
			t.Fatalf("insert job %d: %v", i, err)
		}
	}
	// Queue-reason coverage: counted only for queued/approval-waiting jobs
	// with a non-empty reason.
	extra := []model.Job{
		{ID: metricsAggregateID(0x2000), RunID: metricsAggregateID(30), Key: "deploy", Status: model.StatusWaitingApproval, QueueReason: "WAITING_APPROVAL"},
		{ID: metricsAggregateID(0x2001), RunID: metricsAggregateID(30), Key: "test", Status: model.StatusQueued, QueueReason: "WAITING_DEPENDENCY"},
		{ID: metricsAggregateID(0x2002), RunID: metricsAggregateID(30), Key: "lint", Status: model.StatusQueued},
		{ID: metricsAggregateID(0x2003), RunID: metricsAggregateID(30), Key: "docs", Status: model.StatusSuccess, QueueReason: "STALE_REASON"},
	}
	for _, j := range extra {
		j.CreatedAt = time.Unix(3000, 0).UTC()
		if err := st.InsertJob(ctx, j); err != nil {
			t.Fatalf("insert extra job %s: %v", j.ID, err)
		}
	}
	for i, r := range []model.Runner{
		{ID: metricsAggregateID(0x3000), Name: "zero", Capacity: 0, ActiveJobs: []string{metricsAggregateID(0x1000)}},
		{ID: metricsAggregateID(0x3001), Name: "four", Capacity: 4, ActiveJobs: []string{metricsAggregateID(0x1001), metricsAggregateID(0x1002)}},
		{ID: metricsAggregateID(0x3002), Name: "two", Capacity: 2},
	} {
		r.Registered = time.Unix(4000+int64(i), 0).UTC()
		if err := st.UpsertRunner(ctx, r); err != nil {
			t.Fatalf("upsert runner %s: %v", r.ID, err)
		}
	}
}

// metricsAggregateWant is the reference aggregate of metricsAggregateSeed:
// the expected values for BOTH backends.
func metricsAggregateWant() (map[model.Status]int, map[model.Status]int, map[string]int, RunnerSlotTotals) {
	runs := map[model.Status]int{
		model.StatusFailure: 30,
		model.StatusSuccess: 100,
		model.StatusRunning: 2,
		model.StatusQueued:  1,
	}
	jobs := map[model.Status]int{
		model.StatusSuccess:         31, // 30 jobs in failure runs + the stale-reason success job
		model.StatusFailure:         100,
		model.StatusRunning:         2,
		model.StatusQueued:          3,
		model.StatusWaitingApproval: 1,
	}
	reasons := map[string]int{
		"NO_COMPATIBLE_RUNNER": 1,
		"WAITING_APPROVAL":     1,
		"WAITING_DEPENDENCY":   1,
	}
	slots := RunnerSlotTotals{Runners: 3, Capacity: 1 + 4 + 2, Busy: 3}
	return runs, jobs, reasons, slots
}

// TestMetricsAggregatesMemStoreReference pins the in-memory aggregates to the
// explicitly counted reference: every run, every job (terminal runs
// included), queued/approval-waiting reasons only, and runner capacities
// clamped at one slot.
func TestMetricsAggregatesMemStoreReference(t *testing.T) {
	m := newMemStore()
	metricsAggregateSeed(t, m)
	ctx := context.Background()

	runs, err := m.RunStatusCounts(ctx)
	if err != nil {
		t.Fatalf("RunStatusCounts: %v", err)
	}
	jobs, err := m.JobStatusCounts(ctx)
	if err != nil {
		t.Fatalf("JobStatusCounts: %v", err)
	}
	reasons, err := m.QueuedJobQueueReasonCounts(ctx)
	if err != nil {
		t.Fatalf("QueuedJobQueueReasonCounts: %v", err)
	}
	slots, err := m.RunnerSlotTotals(ctx)
	if err != nil {
		t.Fatalf("RunnerSlotTotals: %v", err)
	}

	wantRuns, wantJobs, wantReasons, wantSlots := metricsAggregateWant()
	if !reflect.DeepEqual(runs, wantRuns) {
		t.Fatalf("runs = %v, want %v", runs, wantRuns)
	}
	if !reflect.DeepEqual(jobs, wantJobs) {
		t.Fatalf("jobs = %v, want %v", jobs, wantJobs)
	}
	if !reflect.DeepEqual(reasons, wantReasons) {
		t.Fatalf("reasons = %v, want %v", reasons, wantReasons)
	}
	if slots != wantSlots {
		t.Fatalf("slots = %+v, want %+v", slots, wantSlots)
	}
	// The newest-100 sampling the old DB path used would have undercounted:
	// the 100 newest runs are all non-failure, yet 30 failure runs exist.
	// (The in-memory ListRuns returns the whole map, so the sample is
	// computed from the seeded order the SQL ORDER BY created_at DESC, id
	// DESC would produce.)
	sampled := map[model.Status]int{}
	all, err := m.ListRuns(ctx, 100)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	for _, r := range all[:100] {
		sampled[r.Status]++
	}
	if sampled[model.StatusFailure] != 0 {
		t.Fatalf("sampled failure runs = %d, want 0 (the sample must be wrong for this dataset)", sampled[model.StatusFailure])
	}
	if runs[model.StatusFailure] != 30 {
		t.Fatalf("aggregate failure runs = %d, want 30", runs[model.StatusFailure])
	}
}

// TestMetricsAggregatesFaultyStoreParity proves the fault-injection wrapper
// delegates the aggregates unchanged and that the read-only calls never
// consume the write-fault counter (even armed, a metrics scrape must not
// inject a write fault).
func TestMetricsAggregatesFaultyStoreParity(t *testing.T) {
	inner := newMemStore()
	metricsAggregateSeed(t, inner)
	faulted := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	ctx := context.Background()

	runs, err := faulted.RunStatusCounts(ctx)
	if err != nil {
		t.Fatalf("RunStatusCounts: %v", err)
	}
	jobs, err := faulted.JobStatusCounts(ctx)
	if err != nil {
		t.Fatalf("JobStatusCounts: %v", err)
	}
	reasons, err := faulted.QueuedJobQueueReasonCounts(ctx)
	if err != nil {
		t.Fatalf("QueuedJobQueueReasonCounts: %v", err)
	}
	slots, err := faulted.RunnerSlotTotals(ctx)
	if err != nil {
		t.Fatalf("RunnerSlotTotals: %v", err)
	}
	wantRuns, wantJobs, wantReasons, wantSlots := metricsAggregateWant()
	if !reflect.DeepEqual(runs, wantRuns) || !reflect.DeepEqual(jobs, wantJobs) || !reflect.DeepEqual(reasons, wantReasons) || slots != wantSlots {
		t.Fatalf("wrapper aggregates diverged: runs=%v jobs=%v reasons=%v slots=%+v", runs, jobs, reasons, slots)
	}
	if faulted.Mutations() != 0 {
		t.Fatalf("read-only aggregates consumed write faults: Mutations() = %d", faulted.Mutations())
	}
}

// TestMetricsAggregatesCanceledContextFailsClosed pins the error contract:
// a cancelled context yields an error and a nil/zero result — never an empty
// map that a caller could render as wrong zeros.
func TestMetricsAggregatesCanceledContextFailsClosed(t *testing.T) {
	m := newMemStore()
	metricsAggregateSeed(t, m)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	for name, call := range map[string]func(MetricsAggregateStore) error{
		"RunStatusCounts": func(a MetricsAggregateStore) error {
			v, err := a.RunStatusCounts(canceled)
			if v != nil {
				t.Errorf("runs on canceled ctx = %v, want nil", v)
			}
			return err
		},
		"JobStatusCounts": func(a MetricsAggregateStore) error {
			v, err := a.JobStatusCounts(canceled)
			if v != nil {
				t.Errorf("jobs on canceled ctx = %v, want nil", v)
			}
			return err
		},
		"QueuedJobQueueReasonCounts": func(a MetricsAggregateStore) error {
			v, err := a.QueuedJobQueueReasonCounts(canceled)
			if v != nil {
				t.Errorf("reasons on canceled ctx = %v, want nil", v)
			}
			return err
		},
		"RunnerSlotTotals": func(a MetricsAggregateStore) error {
			v, err := a.RunnerSlotTotals(canceled)
			if v != (RunnerSlotTotals{}) {
				t.Errorf("slots on canceled ctx = %+v, want zero", v)
			}
			return err
		},
	} {
		t.Run("memStore/"+name, func(t *testing.T) {
			if err := call(m); !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		})
		t.Run("FaultyStore/"+name, func(t *testing.T) {
			if err := call(&FaultyStore{Inner: m}); !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		})
	}
}

// TestMetricsAggregatesEmptyStore pins the empty-store shape: non-nil empty
// maps (a readable, empty family) and a zero slot total, not nil/absent.
func TestMetricsAggregatesEmptyStore(t *testing.T) {
	m := newMemStore()
	runs, err := m.RunStatusCounts(context.Background())
	if err != nil || runs == nil || len(runs) != 0 {
		t.Fatalf("empty runs = %v, %v; want non-nil empty map", runs, err)
	}
	jobs, err := m.JobStatusCounts(context.Background())
	if err != nil || jobs == nil || len(jobs) != 0 {
		t.Fatalf("empty jobs = %v, %v; want non-nil empty map", jobs, err)
	}
	reasons, err := m.QueuedJobQueueReasonCounts(context.Background())
	if err != nil || reasons == nil || len(reasons) != 0 {
		t.Fatalf("empty reasons = %v, %v; want non-nil empty map", reasons, err)
	}
	slots, err := m.RunnerSlotTotals(context.Background())
	if err != nil || slots != (RunnerSlotTotals{}) {
		t.Fatalf("empty slots = %+v, %v; want zero", slots, err)
	}
}
