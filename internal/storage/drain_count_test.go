package storage

// Non-PostgreSQL tests for the S1B drain count: the memStore aggregate must
// match the SQL contract (running jobs only, across every run), and
// FaultyStore must pass reads through untouched while still being able to
// inject a CountRunningJobs failure for the drain error-path tests.

import (
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var errCountRunningBoom = errors.New("storage: injected count failure")

// TestMemStoreCountRunningJobs: the aggregate counts running lease holders
// only, across every run, regardless of run status or ordering.
func TestMemStoreCountRunningJobs(t *testing.T) {
	ctx := ctx()
	m := newMemStore()
	if n, err := m.CountRunningJobs(ctx); err != nil || n != 0 {
		t.Fatalf("empty CountRunningJobs = %d, %v; want 0", n, err)
	}
	// A running job in a TERMINAL run still counts: the aggregate is over
	// jobs, not over non-terminal runs.
	successRun := model.Run{ID: "dddddddddddddddddddddddddddddddd", Status: model.StatusSuccess, CreatedAt: time.Unix(1500, 0).UTC()}
	runningJob := model.Job{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", RunID: successRun.ID, Key: "build", Status: model.StatusRunning, CreatedAt: time.Unix(1501, 0).UTC()}
	if err := m.InsertRun(ctx, successRun); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	if err := m.InsertJob(ctx, runningJob); err != nil {
		t.Fatalf("InsertJob running: %v", err)
	}
	// Queued and terminal jobs never count.
	for _, st := range []model.Status{model.StatusQueued, model.StatusSuccess, model.StatusFailure, model.StatusCancelled} {
		j := testJob
		j.ID = string(st) + "-job-00000000000000000000"
		j.Status = st
		if err := m.InsertJob(ctx, j); err != nil {
			t.Fatalf("InsertJob %s: %v", st, err)
		}
	}
	if n, err := m.CountRunningJobs(ctx); err != nil || n != 1 {
		t.Fatalf("CountRunningJobs = %d, %v; want 1", n, err)
	}
	seedRunningJob(m)
	if n, err := m.CountRunningJobs(ctx); err != nil || n != 2 {
		t.Fatalf("CountRunningJobs after a second running job = %d, %v; want 2", n, err)
	}
}

// TestFaultyStoreCountRunningJobs verifies passthrough and the explicit
// read-fault seam: the write-fault counter never fires on a read, and the
// injected count error is returned and clearable.
func TestFaultyStoreCountRunningJobs(t *testing.T) {
	ctx := ctx()
	inner := newMemStore()
	seedRunningJob(inner)
	f := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	if n, err := f.CountRunningJobs(ctx); err != nil || n != 1 {
		t.Fatalf("CountRunningJobs passthrough = %d, %v; want 1 (reads never fault)", n, err)
	}
	if got := f.Mutations(); got != 0 {
		t.Fatalf("Mutations() = %d after a read; want 0", got)
	}
	f.SetCountRunningJobsError(errCountRunningBoom)
	if n, err := f.CountRunningJobs(ctx); n != 0 || !errors.Is(err, errCountRunningBoom) {
		t.Fatalf("injected CountRunningJobs = %d, %v; want 0, injected error", n, err)
	}
	f.SetCountRunningJobsError(nil)
	if n, err := f.CountRunningJobs(ctx); err != nil || n != 1 {
		t.Fatalf("CountRunningJobs after clearing the fault = %d, %v; want 1", n, err)
	}
}
