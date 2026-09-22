package storage

// Memory-store parity for the leader-promotion resource reconciliation
// (E4-B): the in-memory ledger rebuild must derive the same rows from the
// same job state as the SQL pass — running leases only, live generations
// only, the job's own request, idempotent on repeat — and the FaultyStore
// wrapper must present the same fail-closed contract (missing contract,
// injected stale leadership, injected mutation failure).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestMemReconcileResourceReservationsRebuildsLedger(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := m.UpsertRunner(ctx, model.Runner{ID: "abcdef0123456789abcdef0123456789", Name: "r", Capacity: 8, ResourceCapacity: model.ResourceCapacity{Memory: 8 << 30}}); err != nil {
		t.Fatal(err)
	}
	runID := "mem-rec-run"
	if err := m.InsertRun(ctx, model.Run{ID: runID, Status: model.StatusQueued, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}
	jobs := map[string]model.Job{
		"mem-old":      {ID: "mem-old", RunID: runID, Key: "old", Status: model.StatusQueued, CreatedAt: now, MemoryRequest: fiveGiB.Memory},
		"mem-new":      {ID: "mem-new", RunID: runID, Key: "new", Status: model.StatusQueued, CreatedAt: now.Add(time.Second), MemoryRequest: fiveGiB.Memory},
		"mem-terminal": {ID: "mem-terminal", RunID: runID, Key: "term", Status: model.StatusSuccess, CreatedAt: now, MemoryRequest: fiveGiB.Memory, FinishedAt: &now},
	}
	for _, j := range jobs {
		if err := m.InsertJob(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
	// An old-version leader left mem-old running with a live lease and no
	// reservation row; mem-terminal is done but its stale row survived; a
	// wrong-generation row survives for mem-new.
	old := m.jobs["mem-old"]
	old.Status = model.StatusRunning
	old.LeaseRunnerID = "abcdef0123456789abcdef0123456789"
	old.LeaseGeneration = 4
	m.jobs["mem-old"] = old
	m.reservations["mem-terminal"] = ResourceReservation{JobID: "mem-terminal", RunnerID: "abcdef0123456789abcdef0123456789", Generation: 1, Memory: 5 << 30}
	m.reservations["mem-new"] = ResourceReservation{JobID: "mem-new", RunnerID: "abcdef0123456789abcdef0123456789", Generation: 2, Memory: 1 << 30}
	// The two orphan rows (a terminal job and a stale generation) are
	// PHYSICALLY present but charge nothing: the capacity fold counts only
	// rows that still describe a live lease, exactly like the SQL SUM
	// (K6-B self-healing read).
	if got, _ := m.RunnerReservedResources(ctx, "abcdef0123456789abcdef0123456789"); got != (model.ResourceCapacity{}) {
		t.Fatalf("precondition reserved = %+v, want the orphan rows ignored", got)
	}
	if list, _ := m.ListResourceReservations(ctx, "abcdef0123456789abcdef0123456789"); len(list) != 2 {
		t.Fatalf("precondition ledger rows = %d, want the 2 raw orphan rows (listing is raw)", len(list))
	}

	res, err := m.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Running != 1 || res.Upserted != 1 || res.Deleted != 2 {
		t.Fatalf("reconcile result = %+v, want running=1 upserted=1 deleted=2", res)
	}
	got, err := m.RunnerReservedResources(ctx, "abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if got != fiveGiB {
		t.Fatalf("reserved = %+v, want the running lease's 5GiB", got)
	}
	list, err := m.ListResourceReservations(ctx, "abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].JobID != "mem-old" || list[0].Generation != 4 {
		t.Fatalf("ledger = %+v, want mem-old at generation 4", list)
	}

	// Idempotent repeat.
	res2, err := m.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Running != 1 || res2.Upserted != 1 || res2.Deleted != 0 {
		t.Fatalf("second reconcile = %+v, want running=1 upserted=1 deleted=0", res2)
	}
	// A requeued (no longer running) job loses its row on the next pass.
	old.Status = model.StatusQueued
	old.LeaseRunnerID = ""
	old.LeaseExpiresAt = nil
	m.jobs["mem-old"] = old
	if _, err := m.ReconcileResourceReservations(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.RunnerReservedResources(ctx, "abcdef0123456789abcdef0123456789"); got != (model.ResourceCapacity{}) {
		t.Fatalf("reserved after requeue = %+v, want zero", got)
	}
}

func TestMemReconcileResourceReservationsContextAndFaultyWrapper(t *testing.T) {
	inner := newMemStore()
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := inner.ReconcileResourceReservations(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconcile = %v, want context.Canceled", err)
	}

	// A wrapper over a store without the contract fails closed with the
	// diagnosable missing-interface error.
	var bare Store = &memStoreWithoutReconcile{}
	faulty := &FaultyStore{Inner: bare}
	if _, err := faulty.ReconcileResourceReservations(ctx); err == nil {
		t.Fatal("missing reconcile contract must fail closed")
	}
	// A wrapper over a real store delegates, and an injected stale-leader
	// error prevents the delegation entirely.
	wrapped := &FaultyStore{Inner: inner}
	now := time.Now().UTC()
	inner.mu.Lock()
	inner.jobs["mem-f"] = model.Job{ID: "mem-f", RunID: "r", Key: "f", Status: model.StatusRunning, LeaseRunnerID: "runner", LeaseGeneration: 1, MemoryRequest: 1 << 30, CreatedAt: now}
	inner.mu.Unlock()
	if _, err := wrapped.ReconcileResourceReservations(ctx); err != nil {
		t.Fatalf("faulty wrapper reconcile: %v", err)
	}
	if got, _ := inner.RunnerReservedResources(ctx, "runner"); got.Memory != 1<<30 {
		t.Fatalf("wrapped reconcile reserved = %d, want 1GiB", got.Memory)
	}
	wrapped.FailFencedWith(ErrStaleLeader)
	if _, err := wrapped.ReconcileResourceReservations(ctx); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("fenced wrapper reconcile = %v, want ErrStaleLeader", err)
	}
}

// memStoreWithoutReconcile is a minimal Store for the missing-contract path.
// It embeds nothing: every method fails the test if ever called, because the
// wrapper must reject before reaching Inner.
type memStoreWithoutReconcile struct{ Store }
