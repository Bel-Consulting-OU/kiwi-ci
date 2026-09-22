package storage

// In-memory (mem parity) tests for the aggregate service-envelope
// reservation: the memory-store claim, its derived ledger and the memory
// reconciliation must charge a job's own request PLUS its aggregate service
// envelope, exactly like the SQL claim transaction (reserveResourcesTx) and
// the SQL promotion reconciliation.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemStoreServiceEnvelopeReservation: the memory-store claim reserves
// own + envelope in the ONE per-job row (a runner without room for the
// aggregate is not admitted), a job without services reserves exactly its own
// request, the memory reconciliation reconstructs the same aggregate, and the
// release deletes the single row.
func TestMemStoreServiceEnvelopeReservation(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runnerID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01"
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 8,
		ResourceCapacity: model.ResourceCapacity{Memory: 8 << 30}}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	runID, svcJob, plainJob := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04"
	req := InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: "https://github.com/o/r.git", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			svcJob: {ID: svcJob, RunID: runID, Key: "svc", RepoURL: "https://github.com/o/r.git", Status: model.StatusQueued,
				MemoryRequest: 5 << 30, ServiceEnvelopeRequest: model.ResourceCapacity{CPU: 1, Memory: 2 << 30, PIDs: 512},
				CreatedAt: time.Now().UTC()},
			plainJob: {ID: plainJob, RunID: runID, Key: "plain", RepoURL: "https://github.com/o/r.git", Status: model.StatusQueued,
				MemoryRequest: 3 << 30, CreatedAt: time.Now().UTC().Add(time.Second)},
		},
	}
	if err := m.InsertCompiledRun(ctx, req); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	claimFor := func(jobID string, own model.ResourceCapacity, envelope model.ResourceCapacity) LeaseClaim {
		return LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
			ExpiresAt: time.Now().UTC().Add(time.Hour), Runtime: "container",
			CPURequest: own.CPU, MemoryRequest: own.Memory, DiskRequest: own.Disk, PIDsRequest: own.PIDs,
			ServiceEnvelopeRequest: envelope}
	}
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}

	// A runner with an 8 GiB capacity cannot take a 5 GiB job whose services
	// need 4 GiB more (aggregate 9): the claim is rejected before anything
	// is reserved.
	oversized := claimFor(svcJob, fiveGiB, model.ResourceCapacity{CPU: 1, Memory: 4 << 30, PIDs: 512})
	if _, err := m.AcquireLeaseAtomic(ctx, oversized); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("claim with 5GiB+4GiB envelope = %v, want ErrResourceCapacity", err)
	}
	if got, err := m.RunnerReservedResources(ctx, runnerID); err != nil || got != (model.ResourceCapacity{}) {
		t.Fatalf("reserved after rejected aggregate = %+v err=%v, want zero", got, err)
	}
	if rows, _ := m.ListResourceReservations(ctx, runnerID); len(rows) != 0 {
		t.Fatalf("ledger rows after rejected aggregate = %d, want 0", len(rows))
	}

	// The fitting aggregate (5+2 = 7 <= 8) leases; the ONE row carries the
	// total, not the own request.
	if _, err := m.AcquireLeaseAtomic(ctx, claimFor(svcJob, fiveGiB, model.ResourceCapacity{CPU: 1, Memory: 2 << 30, PIDs: 512})); err != nil {
		t.Fatalf("claim with 5GiB+2GiB envelope: %v", err)
	}
	want := model.ResourceCapacity{CPU: 1, Memory: 7 << 30, PIDs: 512}
	if got, err := m.RunnerReservedResources(ctx, runnerID); err != nil || got != want {
		t.Fatalf("reserved with services = %+v err=%v, want %+v", got, err, want)
	}
	if rows, _ := m.ListResourceReservations(ctx, runnerID); len(rows) != 1 {
		t.Fatalf("ledger rows with services = %d, want 1 (job + services share one row)", len(rows))
	}

	// The plain job's own 3 GiB does not fit the remaining 1 GiB; after the
	// service lease completes it does — and reserves exactly its own request.
	if _, err := m.AcquireLeaseAtomic(ctx, claimFor(plainJob, model.ResourceCapacity{Memory: 3 << 30}, model.ResourceCapacity{})); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("plain claim while services hold capacity = %v, want ErrResourceCapacity", err)
	}
	receipt := model.CompletionReceipt{JobID: svcJob, Generation: 1, RunnerID: runnerID}
	if err := m.CompleteJob(ctx, svcJob, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("complete service job: %v", err)
	}
	if got, err := m.RunnerReservedResources(ctx, runnerID); err != nil || got != (model.ResourceCapacity{}) {
		t.Fatalf("reserved after completion = %+v err=%v, want zero", got, err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx, claimFor(plainJob, model.ResourceCapacity{Memory: 3 << 30}, model.ResourceCapacity{})); err != nil {
		t.Fatalf("plain claim after release: %v", err)
	}
	if got, err := m.RunnerReservedResources(ctx, runnerID); err != nil || got != (model.ResourceCapacity{Memory: 3 << 30}) {
		t.Fatalf("plain reserved = %+v err=%v, want exactly its own 3GiB", got, err)
	}
}

// TestMemStoreServiceEnvelopeReconcile: the memory reconciliation reconstructs
// a running job's TOTAL reservation from its persisted payload (own +
// envelope), matching the SQL reconciliation's payload-derived aggregate.
func TestMemStoreServiceEnvelopeReconcile(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	runnerID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01"
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 8,
		ResourceCapacity: model.ResourceCapacity{Memory: 8 << 30}}); err != nil {
		t.Fatal(err)
	}
	runID, jobID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03"
	req := InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: "https://github.com/o/r.git", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: {ID: jobID, RunID: runID, Key: "svc", RepoURL: "https://github.com/o/r.git",
			Status: model.StatusQueued, MemoryRequest: 5 << 30,
			ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 2 << 30}, CreatedAt: time.Now().UTC()}},
	}
	if err := m.InsertCompiledRun(ctx, req); err != nil {
		t.Fatal(err)
	}
	// A pre-existing running lease with a STALE zero-capacity ledger row (the
	// rolling-upgrade precondition): reconciliation must rebuild the total.
	if _, err := m.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		ExpiresAt: time.Now().UTC().Add(time.Hour), MemoryRequest: 5 << 30,
		ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 2 << 30}}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	m.mu.Lock()
	m.reservations[jobID] = ResourceReservation{JobID: jobID, RunnerID: runnerID, Generation: 1}
	m.mu.Unlock()

	res, err := m.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Running != 1 || res.Upserted != 1 {
		t.Fatalf("reconcile result = %+v, want running=1 upserted=1", res)
	}
	want := model.ResourceCapacity{Memory: 7 << 30}
	if got, err := m.RunnerReservedResources(ctx, runnerID); err != nil || got != want {
		t.Fatalf("reserved after reconcile = %+v err=%v, want own+envelope %+v", got, err, want)
	}
}
