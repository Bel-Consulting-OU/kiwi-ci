package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemStoreApproveJob pins the in-memory approval transition and its
// fail-closed refusals.
func TestMemStoreApproveJob(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()

	if _, err := m.ApproveJob(ctx, "missing", "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing job = %v, want ErrNotFound", err)
	}
	if err := m.InsertJob(ctx, model.Job{ID: "no-approval", Status: model.StatusQueued}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveJob(ctx, "no-approval", "alice"); !errors.Is(err, ErrApprovalNotRequired) {
		t.Fatalf("no-approval job = %v, want ErrApprovalNotRequired", err)
	}
	if err := m.InsertJob(ctx, model.Job{ID: "terminal", Status: model.StatusSuccess, ApprovalRequired: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveJob(ctx, "terminal", "alice"); !errors.Is(err, ErrJobTerminal) {
		t.Fatalf("terminal job = %v, want ErrJobTerminal", err)
	}
	if err := m.InsertJob(ctx, model.Job{ID: "waiting", Status: model.StatusWaitingApproval, ApprovalRequired: true}); err != nil {
		t.Fatal(err)
	}
	got, err := m.ApproveJob(ctx, "waiting", "alice")
	if err != nil || got.Status != model.StatusQueued || got.ApprovedBy != "alice" || got.WaitingSince != nil {
		t.Fatalf("approve = %+v, %v; want queued by alice", got, err)
	}
	// Approving an already-approved queued job records the actor without
	// changing the status.
	again, err := m.ApproveJob(ctx, "waiting", "bob")
	if err != nil || again.Status != model.StatusQueued || again.ApprovedBy != "bob" {
		t.Fatalf("re-approve = %+v, %v", again, err)
	}
}

// TestFaultyStoreApprovalDelegation pins the fault-injection wrapper: the
// armed fault fails before Inner is touched, and the unarmed path delegates.
func TestFaultyStoreApprovalDelegation(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	if err := m.InsertJob(ctx, model.Job{ID: "waiting", Status: model.StatusWaitingApproval, ApprovalRequired: true}); err != nil {
		t.Fatal(err)
	}
	f := &FaultyStore{Inner: m}

	if _, err := f.ApproveJob(ctx, "waiting", "alice"); err != nil {
		t.Fatalf("unarmed approve = %v", err)
	}

	boom := errors.New("approval boom")
	armed := &FaultyStore{Inner: m, FailAfter: 1, Err: boom}
	if _, err := armed.ApproveJob(ctx, "waiting", "alice"); !errors.Is(err, boom) {
		t.Fatalf("armed approve = %v, want the injected fault", err)
	}
}

// TestFaultyStoreUpdateRunnerProfileFields pins the guarded profile-write
// wrapper and the underlying memStore contract.
func TestFaultyStoreUpdateRunnerProfileFields(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	if err := m.UpsertRunner(ctx, model.Runner{ID: "r1", Name: "old", Capacity: 4}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateRunnerProfileFields(ctx, model.Runner{ID: "r1", Name: "new", Capacity: 8}); err != nil {
		t.Fatalf("mem update = %v", err)
	}
	if err := m.UpdateRunnerProfileFields(ctx, model.Runner{ID: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing runner = %v, want ErrNotFound", err)
	}

	f := &FaultyStore{Inner: m}
	if err := f.UpdateRunnerProfileFields(ctx, model.Runner{ID: "r1", Name: "faulty"}); err != nil {
		t.Fatalf("unarmed update = %v", err)
	}
	boom := errors.New("profile write boom")
	armed := &FaultyStore{Inner: m, FailAfter: 1, Err: boom}
	if err := armed.UpdateRunnerProfileFields(ctx, model.Runner{ID: "r1"}); !errors.Is(err, boom) {
		t.Fatalf("armed update = %v, want the injected fault", err)
	}
}

// TestFaultyStoreReadDelegation pins the read-path delegation wrappers that
// inject no faults but must fail closed on a missing inner contract.
func TestFaultyStoreReadDelegation(t *testing.T) {
	ctx := context.Background()
	rid := "0123456789abcdef0123456789abcdef"
	m := newMemStore()
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "p1", MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	if err := m.LinkRunnerProfile(ctx, rid, "p1"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(ctx, model.Runner{ID: rid, Name: rid, Capacity: 2}); err != nil {
		t.Fatal(err)
	}
	f := &FaultyStore{Inner: m}

	if _, err := f.ResolveLiveRunnerProfile(ctx, rid, ""); err != nil {
		t.Fatalf("ResolveLiveRunnerProfile = %v", err)
	}
	if _, err := f.RunnerReservedResources(ctx, rid); err != nil {
		t.Fatalf("RunnerReservedResources = %v", err)
	}
	if _, err := f.ListResourceReservations(ctx, rid); err != nil {
		t.Fatalf("ListResourceReservations = %v", err)
	}
	if _, err := f.FleetRunnerProfileBindings(ctx); err != nil {
		t.Fatalf("FleetRunnerProfileBindings = %v", err)
	}
	if _, err := f.RunnerReservationSums(ctx); err != nil {
		t.Fatalf("RunnerReservationSums = %v", err)
	}
}
