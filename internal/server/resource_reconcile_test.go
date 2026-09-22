package server

// The server-side resource-ledger gate and repair path (E4-B): the lease path
// may only serve leases after the ledger was rebuilt from the live leases,
// a failed reconciliation must refuse leases instead of over-admitting, and
// the exported repair call must re-run the store operation on demand.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// reconcileFakeStore implements the reconcile contract over the fake store so
// the gate's ordering and failure handling are observable.
type reconcileFakeStore struct {
	*dbFakeStore
	calls int
	err   error
}

func (f *reconcileFakeStore) ReconcileResourceReservations(ctx context.Context) (storage.ResourceReconcileResult, error) {
	f.calls++
	if f.err != nil {
		return storage.ResourceReconcileResult{}, f.err
	}
	return storage.ResourceReconcileResult{Running: 1, Upserted: 1}, nil
}

var _ storage.ResourceReconcileStore = (*reconcileFakeStore)(nil)

func TestServerResourceReconcileGateBlocksLeasesUntilReconciled(t *testing.T) {
	f := &reconcileFakeStore{dbFakeStore: newDBFakeStore(), err: errors.New("ledger down")}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["gate-runner"] = model.Runner{ID: "gate-runner", Name: "gate", Capacity: 1}
	f.runs["gate-run"] = model.Run{ID: "gate-run", Status: model.StatusQueued}
	f.jobs["gate-job"] = model.Job{ID: "gate-job", RunID: "gate-run", Key: "build", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
	f.mu.Unlock()

	// A failed reconciliation refuses the lease: no token, no claim.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/gate-runner/next", "token", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreconciled next = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := f.calls; got != 1 {
		t.Fatalf("reconcile calls = %d, want 1", got)
	}
	f.mu.Lock()
	job := f.jobs["gate-job"]
	f.mu.Unlock()
	if job.Status != model.StatusQueued {
		t.Fatalf("job status after refused lease = %s, want queued", job.Status)
	}

	// Once the ledger reconciles, the same poll leases normally and later
	// polls do not reconcile again.
	f.err = nil
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/gate-runner/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("reconciled next = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := f.calls; got != 2 {
		t.Fatalf("reconcile calls = %d, want 2 (one failed + one successful)", got)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/gate-runner/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("busy next = %d, want 204: %s", w.Code, w.Body.String())
	}
	if got := f.calls; got != 2 {
		t.Fatalf("reconcile calls after arming = %d, want 2 (gate is a single load)", got)
	}
}

func TestServerResourceReconcileRepairPathAndMissingContract(t *testing.T) {
	f := &reconcileFakeStore{dbFakeStore: newDBFakeStore()}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	res, err := s.ReconcileResourceReservations(context.Background())
	if err != nil || f.calls != 1 {
		t.Fatalf("repair call = (%+v, %v) with %d calls", res, err, f.calls)
	}
	if res.Running != 1 || res.Upserted != 1 {
		t.Fatalf("repair result = %+v, want the store's result", res)
	}
	// The repair path also arms the gate.
	if err := s.ensureResourceReconciled(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Fatalf("ensure after repair = %d calls, want no extra pass", f.calls)
	}

	// A store without the contract opens the gate (its claim path is the
	// ledger) and the repair path is a documented no-op.
	plain := New("token")
	if err := plain.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if res, err := plain.ReconcileResourceReservations(context.Background()); err != nil || res != (storage.ResourceReconcileResult{}) {
		t.Fatalf("missing-contract repair = (%+v, %v), want a nil no-op", res, err)
	}
	if err := plain.ensureResourceReconciled(context.Background()); err != nil {
		t.Fatal(err)
	}
}
