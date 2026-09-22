package server

// The server-side resource-ledger gate and repair path (E4-B): the lease path
// may only serve leases after the ledger was rebuilt from the live leases,
// a failed reconciliation must refuse leases instead of over-admitting, and
// the exported repair call must re-run the store operation on demand.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
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

// TestServerResourceReconcileStandbyPollQuiet pins K2-C: reconciliation is a
// leader-only fenced mutation, so a standby's poll must not attempt it.
// Before the fix every standby poll attempted the reconcile, failed with
// ErrStaleLeader, logged "resource ledger reconciliation: stale leader epoch"
// at error level and answered 503 "resource ledger not reconciled" with
// X-Kiwi-State: reconciling instead of the normal not-leader rejection. The
// leader path is unchanged: the same poll after regaining the claim
// reconciles once and arms the gate.
func TestServerResourceReconcileStandbyPollQuiet(t *testing.T) {
	f := &reconcileFakeStore{dbFakeStore: newDBFakeStore()}
	s := New("token")
	var logs bytes.Buffer
	s.Logger = logging.NewStructured(&logs)
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.setLeader(false)
	f.mu.Lock()
	f.runners["gate-runner"] = model.Runner{ID: "gate-runner", Name: "gate", Capacity: 1}
	f.mu.Unlock()

	logs.Reset()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/gate-runner/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("standby next = %d, want 503: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "scheduler standby") {
		t.Fatalf("standby next body = %q, want the normal not-leader rejection", w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "" {
		t.Fatalf("standby next reported X-Kiwi-State %q, want none", got)
	}
	if got := f.calls; got != 0 {
		t.Fatalf("standby reconcile attempts = %d, want 0", got)
	}
	if s.resourceReconciled.Load() {
		t.Fatal("standby poll armed the reconcile gate")
	}
	if got := logs.String(); strings.Contains(got, "resource ledger reconciliation") || strings.Contains(got, "stale leader epoch") {
		t.Fatalf("standby poll produced reconcile noise: %s", got)
	}

	// Leader path unchanged: the poll reconciles once, arms the gate, and
	// with no queued work answers 204.
	f.setLeader(true)
	logs.Reset()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/gate-runner/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("leader next = %d, want 204: %s", w.Code, w.Body.String())
	}
	if got := f.calls; got != 1 {
		t.Fatalf("leader reconcile calls = %d, want 1", got)
	}
	if !s.resourceReconciled.Load() {
		t.Fatal("leader poll did not arm the reconcile gate")
	}
	if !strings.Contains(logs.String(), "resource ledger reconciled") {
		t.Fatalf("leader reconcile not logged: %s", logs.String())
	}
}

// TestServerResourceReconcileStaleLeaderRaceIsQuiet pins the second half of
// K2-C: when the leadership check passes but the fenced reconcile still fails
// with ErrStaleLeader (a newer leader published its epoch in between), that is
// "not leader", not a reconciliation failure. It must produce the normal
// not-leader rejection, no error-level reconcile noise and no lease attempt —
// never the misleading "resource ledger not reconciled".
func TestServerResourceReconcileStaleLeaderRaceIsQuiet(t *testing.T) {
	f := &reconcileFakeStore{dbFakeStore: newDBFakeStore(), err: storage.ErrStaleLeader}
	s := New("token")
	var logs bytes.Buffer
	s.Logger = logging.NewStructured(&logs)
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["race-runner"] = model.Runner{ID: "race-runner", Name: "race", Capacity: 1}
	f.mu.Unlock()

	logs.Reset()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/race-runner/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stale-leader next = %d, want 503: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "scheduler standby") {
		t.Fatalf("stale-leader next body = %q, want the normal not-leader rejection", w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "" {
		t.Fatalf("stale-leader next reported X-Kiwi-State %q, want none", got)
	}
	if got := f.calls; got != 1 {
		t.Fatalf("reconcile attempts = %d, want the one fenced attempt", got)
	}
	if s.resourceReconciled.Load() {
		t.Fatal("stale-leader race armed the reconcile gate")
	}
	if got := logs.String(); strings.Contains(got, "resource ledger reconciliation") || strings.Contains(got, "stale leader epoch") {
		t.Fatalf("stale-leader race produced reconcile noise: %s", got)
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
