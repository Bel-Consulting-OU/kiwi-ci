package server

// Resource-admission queue reasons in DB mode: a job whose request exceeds
// the runner's CONFIGURED capacity for good is explained as
// NO_COMPATIBLE_RUNNER (the existing "no runner can take this" semantics), a
// job that fits in principle but not in what is left is explained as
// RUNNER_CAPACITY, and both flow through the same SetQueueReasons contract
// the UI reads. The end-to-end lease behavior over real PostgreSQL lives in
// postgres_resource_reservation_it_test.go.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// reservationFakeStore adds the reservation-ledger contract to the DB-mode
// fake store, so the queue-reason explainer can distinguish the permanent and
// temporary resource reasons.
type reservationFakeStore struct {
	*dbFakeStore
	reserved model.ResourceCapacity
}

func (r *reservationFakeStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	return r.reserved, nil
}

func (r *reservationFakeStore) ListResourceReservations(ctx context.Context, runnerID string) ([]storage.ResourceReservation, error) {
	return nil, nil
}

var _ storage.ResourceReservationStore = (*reservationFakeStore)(nil)

// TestQueueReasonResourceAdmissionDBMode pins the resource reasons: a job
// above the runner's configured capacity is NO_COMPATIBLE_RUNNER, a job that
// fits the capacity but not the remaining reservation is RUNNER_CAPACITY,
// and a job with no configured capacity is never explained away.
func TestQueueReasonResourceAdmissionDBMode(t *testing.T) {
	f := &reservationFakeStore{dbFakeStore: newDBFakeStore(), reserved: model.ResourceCapacity{Memory: 3 << 30}}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	serial := "resource-serial"
	f.mu.Lock()
	f.profiles["resource-prof"] = model.RunnerProfile{ID: "resource-prof", MaxCapacity: 8, MaxMemory: 4 << 30}
	f.certProfiles[serial] = "resource-prof"
	f.runners["runner-res"] = model.Runner{ID: "runner-res", Name: "runner-res", Capacity: 8, CertSerial: serial}
	f.runs["run-res"] = model.Run{ID: "run-res", Status: model.StatusQueued}
	f.jobs["job-over"] = model.Job{ID: "job-over", RunID: "run-res", Key: "over", Status: model.StatusQueued, MemoryRequest: 8 << 30, CreatedAt: time.Now().UTC()}
	f.jobs["job-wait"] = model.Job{ID: "job-wait", RunID: "run-res", Key: "wait", Status: model.StatusQueued, MemoryRequest: 4 << 30, CreatedAt: time.Now().UTC().Add(time.Second)}
	f.mu.Unlock()

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-res/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	if got := f.queueReason("job-over"); got != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("job-over reason = %q, want NO_COMPATIBLE_RUNNER (permanently above capacity)", got)
	}
	if got := f.queueReason("job-wait"); got != "RUNNER_CAPACITY" {
		t.Fatalf("job-wait reason = %q, want RUNNER_CAPACITY (fits capacity, not remaining)", got)
	}

	// Free the reservation: the waiting job is no longer resource-blocked.
	f.mu.Lock()
	f.reserved = model.ResourceCapacity{}
	f.mu.Unlock()
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-res/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next after freeing capacity = %d: %s", w.Code, w.Body.String())
	}
}

// TestQueueReasonResourceAdmissionCapacityLessRunner: an unconstrained
// runner never reports a resource reason.
func TestQueueReasonResourceAdmissionCapacityLessRunner(t *testing.T) {
	f := &reservationFakeStore{dbFakeStore: newDBFakeStore()}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["runner-plain"] = model.Runner{ID: "runner-plain", Name: "runner-plain", Capacity: 2}
	f.runs["run-plain"] = model.Run{ID: "run-plain", Status: model.StatusQueued}
	f.jobs["job-big"] = model.Job{ID: "job-big", RunID: "run-plain", Key: "big", Status: model.StatusQueued, RequiredLabels: []string{"gpu"}, MemoryRequest: 512 << 30, CreatedAt: time.Now().UTC()}
	f.mu.Unlock()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-plain/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	// The label mismatch explains this runner, not the resources.
	if got := f.queueReason("job-big"); got != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("job-big reason = %q, want NO_COMPATIBLE_RUNNER (label)", got)
	}
}
