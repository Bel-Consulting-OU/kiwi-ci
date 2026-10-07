package server

// DB-mode /next clock tests (Round-11 finding B2): the lease tick must use the
// store's database clock, never the serving replica's application clock, and
// a failed clock read must fail the lease request instead of silently falling
// back to time.Now().

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestDBNextUsesTheStoreClock proves the scheduler's `now` is sourced from
// storage.ClockStore: with a store clock an hour past a queued job's queue
// deadline, the wall clock still sees the deadline in the future, but the
// lease must be refused (the Go deadline gate runs on the STORE clock). If
// nextDB used time.Now(), the job would lease.
func TestDBNextUsesTheStoreClock(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ri := registerLeaseRunner(t, s, "token")
	run := submitLeaseRun(t, s, "token", "https://github.com/o/r.git")

	deadline := time.Now().UTC().Add(time.Hour)
	f.mu.Lock()
	for id, j := range f.jobs {
		if j.RunID == run.ID && j.Status == model.StatusQueued {
			j.QueueDeadline = &deadline
			f.jobs[id] = j
		}
	}
	// The database clock is two hours ahead: the deadline (one hour ahead of
	// the wall clock) is already elapsed on the store clock.
	f.leaseNow = func() time.Time { return deadline.Add(time.Hour) }
	f.mu.Unlock()

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next with the job expired on the store clock = %d, want 204: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, j := range f.jobs {
		if j.LeaseRunnerID != "" {
			t.Fatalf("job %s leased %q despite an elapsed store-clock deadline", id, j.LeaseRunnerID)
		}
	}
}

// TestDBNextClockFailureRefusesLease proves a failed database-clock read fails
// the lease request closed (503) instead of falling back to the application
// clock.
func TestDBNextClockFailureRefusesLease(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ri := registerLeaseRunner(t, s, "token")
	_ = submitLeaseRun(t, s, "token", "https://github.com/o/r.git")

	f.mu.Lock()
	f.clockErr = errors.New("database clock unavailable")
	f.mu.Unlock()

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("next with a failed store clock = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, j := range f.jobs {
		if j.LeaseRunnerID != "" {
			t.Fatalf("job %s leased %q after the store clock failed", id, j.LeaseRunnerID)
		}
	}
}
