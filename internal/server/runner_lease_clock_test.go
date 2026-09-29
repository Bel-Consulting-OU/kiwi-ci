package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/scheduler"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestAuthorizeRunnerLeaseDBClockSkew is the HTTP-gate clock regression: in
// DB mode the lease gate asks the STORE for liveness (its own clock domain),
// so a serving replica whose application clock is hours ahead cannot reject
// a database-live lease, and one hours behind cannot admit an expired lease.
func TestAuthorizeRunnerLeaseDBClockSkew(t *testing.T) {
	st := newDBFakeStore()
	key := []byte("lease-key")
	s := &Server{DB: st, RunnerToken: "runner-token", leaseKey: key}

	live := time.Now().UTC().Add(time.Hour)
	job := model.Job{
		ID: "job-1", Status: model.StatusRunning,
		LeaseRunnerID: "runner-1", LeaseGeneration: 3,
		LeaseTokenHash: hashLeaseToken(key, "raw"),
		LeaseExpiresAt: &live,
	}
	st.jobs[job.ID] = job

	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-1/logs", nil)
		r.SetPathValue("id", job.ID)
		r.Header.Set("Authorization", "Bearer runner-token")
		return r
	}

	// The store's clock (the "database") stays accurate; only the replica's
	// application clock is skewed.
	st.leaseNow = func() time.Time { return time.Now().UTC() }

	// Clock 2h AHEAD: the DB-live lease must still authorize.
	s.leaseClock = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	if _, err := s.authorizeRunnerLease(request(), "runner-1", "raw", 3); err != nil {
		t.Fatalf("skewed-ahead replica rejected a DB-live lease: %v", err)
	}

	// DB-expired lease: a replica whose clock is 2h BEHIND must still refuse.
	expired := time.Now().UTC().Add(-time.Hour)
	job.LeaseExpiresAt = &expired
	st.jobs[job.ID] = job
	s.leaseClock = func() time.Time { return time.Now().UTC().Add(-2 * time.Hour) }
	if _, err := s.authorizeRunnerLease(request(), "runner-1", "raw", 3); !errors.Is(err, errStaleLease) {
		t.Fatalf("skewed-behind replica admitted a DB-expired lease: %v", err)
	}
}

// TestAuthorizeRunnerLeaseDBRequiresLiveLeaseStore pins the fail-closed
// wiring contract: a DB-mode server whose store does not implement
// LiveLeaseStore must NOT fall back to the application clock; the gate
// refuses with errLeaseLiveUnsupported (503) instead. Replica-clock liveness
// can never be the authority for a shared database's leases.
func TestAuthorizeRunnerLeaseDBRequiresLiveLeaseStore(t *testing.T) {
	f := newDBFakeStore()
	key := []byte("lease-key")
	live := time.Now().UTC().Add(time.Hour)
	job := model.Job{
		ID: "job-1", Status: model.StatusRunning,
		LeaseRunnerID: "runner-1", LeaseGeneration: 1,
		LeaseTokenHash: hashLeaseToken(key, "raw"),
		LeaseExpiresAt: &live,
	}
	f.jobs[job.ID] = job
	// A live lease and an accurate replica clock still must not authorize:
	// the capability is missing, so there is no database-clock liveness
	// decision to be had.
	s := &Server{DB: struct{ storage.Store }{Store: f}, RunnerToken: "runner-token", leaseKey: key}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-1/heartbeat", nil)
	r.SetPathValue("id", job.ID)
	r.Header.Set("Authorization", "Bearer runner-token")
	if _, err := s.authorizeRunnerLease(r, "runner-1", "raw", 1); !errors.Is(err, errLeaseLiveUnsupported) {
		t.Fatalf("DB gate without LiveLeaseStore = %v, want errLeaseLiveUnsupported", err)
	}
}

// ttlClockDBFake adds the LeaseClockStore capability to the DB-mode fake and
// returns a FIXED store-clock expiry, so handler tests can prove the response
// carries the store's authoritative instant and not the serving replica's
// application-clock estimate.
type ttlClockDBFake struct {
	*dbFakeStore
	expiry time.Time
	err    error
}

func (t *ttlClockDBFake) HeartbeatLeaseWithTTL(ctx context.Context, jobID, runnerID string, generation int64, ttl time.Duration) (time.Time, error) {
	if t.err != nil {
		return time.Time{}, t.err
	}
	return t.expiry, nil
}

// AcquireLeaseWithTTL only satisfies storage.LeaseClockStore (the heartbeat
// test uses the TTL heartbeat path); claims delegate to the underlying fake.
func (t *ttlClockDBFake) AcquireLeaseWithTTL(ctx context.Context, claim storage.LeaseClaim) (model.Job, error) {
	return t.dbFakeStore.AcquireLeaseAtomic(ctx, claim)
}

// TestHeartbeatDBClockSkewUsesStoreExpiry is the END-TO-END heartbeat clock
// regression: the full handler runs with a serving replica two hours ahead,
// yet the database-live lease authorizes and the 200 body carries exactly the
// store-returned expiry (clock_timestamp()+TTL in production) — never the
// replica's app-clock estimate.
func TestHeartbeatDBClockSkewUsesStoreExpiry(t *testing.T) {
	key := []byte("lease-key")
	dbNow := time.Now().UTC()
	live := dbNow.Add(time.Minute)
	st := &ttlClockDBFake{dbFakeStore: newDBFakeStore(), expiry: dbNow.Add(45 * time.Second)}
	st.leaseNow = func() time.Time { return dbNow }
	job := model.Job{
		ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusRunning,
		LeaseRunnerID: "runner-1", LeaseGeneration: 2,
		LeaseTokenHash: hashLeaseToken(key, "raw"),
		LeaseExpiresAt: &live,
	}
	st.jobs[job.ID] = job

	s := &Server{DB: st, RunnerToken: "runner-token", leaseKey: key}
	s.Sched = scheduler.NewDB(st, 45*time.Second, nil, func(raw string) []byte {
		return hashLeaseToken(key, raw)
	})
	// The serving replica's application clock is 2h AHEAD: it must neither
	// reject the DB-live lease nor contribute to the response expiry.
	s.leaseClock = func() time.Time { return dbNow.Add(2 * time.Hour) }

	body, err := json.Marshal(Heartbeat{RunnerID: "runner-1", LeaseToken: "raw", LeaseGeneration: 2})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-1/heartbeat", bytes.NewReader(body))
	r.SetPathValue("id", job.ID)
	r.Header.Set("Authorization", "Bearer runner-token")
	w := httptest.NewRecorder()
	s.heartbeat(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat on a DB-live lease from a skewed-ahead replica = %d (%s)", w.Code, w.Body.String())
	}
	var out HeartbeatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.LeaseExpiresAt.Equal(dbNow.Add(45 * time.Second)) {
		t.Fatalf("heartbeat expiry = %v, want the store's authoritative %v (app-clock estimate would be %v)",
			out.LeaseExpiresAt, dbNow.Add(45*time.Second), s.leaseClock().Add(45*time.Second))
	}
}

// TestLogBatchDBClockSkew exercises the full log-batch handler under skew: a
// replica two hours ahead still accepts a batch for a DB-live lease, and a
// replica two hours behind still refuses a DB-expired lease before any line
// reaches the store.
func TestLogBatchDBClockSkew(t *testing.T) {
	key := []byte("lease-key")
	dbNow := time.Now().UTC()
	live := dbNow.Add(time.Minute)
	st := newDBFakeStore()
	st.leaseNow = func() time.Time { return dbNow }
	job := model.Job{
		ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusRunning,
		LeaseRunnerID: "runner-1", LeaseGeneration: 2,
		LeaseTokenHash: hashLeaseToken(key, "raw"),
		LeaseExpiresAt: &live,
	}
	st.jobs[job.ID] = job
	s := &Server{DB: st, RunnerToken: "runner-token", leaseKey: key}

	request := func(batchID string) *http.Request {
		body, err := json.Marshal(map[string]any{
			"runner_id":        "runner-1",
			"lease_token":      "raw",
			"lease_generation": 2,
			"batch_id":         batchID,
			"batch_sequence":   1,
			"lines":            []map[string]any{{"step": "run", "line": "hello"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-1/log/batch", bytes.NewReader(body))
		r.SetPathValue("id", job.ID)
		r.Header.Set("Authorization", "Bearer runner-token")
		return r
	}

	// Clock 2h AHEAD: the DB-live lease must accept the batch.
	s.leaseClock = func() time.Time { return dbNow.Add(2 * time.Hour) }
	w := httptest.NewRecorder()
	s.logBatch(w, request("batch-live"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("skewed-ahead replica rejected a DB-live log batch: %d (%s)", w.Code, w.Body.String())
	}

	// DB-expired lease: a replica whose clock is 2h BEHIND must still refuse,
	// and must not persist the batch it tried to send.
	expired := dbNow.Add(-time.Minute)
	job.LeaseExpiresAt = &expired
	st.jobs[job.ID] = job
	s.leaseClock = func() time.Time { return dbNow.Add(-2 * time.Hour) }
	w = httptest.NewRecorder()
	s.logBatch(w, request("batch-expired"))
	if w.Code != http.StatusConflict {
		t.Fatalf("skewed-behind replica admitted a DB-expired log batch: %d (%s)", w.Code, w.Body.String())
	}
	st.mu.Lock()
	lines := len(st.logs)
	st.mu.Unlock()
	if lines != 1 {
		t.Fatalf("store holds %d log lines, want only the DB-live batch's 1", lines)
	}
}
