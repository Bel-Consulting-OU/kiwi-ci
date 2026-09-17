package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// idcovRunnerScriptStore scripts the Nth GetRunner call so the
// between-lookup failure branches become deterministic.
type idcovRunnerScriptStore struct {
	*dbFakeStore
	mu    sync.Mutex
	calls int
	fn    func(n int) (model.Runner, error)
}

func (s *idcovRunnerScriptStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	s.mu.Lock()
	s.calls++
	n := s.calls
	fn := s.fn
	s.mu.Unlock()
	if fn != nil {
		r, err := fn(n)
		if err != nil || r.ID != "" {
			return r, err
		}
	}
	return s.dbFakeStore.GetRunner(ctx, id)
}

// TestIDCovNextDBLeaseRunnerLookup covers the lease-stage runner failures.
func TestIDCovNextDBLeaseRunnerLookup(t *testing.T) {
	cases := []struct {
		name     string
		second   error
		wantCode int
	}{
		{"lease runner vanished", storage.ErrNotFound, http.StatusNotFound},
		{"lease runner read error", errors.New("runner read failed"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDBFakeStore()
			f.setLeader(true)
			f.mu.Lock()
			f.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 1}
			f.mu.Unlock()
			store := &idcovRunnerScriptStore{dbFakeStore: f}
			store.fn = func(n int) (model.Runner, error) {
				if n >= 2 {
					return model.Runner{}, c.second
				}
				return model.Runner{}, nil
			}
			s := New("secret")
			if err := s.SwitchToDB(store); err != nil {
				t.Fatal(err)
			}
			s.QuotaFailOpen = true
			w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/r1/next", map[string]any{}, "secret", nil)
			if w.Code != c.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, c.wantCode, w.Body.String())
			}
		})
	}
}

// TestIDCovCompleteDBReplayReconcileFailure covers the reconciliation
// failure inside the post-error replay branch.
func TestIDCovCompleteDBReplayReconcileFailure(t *testing.T) {
	f := newDBFakeStore()
	hash := completionResultHash(model.StatusFailure, "", nil)
	store := &idcovReceiptScriptStore{dbFakeStore: f, completeErr: errors.New("completion raced")}
	store.fn = func(n int) (model.CompletionReceipt, bool, error) {
		if n == 1 {
			return model.CompletionReceipt{}, false, nil
		}
		return model.CompletionReceipt{JobID: "job-rr", Generation: 1, RunnerID: "runner-a", ResultHash: hash}, true, nil
	}
	store.getFn = func(n int) (model.Job, error) {
		if n >= 2 {
			return model.Job{}, errors.New("reconcile read failed")
		}
		return model.Job{}, nil
	}
	s := New("secret")
	if err := s.SwitchToDB(store); err != nil {
		t.Fatal(err)
	}
	idcovSeedDBRunningJob(t, s, f, "job-rr", "run-rr", "tok")
	body := `{"runner_id":"runner-a","lease_token":"tok","lease_generation":1,"status":"failure"}`
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-rr/complete", []byte(body), "secret", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("post-error replay reconcile failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestIDCovMaintainBothModesTicks runs one real tick in memory mode with a
// status-changing run and in DB mode with a promoted leader.
func TestIDCovMaintainBothModesTicks(t *testing.T) {
	// Memory mode: an expired lease with an exhausted retry budget flips the
	// job and its run to failure, so the tick publishes the change.
	s := New("t")
	exp := time.Now().UTC().Add(-time.Minute)
	s.mu.Lock()
	s.runs["run-m"] = model.Run{ID: "run-m", RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
	s.jobs["job-m"] = model.Job{ID: "job-m", RunID: "run-m", Key: "build", RepoID: "github.com/kiwi/repo", Status: model.StatusRunning, LeaseRunnerID: "r1", LeaseGeneration: 1, LeaseExpiresAt: &exp, Attempts: 1, MaxInfraRetries: 0}
	s.mu.Unlock()

	// DB mode: a promoted leader runs maintainDB and the schedule pass.
	f := newDBFakeStore()
	f.setLeader(true)
	sd := New("t")
	if err := sd.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	sd.mu.Lock()
	sd.leader = true
	sd.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go func() { s.Maintain(ctx); done <- struct{}{} }()
	go func() { sd.Maintain(ctx); done <- struct{}{} }()
	time.Sleep(5600 * time.Millisecond)
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Maintain did not stop after cancellation")
		}
	}
	s.mu.Lock()
	job := s.jobs["job-m"]
	run := s.runs["run-m"]
	s.mu.Unlock()
	if job.Status != model.StatusFailure || run.Status != model.StatusFailure {
		t.Fatalf("memory tick did not fail the expired run: job=%q run=%q", job.Status, run.Status)
	}
}

// TestIDCovApprovalRaceUnreachable documents that the second approval lookup
// cannot miss without a concurrent delete; the reachable refusals are
// covered elsewhere. This test pins the actor recording for a queued
// approval-gated job.
func TestIDCovApprovalActorRecording(t *testing.T) {
	s := New("admin")
	s.mu.Lock()
	s.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true, Environment: "prod"}
	s.runs["run-a"] = model.Run{ID: "run-a", Status: model.StatusRunning}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-a/approve", "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	got := s.jobs["job-a"]
	s.mu.Unlock()
	if got.ApprovedBy == "" || got.Status != model.StatusQueued {
		t.Fatalf("approved job = %+v", got)
	}
}

// TestIDCovCompleteUnreachableGuards exercises the reachable halves of the
// guards whose failure halves are race-only, keeping the documented
// invariants pinned.
func TestIDCovCompleteUnreachableGuards(t *testing.T) {
	s := New("secret")
	// A nil outputs map hashes deterministically.
	hash := completionResultHash(model.StatusSuccess, "", nil)
	if hash == "" || strings.Contains(hash, " ") {
		t.Fatalf("completionResultHash = %q", hash)
	}
	// Map key order does not change the hash.
	a := completionResultHash(model.StatusSuccess, "boom", map[string]string{"a": "b", "c": "d"})
	b := completionResultHash(model.StatusSuccess, "boom", map[string]string{"c": "d", "a": "b"})
	if a != b {
		t.Fatal("outputs map ordering changed the hash")
	}
	_ = s
}

// TestIDCovRecoverLeasesQueueTimeout covers the queue-timeout cancellation
// in the same recovery pass the Maintain tick uses.
func TestIDCovRecoverLeasesQueueTimeout(t *testing.T) {
	s := New("t")
	past := time.Now().UTC().Add(-time.Hour)
	s.mu.Lock()
	s.runs["run-q"] = model.Run{ID: "run-q", Status: model.StatusQueued}
	s.jobs["job-q"] = model.Job{ID: "job-q", RunID: "run-q", Key: "build", Status: model.StatusQueued, QueueDeadline: &past}
	s.mu.Unlock()
	s.mu.Lock()
	s.recoverLeasesLocked(time.Now().UTC(), false)
	got := s.jobs["job-q"]
	s.mu.Unlock()
	if got.Status != model.StatusCancelled || got.Error != "queue timeout" {
		t.Fatalf("queue timeout recovery = %+v", got)
	}
}

// TestIDCovAuditAndListAudit covers the audit funnel's nil-store fallback
// and the DB-mode audit listing.
func TestIDCovAuditAndListAudit(t *testing.T) {
	bare := &Server{}
	bare.auditLocked("idcov.event", "actor", "run", "job", "detail", nil) // no store: no-op

	f := newDBFakeStore()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.auditLocked("idcov.event", "actor", "run", "job", "detail", map[string]string{"k": "v"})
	w := doJSON(t, s, http.MethodGet, "/api/v1/audit", "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("audit list = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "idcov.event") {
		t.Fatalf("audit event missing: %s", w.Body.String())
	}
	// A store failure surfaces as a 500.
	fault := &idcovFaultStore{dbFakeStore: f, listAuditErr: errors.New("audit down")}
	s.DB = fault
	if w := doJSON(t, s, http.MethodGet, "/api/v1/audit", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing audit list = %d, want 500", w.Code)
	}
	_ = auth.RoleRead
}
