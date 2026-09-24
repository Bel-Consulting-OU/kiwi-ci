package server

// G1-A handler-level regressions: the DB-mode approval/drain/enable paths
// must go through the transactional job-approval and guarded runner-profile
// contracts, so a read taken BEFORE a concurrent claim can never clobber the
// lease, runner slot, quota reservation or resource reservation the claim
// committed.

import (
	"context"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// staleJobStore models the approval-vs-claim race deterministically: GetJob
// returns the pre-claim snapshot the handler authorizes against, while the
// durable row already holds a running lease. The transactional ApproveJob
// re-reads the durable row, so the stale read is harmless.
type staleJobStore struct {
	*dbFakeStore
}

func (f *staleJobStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	j, err := f.dbFakeStore.GetJob(ctx, id)
	if err != nil {
		return j, err
	}
	j.Status = model.StatusWaitingApproval
	j.ApprovalRequired = true
	j.LeaseRunnerID = ""
	j.LeaseGeneration = 0
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	return j, nil
}

// staleLeaseRunnerStore models the drain/enable-vs-claim race: GetRunner
// returns the runner as it looked before the claim reserved a slot, while the
// durable row holds the lease. The guarded profile write preserves the
// durable lease-owned fields.
type staleLeaseRunnerStore struct {
	*dbFakeStore
}

func (f *staleLeaseRunnerStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	r, err := f.dbFakeStore.GetRunner(ctx, id)
	if err != nil {
		return r, err
	}
	r.ActiveJobs = nil
	r.CurrentJob = ""
	r.Busy = false
	r.Completed = 0
	r.Failed = 0
	return r, nil
}

// TestDBApprovalDoesNotClobberConcurrentLease pins the approval half: a
// duplicate approval authorized against the pre-claim snapshot must keep the
// job's running status and lease intact (pre-fix the whole-row UpdateJob
// reset it to queued and dropped the lease).
func TestDBApprovalDoesNotClobberConcurrentLease(t *testing.T) {
	f := newDBFakeStore()
	f.mu.Lock()
	f.jobs["job-lease"] = model.Job{
		ID: "job-lease", RunID: "run-lease", Key: "deploy", RepoFullName: "o/r", RepoURL: "https://github.com/o/r.git",
		Status: model.StatusRunning, ApprovalRequired: true, Environment: "prod",
		LeaseRunnerID: "runner-lease", LeaseGeneration: 2, LeaseTokenHash: []byte("h"),
	}
	f.mu.Unlock()
	s := New("admin")
	if err := s.SwitchToDB(&staleJobStore{dbFakeStore: f}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-lease/approve", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("approve racing a claim = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	got := f.jobs["job-lease"]
	f.mu.Unlock()
	if got.Status != model.StatusRunning || got.LeaseRunnerID != "runner-lease" || got.LeaseGeneration != 2 || len(got.LeaseTokenHash) == 0 {
		t.Fatalf("approval clobbered the concurrent lease: %+v", got)
	}
	if got.ApprovedBy == "" {
		t.Fatalf("approval did not record the approver: %+v", got)
	}
}

// TestDBDrainAndEnablePreserveConcurrentLease pins the drain/enable half: the
// profile write must preserve the active slot and the completed/failed
// counters a concurrent claim committed, even when the handler's read
// predates the claim.
func TestDBDrainAndEnablePreserveConcurrentLease(t *testing.T) {
	for _, action := range []string{"drain", "enable"} {
		t.Run(action, func(t *testing.T) {
			f := newDBFakeStore()
			f.mu.Lock()
			f.runners["r1"] = model.Runner{
				ID: "r1", Name: "r1", Capacity: 1,
				ActiveJobs: []string{"job-lease"}, CurrentJob: "job-lease", Busy: true,
				Completed: 5, Failed: 1,
			}
			f.mu.Unlock()
			s := New("admin")
			if err := s.SwitchToDB(&staleLeaseRunnerStore{dbFakeStore: f}); err != nil {
				t.Fatal(err)
			}
			if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/"+action, "admin", ""); w.Code != http.StatusOK {
				t.Fatalf("%s racing a claim = %d: %s", action, w.Code, w.Body.String())
			}
			f.mu.Lock()
			got := f.runners["r1"]
			f.mu.Unlock()
			if len(got.ActiveJobs) != 1 || got.ActiveJobs[0] != "job-lease" || got.CurrentJob != "job-lease" || !got.Busy {
				t.Fatalf("%s clobbered the concurrent lease slot: %+v", action, got)
			}
			if got.Completed != 5 || got.Failed != 1 {
				t.Fatalf("%s clobbered the counters: %+v", action, got)
			}
			switch action {
			case "drain":
				if !got.Draining {
					t.Fatalf("drain did not set the flag: %+v", got)
				}
			case "enable":
				if got.Disabled || got.Draining {
					t.Fatalf("enable did not clear the flags: %+v", got)
				}
			}
		})
	}
}
