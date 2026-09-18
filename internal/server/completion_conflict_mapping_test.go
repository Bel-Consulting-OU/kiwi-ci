package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// completionConflictStore wraps the DB fake store and forces CompleteJob to
// fail with storage.ErrCompletionConflict, so the DB-mode completion handler's
// error mapping can be pinned without racing real completions.
type completionConflictStore struct {
	*dbFakeStore
	err error
}

func (s *completionConflictStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	if s.err != nil {
		return s.err
	}
	return s.dbFakeStore.CompleteJob(ctx, jobID, generation, runnerID, status, errMsg, outputs, receipt)
}

// TestCompleteDBMapsCompletionConflictTo409 pins the completion-error -> HTTP
// mapping: ErrCompletionConflict (a concurrent completion of the same lease
// with a different result_hash) must answer 409 Conflict, never 204/500.
func TestCompleteDBMapsCompletionConflictTo409(t *testing.T) {
	const (
		token    = "lease-token"
		jobID    = "job-conflict"
		runID    = "run-conflict"
		runnerID = "runner-a"
	)
	f := newDBFakeStore()
	s := New("secret")
	exp := time.Now().UTC().Add(time.Minute)
	f.mu.Lock()
	f.runs[runID] = model.Run{ID: runID, RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Repo: "https://github.com/kiwi/repo.git", Ref: "refs/heads/main", Status: model.StatusRunning}
	f.jobs[jobID] = model.Job{
		ID: jobID, RunID: runID, Key: "build",
		RepoID: "github.com/kiwi/repo", RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Status: model.StatusRunning, LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, token),
		LeaseGeneration: 1, LeaseExpiresAt: &exp,
	}
	f.mu.Unlock()
	store := &completionConflictStore{dbFakeStore: f, err: storage.ErrCompletionConflict}
	if err := s.SwitchToDB(store); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	body := `{"runner_id":"` + runnerID + `","lease_token":"` + token + `","lease_generation":1,"status":"failure"}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", "secret", body)
	if w.Code != http.StatusConflict {
		t.Fatalf("complete = %d, want 409: %s", w.Code, w.Body.String())
	}
}
