package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestFSCompletionPersistsObservedSemantics: the in-memory (non-DB)
// completion path must persist the observed interpreter stamp on the job so
// evidence can prove requested == observed, not only refuse a mismatch.
func TestFSCompletionPersistsObservedSemantics(t *testing.T) {
	s := New("token")
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := registerUsageRunner(t, s)
	if task.Job.ExecutionSemantics == "" {
		t.Fatal("job not stamped with execution semantics")
	}
	w := completeTask(t, s, task, runnerID, "success")
	if w.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if j.ObservedExecutionSemantics != task.Job.ExecutionSemantics {
		t.Fatalf("ObservedExecutionSemantics = %q, want %q", j.ObservedExecutionSemantics, task.Job.ExecutionSemantics)
	}
}

// TestDBCompletionReceiptCarriesObservedSemantics: the DB scheduler must
// stamp the completion receipt with the observed interpreter version so
// CompleteJob can persist Job.ObservedExecutionSemantics atomically.
func TestDBCompletionReceiptCarriesObservedSemantics(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1","protocol_version":2,"supported_execution_semantics":["kiwi.execution.v3"],"protocol_min":2,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if err := s.Sched.CompleteWithSemantics(context.Background(), task.Job.ID, task.LeaseGeneration, ri.ID,
		model.StatusSuccess, "", nil, "hash-obs", model.ExecutionSemanticsVersion); err != nil {
		t.Fatalf("complete: %v", err)
	}
	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	f.mu.Unlock()
	if j.ObservedExecutionSemantics != model.ExecutionSemanticsVersion {
		t.Fatalf("db job ObservedExecutionSemantics = %q, want %q", j.ObservedExecutionSemantics, model.ExecutionSemanticsVersion)
	}
}
