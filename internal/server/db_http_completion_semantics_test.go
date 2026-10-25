package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestDBHTTPCompletionSemanticsMismatch409: the DB-mode receipt fast path
// (and the primary path) must refuse a contradictory observed interpreter
// stamp with 409 — a matching result hash is not authority to accept it.
func TestDBHTTPCompletionSemanticsMismatch409(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(t.Context(), SubmitRun{
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
	if task.Job.ExecutionSemantics == "" {
		t.Fatal("job not stamped")
	}
	post := func(sem string) int {
		body := map[string]any{
			"runner_id": ri.ID, "lease_token": task.LeaseToken,
			"lease_generation": task.LeaseGeneration, "status": "success",
			"execution_semantics": sem,
		}
		raw, _ := json.Marshal(body)
		return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(raw)).Code
	}
	// Mismatch on the primary path → 409.
	if got := post(model.LegacyExecutionSemanticsVersion); got != http.StatusConflict {
		t.Fatalf("primary mismatch = %d, want 409", got)
	}
	// Matching stamp → 204.
	if got := post(task.Job.ExecutionSemantics); got != http.StatusNoContent {
		t.Fatalf("matching completion = %d, want 204", got)
	}
	// Receipt fast-path replay with a contradictory stamp → 409 (not 204).
	if got := post(model.LegacyExecutionSemanticsVersion); got != http.StatusConflict {
		t.Fatalf("receipt replay mismatch = %d, want 409", got)
	}
	// Receipt fast-path replay OMITTING the stamp on a stamped job → 409
	// (no inference: a pre-gate lease may be a v2 interpreter).
	if got := post(""); got != http.StatusConflict {
		t.Fatalf("receipt replay omission = %d, want 409", got)
	}
	// Idempotent replay with the SAME stamp → still 204.
	body := map[string]any{
		"runner_id": ri.ID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": task.Job.ExecutionSemantics,
	}
	raw, _ := json.Marshal(body)
	if got := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(raw)).Code; got != http.StatusNoContent {
		t.Fatalf("idempotent replay = %d, want 204", got)
	}
}
