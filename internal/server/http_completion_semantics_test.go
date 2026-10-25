package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestHTTPCompletionSemanticsMismatch409 drives the REAL complete endpoint:
// a stamped job completed with a contradictory observed interpreter stamp is
// refused 409 (never persisted, never acked), while the matching stamp and
// the empty-omission fill path both succeed and record ObservedExecutionSemantics.
func TestHTTPCompletionSemanticsMismatch409(t *testing.T) {
	s := New("token")
	if _, err := s.enqueue(t.Context(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := registerUsageRunner(t, s)
	if task.Job.ExecutionSemantics == "" {
		t.Fatal("job not stamped")
	}

	post := func(sem string) *int {
		body := map[string]any{
			"runner_id": runnerID, "lease_token": task.LeaseToken,
			"lease_generation": task.LeaseGeneration, "status": "success",
			// Always present: "" means explicit omission (409 on stamped jobs);
			// doJSON's test injector must NOT fill an explicit empty value.
			"execution_semantics": sem,
		}
		raw, _ := json.Marshal(body)
		w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(raw))
		code := w.Code
		return &code
	}

	// Mismatch: v2 stamp against a v3 job → 409, job stays running.
	if got := post(model.LegacyExecutionSemanticsVersion); *got != http.StatusConflict {
		t.Fatalf("mismatch completion = %d, want 409", *got)
	}
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if j.Status != model.StatusRunning {
		t.Fatalf("mismatch completion mutated status to %q", j.Status)
	}
	if j.ObservedExecutionSemantics != "" {
		t.Fatalf("mismatch completion wrote observed stamp %q", j.ObservedExecutionSemantics)
	}

	// Omission on a STAMPED job → 409 (no inference from the job stamp;
	// a pre-gate lease could be a v2 interpreter omitting the field).
	if got := post(""); *got != http.StatusConflict {
		t.Fatalf("omitted completion on stamped job = %d, want 409", *got)
	}

	// Matching stamp → 204 and durable observed evidence.
	if got := post(task.Job.ExecutionSemantics); *got != http.StatusNoContent {
		t.Fatalf("matching completion = %d, want 204", *got)
	}
	s.mu.Lock()
	j = s.jobs[task.Job.ID]
	s.mu.Unlock()
	if j.ObservedExecutionSemantics != task.Job.ExecutionSemantics {
		t.Fatalf("ObservedExecutionSemantics = %q, want %q", j.ObservedExecutionSemantics, task.Job.ExecutionSemantics)
	}
}

// TestHTTPCompletionReplaySemanticsMismatch409: an idempotent replay of the
// same result hash still refuses a contradictory interpreter stamp (the
// replay path used to ack on hash match alone).
func TestHTTPCompletionReplaySemanticsMismatch409(t *testing.T) {
	s := New("token")
	if _, err := s.enqueue(t.Context(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := registerUsageRunner(t, s)

	// First delivery: correct stamp, terminal.
	okBody, _ := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": task.Job.ExecutionSemantics,
	})
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(okBody))
	if w.Code != http.StatusNoContent {
		t.Fatalf("first completion = %d %s", w.Code, w.Body.String())
	}

	// Replay with a contradictory stamp (lease is spent → stale path).
	badBody, _ := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": model.LegacyExecutionSemanticsVersion,
	})
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(badBody))
	if w.Code != http.StatusConflict {
		t.Fatalf("replay mismatch = %d, want 409 (%s)", w.Code, w.Body.String())
	}

	// Replay OMITTING the stamp on a stamped job is also refused (no fill).
	// Explicit empty key so the test injector does not backfill it.
	omitBody, _ := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": "",
	})
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(omitBody))
	if w.Code != http.StatusConflict {
		t.Fatalf("replay omission on stamped job = %d, want 409 (%s)", w.Code, w.Body.String())
	}

	// Replay with the SAME stamp is still an idempotent ack.
	goodReplay, _ := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": task.Job.ExecutionSemantics,
	})
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(goodReplay))
	if w.Code != http.StatusNoContent {
		t.Fatalf("idempotent replay = %d, want 204 (%s)", w.Code, w.Body.String())
	}
}
