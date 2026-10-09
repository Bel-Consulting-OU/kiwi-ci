package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestCompletionReplayV2RuntimeEvidence proves the fs/memory completion
// identity is the v2 digest: retrying with contradictory observed runtime
// evidence (or changed outputs/status/error) is refused with 409, the
// identical replay is a 204, and the durable receipt keeps the first v2
// identity.
func TestCompletionReplayV2RuntimeEvidence(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := registerUsageRunner(t, s)
	body := func(fields map[string]any) string {
		fields["runner_id"] = runnerID
		fields["lease_token"] = task.LeaseToken
		fields["lease_generation"] = task.LeaseGeneration
		b, merr := json.Marshal(fields)
		if merr != nil {
			t.Fatal(merr)
		}
		return string(b)
	}
	post := func(fields map[string]any) int {
		return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", body(fields)).Code
	}

	first := map[string]any{
		"status":           "success",
		"outputs":          map[string]string{"release": "one"},
		"observed_runtime": map[string]any{"os": "linux", "arch": "amd64"},
	}
	if code := post(first); code != http.StatusNoContent {
		t.Fatalf("first completion = %d, want 204", code)
	}
	// An identical logical payload (map order is irrelevant: the digest is
	// canonical) is idempotent.
	if code := post(map[string]any{
		"observed_runtime": map[string]any{"arch": "amd64", "os": "linux"},
		"outputs":          map[string]string{"release": "one"},
		"status":           "success",
	}); code != http.StatusNoContent {
		t.Fatalf("identical replay = %d, want 204", code)
	}
	// Contradictory runtime evidence for the same identity conflicts.
	if code := post(map[string]any{
		"status":           "success",
		"outputs":          map[string]string{"release": "one"},
		"observed_runtime": map[string]any{"os": "linux", "arch": "arm64"},
	}); code != http.StatusConflict {
		t.Fatalf("changed-runtime replay = %d, want 409", code)
	}
	// Changed outputs / status / error conflict under the v2 digest.
	if code := post(map[string]any{
		"status":           "success",
		"outputs":          map[string]string{"release": "two"},
		"observed_runtime": map[string]any{"os": "linux", "arch": "amd64"},
	}); code != http.StatusConflict {
		t.Fatalf("changed-outputs replay = %d, want 409", code)
	}
	if code := post(map[string]any{
		"status":           "failure",
		"observed_runtime": map[string]any{"os": "linux", "arch": "amd64"},
	}); code != http.StatusConflict {
		t.Fatalf("changed-status replay = %d, want 409", code)
	}
	if code := post(map[string]any{
		"status":           "failure",
		"error":            "boom",
		"observed_runtime": map[string]any{"os": "linux", "arch": "amd64"},
	}); code != http.StatusConflict {
		t.Fatalf("changed-error replay = %d, want 409", code)
	}
	// The original identity still replays after the conflicts.
	if code := post(first); code != http.StatusNoContent {
		t.Fatalf("replay after conflicts = %d, want 204", code)
	}

	s.mu.Lock()
	rec := s.completions[completionReceiptKey(task.Job.ID, task.LeaseGeneration, runnerID)]
	job := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if rec.ResultHashVersion != storage.CompletionResultHashVersionV2 || rec.ResultHash == "" {
		t.Fatalf("stored receipt = %+v, want the first v2 identity", rec)
	}
	if job.Status != model.StatusSuccess || job.ObservedRuntime == nil || job.ObservedRuntime.Arch != "amd64" {
		t.Fatalf("contradictory attempts rewrote the job: %+v %+v", job.Status, job.ObservedRuntime)
	}
}
