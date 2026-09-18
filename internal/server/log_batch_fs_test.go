package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fsLogBatchBody builds one /log/batch request body for a leased task.
func fsLogBatchBody(t *testing.T, runnerID string, task Task, batchID string, sequence int64, lines ...map[string]string) string {
	t.Helper()
	body := leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, map[string]any{
		"batch_id":       batchID,
		"batch_sequence": sequence,
		"lines":          lines,
	})
	return string(body)
}

func fsLogBatchLine(key, step, line string) map[string]string {
	return map[string]string{"job_key": key, "step": step, "line": line}
}

// TestFSLogBatchIdempotentConflictAndNoPartial is B8: the fs-mode batch
// endpoint writes through Repository.AppendLogBatch, so a duplicate delivery
// is one copy with a 204, a reused identity with different lines is the same
// fail-closed response the DB path gives, and an interrupted write exposes no
// partial batch.
func TestFSLogBatchIdempotentConflictAndNoPartial(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/log/batch"

	line1 := fsLogBatchLine(task.Job.Key, "run", "one")
	line2 := fsLogBatchLine(task.Job.Key, "run", "two")
	body := fsLogBatchBody(t, runnerID, task, "batch-1", 1, line1, line2)

	// Inject a journal write failure by making the pending directory path a
	// regular file: the append fails closed and no partial batch is visible.
	logBatches := filepath.Join(dir, "logbatches")
	if err := os.MkdirAll(logBatches, 0o700); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(logBatches, "pending")
	if err := os.WriteFile(pending, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, path, "token", body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("interrupted batch write = %d, want 500: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "log batch append failed\n" {
		t.Fatalf("interrupted batch body = %q", body)
	}
	// Clear the injected failure and prove the interrupted attempt exposed
	// nothing: the store sees no lines (no partial batch), and the retry
	// leaves exactly one copy.
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	logs, err := s.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 0 {
		t.Fatalf("interrupted batch exposed %d partial line(s): %+v", len(logs), logs)
	}

	if w = doJSON(t, s, http.MethodPost, path, "token", body); w.Code != http.StatusNoContent {
		t.Fatalf("first delivery = %d, want 204: %s", w.Code, w.Body.String())
	}
	// The duplicate delivery reuses the identity and is an idempotent 204.
	if w = doJSON(t, s, http.MethodPost, path, "token", body); w.Code != http.StatusNoContent {
		t.Fatalf("duplicate delivery = %d, want 204: %s", w.Code, w.Body.String())
	}
	logs, err = s.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("duplicate delivery stored %d lines, want exactly 2: %+v", len(logs), logs)
	}
	if logs[0].Line != "one" || logs[1].Line != "two" || logs[0].Seq >= logs[1].Seq {
		t.Fatalf("stored batch lines out of order: %+v", logs)
	}

	// The same identity with different lines is a conflict; the DB path maps
	// every append failure to the fixed 500 body, and so does the fs path.
	conflict := fsLogBatchBody(t, runnerID, task, "batch-1", 1, line1, fsLogBatchLine(task.Job.Key, "run", "changed"))
	if w = doJSON(t, s, http.MethodPost, path, "token", conflict); w.Code != http.StatusInternalServerError {
		t.Fatalf("conflicting batch = %d, want 500: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "log batch append failed\n" {
		t.Fatalf("conflicting batch body = %q", body)
	}
	logs, err = s.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 || logs[1].Line != "two" {
		t.Fatalf("conflict mutated the stored batch: %+v", logs)
	}

	// A disjoint batch identity still appends normally, and the durable
	// sequence continues past the batch lines.
	second := fsLogBatchBody(t, runnerID, task, "batch-2", 2, fsLogBatchLine(task.Job.Key, "run", "three"))
	if w = doJSON(t, s, http.MethodPost, path, "token", second); w.Code != http.StatusNoContent {
		t.Fatalf("second batch = %d, want 204: %s", w.Code, w.Body.String())
	}
	logs, err = s.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 3 || logs[2].Line != "three" {
		t.Fatalf("second batch logs = %+v, want three lines", logs)
	}

	// The batch lines survive a restart (they are durable, not RAM-only).
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	logs, err = s2.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 3 {
		t.Fatalf("restart lost batch lines: %d, want 3", len(logs))
	}
	var restored []string
	for _, l := range logs {
		restored = append(restored, l.Line)
	}
	if strings.Join(restored, ",") != "one,two,three" {
		t.Fatalf("restored batch order = %v", restored)
	}
	// MaxLogSeq must include the batch lines so a restarted server never
	// reuses a durable sequence.
	maxSeq, err := s2.store.MaxLogSeq()
	if err != nil {
		t.Fatal(err)
	}
	if maxSeq < logs[2].Seq {
		t.Fatalf("MaxLogSeq %d below the highest batch Seq %d", maxSeq, logs[2].Seq)
	}

	// A redelivery after a process restart (fresh Repository load, fresh
	// per-request arrival time, re-allocated Seq values) is still an
	// idempotent 204: with CreatedAt/Seq excluded from the payload digest no
	// first-delivery state has to survive the restart, and exactly one copy
	// of every line stays stored.
	if w = doJSON(t, s2, http.MethodPost, path, "token", body); w.Code != http.StatusNoContent {
		t.Fatalf("post-restart retry of batch-1 = %d, want 204: %s", w.Code, w.Body.String())
	}
	if w = doJSON(t, s2, http.MethodPost, path, "token", second); w.Code != http.StatusNoContent {
		t.Fatalf("post-restart retry of batch-2 = %d, want 204: %s", w.Code, w.Body.String())
	}
	logs, err = s2.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 3 {
		t.Fatalf("post-restart retries stored %d lines, want exactly 3: %+v", len(logs), logs)
	}
	if logs[0].Line != "one" || logs[1].Line != "two" || logs[2].Line != "three" {
		t.Fatalf("post-restart retries altered the committed lines: %+v", logs)
	}
}

// TestFSLogBatchRejectsEmptyBatchShape pins the validation that runs before
// the batch API is reached (the storage layer also refuses malformed
// identities defensively).
func TestFSLogBatchRejectsEmptyBatchShape(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/log/batch"

	empty := leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, map[string]any{"batch_id": "b", "lines": []map[string]string{}})
	if w := doJSON(t, s, http.MethodPost, path, "token", string(empty)); w.Code != http.StatusBadRequest {
		t.Fatalf("empty batch = %d, want 400: %s", w.Code, w.Body.String())
	}
	tooLong := strings.Repeat("x", 129)
	longID := leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, map[string]any{
		"batch_id": tooLong, "lines": []map[string]string{fsLogBatchLine(task.Job.Key, "run", "one")},
	})
	if w := doJSON(t, s, http.MethodPost, path, "token", string(longID)); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch id = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// TestFSLogBatchDerivesIdentityForLegacyClients covers the fallback identity:
// a client that omits batch_id gets a deterministic one, so an identical
// retry still dedupes instead of appending twice.
func TestFSLogBatchDerivesIdentityForLegacyClients(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/log/batch"
	body := leaseBodyFor(t, runnerID, task.LeaseToken, task.LeaseGeneration, map[string]any{
		"batch_sequence": 7,
		"lines":          []map[string]string{fsLogBatchLine(task.Job.Key, "run", "one")},
	})
	if w := doJSON(t, s, http.MethodPost, path, "token", string(body)); w.Code != http.StatusNoContent {
		t.Fatalf("legacy batch = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, path, "token", string(body)); w.Code != http.StatusNoContent {
		t.Fatalf("legacy retry = %d: %s", w.Code, w.Body.String())
	}
	logs, err := s.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 {
		t.Fatalf("legacy retry stored %d lines, want exactly 1", len(logs))
	}
	entry := logs[0]
	if entry.Line != "one" {
		t.Fatalf("legacy batch line = %+v", entry)
	}
	raw, err := json.Marshal(entry.CreatedAt)
	if err != nil || len(raw) == 0 || string(raw) == `"0001-01-01T00:00:00Z"` {
		t.Fatalf("legacy batch lost its arrival timestamp: %s (%v)", raw, err)
	}
}
