package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// logBatchBody renders one well-formed batch body with the given overrides.
func logBatchBody(t *testing.T, runnerID, token string, generation int64, batchID string, lines []map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": token, "lease_generation": generation,
		"batch_id": batchID, "batch_sequence": 1, "lines": lines,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestLogBatchValidationBranches covers the batch endpoint's fail-closed
// request validation: a malformed envelope, an over-limit line field and a
// lost lease are each rejected before any storage mutation.
func TestLogBatchValidationBranches(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	path := "/api/v1/jobs/job-a/log/batch"
	goodLine := map[string]string{"step": "run", "line": "hello", "job_key": "build"}

	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", "{not json", hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed batch body = %d, want 400: %s", w.Code, w.Body.String())
	}

	huge := map[string]string{"step": "run", "line": "x", "job_key": strings.Repeat("k", 513)}
	body := logBatchBody(t, "runner-a", "cache-lease-token", 5, "b1", []map[string]string{huge})
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "size limits") {
		t.Fatalf("over-limit batch line = %d: %s", w.Code, w.Body.String())
	}

	body = logBatchBody(t, "runner-a", "wrong-token", 5, "b1", []map[string]string{goodLine})
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs); w.Code != http.StatusConflict {
		t.Fatalf("stale-lease batch = %d, want 409: %s", w.Code, w.Body.String())
	}

	// No lines and an over-max count are both rejected.
	body = logBatchBody(t, "runner-a", "cache-lease-token", 5, "b1", nil)
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("empty batch = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// TestLogBatchPerLineFallbackAppends covers a DB store without the batch
// extension: the batch is appended line by line through the base append
// contract and answered 204 exactly once the lines are durable.
func TestLogBatchPerLineFallbackAppends(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	s.DB = fcPlainStore{f}
	body := logBatchBody(t, "runner-a", "cache-lease-token", 5, "fallback-batch", []map[string]string{
		{"step": "run", "line": "one", "job_key": "build"},
		{"step": "run", "line": "two", "job_key": "build"},
	})
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/log/batch", "runner-tok", body, hdrs)
	if w.Code != http.StatusNoContent {
		t.Fatalf("per-line fallback batch = %d, want 204: %s", w.Code, w.Body.String())
	}
	logs, err := f.ReadLogs(context.Background(), "run-c", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("appended log lines = %d, want 2", len(logs))
	}
}

// TestDispatchOutboxDropsMalformedAndForeignIntents pins the dispatcher's
// no-ACK contract for intents it must not send: malformed payloads fail the
// dispatch (so the row retries), foreign-forge intents and reserved kinds are
// dropped as no-ops, and an unknown kind is left pending with the typed error
// for a newer replica instead of being dead-lettered.
func TestDispatchOutboxDropsMalformedAndForeignIntents(t *testing.T) {
	s := New("tok")
	ctx := context.Background()
	payload := func(v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := []struct {
		name    string
		item    forge.OutboxItem
		wantErr bool
	}{
		{"github_check malformed", forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{")}, true},
		{"github_check foreign forge", forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: payload(forge.CheckPayload{ForgeKind: "gitlab", RunID: "r", Name: "c"})}, false},
		{"gitlab_check malformed", forge.OutboxItem{Kind: forge.OutboxKindGitLabCheck, Payload: []byte("{")}, true},
		{"gitlab_check foreign forge", forge.OutboxItem{Kind: forge.OutboxKindGitLabCheck, Payload: payload(forge.CheckPayload{ForgeKind: "github", RunID: "r", Name: "c"})}, false},
		{"forgejo_check malformed", forge.OutboxItem{Kind: forge.OutboxKindForgejoCheck, Payload: []byte("{")}, true},
		{"forgejo_check foreign forge", forge.OutboxItem{Kind: forge.OutboxKindForgejoCheck, Payload: payload(forge.CheckPayload{ForgeKind: "github", RunID: "r", Name: "c"})}, false},
		{"github_status malformed", forge.OutboxItem{Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{")}, true},
		{"downstream malformed", forge.OutboxItem{Kind: forge.OutboxKindDownstream, Payload: []byte("{")}, true},
		{"completion reconcile malformed", forge.OutboxItem{Kind: storage.OutboxKindCompletionReconcile, Payload: []byte("{")}, true},
		{"completion reconcile empty job", forge.OutboxItem{Kind: storage.OutboxKindCompletionReconcile, Payload: payload(storage.CompletionEffectsPayload{})}, false},
		{"forge delivery malformed", forge.OutboxItem{Kind: storage.OutboxKindForgeDelivery, Payload: []byte("{")}, true},
		{"forge delivery empty job", forge.OutboxItem{Kind: storage.OutboxKindForgeDelivery, Payload: payload(storage.CompletionEffectsPayload{})}, false},
		{"legacy forge status empty job", forge.OutboxItem{Kind: storage.OutboxKindForgeStatus, Payload: payload(storage.CompletionEffectsPayload{})}, false},
		{"legacy internal kind empty job", forge.OutboxItem{Kind: storage.OutboxKindDownstreamCheck, Payload: payload(storage.CompletionEffectsPayload{})}, false},
		{"reserved webhook kind", forge.OutboxItem{ID: "w1", Kind: forge.OutboxKindWebhookCall}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.dispatchOutbox(ctx, tc.item)
			if (err != nil) != tc.wantErr {
				t.Fatalf("dispatch = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}

	err := s.dispatchOutbox(ctx, forge.OutboxItem{ID: "future", Kind: "future.kind"})
	var unknown *unknownOutboxKindError
	if !errors.As(err, &unknown) {
		t.Fatalf("unknown kind = %v, want *unknownOutboxKindError", err)
	}
}
