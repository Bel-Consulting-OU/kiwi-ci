package server

// Seam tests for the package JSON encoder: production always uses
// encoding/json.Marshal (jsonMarshal's default); tests override it with a
// failing encoder to exercise the fail-closed error branches (or the
// documented fallback) that a working encoder can never reach.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var errSeamJSON = errors.New("seam: json marshal failed")

// seamJSON overrides jsonMarshal for the duration of a test and returns the
// restore function. Seam tests are sequential, so the process-wide override
// cannot race a parallel reader.
func seamJSON(t *testing.T) func() {
	t.Helper()
	old := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, errSeamJSON }
	restored := false
	restore := func() {
		if !restored {
			jsonMarshal = old
			restored = true
		}
	}
	t.Cleanup(restore)
	return restore
}

// seamJSONFailAt lets the first failAt-1 marshals succeed (so earlier work in
// the same call performs normally) and fails at the failAt-th call.
func seamJSONFailAt(t *testing.T, failAt int) func() {
	t.Helper()
	old := jsonMarshal
	calls := 0
	jsonMarshal = func(v any) ([]byte, error) {
		calls++
		if calls >= failAt {
			return nil, errSeamJSON
		}
		return json.Marshal(v)
	}
	restored := false
	restore := func() {
		if !restored {
			jsonMarshal = old
			restored = true
		}
	}
	t.Cleanup(restore)
	return restore
}

func TestSeamJSONSubmitFailsClosed(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	in := SubmitRun{RepoURL: "https://github.com/o/r.git", Ref: "main", Pipeline: testPipeline}

	restore := seamJSON(t)
	if w := c.do(http.MethodPost, "/api/v1/runs", in, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("submit with failing encoder = %d: %s; want 400", w.Code, w.Body.String())
	}
	restore()

	// Second call: the capability marshal succeeds and the compiled-job
	// payload marshal fails.
	restore2 := seamJSONFailAt(t, 2)
	defer restore2()
	if w := c.do(http.MethodPost, "/api/v1/runs", in, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "seam: json marshal failed") {
		t.Fatalf("submit with failing compiled-job encoder = %d: %s; want 400", w.Code, w.Body.String())
	}
}

func TestSeamJSONCompletionEffects(t *testing.T) {
	s := New("secret")
	j := model.Job{ID: "job-1", RunID: "run-1"}
	run := model.Run{ID: "run-1"}
	restore := seamJSON(t)
	defer restore()
	if err := s.enqueueCompletionEffects(j, run); !errors.Is(err, errSeamJSON) {
		t.Fatalf("enqueueCompletionEffects = %v; want encoder error", err)
	}
	// The local variant has no error return: it must drop the intents
	// without queueing anything.
	before := len(s.outbox.Pending())
	s.enqueueCompletionEffectsLocal("job-1", "run-1", 1)
	if after := len(s.outbox.Pending()); after != before {
		t.Fatalf("enqueueCompletionEffectsLocal queued intents on encoder failure: %d -> %d", before, after)
	}
}

func TestSeamJSONDownstreamIntentsFailClosed(t *testing.T) {
	s, run := downstreamServer(t, downstreamPipeline)
	s.mu.Lock()
	var j model.Job
	for _, cand := range s.jobs {
		if cand.RunID == run.ID {
			j = cand
			break
		}
	}
	s.mu.Unlock()
	if j.ID == "" {
		t.Fatal("no parent job for the downstream run")
	}
	restore := seamJSON(t)
	defer restore()
	if err := s.recordDownstreamIntents(context.Background(), j, run); !errors.Is(err, errSeamJSON) {
		t.Fatalf("recordDownstreamIntents = %v; want encoder error", err)
	}
}

func TestSeamJSONCheckIntentFallsBack(t *testing.T) {
	s := New("secret")
	run := model.Run{ID: "run-1", RepoFullName: "o/r", SHA: "abc"}
	restore := seamJSON(t)
	defer restore()
	item := s.checkIntent(run, "kiwi", "completed", "success", "summary", nil)
	if string(item.Payload) != "{}" {
		t.Fatalf("checkIntent fallback payload = %q; want {}", item.Payload)
	}
	if item.Kind != forge.OutboxKindGitHubCheck {
		t.Fatalf("checkIntent kind = %q", item.Kind)
	}
}

func TestSeamJSONPublishStatusFromPayloadFailsClosed(t *testing.T) {
	s := New("secret")
	restore := seamJSON(t)
	defer restore()
	err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{RepoFullName: "o/r", SHA: "abc", State: "success"})
	if !errors.Is(err, errSeamJSON) {
		t.Fatalf("publishGitHubStatusFromPayload = %v; want encoder error", err)
	}
}

func TestSeamJSONStreamLogsSkipsUndeliverableEntries(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusRunning}
	s.mu.Unlock()
	if err := s.store.AppendLog(model.LogEntry{Seq: 1, RunID: "run-1", JobKey: "build", Step: "s", Line: "hello", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	restore := seamJSON(t)
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-1/logs/stream", nil).WithContext(ctx)
	r.SetPathValue("id", "run-1")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.streamLogs(w, r)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not stop after cancellation")
	}
	if body := w.Body.String(); strings.Contains(body, "data: {") {
		t.Fatalf("undeliverable entry was streamed: %q", body)
	}
}

func TestSeamJSONOIDCFailsClosed(t *testing.T) {
	s := newOIDCTestServer(t, true)
	_, jobID := seedOIDCJob(t, s, "lease-1")
	c := newTestClient(t, s.Handler(), "secret")
	restore := seamJSON(t)
	defer restore()

	// JWKS: the body cannot be encoded, so the endpoint reports 500 rather
	// than serving a partial key set.
	if w := c.do(http.MethodGet, "/api/v1/oidc/jwks", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("jwks with failing encoder = %d; want 500", w.Code)
	}
	// Issuance: the JWT claims cannot be encoded, so signing fails closed.
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", map[string]any{"audience": "https://audience.example"}, map[string]string{"Authorization": "Bearer lease-1"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("oidc issue with failing encoder = %d: %s; want 500", w.Code, w.Body.String())
	}
}

func TestSeamJSONDrainFlagPersistDropsFlag(t *testing.T) {
	s := New("secret")
	s.dataDir = t.TempDir()
	s.drainReason = "maintenance"
	restore := seamJSON(t)
	defer restore()
	s.persistDrainFlagLocked()
	// The flag file must not exist: a partially encoded flag is never
	// persisted.
	if b, err := readFileIfExists(s.dataDir, drainFlagFile); err == nil && len(b) > 0 {
		t.Fatalf("drain flag persisted despite encoder failure: %q", b)
	}
}

func TestSeamJSONGeneratedFragmentFailsClosed(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	body := fragmentBody(t, frag)

	// Every marshal fails: the parent's stored effective-policy decode falls
	// back to its trust defaults, which do not permit child graphs, so the
	// request is denied rather than admitted with a degraded ceiling.
	restore := seamJSON(t)
	if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", body, leaseHeaders(task, runnerID)); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "do not permit generated child graphs") {
		t.Fatalf("generated with failing effective-policy encoder = %d: %s; want 403 policy denial", w.Code, w.Body.String())
	}
	restore()

	// The effective-policy decode succeeds and the child-capability payload
	// marshal fails.
	restore2 := seamJSONFailAt(t, 2)
	if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", body, leaseHeaders(task, runnerID)); w.Code != http.StatusBadRequest {
		t.Fatalf("generated with failing child-capability encoder = %d: %s; want 400", w.Code, w.Body.String())
	}
	restore2()

	// The child-capability marshal succeeds and the compiled-child payload
	// marshal fails.
	restore3 := seamJSONFailAt(t, 3)
	defer restore3()
	if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", body, leaseHeaders(task, runnerID)); w.Code != http.StatusBadRequest {
		t.Fatalf("generated with failing child-payload encoder = %d: %s; want 400", w.Code, w.Body.String())
	}
}

func TestSeamJSONCompletionResultHashFallback(t *testing.T) {
	restore := seamJSON(t)
	defer restore()
	got := completionResultHash(model.StatusSuccess, "", map[string]string{"a": "b"})
	if got == "" {
		t.Fatal("completionResultHash returned an empty hash on encoder failure")
	}
	if again := completionResultHash(model.StatusSuccess, "", map[string]string{"a": "b"}); again != got {
		t.Fatalf("completionResultHash not deterministic: %q vs %q", got, again)
	}
}
