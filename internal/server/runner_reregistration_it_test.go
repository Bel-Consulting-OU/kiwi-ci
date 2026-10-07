package server

// Real-PostgreSQL regression for finding 3: re-registering a stable runner ID
// revokes the predecessor incarnation's leases in the same transaction as the
// registration swap, and the sensitive durable-write endpoints refuse the
// superseded incarnation while the current one succeeds.
//
// Gated on KIWI_TEST_POSTGRES_URL like every other *_it_test.go in this
// package; each test owns its own throwaway database.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITIncarnationPipeline declares an id-token permission and one artifact so
// the re-registration test can drive both OIDC issuance and artifact upload.
const pgITIncarnationPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    permissions:
      id_token: true
    artifacts:
      - name: bin
        paths:
          - out/
        retention: 1h
    steps:
      - run: echo hi
`

// TestIntegrationRegisterRevokesPredecessorIncarnation drives the full
// protocol flow on real PostgreSQL: register R (incarnation A) -> claim a
// job -> re-register R (incarnation B) -> the predecessor lease is revoked
// (requeued, LeaseLive false) -> B re-claims the job and OIDC/artifact
// requests carrying B succeed while A's incarnation is refused.
func TestIntegrationRegisterRevokesPredecessorIncarnation(t *testing.T) {
	s, st := pgITServer(t, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	ctx := context.Background()
	s.ExternalURL = "https://ci.example.com"

	// Fake forge API so the trusted run's pipeline/compare fetches stay
	// local (mirrors newGitHubHookServer, which is HTTP-handler only).
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/contents/.kiwi/pipeline.yaml"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(pgITIncarnationPipeline)),
				"encoding": "base64",
			})
		case strings.Contains(r.URL.Path, "/compare/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]string{{"filename": "src/main.go"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	s.GitHubWebhookSecret = "hunter2"
	s.gitHubAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"

	runnerID := pgITServerRandomHex(t, 32)
	register := func() registerResponse {
		t.Helper()
		body := `{"id":"` + runnerID + `","name":"r","capacity":1,"labels":["container"],"protocol_min":3,"protocol_max":3}`
		w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token", body, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("register: %d %s", w.Code, w.Body.String())
		}
		var out registerResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode registration: %v", err)
		}
		return out
	}

	incarnationA := register()
	if incarnationA.Incarnation == "" {
		t.Fatal("first registration returned no incarnation")
	}

	// A trusted webhook creates the run (API submits are untrusted, and OIDC
	// requires a trusted job).
	webhookBody := pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b")
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(webhookBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", "incarnation-it-1")
	req.Header.Set("X-Hub-Signature-256", signGitHubPayload("hunter2", []byte(webhookBody)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("webhook submit = %d %s", w.Code, w.Body.String())
	}

	taskA := pgITNext(t, s, runnerID)
	jobID := taskA.Job.ID
	if !taskA.Job.Trusted || !taskA.Job.OIDCAllowed {
		t.Fatalf("claimed job is not OIDC-capable: trusted=%v oidc=%v", taskA.Job.Trusted, taskA.Job.OIDCAllowed)
	}

	incarnationB := register()
	if incarnationB.Incarnation == incarnationA.Incarnation {
		t.Fatal("re-registration reused the predecessor incarnation")
	}

	// Durable revocation: the job requeued, every lease column cleared, and
	// the predecessor's lease is no longer live at the database clock.
	durable, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob after re-registration: %v", err)
	}
	if durable.Status != model.StatusQueued {
		t.Fatalf("job after re-registration = %s, want queued (requeued by revocation)", durable.Status)
	}
	if durable.LeaseRunnerID != "" || durable.LeaseTokenHash != nil || durable.LeaseExpiresAt != nil {
		t.Fatalf("lease columns not cleared by revocation: %+v", durable)
	}
	live, err := st.LeaseLive(ctx, jobID, runnerID, taskA.LeaseGeneration)
	if err != nil {
		t.Fatalf("LeaseLive: %v", err)
	}
	if live {
		t.Fatal("predecessor lease still live after re-registration")
	}

	// A's identity (revoked lease) cannot mint an OIDC token.
	w = pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", taskA.LeaseToken,
		`{"audience":"https://aud.example.com"}`, map[string]string{RunnerIncarnationHeader: incarnationA.Incarnation})
	if w.Code == http.StatusOK {
		t.Fatalf("predecessor identity minted an OIDC token: %s", w.Body.String())
	}

	// B re-claims the requeued job under its own incarnation.
	w = pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "",
		map[string]string{RunnerIncarnationHeader: incarnationB.Incarnation})
	if w.Code != http.StatusOK {
		t.Fatalf("incarnation B next = %d %s", w.Code, w.Body.String())
	}
	// The next call above claimed the job; decode its body.
	taskB := Task{}
	if err := json.Unmarshal(w.Body.Bytes(), &taskB); err != nil {
		t.Fatalf("decode task B: %v", err)
	}
	if taskB.Job.ID != jobID || taskB.LeaseToken == "" {
		t.Fatalf("incarnation B did not re-claim the job: %+v", taskB)
	}
	headers := func(task Task, incarnation string) map[string]string {
		return map[string]string{
			"X-Kiwi-Runner-ID":        runnerID,
			"X-Kiwi-Lease-Token":      task.LeaseToken,
			"X-Kiwi-Lease-Generation": strconv.FormatInt(task.LeaseGeneration, 10),
			RunnerIncarnationHeader:   incarnation,
		}
	}

	// Artifact upload on B's live lease: A's incarnation is refused, B's
	// succeeds.
	w = pgITDo(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "artifact-bytes",
		headers(taskB, incarnationA.Incarnation))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "superseded") {
		t.Fatalf("predecessor incarnation artifact upload = %d %q, want 409 superseded", w.Code, w.Body.String())
	}
	w = pgITDo(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "artifact-bytes",
		headers(taskB, incarnationB.Incarnation))
	if w.Code != http.StatusCreated {
		t.Fatalf("current incarnation artifact upload = %d %q, want 201", w.Code, w.Body.String())
	}

	// OIDC on B's live lease: B succeeds, A's incarnation is refused.
	w = pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", taskB.LeaseToken,
		`{"audience":"https://aud.example.com"}`, headers(taskB, incarnationA.Incarnation))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "superseded") {
		t.Fatalf("predecessor incarnation OIDC = %d %q, want 409 superseded", w.Code, w.Body.String())
	}
	w = pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", taskB.LeaseToken,
		`{"audience":"https://aud.example.com"}`, headers(taskB, incarnationB.Incarnation))
	if w.Code != http.StatusOK {
		t.Fatalf("current incarnation OIDC = %d %q, want 200", w.Code, w.Body.String())
	}
}
