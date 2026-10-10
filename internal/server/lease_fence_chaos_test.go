package server

// Lease-fence chaos matrix (closure gate 3, I3 GAP-1/GAP-2).
//
// One job is claimed at generation 1 by runner A, the lease is then lost
// through the store's own recovery path (expired, token cleared, job
// requeued), and a second runner B claims generation 2 and completes it
// successfully. Every request runner A can still make with its dead
// generation-1 lease is then replayed: heartbeat, single log, log batch,
// artifact upload, snapshot upload, cache manifest upload, secret delivery,
// OIDC issuance, test report, completion and generated fragment. Each must
// be rejected (409/403; OIDC authenticates the cleared token directly and
// answers 401) and no authoritative state may change: the job stays success
// at generation 2, and no artifact, snapshot, cache manifest, test report,
// log line, execution event, audit row, completion receipt or outbox item is
// attributed to the dead generation.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const chaosPipeline = `version: 1
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

// chaosState is a deep snapshot of every authoritative collection the stale
// replay must leave untouched.
type chaosState struct {
	status     model.Status
	runner     string
	generation int64
	artifacts  []model.ArtifactRecord
	snapshots  []model.SnapshotRecord
	manifests  map[string]storage.CacheManifestRecord
	reports    []model.TestReport
	logs       []model.LogEntry
	events     []model.ExecutionEvent
	audit      []model.AuditEvent
	receipts   map[string]model.CompletionReceipt
	links      map[string]storage.DownstreamLink
	outbox     []storage.OutboxItem
}

func readChaosState(t *testing.T, f *eventsFakeStore, jobID string) chaosState {
	t.Helper()
	f.mu.Lock()
	j, ok := f.jobs[jobID]
	if !ok {
		f.mu.Unlock()
		t.Fatalf("job %s vanished", jobID)
	}
	st := chaosState{
		status:     j.Status,
		runner:     j.LeaseRunnerID,
		generation: j.LeaseGeneration,
		artifacts:  append([]model.ArtifactRecord(nil), f.artifacts...),
		snapshots:  append([]model.SnapshotRecord(nil), f.snapshots...),
		manifests:  make(map[string]storage.CacheManifestRecord, len(f.cacheMans)),
		reports:    append([]model.TestReport(nil), f.reports...),
		logs:       append([]model.LogEntry(nil), f.logs...),
		audit:      append([]model.AuditEvent(nil), f.audit...),
		receipts:   make(map[string]model.CompletionReceipt, len(f.receipts)),
		links:      make(map[string]storage.DownstreamLink, len(f.downstreamLinks)),
		outbox:     append([]storage.OutboxItem(nil), f.outboxItems...),
	}
	for k, v := range f.cacheMans {
		st.manifests[k] = v
	}
	for k, v := range f.receipts {
		st.receipts[k] = v
	}
	for k, v := range f.downstreamLinks {
		st.links[k] = v
	}
	f.mu.Unlock()
	f.eventsMu.Lock()
	st.events = append([]model.ExecutionEvent(nil), f.events...)
	f.eventsMu.Unlock()
	return st
}

// TestLeaseFenceChaosMatrixStaleGenerationRejected is the closure test for
// the runner-originated authoritative mutations: every path must be fenced
// by the live lease generation, so a superseded generation can never commit
// anything at all.
func TestLeaseFenceChaosMatrixStaleGenerationRejected(t *testing.T) {
	ctx := context.Background()
	f := &eventsFakeStore{dbFakeStore: newDBFakeStore()}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	// OIDC issuance requires an external URL; the stale request is refused
	// before any signer work, but the endpoint must get past the issuer
	// lookup to prove that.
	s.ExternalURL = "https://ci.example.com"
	if _, err := s.enqueue(ctx, SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: chaosPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	register := func() string {
		t.Helper()
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
			`{"name":"chaos","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
		if w.Code != http.StatusOK {
			t.Fatalf("register: %d %s", w.Code, w.Body.String())
		}
		var ri model.Runner
		if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
			t.Fatal(err)
		}
		return ri.ID
	}
	claim := func(runnerID string) Task {
		t.Helper()
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
		if w.Code != http.StatusOK {
			t.Fatalf("next for %s: %d %s", runnerID, w.Code, w.Body.String())
		}
		var task Task
		if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
			t.Fatal(err)
		}
		return task
	}

	// Generation 1: runner A claims the only job.
	runnerA := register()
	taskA := claim(runnerA)
	jobID := taskA.Job.ID
	if taskA.LeaseGeneration != 1 {
		t.Fatalf("first claim generation = %d, want 1", taskA.LeaseGeneration)
	}

	// Lose the lease through the store's recovery path: expire it, then run
	// RecoverExpiredLease, which clears the token and requeues the job. A's
	// generation-1 credential is now dead.
	f.mu.Lock()
	j := f.jobs[jobID]
	past := time.Now().UTC().Add(-time.Minute)
	j.LeaseExpiresAt = &past
	f.jobs[jobID] = j
	f.mu.Unlock()
	if err := f.RecoverExpiredLease(ctx, jobID, 1, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpiredLease: %v", err)
	}
	f.mu.Lock()
	recovered := f.jobs[jobID]
	f.mu.Unlock()
	if recovered.Status != model.StatusQueued || recovered.LeaseRunnerID != "" || recovered.LeaseTokenHash != nil || recovered.LeaseExpiresAt != nil {
		t.Fatalf("recovered job = %+v, want queued with every lease column cleared", recovered)
	}

	// Generation 2: runner B claims the requeued job and completes it
	// successfully.
	runnerB := register()
	taskB := claim(runnerB)
	if taskB.Job.ID != jobID || taskB.LeaseGeneration != 2 {
		t.Fatalf("second claim = job %s gen %d, want job %s gen 2", taskB.Job.ID, taskB.LeaseGeneration, jobID)
	}
	if w := completeTask(t, s, taskB, runnerB, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("completion by B = %d: %s", w.Code, w.Body.String())
	}
	if rec, has, err := f.HasCompletionReceipt(ctx, jobID, 2, runnerB); err != nil || !has {
		t.Fatalf("gen-2 completion receipt = %+v/%v/%v, want present", rec, has, err)
	}
	if _, has, err := f.HasCompletionReceipt(ctx, jobID, 1, runnerA); err != nil || has {
		t.Fatalf("gen-1 receipt for A = %v/%v, want absent", has, err)
	}

	baseline := readChaosState(t, f, jobID)
	// Completion clears the lease columns; the attempt generation remains 2.
	if baseline.status != model.StatusSuccess || baseline.generation != 2 || baseline.runner != "" {
		t.Fatalf("baseline job = %s/%d/%q, want success/2/cleared", baseline.status, baseline.generation, baseline.runner)
	}

	// Every stale request runner A can still make with generation 1.
	staleHeaders := leaseHeaders(taskA, runnerA)
	ephemeral := base64.StdEncoding.EncodeToString(make([]byte, 32))
	staleLogBatch := logBatchBody(t, runnerA, taskA.LeaseToken, 1, "chaos-stale-batch", []map[string]string{
		{"step": "run", "line": "stale-one", "job_key": taskA.Job.Key},
		{"step": "run", "line": "stale-two", "job_key": taskA.Job.Key},
	})
	staleReport := uploadReportBody(taskA, runnerA, []map[string]any{{"name": "stale-case", "passed": true}})

	staleConflict := map[int]bool{http.StatusConflict: true}
	cases := []struct {
		name    string
		allowed map[int]bool
		run     func() *httptest.ResponseRecorder
	}{
		{
			name:    "heartbeat",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				body := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":1}`, runnerA, taskA.LeaseToken)
				return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", "token", body)
			},
		},
		{
			name:    "log",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				body := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":1,"step":"run","line":"stale","job_key":%q}`, runnerA, taskA.LeaseToken, taskA.Job.Key)
				return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/log", "token", body)
			},
		},
		{
			name:    "log batch",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/log/batch", "token", staleLogBatch)
			},
		},
		{
			name:    "artifact upload",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				return doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "stale-bytes", staleHeaders)
			},
		},
		{
			name:    "snapshot upload",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				return doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", "token", "stale-snapshot-bytes", staleHeaders)
			},
		},
		{
			name:    "cache manifest upload",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				return doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/cache/chaos-stale-key", "token", "stale-cache-bytes", staleHeaders)
			},
		},
		{
			name:    "secret delivery",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				body := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":1,"name":"TOKEN","ephemeral_public":%q}`, runnerA, taskA.LeaseToken, ephemeral)
				return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/secrets", "token", body)
			},
		},
		{
			// OIDC authenticates the lease token directly (Authorization
			// bearer): the recovery cleared A's token hash, so the dead
			// credential is refused 401 before the lease-generation check.
			// 403 (a job-side capability refusal) is tolerated for the same
			// "no credential is issued" outcome, never a success.
			name:    "oidc issuance",
			allowed: map[int]bool{http.StatusUnauthorized: true, http.StatusForbidden: true, http.StatusConflict: true},
			run: func() *httptest.ResponseRecorder {
				return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", taskA.LeaseToken, `{"audience":"https://aud.example.com"}`)
			},
		},
		{
			name:    "test report",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/tests", "token", staleReport)
			},
		},
		{
			name:    "completion success",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				return completeTask(t, s, taskA, runnerA, "success")
			},
		},
		{
			name:    "generated fragment",
			allowed: staleConflict,
			run: func() *httptest.ResponseRecorder {
				return doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/generated", "token", `{"jobs":{},"deps":{}}`, staleHeaders)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.run()
			if !tc.allowed[w.Code] {
				t.Fatalf("stale gen-1 %s = %d, want one of %v: %s", tc.name, w.Code, tc.allowed, w.Body.String())
			}
		})
	}

	// The whole authoritative state is byte-identical: nothing the dead
	// generation tried was persisted, and B's success at generation 2 (with
	// its completion receipt and link) is untouched.
	after := readChaosState(t, f, jobID)
	if !reflect.DeepEqual(baseline, after) {
		t.Fatalf("authoritative state changed under stale generation-1 replays:\nbefore=%+v\nafter=%+v", baseline, after)
	}
	if j, err := f.GetJob(ctx, jobID); err != nil || j.Status != model.StatusSuccess || j.LeaseGeneration != 2 {
		t.Fatalf("job after stale replays = %+v/%v, want success at generation 2", j, err)
	}
}
