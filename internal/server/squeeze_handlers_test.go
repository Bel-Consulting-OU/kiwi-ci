package server

import (
	"context"
	"encoding/json"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/scheduler"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func leaseBodyFor(t *testing.T, runnerID, token string, gen int64, extra map[string]any) []byte {
	t.Helper()
	m := map[string]any{"runner_id": runnerID, "lease_token": token, "lease_generation": gen}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSqueezeHeartbeatBranches covers the memory-mode heartbeat edges.
func TestSqueezeHeartbeatBranches(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/missing/heartbeat", map[string]any{"runner_id": "r", "lease_token": "t", "lease_generation": 1}, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown job = %d, want 404", w.Code)
	}

	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	// A wrong generation is a stale lease.
	if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", leaseBodyFor(t, runnerID, token, gen+5, nil), nil); w.Code != http.StatusConflict {
		t.Fatalf("stale lease = %d, want 409", w.Code)
	}
	// A cancelled job answers with the cancellation flag.
	s.mu.Lock()
	j := s.jobs[jobID]
	j.Status = model.StatusCancelled
	s.jobs[jobID] = j
	s.mu.Unlock()
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", leaseBodyFor(t, runnerID, token, gen, nil), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("cancelled heartbeat = %d: %s", w.Code, w.Body.String())
	}
	var hb HeartbeatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &hb); err != nil {
		t.Fatal(err)
	}
	if !hb.Cancel {
		t.Fatalf("cancelled heartbeat response = %+v", hb)
	}
}

// TestSqueezeLogBranches covers the memory-mode log edges.
func TestSqueezeLogBranches(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/missing/log", map[string]any{"runner_id": "r", "lease_token": "t", "lease_generation": 1, "line": "x"}, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown job = %d, want 404", w.Code)
	}
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/log", leaseBodyFor(t, runnerID, token, gen+3, map[string]any{"line": "hi"}), nil); w.Code != http.StatusConflict {
		t.Fatalf("stale lease log = %d, want 409", w.Code)
	}
}

// TestSqueezeCompleteReceiptReplay covers the completion idempotency receipt
// path: a duplicate delivery of the same result is acknowledged without
// error.
func TestSqueezeCompleteReceiptReplay(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	body := leaseBodyFor(t, runnerID, token, gen, map[string]any{"status": model.StatusSuccess})
	if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", body, nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", body, nil); w.Code != http.StatusNoContent {
		t.Fatalf("replayed complete = %d, want 204 (receipt dedupe): %s", w.Code, w.Body.String())
	}
	// A duplicate with a different result is refused as a stale lease.
	other := leaseBodyFor(t, runnerID, token, gen, map[string]any{"status": model.StatusFailure, "error": "different"})
	if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", other, nil); w.Code != http.StatusConflict {
		t.Fatalf("conflicting replay = %d, want 409", w.Code)
	}
}

// TestSqueezeValidJobOutputs covers the output bounds directly.
func TestSqueezeValidJobOutputs(t *testing.T) {
	big := map[string]string{}
	for i := 0; i < 257; i++ {
		big[string(rune('a'+i%26))+string(rune('0'+i/26))] = "v"
	}
	if validJobOutputs(big) {
		t.Fatal("257 outputs must be rejected")
	}
	if validJobOutputs(map[string]string{"": "v"}) {
		t.Fatal("empty key must be rejected")
	}
	if validJobOutputs(map[string]string{string(make([]byte, 129)): "v"}) {
		t.Fatal("oversized key must be rejected")
	}
	if validJobOutputs(map[string]string{"k": string(make([]byte, 64<<10+1))}) {
		t.Fatal("oversized value must be rejected")
	}
	total := map[string]string{}
	for i := 0; i < 20; i++ {
		total[string(rune('a'+i))] = string(make([]byte, 60<<10))
	}
	if validJobOutputs(total) {
		t.Fatal("total over 1 MiB must be rejected")
	}
	if !validJobOutputs(map[string]string{"k": "v"}) {
		t.Fatal("small outputs must be accepted")
	}
}

// TestSqueezeEnvironmentCapacity covers the not-at-capacity return.
func TestSqueezeEnvironmentCapacity(t *testing.T) {
	jobs := map[string]model.Job{
		"other": {ID: "other", Status: model.StatusSuccess, Environment: "prod", EnvironmentConcurrency: 1},
	}
	if environmentAtCapacityScoped(model.Job{ID: "j", Environment: "prod", EnvironmentConcurrency: 1}, jobs) {
		t.Fatal("a non-running environment job must not hold capacity")
	}
	if !environmentAtCapacityScoped(model.Job{ID: "j", Environment: "prod", EnvironmentConcurrency: 1, RepoURL: "https://github.com/o/r.git"}, map[string]model.Job{
		"run": {ID: "run", Status: model.StatusRunning, Environment: "prod", RepoURL: "https://github.com/o/r.git"},
	}) {
		t.Fatal("a running same-repo environment job must hold capacity")
	}
}

// TestSqueezeRerunMemoryEdges covers the memory rerun 404 and enqueue-error
// branches.
func TestSqueezeRerunMemoryEdges(t *testing.T) {
	testutil.UnixChmod(t)
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/runs/missing/rerun", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("rerun unknown = %d, want 404", w.Code)
	}
	// A run with no job pipeline text cannot be rerun.
	s.mu.Lock()
	s.runs["empty"] = model.Run{ID: "empty", Repo: "https://github.com/o/r.git", Ref: "main", Trusted: true}
	s.mu.Unlock()
	if w := c.do(http.MethodPost, "/api/v1/runs/empty/rerun", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("rerun pipeline-less run = %d, want 404", w.Code)
	}
	// An unrunnable stored pipeline fails the enqueue with 400.
	s.mu.Lock()
	s.runs["broken"] = model.Run{ID: "broken", Repo: "https://github.com/o/r.git", Ref: "main", Trusted: true}
	s.jobs["broken-job"] = model.Job{ID: "broken-job", RunID: "broken", Pipeline: "{{{"}
	s.mu.Unlock()
	if w := c.do(http.MethodPost, "/api/v1/runs/broken/rerun", nil, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("rerun broken pipeline = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// TestSqueezeRerunDBEdges covers rerunRunDB's not-found, store-error,
// pipeline-less and enqueue-error branches.
func TestSqueezeRerunDBEdges(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/runs/missing/rerun", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d, want 404", w.Code)
	}
	f.getRunErr = errStaticKindMissing
	if w := c.do(http.MethodPost, "/api/v1/runs/missing/rerun", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("store error = %d, want 500", w.Code)
	}
	f.getRunErr = nil
	if err := f.InsertRun(context.Background(), model.Run{ID: "run-1", RepoFullName: "o/r", Repo: "https://github.com/o/r.git", Ref: "main", Trusted: true}); err != nil {
		t.Fatal(err)
	}
	if w := c.do(http.MethodPost, "/api/v1/runs/run-1/rerun", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("pipeline-less run = %d, want 404", w.Code)
	}
	f.listJobsByRunErr = errStaticKindMissing
	if w := c.do(http.MethodPost, "/api/v1/runs/run-1/rerun", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("job list error = %d, want 500", w.Code)
	}
	f.listJobsByRunErr = nil
	if err := f.InsertJob(context.Background(), model.Job{ID: "job-1", RunID: "run-1", Pipeline: "{{{"}); err != nil {
		t.Fatal(err)
	}
	if w := c.do(http.MethodPost, "/api/v1/runs/run-1/rerun", nil, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("broken pipeline rerun = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// TestSqueezeCancelBranches covers the memory cancel edges and the DB-mode
// not-found/store-error paths.
func TestSqueezeCancelBranches(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/runs/missing/cancel", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("cancel unknown = %d, want 404", w.Code)
	}
	// A terminal job is skipped by the cancellation sweep.
	now := time.Now().UTC()
	s.mu.Lock()
	s.runs["run-x"] = model.Run{ID: "run-x", Status: model.StatusRunning}
	s.jobs["done"] = model.Job{ID: "done", RunID: "run-x", Status: model.StatusSuccess, FinishedAt: &now}
	s.jobs["live"] = model.Job{ID: "live", RunID: "run-x", Status: model.StatusRunning}
	s.mu.Unlock()
	if w := c.do(http.MethodPost, "/api/v1/runs/run-x/cancel", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	done := s.jobs["done"]
	s.mu.Unlock()
	if done.Status != model.StatusSuccess {
		t.Fatalf("terminal job was rewritten: %+v", done)
	}

	db, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := db.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	dc := newTestClient(t, db.Handler(), "secret")
	if w := dc.do(http.MethodPost, "/api/v1/runs/missing/cancel", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("db cancel unknown = %d, want 404", w.Code)
	}
	f.getRunErr = errStaticKindMissing
	if w := dc.do(http.MethodPost, "/api/v1/runs/x/cancel", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("db cancel store error = %d, want 500", w.Code)
	}
	f.getRunErr = nil
	if err := f.InsertRun(context.Background(), model.Run{ID: "run-1", RepoFullName: "o/r", Repo: "https://github.com/o/r.git", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertJob(context.Background(), model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	f.cancelRunJobsErr = errStaticKindMissing
	if w := dc.do(http.MethodPost, "/api/v1/runs/run-1/cancel", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("db cancel scheduler error = %d, want 500", w.Code)
	}
}

// TestSqueezeCancelUnauthenticated covers the requireAction refusal in the
// DB cancellation path.
func TestSqueezeCancelUnauthenticated(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertRun(context.Background(), model.Run{ID: "run-1"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs/run-1/cancel", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated cancel = %d, want 401/403", w.Code)
	}
}

// TestSqueezeListAuditBranches covers the no-store empty listing and a store
// read error.
func TestSqueezeListAuditBranches(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodGet, "/api/v1/audit", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("audit without store = %d: %s", w.Code, w.Body.String())
	}
	var events []model.AuditEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("audit without store = %+v, want empty", events)
	}

	dir := t.TempDir()
	ps, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "audit.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	pc := newTestClient(t, ps.Handler(), "secret")
	if w := pc.do(http.MethodGet, "/api/v1/audit", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("audit read error = %d, want 500", w.Code)
	}
}

// TestSqueezeEnqueueMemoryDownstreamClaims covers the in-memory downstream
// launch claim branches.
func TestSqueezeEnqueueMemoryDownstreamClaims(t *testing.T) {
	s := New("secret")
	claim := func(linkKey, childID string) SubmitRun {
		return SubmitRun{
			RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
			Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: untrustedPipeline,
			DownstreamLaunch: &storage.DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: childID},
		}
	}
	// First launch records the link.
	run, err := s.enqueueID(claim("o/r|refs/heads/main|child", "stable-1"), "child-run-1")
	if err != nil {
		t.Fatalf("first launch: %v", err)
	}
	s.mu.Lock()
	link := s.downstreamLinks["o/r|refs/heads/main|child"]
	s.mu.Unlock()
	if link.ChildRunID != run.ID || link.StableChildID != "stable-1" {
		t.Fatalf("link = %+v", link)
	}
	// A replay of the same stable child returns the existing run.
	prior, err := s.enqueueID(claim("o/r|refs/heads/main|child", "stable-1"), "child-run-1")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if prior.ID != run.ID {
		t.Fatalf("replay returned %s want %s", prior.ID, run.ID)
	}
	// A conflicting claim for the same link fails closed.
	if _, err := s.enqueueID(claim("o/r|refs/heads/main|child", "stable-2"), "child-run-2"); err == nil {
		t.Fatal("conflicting downstream claim = nil error")
	}
}

// TestSqueezeEnqueueMemoryDeliveryDedupe covers the in-lock webhook dedupe.
func TestSqueezeEnqueueMemoryDeliveryDedupe(t *testing.T) {
	s := New("secret")
	in := SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: untrustedPipeline,
		Metadata: map[string]string{"github_delivery": "dup-1"},
	}
	first, err := s.enqueue(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.enqueue(in)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("delivery replay enqueued a new run: %s vs %s", second.ID, first.ID)
	}
	// A delivery collision across repositories is not a dedupe.
	in2 := in
	in2.RepoURL = "https://github.com/other/backend.git"
	in2.RepoFullName = "other/backend"
	if run, err := s.enqueue(in2); err != nil || run.ID == first.ID {
		t.Fatalf("cross-repo delivery dedupe = %+v, %v", run, err)
	}
}

// TestSqueezeEnqueueMemoryPersistFailure covers the enqueue persist error.
func TestSqueezeEnqueueMemoryPersistFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err = s.enqueue(SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: untrustedPipeline,
	})
	if err == nil {
		t.Fatal("enqueue with unwritable data dir = nil error")
	}
}

// noAtomicEnqueueStore hides InsertCompiledRun (a RunEnqueueStore-only
// method) behind the base storage.Store interface so the server takes the
// scheduler fallback path.
type noAtomicEnqueueStore struct{ storage.Store }

// TestSqueezeEnqueueDBFallback covers the non-RunEnqueueStore fallback and
// its delivery-upsert failure log.
func TestSqueezeEnqueueDBFallback(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	s.Sched = scheduler.NewDB(f, time.Minute, nil, nil)
	s.DB = noAtomicEnqueueStore{f}
	in := SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: untrustedPipeline,
		Metadata: map[string]string{"github_delivery": "fallback-1"},
	}
	run, err := s.enqueue(in)
	if err != nil {
		t.Fatalf("fallback enqueue: %v", err)
	}
	if run.ID == "" {
		t.Fatal("empty run")
	}

	f.upsertDeliveryErr = errStaticKindMissing
	in.Metadata["github_delivery"] = "fallback-2"
	if _, err := s.enqueue(in); err != nil {
		t.Fatalf("fallback enqueue with failing delivery upsert: %v", err)
	}
}

// TestSqueezeEnqueueDBErrorBranches covers the InsertCompiledRun sentinel
// handling in enqueueDB.
func TestSqueezeEnqueueDBErrorBranches(t *testing.T) {
	newServer := func(t *testing.T) (*Server, *dbFakeStore) {
		t.Helper()
		s, err := NewPersistent("secret", "secret", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		f := newDBFakeStore()
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		return s, f
	}
	base := SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: untrustedPipeline,
	}
	t.Run("duplicate without claim", func(t *testing.T) {
		s, f := newServer(t)
		f.enqueueErr = storage.ErrDeliveryDuplicate
		if _, err := s.enqueue(base); !errors.Is(err, storage.ErrDeliveryDuplicate) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("duplicate lookup error", func(t *testing.T) {
		s, f := newServer(t)
		f.enqueueErr = storage.ErrDeliveryDuplicate
		f.findDeliveryErr = errStaticKindMissing
		in := base
		in.Metadata = map[string]string{"github_delivery": "d1"}
		if _, err := s.enqueue(in); err == nil || !strings.Contains(err.Error(), "lookup delivery") {
			t.Fatalf("err = %v, want lookup failure", err)
		}
	})
	t.Run("duplicate not found", func(t *testing.T) {
		s, f := newServer(t)
		f.enqueueErr = storage.ErrDeliveryDuplicate
		in := base
		in.Metadata = map[string]string{"github_delivery": "d1"}
		if _, err := s.enqueue(in); !errors.Is(err, storage.ErrDeliveryDuplicate) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("schedule claim lost", func(t *testing.T) {
		s, f := newServer(t)
		f.enqueueErr = storage.ErrScheduleClaimLost
		in := base
		in.ScheduleClaim = &storage.ScheduleClaim{ScheduleID: "s1", Nominal: time.Now().UTC()}
		if _, err := s.enqueue(in); !errors.Is(err, storage.ErrScheduleClaimLost) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("downstream launched replay", func(t *testing.T) {
		s, f := newServer(t)
		if err := f.InsertRun(context.Background(), model.Run{ID: "child-run", Status: model.StatusQueued}); err != nil {
			t.Fatal(err)
		}
		f.enqueueErr = storage.ErrDownstreamLaunched
		in := base
		in.DownstreamLaunch = &storage.DownstreamLaunchClaim{LinkKey: "k", StableChildID: "stable"}
		run, err := s.enqueueID(in, "child-run")
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		if run.ID != "child-run" {
			t.Fatalf("replay run = %+v", run)
		}
	})
	t.Run("downstream launched missing child", func(t *testing.T) {
		s, f := newServer(t)
		f.enqueueErr = storage.ErrDownstreamLaunched
		in := base
		in.DownstreamLaunch = &storage.DownstreamLaunchClaim{LinkKey: "k", StableChildID: "stable"}
		if _, err := s.enqueueID(in, "child-run"); !errors.Is(err, storage.ErrDownstreamLaunched) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestSqueezeEnqueueDBGating covers the DB-mode environment-branch and
// approval gating performed before the insert.
func TestSqueezeEnqueueDBGating(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	grantDeployments(s)
	gated := `version: 1
jobs:
  deploy:
    runtime: native
    environment:
      name: prod
      branches: ["release/*"]
    steps:
      - run: echo hi
  gate:
    runtime: native
    environment:
      name: staging
      approval: true
    steps:
      - run: echo hi
`
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: gated, Trusted: true,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	f.mu.Lock()
	jobs := map[string]model.Job{}
	for _, j := range f.jobs {
		if j.RunID == run.ID {
			jobs[j.Key] = j
		}
	}
	f.mu.Unlock()
	if jobs["deploy"].Status != model.StatusBlocked {
		t.Fatalf("branch-mismatched job = %+v", jobs["deploy"])
	}
	if jobs["gate"].Status != model.StatusWaitingApproval || jobs["gate"].WaitingSince == nil {
		t.Fatalf("approval-gated job = %+v", jobs["gate"])
	}
}

// TestSqueezeSwitchToDBReplayFailures covers the outbox replay and schedule
// reload failure logs during the switch.
func TestSqueezeSwitchToDBReplayFailures(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	f.outboxPendingErr = errStaticKindMissing
	f.listSchedulesErr = errStaticKindMissing
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB must tolerate replay failures: %v", err)
	}
}
