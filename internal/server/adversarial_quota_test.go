package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// twoJobPipeline declares two independent container jobs so a run offers two
// sequential lease candidates.
const twoJobPipeline = `version: 1
jobs:
  first:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo first
  second:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo second
`

// TestDBQuotaSlotReleasedOnComplete: with a repository concurrency limit of 1,
// the running reservation acquired by the first lease must be released by its
// completion, so the second job of the same repository can lease. A store
// that leaks the running counter permanently starves the repository.
func TestDBQuotaSlotReleasedOnComplete(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.QuotaLimits.RepoConcurrency = 1
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: twoJobPipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	next := func() (int, Task) {
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
		if w.Code != http.StatusOK {
			return w.Code, Task{}
		}
		var task Task
		if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
			t.Fatal(err)
		}
		return w.Code, task
	}
	code, task := next()
	if code != http.StatusOK {
		t.Fatalf("first lease = %d, want 200", code)
	}
	// The repo concurrency budget is spent: the second job waits.
	if code, _ := next(); code != http.StatusNoContent {
		t.Fatalf("second lease while at quota = %d, want 204", code)
	}
	running, queued := quotaCountsOf(f, "https://github.com/o/r.git")
	if running != 1 || queued != 1 {
		t.Fatalf("counters after first lease = %d/%d, want 1/1", running, queued)
	}
	// Complete the first job: its running slot is released in the same
	// transaction, so the queued job leases next.
	if w := completeTask(t, s, task, ri.ID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	running, queued = quotaCountsOf(f, "https://github.com/o/r.git")
	if running != 0 || queued != 1 {
		t.Fatalf("counters after complete = %d/%d, want 0/1", running, queued)
	}
	code, second := next()
	if code != http.StatusOK {
		t.Fatalf("second lease after completion = %d, want 200 (running slot not released)", code)
	}
	if second.Job.ID == task.Job.ID {
		t.Fatalf("same job leased twice: %s", second.Job.ID)
	}
}

// TestDBQuotaSlotReleasedOnCancel: the same repository budget is released by
// cancelling the running job, and cancelling a QUEUED job returns its queued
// reservation.
func TestDBQuotaSlotReleasedOnCancel(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.QuotaLimits.RepoConcurrency = 1
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: twoJobPipeline,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("first lease = %d", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", w.Code, w.Body.String())
	}
	running, queued := quotaCountsOf(f, "https://github.com/o/r.git")
	if running != 0 || queued != 0 {
		t.Fatalf("counters after cancelling the whole run = %d/%d, want 0/0", running, queued)
	}
}

// envPipeline declares one environment job with concurrency 1.
const envPipeline = `version: 1
jobs:
  deploy:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    environment:
      name: production
      concurrency: 1
    steps:
      - run: echo deploy
`

// TestMemoryEnvironmentConcurrencyRepoScoped: in memory mode the environment
// concurrency key is (repository, environment). Two repositories using the
// same environment name lease in parallel; a second job of the same
// repository/environment waits.
func TestMemoryEnvironmentConcurrencyRepoScoped(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caps := policy.DefaultTrustedCapabilities()
	caps.Deployments = true
	s.AdmissionCapabilities = &caps
	for _, repo := range []string{"https://example.com/o/r.git", "https://example.com/other/s.git"} {
		full := repo[len("https://example.com/"):]
		full = full[:len(full)-len(".git")]
		if _, err := s.enqueue(SubmitRun{RepoURL: repo, RepoFullName: full, Ref: "refs/heads/main", SHA: "abc", Event: "push", Pipeline: envPipeline, Trusted: true}); err != nil {
			t.Fatalf("enqueue %s: %v", repo, err)
		}
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	leased := map[string]bool{}
	for i := 0; i < 2; i++ {
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
		if w.Code != http.StatusOK {
			t.Fatalf("next %d = %d, want 200 (same env name in a different repo must not block): %s", i, w.Code, w.Body.String())
		}
		var task Task
		if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
			t.Fatal(err)
		}
		if task.Job.Environment != "production" {
			t.Fatalf("leased job environment = %q", task.Job.Environment)
		}
		leased[task.Job.RepoFullName] = true
	}
	if len(leased) != 2 {
		t.Fatalf("leased repositories = %v, want both", leased)
	}
	// Both environment slots are now taken: no third lease exists.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("third next = %d, want 204", w.Code)
	}
}

// TestMemoryEnvironmentConcurrencySameRepoSerializes: the same repository and
// environment name do serialize even across independent runs.
func TestMemoryEnvironmentConcurrencySameRepoSerializes(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caps := policy.DefaultTrustedCapabilities()
	caps.Deployments = true
	s.AdmissionCapabilities = &caps
	// Two runs of the same repository and environment.
	for i := 0; i < 2; i++ {
		if _, err := s.enqueue(SubmitRun{RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r", Ref: "refs/heads/main", SHA: "abc", Event: "push", Pipeline: envPipeline, Trusted: true}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("first next = %d", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("second next = %d, want 204 (same repository+environment serializes)", w.Code)
	}
}

// quotaCountsOf reads the reserved counters for one repository key.
func quotaCountsOf(f *dbFakeStore, repoKey string) (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.quotas[repoKey]
	return c[0], c[1]
}

// TestDBFakeArtifactEmptyJobIDNeverConflicts pins the SQL NULL semantics of
// the artifact idempotency key: records without a job ID are not part of the
// unique key and never conflict.
func TestDBFakeArtifactEmptyJobIDNeverConflicts(t *testing.T) {
	f := newDBFakeStore()
	rec := model.ArtifactRecord{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RunID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Name: "log", SHA256: "d1", CreatedAt: time.Now().UTC()}
	if _, created, err := f.InsertArtifactOnce(context.Background(), rec); err != nil || !created {
		t.Fatalf("first insert created=%v err=%v", created, err)
	}
	rec.ID = "cccccccccccccccccccccccccccccccc"
	rec.SHA256 = "d2"
	if _, created, err := f.InsertArtifactOnce(context.Background(), rec); err != nil || !created {
		t.Fatalf("second empty-job insert created=%v err=%v (NULL keys never conflict)", created, err)
	}
	f.mu.Lock()
	rows := len(f.artifacts)
	f.mu.Unlock()
	if rows != 2 {
		t.Fatalf("rows = %d, want 2", rows)
	}
}
