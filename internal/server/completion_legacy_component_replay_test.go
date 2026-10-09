package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// componentJobDigest is a synthetic resolved component digest for the
// upgrade-window replay regressions: the runner never sends Components, so
// the stored attempt evidence carries this server-owned entry while the raw
// retry carries none.
var componentJobDigest = "sha256:" + strings.Repeat("c", 64)

// TestCompletionLegacyV1ReceiptComponentReplayDBFake is the DB/fake half of
// the upgrade-window regression: a component job's completion stored a legacy
// (v1) receipt and the server-normalized runtime evidence (Components filled
// from ComponentDigest); the raw retry (Components nil, as every runner
// sends) must replay 204, a genuinely different capture must still conflict
// 409, and a v2 receipt must replay by the raw digest.
func TestCompletionLegacyV1ReceiptComponentReplayDBFake(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	enqueue := func(sha string) {
		t.Helper()
		if _, err := s.enqueue(ctx, SubmitRun{
			RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
			Ref: "refs/heads/main", SHA: sha, Event: "push", Pipeline: smokePipeline,
		}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	setComponentJob := func(jobID string) model.Job {
		t.Helper()
		f.mu.Lock()
		defer f.mu.Unlock()
		j, ok := f.jobs[jobID]
		if !ok {
			t.Fatalf("job %s missing from fake store", jobID)
		}
		if j.BaseKey == "" {
			j.BaseKey = j.Key
		}
		j.ComponentDigest = componentJobDigest
		f.jobs[jobID] = j
		return j
	}
	completeBody := func(task Task, runnerID string, fields map[string]any) string {
		t.Helper()
		fields["runner_id"] = runnerID
		fields["lease_token"] = task.LeaseToken
		fields["lease_generation"] = task.LeaseGeneration
		b, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	post := func(task Task, body string) int {
		return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", body).Code
	}

	outputs := map[string]string{"out": "1"}
	rawRuntime := &model.ObservedRuntime{OS: "linux", Arch: "amd64"}

	// Scenario 1: legacy v1 receipt + normalized stored evidence.
	enqueue("abc")
	runnerID, task := registerUsageRunner(t, s)
	job := setComponentJob(task.Job.ID)
	normalized := observedRuntimeWithComponents(rawRuntime, job)
	if normalized == nil || normalized.Components[job.BaseKey] != componentJobDigest {
		t.Fatalf("normalized evidence = %+v, want the component digest under %q", normalized, job.BaseKey)
	}
	legacy := model.CompletionReceipt{
		JobID: task.Job.ID, Generation: task.LeaseGeneration, RunnerID: runnerID,
		ResultHash:        storage.CompletionResultDigestV1(model.StatusSuccess, "", outputs),
		ResultHashVersion: storage.CompletionResultHashVersionLegacy,
	}
	if err := f.CompleteJob(ctx, task.Job.ID, task.LeaseGeneration, runnerID, model.StatusSuccess, "", outputs, legacy, normalized); err != nil {
		t.Fatalf("legacy completion: %v", err)
	}
	identical := completeBody(task, runnerID, map[string]any{
		"status":           "success",
		"outputs":          outputs,
		"observed_runtime": map[string]any{"os": "linux", "arch": "amd64"},
	})
	if code := post(task, identical); code != http.StatusNoContent {
		t.Fatalf("legacy component replay = %d, want 204", code)
	}
	differing := completeBody(task, runnerID, map[string]any{
		"status":           "success",
		"outputs":          outputs,
		"observed_runtime": map[string]any{"os": "freebsd", "arch": "amd64"},
	})
	if code := post(task, differing); code != http.StatusConflict {
		t.Fatalf("legacy component replay with different evidence = %d, want 409", code)
	}

	// Scenario 2: a v2 receipt replays by the RAW request digest, even though
	// the stored attempt evidence is normalized: the v2 identity binds
	// exactly what the runner sent.
	enqueue("def")
	runner2, task2 := registerUsageRunner(t, s)
	job2 := setComponentJob(task2.Job.ID)
	normalized2 := observedRuntimeWithComponents(rawRuntime, job2)
	v2 := model.CompletionReceipt{
		JobID: task2.Job.ID, Generation: task2.LeaseGeneration, RunnerID: runner2,
		ResultHash:        storage.CompletionResultDigestV2(model.StatusSuccess, "", outputs, rawRuntime),
		ResultHashVersion: storage.CompletionResultHashVersionV2,
	}
	if err := f.CompleteJob(ctx, task2.Job.ID, task2.LeaseGeneration, runner2, model.StatusSuccess, "", outputs, v2, normalized2); err != nil {
		t.Fatalf("v2 completion: %v", err)
	}
	if code := post(task2, completeBody(task2, runner2, map[string]any{
		"status": "success", "outputs": outputs,
		"observed_runtime": map[string]any{"os": "linux", "arch": "amd64"},
	})); code != http.StatusNoContent {
		t.Fatalf("v2 component replay = %d, want 204", code)
	}
	if code := post(task2, completeBody(task2, runner2, map[string]any{
		"status": "success", "outputs": outputs,
		"observed_runtime": map[string]any{"os": "freebsd", "arch": "amd64"},
	})); code != http.StatusConflict {
		t.Fatalf("v2 component replay with different evidence = %d, want 409", code)
	}
}

// TestCompletionLegacyV1ReceiptComponentReplayFS is the fs/memory half of the
// same regression: the durable receipt is rewritten to the legacy v1 identity
// (a test seam over the in-memory receipt record, mirroring a receipt written
// by a pre-upgrade binary) and the byte-identical raw retry must replay 204
// against the job's normalized component evidence.
func TestCompletionLegacyV1ReceiptComponentReplayFS(t *testing.T) {
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
	s.mu.Lock()
	job := s.jobs[task.Job.ID]
	job.ComponentDigest = componentJobDigest
	if job.BaseKey == "" {
		job.BaseKey = job.Key
	}
	s.jobs[job.ID] = job
	s.mu.Unlock()

	body := func(runtime map[string]any) string {
		b, merr := json.Marshal(map[string]any{
			"runner_id": runnerID, "lease_token": task.LeaseToken,
			"lease_generation": task.LeaseGeneration,
			"status":           "success", "outputs": map[string]string{"out": "1"},
			"observed_runtime": runtime,
		})
		if merr != nil {
			t.Fatal(merr)
		}
		return string(b)
	}
	post := func(runtime map[string]any) int {
		return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", body(runtime)).Code
	}
	raw := map[string]any{"os": "linux", "arch": "amd64"}
	if code := post(raw); code != http.StatusNoContent {
		t.Fatalf("first completion = %d, want 204", code)
	}
	s.mu.Lock()
	stored := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if stored.ObservedRuntime == nil || stored.ObservedRuntime.Components[stored.BaseKey] != componentJobDigest {
		t.Fatalf("stored evidence = %+v, want the normalized component digest", stored.ObservedRuntime)
	}
	// Rewrite the receipt as the legacy v1 identity a pre-upgrade binary
	// would have stored for the same (job, generation, runner) triple.
	s.mu.Lock()
	s.completions[completionReceiptKey(task.Job.ID, task.LeaseGeneration, runnerID)] = model.CompletionReceipt{
		JobID: task.Job.ID, Generation: task.LeaseGeneration, RunnerID: runnerID,
		ResultHash:        storage.CompletionResultDigestV1(model.StatusSuccess, "", map[string]string{"out": "1"}),
		ResultHashVersion: storage.CompletionResultHashVersionLegacy,
	}
	s.markCompletionReceiptsChangedLocked()
	s.mu.Unlock()

	if code := post(raw); code != http.StatusNoContent {
		t.Fatalf("legacy component replay = %d, want 204", code)
	}
	if code := post(map[string]any{"os": "freebsd", "arch": "amd64"}); code != http.StatusConflict {
		t.Fatalf("legacy component replay with different evidence = %d, want 409", code)
	}
	// A v2 receipt (rewritten again as a test seam) replays by the raw digest.
	s.mu.Lock()
	s.completions[completionReceiptKey(task.Job.ID, task.LeaseGeneration, runnerID)] = model.CompletionReceipt{
		JobID: task.Job.ID, Generation: task.LeaseGeneration, RunnerID: runnerID,
		ResultHash:        storage.CompletionResultDigestV2(model.StatusSuccess, "", map[string]string{"out": "1"}, &model.ObservedRuntime{OS: "linux", Arch: "amd64"}),
		ResultHashVersion: storage.CompletionResultHashVersionV2,
	}
	s.markCompletionReceiptsChangedLocked()
	s.mu.Unlock()
	if code := post(raw); code != http.StatusNoContent {
		t.Fatalf("v2 component replay = %d, want 204", code)
	}
	if code := post(map[string]any{"os": "freebsd", "arch": "amd64"}); code != http.StatusConflict {
		t.Fatalf("v2 component replay with different evidence = %d, want 409", code)
	}
}

// pgComponentPipeline is the component reference resolved at enqueue for the
// PostgreSQL replay IT.
const pgComponentPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    component: build@sha256:PLACEHOLDER
    steps:
      - run: echo replaced
`

// TestPostgresIntegrationServerCompletionLegacyV1ComponentReplay is the
// real-PostgreSQL mapping of the upgrade-window regression: a component job's
// completion persisted the NORMALIZED runtime evidence and a legacy v1
// receipt (as a pre-upgrade binary did); the byte-identical raw retry must
// replay 204 through completionReceiptReplay, a genuinely different capture
// must conflict 409, and a v2 receipt must replay by the raw digest.
func TestPostgresIntegrationServerCompletionLegacyV1ComponentReplay(t *testing.T) {
	ctx := context.Background()
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)

	s.ComponentRegistry = components.NewLocalRegistry()
	spec := components.Spec{Name: "build", Steps: []pipeline.Step{{ID: "compile", Run: "make build"}}}
	digest, err := components.Digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	s.ComponentRegistry.(*components.LocalRegistry).Register(spec)

	submit := func() Task {
		t.Helper()
		pgITSubmit(t, s, strings.Replace(pgComponentPipeline, "PLACEHOLDER", digest, 1))
		runnerID := pgITRegisterRunner(t, s)
		task := pgITNext(t, s, runnerID)
		job, err := st.GetJob(ctx, task.Job.ID)
		if err != nil {
			t.Fatalf("durable job: %v", err)
		}
		if job.ComponentDigest == "" || job.ComponentDigest != digest {
			t.Fatalf("durable component digest = %q, want %q", job.ComponentDigest, digest)
		}
		return task
	}
	outputs := map[string]string{"out": "1"}
	rawRuntime := &model.ObservedRuntime{OS: "linux", Arch: "amd64"}

	// Scenario 1: legacy v1 receipt + normalized stored evidence.
	task := submit()
	job, err := st.GetJob(ctx, task.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	normalized := observedRuntimeWithComponents(rawRuntime, job)
	legacy := model.CompletionReceipt{
		JobID: task.Job.ID, Generation: task.LeaseGeneration, RunnerID: job.LeaseRunnerID,
		ResultHash:        storage.CompletionResultDigestV1(model.StatusSuccess, "", outputs),
		ResultHashVersion: storage.CompletionResultHashVersionLegacy,
	}
	if err := st.CompleteJob(ctx, task.Job.ID, task.LeaseGeneration, job.LeaseRunnerID, model.StatusSuccess, "", outputs, legacy, normalized); err != nil {
		t.Fatalf("legacy completion: %v", err)
	}
	body := func(runtime map[string]any) string {
		b, merr := json.Marshal(map[string]any{
			"runner_id": job.LeaseRunnerID, "lease_token": task.LeaseToken,
			"lease_generation": task.LeaseGeneration,
			"status":           "success", "outputs": outputs, "observed_runtime": runtime,
		})
		if merr != nil {
			t.Fatal(merr)
		}
		return string(b)
	}
	post := func(runtime map[string]any) int {
		return pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", body(runtime), nil).Code
	}
	if code := post(map[string]any{"os": "linux", "arch": "amd64"}); code != http.StatusNoContent {
		t.Fatalf("legacy component replay = %d, want 204", code)
	}
	if code := post(map[string]any{"os": "freebsd", "arch": "amd64"}); code != http.StatusConflict {
		t.Fatalf("legacy component replay with different evidence = %d, want 409", code)
	}

	// Scenario 2: the same shape with a v2 receipt replays by the raw digest.
	task2 := submit()
	job2, err := st.GetJob(ctx, task2.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	normalized2 := observedRuntimeWithComponents(rawRuntime, job2)
	v2 := model.CompletionReceipt{
		JobID: task2.Job.ID, Generation: task2.LeaseGeneration, RunnerID: job2.LeaseRunnerID,
		ResultHash:        storage.CompletionResultDigestV2(model.StatusSuccess, "", outputs, rawRuntime),
		ResultHashVersion: storage.CompletionResultHashVersionV2,
	}
	if err := st.CompleteJob(ctx, task2.Job.ID, task2.LeaseGeneration, job2.LeaseRunnerID, model.StatusSuccess, "", outputs, v2, normalized2); err != nil {
		t.Fatalf("v2 completion: %v", err)
	}
	body2 := func(runtime map[string]any) string {
		b, merr := json.Marshal(map[string]any{
			"runner_id": job2.LeaseRunnerID, "lease_token": task2.LeaseToken,
			"lease_generation": task2.LeaseGeneration,
			"status":           "success", "outputs": outputs, "observed_runtime": runtime,
		})
		if merr != nil {
			t.Fatal(merr)
		}
		return string(b)
	}
	if code := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task2.Job.ID+"/complete", "token", body2(map[string]any{"os": "linux", "arch": "amd64"}), nil).Code; code != http.StatusNoContent {
		t.Fatalf("v2 component replay = %d, want 204", code)
	}
	if code := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task2.Job.ID+"/complete", "token", body2(map[string]any{"os": "freebsd", "arch": "amd64"}), nil).Code; code != http.StatusConflict {
		t.Fatalf("v2 component replay with different evidence = %d, want 409", code)
	}
}
