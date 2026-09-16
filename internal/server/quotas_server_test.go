package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/quotas"
)

const threeJobPipeline = `version: 1
jobs:
  a:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo a
  b:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo b
  c:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo c
`

func TestQuotaRepoConcurrencyRejection(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.QuotaLimits = quotas.Limits{RepoConcurrency: 1}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatalf("enqueue A: %v", err)
	}
	_, task := leaseRunJob(t, s) // job A running
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","pipeline":`+jsonString(smokePipeline)+`}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second run = %d, want 429: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != "REPO_QUOTA" {
		t.Fatalf("reason = %q, want REPO_QUOTA", body["reason"])
	}
	// Once the running job completes, the repo is admissible again.
	runnerID := runnerIDFor(s, task.Job.ID)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","pipeline":`+jsonString(smokePipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("run after completion = %d, want 202: %s", w.Code, w.Body.String())
	}
}

func TestQuotaTeamConcurrencyRejection(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.QuotaLimits = quotas.Limits{TeamConcurrency: 1}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r1.git", RepoFullName: "o/r1",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatalf("enqueue A: %v", err)
	}
	leaseRunJob(t, s) // one running job in team example.com/o
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/o/r2.git","repo_full_name":"o/r2","ref":"refs/heads/main","pipeline":`+jsonString(smokePipeline)+`}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("other repo same team = %d, want 429: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != "TEAM_QUOTA" {
		t.Fatalf("reason = %q, want TEAM_QUOTA", body["reason"])
	}
}

func TestQuotaQueueDepthRejection(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.QuotaLimits = quotas.Limits{RepoQueueDepth: 2}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","pipeline":`+jsonString(threeJobPipeline)+`}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("3-job run with depth 2 = %d, want 429: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != "REPO_QUOTA" {
		t.Fatalf("reason = %q, want REPO_QUOTA", body["reason"])
	}
	// A 2-job run fits the limit exactly.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","pipeline":`+jsonString(`version: 1
jobs:
  a:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo a
  b:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo b
`)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("2-job run with depth 2 = %d, want 202: %s", w.Code, w.Body.String())
	}
}

func TestQuotaZeroLimitsUnlimited(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.QuotaLimits.Validate(); err != nil {
		t.Fatalf("zero limits must be valid: %v", err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: threeJobPipeline,
	}); err != nil {
		t.Fatalf("zero limits must not reject: %v", err)
	}
}

func TestLeaseFreezesRates(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2,"cost_per_hour":2.5,"power_watts":100}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.CostRate != 2.5 || task.Job.PowerWatts != 100 {
		t.Fatalf("frozen rates = %g/%g, want 2.5/100", task.Job.CostRate, task.Job.PowerWatts)
	}
	s.mu.Lock()
	stored := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if stored.CostRate != 2.5 || stored.PowerWatts != 100 {
		t.Fatalf("persisted rates = %g/%g, want 2.5/100", stored.CostRate, stored.PowerWatts)
	}
}

func TestCompletionAggregatesUsage(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2,"cost_per_hour":7200,"power_watts":500}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if w := completeTask(t, s, task, ri.ID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	job := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if job.Cost <= 0 || job.EnergyWh <= 0 {
		t.Fatalf("usage not recorded: cost=%g energy=%g", job.Cost, job.EnergyWh)
	}
	// 7200/h => 2/s: cost ≈ durationSeconds*2; energy 500W => 500/3600 Wh per s.
	wantCost := float64(job.FinishedAt.Sub(*job.StartedAt)) / float64(time.Hour) * 7200
	if job.Cost < wantCost*0.9 || job.Cost > wantCost*1.1 {
		t.Fatalf("cost = %g, want ≈%g", job.Cost, wantCost)
	}
	s.Metrics.mu.Lock()
	costTotal := s.Metrics.counters["kiwi_usage_cost_total"][""]
	energyTotal := s.Metrics.counters["kiwi_usage_energy_total"][""]
	s.Metrics.mu.Unlock()
	if costTotal <= 0 || energyTotal <= 0 {
		t.Fatalf("usage metrics = %g/%g, want positive", costTotal, energyTotal)
	}
}

func TestDailyBudgetBlocksLeasesMemory(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Seed the trailing window with cost 5 and energy 50.
	s.usageMu.Lock()
	s.usage = append(s.usage, usageEntry{FinishedAt: time.Now().UTC(), Cost: 5, EnergyWh: 50})
	s.usageMu.Unlock()
	s.DailyCostLimit = 1
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next under budget = %d, want 204", w.Code)
	}
	if w.Header().Get("X-Kiwi-Quota") != queueReasonDailyCostExceeded {
		t.Fatalf("quota header = %q", w.Header().Get("X-Kiwi-Quota"))
	}
	s.mu.Lock()
	var reason string
	for _, j := range s.jobs {
		if j.Status == model.StatusQueued {
			reason = j.QueueReason
		}
	}
	s.mu.Unlock()
	if reason != queueReasonDailyCostExceeded {
		t.Fatalf("queue reason = %q, want %q", reason, queueReasonDailyCostExceeded)
	}
	// Energy budget gates with its own reason.
	s.DailyCostLimit = 0
	s.DailyEnergyLimit = 1
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Header().Get("X-Kiwi-Quota") != queueReasonDailyEnergyExceeded {
		t.Fatalf("energy quota header = %q", w.Header().Get("X-Kiwi-Quota"))
	}
}

func TestDailyBudgetBlocksLeasesDB(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	finished := time.Now().UTC()
	f.mu.Lock()
	f.jobs["seeded"] = model.Job{ID: "seeded", RunID: "run", Key: "k", Status: model.StatusSuccess, FinishedAt: &finished, Cost: 7, EnergyWh: 9}
	f.runs["run"] = model.Run{ID: "run", Status: model.StatusSuccess, CreatedAt: finished.Add(-time.Hour)}
	f.mu.Unlock()
	s.DailyCostLimit = 1
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("db next under budget = %d, want 204", w.Code)
	}
	if w.Header().Get("X-Kiwi-Quota") != queueReasonDailyCostExceeded {
		t.Fatalf("db quota header = %q", w.Header().Get("X-Kiwi-Quota"))
	}
	// The DB queue-reason store received the annotation.
	if got := f.queueReason("seeded"); got != "" {
		t.Fatalf("seeded terminal job annotated: %q", got)
	}
}

func TestCompletionAggregatesUsageDB(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2,"cost_per_hour":7200,"power_watts":500}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.CostRate != 7200 || task.Job.PowerWatts != 500 {
		t.Fatalf("frozen rates = %g/%g, want 7200/500", task.Job.CostRate, task.Job.PowerWatts)
	}
	// The fake scheduler does not set StartedAt; seed it so the usage
	// window has a duration to bill.
	started := time.Now().UTC().Add(-50 * time.Millisecond)
	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	j.StartedAt = &started
	f.jobs[task.Job.ID] = j
	f.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	if w := completeTask(t, s, task, ri.ID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	done := f.jobs[task.Job.ID]
	f.mu.Unlock()
	if done.Cost <= 0 || done.EnergyWh <= 0 {
		t.Fatalf("db usage not persisted: cost=%g energy=%g", done.Cost, done.EnergyWh)
	}
	cost, energy, err := f.RecentUsage(context.Background(), time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("RecentUsage: %v", err)
	}
	if cost <= 0 || energy <= 0 {
		t.Fatalf("RecentUsage = %g/%g, want positive", cost, energy)
	}
	// Usage aggregates into the server metrics.
	s.Metrics.mu.Lock()
	costTotal := s.Metrics.counters["kiwi_usage_cost_total"][""]
	s.Metrics.mu.Unlock()
	if costTotal <= 0 {
		t.Fatalf("usage cost metric = %g, want positive", costTotal)
	}
}

func TestSatAddFClamps(t *testing.T) {
	if got := satAddF(math.MaxFloat64, 1); got != math.MaxFloat64 {
		t.Fatalf("satAddF(MaxFloat64, 1) = %g", got)
	}
	if got := satAddF(1, 2); got != 3 {
		t.Fatalf("satAddF(1, 2) = %g", got)
	}
}
