package server

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func fcQuotaJob(id, repoURL, status string) model.Job {
	full := strings.TrimSuffix(strings.TrimPrefix(repoURL, "https://github.com/"), ".git")
	return model.Job{ID: id, RunID: "run-" + id, RepoID: "github.com/" + full, RepoURL: repoURL, RepoFullName: full, Status: model.Status(status)}
}

func TestFlowQuotaSatAddF(t *testing.T) {
	if got := satAddF(math.MaxFloat64, math.MaxFloat64); got != math.MaxFloat64 {
		t.Fatalf("saturating add = %v", got)
	}
	if got := satAddF(1, 2); got != 3 {
		t.Fatalf("plain add = %v", got)
	}
}

func TestFlowQuotaDenialsMemory(t *testing.T) {
	run := model.Run{ID: "new", Repo: "https://github.com/acme/app.git", RepoFullName: "acme/app"}

	// Repo concurrency.
	s := New("tok")
	s.QuotaLimits.RepoConcurrency = 1
	s.jobs["running"] = fcQuotaJob("running", "https://github.com/acme/app.git", "running")
	if err := s.admitQuotaLocked(run, 1); err == nil || !isQuotaError(err, "REPO_QUOTA") {
		t.Fatalf("repo concurrency denial = %v", err)
	}

	// Team concurrency: a sibling repo in the same org.
	s = New("tok")
	s.QuotaLimits.TeamConcurrency = 1
	s.jobs["sibling"] = fcQuotaJob("sibling", "https://github.com/acme/other.git", "running")
	if err := s.admitQuotaLocked(run, 1); err == nil || !isQuotaError(err, "TEAM_QUOTA") {
		t.Fatalf("team concurrency denial = %v", err)
	}

	// Repo queue depth.
	s = New("tok")
	s.QuotaLimits.RepoQueueDepth = 1
	s.jobs["waiting"] = fcQuotaJob("waiting", "https://github.com/acme/app.git", "queued")
	if err := s.admitQuotaLocked(run, 2); err == nil || !isQuotaError(err, "REPO_QUOTA") {
		t.Fatalf("repo queue depth denial = %v", err)
	}

	// Team queue depth.
	s = New("tok")
	s.QuotaLimits.TeamQueueDepth = 1
	s.jobs["sibling"] = fcQuotaJob("sibling", "https://github.com/acme/other.git", "queued")
	if err := s.admitQuotaLocked(run, 1); err == nil || !isQuotaError(err, "TEAM_QUOTA") {
		t.Fatalf("team queue depth denial = %v", err)
	}

	// Under every limit: allowed.
	s = New("tok")
	s.QuotaLimits.RepoConcurrency = 5
	s.QuotaLimits.TeamConcurrency = 5
	s.QuotaLimits.RepoQueueDepth = 5
	s.QuotaLimits.TeamQueueDepth = 5
	if err := s.admitQuotaLocked(run, 1); err != nil {
		t.Fatalf("under-limit admission = %v", err)
	}
}

func isQuotaError(err error, reason string) bool {
	var ae *admissionError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Reason == reason && ae.Status == 429
}

func TestFlowQuotaCountsDB(t *testing.T) {
	ctx := context.Background()
	run := model.Run{ID: "new", RepoID: "github.com/acme/app", Repo: "https://github.com/acme/app.git", RepoFullName: "acme/app"}

	// ListQueuedJobs failure degrades to running-only counting; ListRuns
	// failure returns zeros.
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listQueuedErr: errors.New("queued down"), listRunsErr: errors.New("runs down")}
	if r, q, tr, tq := s.quotaCountsLocked(run); r != 0 || q != 0 || tr != 0 || tq != 0 {
		t.Fatalf("degraded counts = %d %d %d %d", r, q, tr, tq)
	}

	// Queued and running jobs count per repo and per team; terminal runs and
	// unreadable job lists are skipped.
	f2 := newDBFakeStore()
	s2 := New("tok")
	if err := s2.SwitchToDB(f2); err != nil {
		t.Fatal(err)
	}
	f2.mu.Lock()
	f2.jobs["q1"] = model.Job{ID: "q1", RunID: "run-q", RepoID: "github.com/acme/app", Status: model.StatusQueued}
	f2.jobs["q2"] = model.Job{ID: "q2", RunID: "run-q", RepoID: "github.com/acme/other", Status: model.StatusQueued}
	f2.runs["run-q"] = model.Run{ID: "run-q", RepoID: "github.com/acme/app", Status: model.StatusRunning}
	f2.jobs["r1"] = model.Job{ID: "r1", RunID: "run-r", RepoID: "github.com/acme/app", Status: model.StatusRunning}
	f2.jobs["r2"] = model.Job{ID: "r2", RunID: "run-r", RepoID: "github.com/acme/other", Status: model.StatusRunning}
	f2.jobs["r3"] = model.Job{ID: "r3", RunID: "run-r", RepoID: "github.com/acme/app", Status: model.StatusSuccess}
	f2.runs["run-r"] = model.Run{ID: "run-r", RepoID: "github.com/acme/app", Status: model.StatusRunning}
	f2.runs["run-done"] = model.Run{ID: "run-done", RepoID: "github.com/acme/app", Status: model.StatusSuccess}
	f2.runs["run-broken"] = model.Run{ID: "run-broken", RepoID: "github.com/acme/app", Status: model.StatusRunning}
	f2.mu.Unlock()
	s2.DB = f2
	repoRunning, repoQueued, teamRunning, teamQueued := s2.quotaCountsLocked(run)
	if repoRunning != 1 || repoQueued != 1 || teamRunning != 2 || teamQueued != 2 {
		t.Fatalf("counts = running %d queued %d teamRunning %d teamQueued %d", repoRunning, repoQueued, teamRunning, teamQueued)
	}
	// Unreadable job rows for one run are skipped entirely.
	s2.DB = &fcStore{dbFakeStore: f2, listJobsErr: errors.New("jobs down")}
	if r, q, _, _ := s2.quotaCountsLocked(run); r != 0 || q != 1 {
		t.Fatalf("degraded run counts = %d %d", r, q)
	}
	_ = ctx
}

// TestFlowQuotaEffectUsageNegativeDuration exercises the live usage effect on
// a completion whose clock ran backwards: computeJobUsage refuses the
// negative duration, so nothing is accounted (no amounts on the job, no
// metrics, no trailing-window entry) while the usage marker still converges
// so the effect is not retried forever.
func TestFlowQuotaEffectUsageNegativeDuration(t *testing.T) {
	s := New("tok")
	started := time.Now().UTC()
	finished := started.Add(-time.Minute)
	j := model.Job{ID: "j", RunID: "run-j", Status: model.StatusRunning, StartedAt: &started, FinishedAt: &finished}
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.mu.Unlock()
	if err := s.effectUsageAccount(context.Background(), j); err != nil {
		t.Fatalf("effect usage = %v", err)
	}
	s.mu.Lock()
	live := s.jobs[j.ID]
	s.mu.Unlock()
	if live.Cost != 0 || live.EnergyWh != 0 {
		t.Fatalf("negative-duration completion accounted usage: %+v", live)
	}
	if !live.UsageRecorded {
		t.Fatal("negative-duration completion did not converge the usage marker")
	}
	s.usageMu.Lock()
	entries := len(s.usage)
	s.usageMu.Unlock()
	if entries != 0 {
		t.Fatalf("negative-duration completion appended %d usage window entries", entries)
	}
}

func TestFlowQuotaDailyBudgetMemory(t *testing.T) {
	s := New("tok")
	s.DailyCostLimit = 10
	s.DailyEnergyLimit = 100
	now := time.Now().UTC()
	s.usageMu.Lock()
	s.usage = []usageEntry{
		{FinishedAt: now.Add(-time.Hour), Cost: 9, EnergyWh: 5},
		{FinishedAt: now.Add(-48 * time.Hour), Cost: 100, EnergyWh: 1000},
	}
	s.usageMu.Unlock()
	if reason, exceeded := s.dailyBudgetExceeded(context.Background()); exceeded || reason != "" {
		t.Fatalf("under-budget = %q %v", reason, exceeded)
	}
	s.DailyCostLimit = 5
	if reason, exceeded := s.dailyBudgetExceeded(context.Background()); !exceeded || reason != queueReasonDailyCostExceeded {
		t.Fatalf("cost budget = %q %v", reason, exceeded)
	}
	s.DailyCostLimit = 0
	s.DailyEnergyLimit = 1
	if reason, exceeded := s.dailyBudgetExceeded(context.Background()); !exceeded || reason != queueReasonDailyEnergyExceeded {
		t.Fatalf("energy budget = %q %v", reason, exceeded)
	}
}

func TestFlowQuotaDailyBudgetDB(t *testing.T) {
	ctx := context.Background()
	s, f, _, _ := cacheFixture(t)
	finished := time.Now().UTC().Add(-time.Hour)
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", FinishedAt: &finished, Cost: 12, EnergyWh: 3}
	f.mu.Unlock()
	s.DailyCostLimit = 10
	if reason, exceeded := s.dailyBudgetExceeded(ctx); !exceeded || reason != queueReasonDailyCostExceeded {
		t.Fatalf("db cost budget = %q %v", reason, exceeded)
	}
	// A usage-store failure is reported separately for the fail-closed gate.
	f.mu.Lock()
	f.usageErr = errors.New("usage down")
	f.mu.Unlock()
	if _, _, err := s.dailyBudgetStateDB(ctx); err == nil {
		t.Fatal("usage read failure must surface")
	}
	f.mu.Lock()
	f.usageErr = nil
	f.mu.Unlock()
	// Store without the usage extension: zero usage.
	f2 := newDBFakeStore()
	s2 := New("tok")
	if err := s2.SwitchToDB(f2); err != nil {
		t.Fatal(err)
	}
	s2.DB = fcPlainStore{f2}
	s2.DailyCostLimit = 1
	if reason, exceeded := s2.dailyBudgetExceeded(ctx); exceeded || reason != "" {
		t.Fatalf("usageless db budget = %q %v", reason, exceeded)
	}
}

func TestFlowQuotaMarkQueueReasonsAll(t *testing.T) {
	ctx := context.Background()
	// DB list failure is a no-op.
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listQueuedErr: errors.New("queued down")}
	s.markQueueReasonsAll(ctx, "BUDGET")

	// DB persist failure is logged.
	f2 := newDBFakeStore()
	s2 := New("tok")
	if err := s2.SwitchToDB(f2); err != nil {
		t.Fatal(err)
	}
	f2.mu.Lock()
	f2.jobs["q"] = model.Job{ID: "q", RunID: "run-c", Status: model.StatusQueued}
	f2.mu.Unlock()
	s2.DB = &fcStore{dbFakeStore: f2, setQueueReasonsErr: errors.New("reason write down")}
	s2.markQueueReasonsAll(ctx, "BUDGET")

	// Memory: only queued jobs are annotated.
	s3 := New("tok")
	s3.jobs["q"] = model.Job{ID: "q", Status: model.StatusQueued}
	s3.jobs["r"] = model.Job{ID: "r", Status: model.StatusRunning}
	s3.markQueueReasonsAll(ctx, "BUDGET")
	s3.mu.Lock()
	q := s3.jobs["q"]
	r := s3.jobs["r"]
	s3.mu.Unlock()
	if q.QueueReason != "BUDGET" {
		t.Fatalf("queued job reason = %q", q.QueueReason)
	}
	if r.QueueReason != "" {
		t.Fatalf("running job reason = %q", r.QueueReason)
	}
}
