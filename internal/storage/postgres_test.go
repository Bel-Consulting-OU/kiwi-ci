package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// requiredTables are the 22 tables audit item 5 mandates in 0001_init.sql.
var requiredTables = []string{
	"runs", "jobs", "job_dependencies", "job_leases", "completion_receipts",
	"runners", "runner_certificates", "runner_capabilities", "artifacts",
	"cache_manifests", "deployments", "environments", "approvals", "schedules",
	"test_cases", "test_results", "audit_events", "log_chunks", "usage_records",
	"webhook_deliveries", "downstream_links", "workspace_snapshots",
}

// requiredTables0002 are the tables the outbox/schedules migration adds
// (0002 supersedes 0001's provisional schedules table with the full shape).
var requiredTables0002 = []string{
	"outbox", "schedules", "schedule_occurrences",
}

// requiredIndexes are the hot-path indexes the audit calls out; their names
// appear in 0001_init.sql.
var requiredIndexes = []string{
	"runs_status_idx",
	"jobs_run_id_idx",
	"jobs_status_priority_idx",
	"job_leases_expires_at_idx",
	"audit_events_created_at_idx",
	"log_chunks_run_id_seq_idx",
}

func TestMigrationFilesOrderedAndComplete(t *testing.T) {
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no embedded migrations")
	}
	// Versions must start at 1 and increase by exactly one (no gaps).
	want := 1
	for _, m := range all {
		if m.Version != want {
			t.Fatalf("migration %s has version %d, want %d (strictly increasing from 1, no gaps)", m.Name, m.Version, want)
		}
		want++
		if len(m.Statements) == 0 {
			t.Errorf("%s: no statements", m.Name)
		}
		for i, stmt := range m.Statements {
			if strings.TrimSpace(stmt) == "" {
				t.Errorf("%s: statement %d is empty after splitting", m.Name, i)
			}
			if !balancedQuotes(stmt) {
				t.Errorf("%s: statement %d has unbalanced quotes", m.Name, i)
			}
		}
	}

	raw, err := migrations.FS.ReadFile("0001_init.sql")
	if err != nil {
		t.Fatalf("read 0001_init.sql: %v", err)
	}
	for _, name := range requiredTables {
		re := regexp.MustCompile(`(?i)\bCREATE TABLE\s+` + regexp.QuoteMeta(name) + `\b`)
		if !re.Match(raw) {
			t.Errorf("0001_init.sql is missing CREATE TABLE %s", name)
		}
	}
	for _, name := range requiredIndexes {
		if !strings.Contains(string(raw), name) {
			t.Errorf("0001_init.sql is missing index %s", name)
		}
	}
	// schema_migrations is created by the same file so Migrate is self-bootstrapping.
	if !regexp.MustCompile(`(?i)\bCREATE TABLE\s+schema_migrations\b`).Match(raw) {
		t.Error("0001_init.sql is missing CREATE TABLE schema_migrations")
	}

	raw2, err := migrations.FS.ReadFile("0002_outbox_schedules.sql")
	if err != nil {
		t.Fatalf("read 0002_outbox_schedules.sql: %v", err)
	}
	for _, name := range requiredTables0002 {
		re := regexp.MustCompile(`(?i)\bCREATE TABLE\s+` + regexp.QuoteMeta(name) + `\b`)
		if !re.Match(raw2) {
			t.Errorf("0002_outbox_schedules.sql is missing CREATE TABLE %s", name)
		}
	}
}

// balancedQuotes is a heuristic syntax check: every unescaped single quote
// must have a partner (” is a literal escaped quote).
func balancedQuotes(s string) bool {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '\'' {
			i++
			continue
		}
		count++
	}
	return count%2 == 0
}

func TestSplitStatements(t *testing.T) {
	sql := "-- leading comment\nCREATE TABLE a (id TEXT PRIMARY KEY);\n-- middle comment\nCREATE TABLE b (id TEXT PRIMARY KEY);\n-- trailing comment"
	got := migrations.SplitStatements(sql)
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
	if !strings.Contains(got[0], "CREATE TABLE a") || strings.Contains(got[0], "--") {
		t.Errorf("first statement wrong: %q", got[0])
	}
	if !strings.Contains(got[1], "CREATE TABLE b") || strings.Contains(got[1], "--") {
		t.Errorf("second statement wrong: %q", got[1])
	}
}

func roundTrip(t *testing.T, in, out any) error {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal %T: %v", in, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal %T: %v", in, err)
	}
	return nil
}

func TestModelJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	later := now.Add(time.Hour).UTC()

	t.Run("Job", func(t *testing.T) {
		j := model.Job{
			ID: "job", RunID: "run", Key: "build", BaseKey: "base",
			RepoURL: "https://example.com/repo.git", Ref: "refs/heads/main",
			SHA: "abc123", Event: "push", Condition: "always()",
			DependencyStatus: model.StatusSuccess, Pipeline: "jobs:\n  build: {run: echo hi}",
			Trusted: true, ChangedFiles: []string{"a.go", "b.go"},
			Needs: []string{"d1", "d2"}, RequiredLabels: []string{"native", "os:darwin"},
			Network: "bridge", Environment: "prod", ApprovalRequired: true,
			EnvironmentBranches: []string{"main"}, EnvironmentConcurrency: 1,
			OIDCAllowed: true, OIDCAudiences: []string{"aud1"},
			DeclaredSecrets: []string{"S1", "S2"}, Status: model.StatusRunning,
			Priority: 3, MaxInfraRetries: 2, CreatedAt: now, StartedAt: &now,
			Error: "", Outputs: map[string]string{"k": "v"},
			NeedsOutputs: map[string]map[string]string{"d1": {"o": "1"}},
			Attempts:     1, LeaseRunnerID: "runner1",
			LeaseTokenHash:  []byte{0xde, 0xad, 0xbe, 0xef},
			LeaseGeneration: 7, LeaseExpiresAt: &later, ApprovedBy: "alice",
		}
		var out model.Job
		if err := roundTrip(t, j, &out); err != nil {
			return
		}
		if out.ID != j.ID || out.RunID != j.RunID || out.Key != j.Key || out.Pipeline != j.Pipeline {
			t.Errorf("identity fields lost: %+v", out)
		}
		if !reflect.DeepEqual(out.Needs, j.Needs) {
			t.Errorf("Needs changed: %v", out.Needs)
		}
		if !reflect.DeepEqual(out.NeedsOutputs, j.NeedsOutputs) {
			t.Errorf("NeedsOutputs changed: %v", out.NeedsOutputs)
		}
		if !bytes.Equal(out.LeaseTokenHash, j.LeaseTokenHash) {
			t.Fatalf("LeaseTokenHash did not survive round trip: %x", out.LeaseTokenHash)
		}
		if out.LeaseGeneration != j.LeaseGeneration || out.LeaseRunnerID != j.LeaseRunnerID {
			t.Errorf("lease fields changed: gen=%d runner=%q", out.LeaseGeneration, out.LeaseRunnerID)
		}
		if out.LeaseExpiresAt == nil || !out.LeaseExpiresAt.Equal(later) {
			t.Errorf("LeaseExpiresAt changed: %v", out.LeaseExpiresAt)
		}
		if out.StartedAt == nil || !out.StartedAt.Equal(now) {
			t.Errorf("StartedAt changed: %v", out.StartedAt)
		}
		if out.FinishedAt != nil {
			t.Errorf("nil FinishedAt became %v", out.FinishedAt)
		}
		if out.Outputs["k"] != "v" || len(out.Outputs) != 1 {
			t.Errorf("Outputs changed: %v", out.Outputs)
		}
		if out.Status != j.Status || out.Attempts != j.Attempts || out.Priority != j.Priority {
			t.Errorf("scalar fields changed: %+v", out)
		}
		if !out.CreatedAt.Equal(now) {
			t.Errorf("CreatedAt changed: %v", out.CreatedAt)
		}
	})

	t.Run("Run", func(t *testing.T) {
		r := model.Run{
			ID: "run", Repo: "https://example.com/repo.git", RepoFullName: "acme/repo",
			Ref: "refs/heads/main", SHA: "abc123", Event: "push",
			Status: model.StatusQueued, Trusted: true, ConcurrencyGroup: "grp",
			CreatedAt: now, StartedAt: &now, FinishedAt: &later,
			Metadata: map[string]string{"github_delivery": "d123"},
		}
		var out model.Run
		if err := roundTrip(t, r, &out); err != nil {
			return
		}
		if out.ID != r.ID || out.Status != r.Status || out.SHA != r.SHA || out.Trusted != r.Trusted {
			t.Errorf("identity fields lost: %+v", out)
		}
		if out.Metadata["github_delivery"] != "d123" {
			t.Errorf("metadata changed: %v", out.Metadata)
		}
		if out.StartedAt == nil || !out.StartedAt.Equal(now) || out.FinishedAt == nil || !out.FinishedAt.Equal(later) {
			t.Errorf("timestamps changed: %v %v", out.StartedAt, out.FinishedAt)
		}
	})

	t.Run("Runner", func(t *testing.T) {
		r := model.Runner{
			ID: "runner", Name: "mac-1", Labels: []string{"native", "os:darwin"},
			Metadata: map[string]string{"zone": "us-east"}, Capacity: 4,
			Registered: now, Completed: 12, Failed: 3, LastSeen: later,
			ActiveJobs: []string{"j1", "j2"}, CurrentJob: "j1", Busy: true,
			Disabled: true, Draining: false, Region: "us-east", Version: "1.0",
			ProtocolMin: 1, ProtocolMax: 3, Capabilities: []string{"m", "t"},
			AllowedRepositories: []string{"acme/*"}, CostPerHour: 0.5, PowerWatts: 90,
			CertSerial: "s123", RevokedAt: &later,
		}
		var out model.Runner
		if err := roundTrip(t, r, &out); err != nil {
			return
		}
		if out.ID != r.ID || out.Busy != r.Busy || out.Capacity != r.Capacity ||
			out.Completed != r.Completed || out.Failed != r.Failed || out.CurrentJob != r.CurrentJob {
			t.Errorf("hot-path fields lost: %+v", out)
		}
		if !reflect.DeepEqual(out.ActiveJobs, r.ActiveJobs) {
			t.Errorf("ActiveJobs changed: %v", out.ActiveJobs)
		}
		if !out.LastSeen.Equal(later) || !out.Registered.Equal(now) {
			t.Errorf("timestamps changed")
		}
		if out.RevokedAt == nil || !out.RevokedAt.Equal(later) {
			t.Errorf("RevokedAt changed: %v", out.RevokedAt)
		}
		if !reflect.DeepEqual(out.Labels, r.Labels) || !reflect.DeepEqual(out.Capabilities, r.Capabilities) {
			t.Errorf("lists changed")
		}
	})

	t.Run("ArtifactRecord", func(t *testing.T) {
		a := model.ArtifactRecord{
			ID: "art", RunID: "run", JobID: "job", JobKey: "build",
			Name: "bundle.tar.gz", Path: "/artifacts/bundle.tar.gz", Size: 4096,
			SHA256: "sha256", ContentType: "application/gzip", CreatedAt: now,
			ExpiresAt: &later, ProvenancePath: "/artifacts/bundle.tar.gz.intoto.json",
			ProvenanceSHA256: "sha256p",
		}
		var out model.ArtifactRecord
		if err := roundTrip(t, a, &out); err != nil {
			return
		}
		if out.ID != a.ID || out.RunID != a.RunID || out.JobID != a.JobID ||
			out.Name != a.Name || out.Size != a.Size || out.SHA256 != a.SHA256 {
			t.Errorf("identity fields lost: %+v", out)
		}
		if out.ExpiresAt == nil || !out.ExpiresAt.Equal(later) {
			t.Errorf("ExpiresAt changed: %v", out.ExpiresAt)
		}
		if !out.CreatedAt.Equal(now) {
			t.Errorf("CreatedAt changed: %v", out.CreatedAt)
		}
	})

	t.Run("TestReport", func(t *testing.T) {
		rep := model.TestReport{
			ID: "rep", RunID: "run", JobID: "job", JobKey: "test", Path: "results.xml",
			Tests: 3, Failures: 1, Duration: 1.5,
			Cases: []model.TestResult{
				{Name: "TestA", Class: "pkg", Duration: 0.1, Passed: true},
				{Name: "TestB", Class: "pkg", Duration: 0.2, Passed: false, Message: "boom"},
			},
			CreatedAt: now,
		}
		var out model.TestReport
		if err := roundTrip(t, rep, &out); err != nil {
			return
		}
		if out.ID != rep.ID || out.RunID != rep.RunID || out.Tests != rep.Tests ||
			out.Failures != rep.Failures || out.Duration != rep.Duration {
			t.Errorf("summary fields lost: %+v", out)
		}
		if len(out.Cases) != 2 || !reflect.DeepEqual(out.Cases, rep.Cases) {
			t.Errorf("cases changed: %+v", out.Cases)
		}
	})

	t.Run("LogEntry", func(t *testing.T) {
		e := model.LogEntry{Seq: 42, RunID: "run", JobID: "job", JobKey: "build", Step: "run", Line: "hello world", CreatedAt: now}
		var out model.LogEntry
		if err := roundTrip(t, e, &out); err != nil {
			return
		}
		if out.Seq != e.Seq || out.RunID != e.RunID || out.JobID != e.JobID ||
			out.JobKey != e.JobKey || out.Step != e.Step || out.Line != e.Line || !out.CreatedAt.Equal(now) {
			t.Errorf("log entry changed: %+v", out)
		}
	})

	t.Run("AuditEvent", func(t *testing.T) {
		e := model.AuditEvent{
			ID: "aud", Action: "job.completed", Actor: "runner1", RunID: "run",
			JobID: "job", Message: "success", Metadata: map[string]string{"job": "build"},
			CreatedAt: now,
		}
		var out model.AuditEvent
		if err := roundTrip(t, e, &out); err != nil {
			return
		}
		if out.ID != e.ID || out.Action != e.Action || out.Actor != e.Actor ||
			out.Message != e.Message || out.Metadata["job"] != "build" || !out.CreatedAt.Equal(now) {
			t.Errorf("audit event changed: %+v", out)
		}
	})

	t.Run("CompletionReceipt", func(t *testing.T) {
		r := model.CompletionReceipt{JobID: "job", Generation: 7, RunnerID: "runner1", ResultHash: "abcdef"}
		var out model.CompletionReceipt
		if err := roundTrip(t, r, &out); err != nil {
			return
		}
		if out != r {
			t.Errorf("receipt changed: %+v", out)
		}
	})

	t.Run("Deployment", func(t *testing.T) {
		d := model.Deployment{
			ID: "dep", RunID: "run", JobID: "job", Repository: "https://example.com/repo.git",
			Environment: "staging", URL: "https://staging.example.com", Commit: "abc123",
			Status: model.StatusSuccess, ApprovedBy: "alice", ApprovedAt: &now,
			StartedAt: &now, FinishedAt: &later, CreatedAt: now,
		}
		var out model.Deployment
		if err := roundTrip(t, d, &out); err != nil {
			return
		}
		if out.ID != d.ID || out.RunID != d.RunID || out.JobID != d.JobID ||
			out.Environment != d.Environment || out.Status != d.Status || out.Commit != d.Commit {
			t.Errorf("identity fields lost: %+v", out)
		}
		if out.ApprovedAt == nil || !out.ApprovedAt.Equal(now) || out.FinishedAt == nil || !out.FinishedAt.Equal(later) {
			t.Errorf("timestamps changed: %v %v", out.ApprovedAt, out.FinishedAt)
		}
	})

	t.Run("SnapshotRecord", func(t *testing.T) {
		rec := model.SnapshotRecord{
			ID: "snap", RunID: "run", JobID: "job", JobKey: "build", Path: "/snapshots/snap.tar",
			Size: 4096, SHA256: "sha256", Version: 3, RootSHA256: "root",
			Entries:   []model.SnapshotEntry{{Path: "a.go", Mode: 0o644, Size: 10, SHA256: "a"}},
			CreatedAt: now,
		}
		var out model.SnapshotRecord
		if err := roundTrip(t, rec, &out); err != nil {
			return
		}
		if out.ID != rec.ID || out.RunID != rec.RunID || out.JobID != rec.JobID ||
			out.Size != rec.Size || out.SHA256 != rec.SHA256 || out.Version != rec.Version || out.RootSHA256 != rec.RootSHA256 {
			t.Errorf("identity fields lost: %+v", out)
		}
		if len(out.Entries) != 1 || out.Entries[0].Path != "a.go" || out.Entries[0].Mode != 0o644 {
			t.Errorf("entries changed: %+v", out.Entries)
		}
	})

	t.Run("OutboxItem", func(t *testing.T) {
		it := OutboxItem{ID: "out1", Kind: "github_check", Payload: []byte(`{"sha":"abc123"}`), CreatedAt: now}
		var out OutboxItem
		if err := roundTrip(t, it, &out); err != nil {
			return
		}
		if out.ID != it.ID || out.Kind != it.Kind || !bytes.Equal(out.Payload, it.Payload) || !out.CreatedAt.Equal(now) {
			t.Errorf("outbox item changed: %+v", out)
		}
	})

	t.Run("Schedule", func(t *testing.T) {
		sc := Schedule{
			ID: "sched", Repository: "https://example.com/repo.git", Spec: "0 2 * * *",
			Enabled: true, LastRun: &later, CreatedAt: now,
		}
		var out Schedule
		if err := roundTrip(t, sc, &out); err != nil {
			return
		}
		if out.ID != sc.ID || out.Repository != sc.Repository || out.Spec != sc.Spec || !out.Enabled {
			t.Errorf("schedule changed: %+v", out)
		}
		if out.LastRun == nil || !out.LastRun.Equal(later) || !out.CreatedAt.Equal(now) {
			t.Errorf("schedule timestamps changed: %v", out.LastRun)
		}
	})

	t.Run("Occurrence", func(t *testing.T) {
		o := Occurrence{ScheduleID: "sched", Nominal: now, RunID: "run"}
		var out Occurrence
		if err := roundTrip(t, o, &out); err != nil {
			return
		}
		if out.ScheduleID != o.ScheduleID || !out.Nominal.Equal(now) || out.RunID != o.RunID {
			t.Errorf("occurrence changed: %+v", out)
		}
	})

	t.Run("ArtifactContract", func(t *testing.T) {
		c := ArtifactContract{
			Name: "bundle", Paths: []string{"dist/", "build/"}, Required: true,
			Retention: 24 * time.Hour, MaxSize: 8192, SHA256: "sha256",
		}
		var out ArtifactContract
		if err := roundTrip(t, c, &out); err != nil {
			return
		}
		if out.Name != c.Name || out.Required != c.Required || out.Retention != c.Retention ||
			out.MaxSize != c.MaxSize || out.SHA256 != c.SHA256 {
			t.Errorf("artifact contract changed: %+v", out)
		}
		if !reflect.DeepEqual(out.Paths, c.Paths) {
			t.Errorf("artifact contract paths changed: %v", out.Paths)
		}
	})
}

func TestIDValidation(t *testing.T) {
	valid := strings.Repeat("a", 31) + "9"
	if err := ValidateID(valid); err != nil {
		t.Errorf("valid id rejected: %v", err)
	}
	if err := ValidateRunID(valid); err != nil {
		t.Errorf("ValidateRunID rejected valid id: %v", err)
	}
	if err := ValidateJobID(valid); err != nil {
		t.Errorf("ValidateJobID rejected valid id: %v", err)
	}
	if err := ValidateRunnerID(valid); err != nil {
		t.Errorf("ValidateRunnerID rejected valid id: %v", err)
	}
	bad := []string{
		"",
		"abc",
		strings.Repeat("a", 33),        // too long
		strings.Repeat("a", 31),        // too short
		strings.Repeat("A", 32),        // uppercase not produced by the generator
		strings.Repeat("g", 32),        // non-hex
		"zz" + strings.Repeat("a", 30), // non-hex prefix
		strings.Repeat("a", 31) + " ",  // whitespace
	}
	for _, id := range bad {
		if err := ValidateID(id); err == nil {
			t.Errorf("ValidateID(%q): expected error", id)
		}
		if err := ValidateRunID(id); err == nil {
			t.Errorf("ValidateRunID(%q): expected error", id)
		}
		if err := ValidateJobID(id); err == nil {
			t.Errorf("ValidateJobID(%q): expected error", id)
		}
	}
}

func TestSentinelErrors(t *testing.T) {
	if ErrNotFound == nil || ErrLeaseConflict == nil || ErrGenerationMismatch == nil {
		t.Fatal("sentinel errors must be non-nil")
	}
	distinct := map[string]bool{
		ErrNotFound.Error():           true,
		ErrLeaseConflict.Error():      true,
		ErrGenerationMismatch.Error(): true,
	}
	if len(distinct) != 3 {
		t.Fatal("sentinel errors must be distinct")
	}
	for name, want := range map[string]error{
		"not found":           ErrNotFound,
		"lease conflict":      ErrLeaseConflict,
		"generation mismatch": ErrGenerationMismatch,
	} {
		got := fmt.Errorf("wrap: %w", want)
		if !errors.Is(got, want) {
			t.Errorf("%s: errors.Is failed across wrapping", name)
		}
	}
}

func TestRecomputeRunStatus(t *testing.T) {
	start := time.Now().UTC()
	fin := start.Add(time.Minute)

	mk := func(status model.Status) jobState {
		st := jobState{status: status, startedAt: &start}
		if status.Terminal() {
			st.finishedAt = &fin
		}
		return st
	}

	run := &model.Run{Status: model.StatusQueued}
	if !recomputeRunStatus(run, []jobState{mk(model.StatusRunning)}) || run.Status != model.StatusRunning {
		t.Fatalf("running job should make the run running, got %s", run.Status)
	}
	if run.StartedAt == nil || !run.StartedAt.Equal(start) {
		t.Fatalf("run should adopt the earliest job start")
	}

	run = &model.Run{Status: model.StatusQueued}
	if !recomputeRunStatus(run, []jobState{mk(model.StatusSuccess), mk(model.StatusFailure)}) || run.Status != model.StatusFailure {
		t.Fatalf("any failure should fail the run, got %s", run.Status)
	}

	run = &model.Run{Status: model.StatusQueued}
	if !recomputeRunStatus(run, []jobState{mk(model.StatusSuccess)}) || run.Status != model.StatusSuccess {
		t.Fatalf("all success should succeed the run, got %s", run.Status)
	}
	if run.FinishedAt == nil || !run.FinishedAt.Equal(fin) {
		t.Fatalf("run should adopt the last finish time")
	}

	run = &model.Run{Status: model.StatusCancelled}
	if recomputeRunStatus(run, []jobState{mk(model.StatusSuccess)}) {
		t.Fatalf("cancelled runs must stay cancelled")
	}

	if recomputeRunStatus(&model.Run{}, nil) {
		t.Fatalf("no jobs should not change the run")
	}
}

func TestDependencyOutcome(t *testing.T) {
	statuses := map[string]model.Status{
		"ok":  model.StatusSuccess,
		"bad": model.StatusFailure,
		"run": model.StatusRunning,
		"x":   model.StatusCancelled,
	}
	ready, outcome := dependencyOutcome(statuses, []string{"ok"})
	if !ready || outcome != model.StatusSuccess {
		t.Fatalf("success deps: ready=%v outcome=%s", ready, outcome)
	}
	ready, _ = dependencyOutcome(statuses, []string{"run"})
	if ready {
		t.Fatal("non-terminal dep must not be ready")
	}
	ready, outcome = dependencyOutcome(statuses, []string{"bad"})
	if !ready || outcome != model.StatusFailure {
		t.Fatalf("failure dep: ready=%v outcome=%s", ready, outcome)
	}
	ready, outcome = dependencyOutcome(statuses, []string{"x"})
	if !ready || outcome != model.StatusCancelled {
		t.Fatalf("cancelled dep: ready=%v outcome=%s", ready, outcome)
	}
	ready, outcome = dependencyOutcome(statuses, []string{"missing"})
	if !ready || outcome != model.StatusFailure {
		t.Fatalf("missing dep: ready=%v outcome=%s", ready, outcome)
	}

	if !dependencyConditionAllows("always()", model.StatusFailure) {
		t.Error("always() must allow failure")
	}
	if !dependencyConditionAllows("failure()", model.StatusFailure) || dependencyConditionAllows("failure()", model.StatusSuccess) {
		t.Error("failure() semantics wrong")
	}
	if !dependencyConditionAllows("cancelled()", model.StatusCancelled) || dependencyConditionAllows("cancelled()", model.StatusFailure) {
		t.Error("cancelled() semantics wrong")
	}
	// Unified semantics: an empty condition behaves like success().
	if dependencyConditionAllows("", model.StatusFailure) {
		t.Error("empty condition must not allow failure")
	}
	if dependencyConditionAllows("", model.StatusSuccess) != true {
		t.Error("empty condition must allow success")
	}
	if !dependencyConditionAllows("success()", model.StatusSuccess) {
		t.Error("success() must allow success")
	}
	if dependencyConditionAllows("success()", model.StatusFailure) {
		t.Error("success() must not allow failure")
	}
	if dependencyConditionAllows("garbage()", model.StatusFailure) {
		t.Error("unknown conditions must not allow failure")
	}
}
