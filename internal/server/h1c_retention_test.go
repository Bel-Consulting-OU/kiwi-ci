package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func retTimePtr(t time.Time) *time.Time { return &t }

// TestRunRetentionPrunesOnlyTerminalAgedData is the H1-C regression: the
// retention pass removes an aged TERMINAL run and its derived records, while
// a recent terminal run and an active (non-terminal) run survive untouched.
func TestRunRetentionPrunesOnlyTerminalAgedData(t *testing.T) {
	now := time.Now().UTC()
	s := New("tok")
	s.RunRetention = time.Hour
	s.MaxRetainedRuns = 0 // count bound disabled for this case
	s.mu.Lock()
	s.runs = map[string]model.Run{
		"aged":   {ID: "aged", Status: model.StatusSuccess, CreatedAt: now.Add(-3 * time.Hour), FinishedAt: retTimePtr(now.Add(-2 * time.Hour))},
		"recent": {ID: "recent", Status: model.StatusSuccess, CreatedAt: now.Add(-time.Minute), FinishedAt: retTimePtr(now)},
		"active": {ID: "active", Status: model.StatusRunning, CreatedAt: now.Add(-3 * time.Hour)},
	}
	s.jobs = map[string]model.Job{
		"ja": {ID: "ja", RunID: "aged", Status: model.StatusSuccess},
		"jr": {ID: "jr", RunID: "recent", Status: model.StatusSuccess},
		"jx": {ID: "jx", RunID: "active", Status: model.StatusRunning},
	}
	s.reports = map[string]model.TestReport{"ra": {ID: "ra", RunID: "aged"}, "rr": {ID: "rr", RunID: "recent"}}
	s.snapshots = map[string]model.SnapshotRecord{"sa": {ID: "sa", RunID: "aged"}, "sr": {ID: "sr", RunID: "recent"}}
	s.mu.Unlock()

	stats := s.GC(context.Background(), now)
	if stats.RunsRemoved != 1 {
		t.Fatalf("RunsRemoved = %d, want 1", stats.RunsRemoved)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs["aged"]; ok {
		t.Fatal("aged terminal run survived retention")
	}
	if _, ok := s.jobs["ja"]; ok {
		t.Fatal("job of the pruned run survived")
	}
	if _, ok := s.reports["ra"]; ok {
		t.Fatal("report of the pruned run survived")
	}
	if _, ok := s.snapshots["sa"]; ok {
		t.Fatal("snapshot of the pruned run survived")
	}
	for _, id := range []string{"recent", "active"} {
		if _, ok := s.runs[id]; !ok {
			t.Fatalf("%s run was pruned", id)
		}
	}
	if _, ok := s.reports["rr"]; !ok {
		t.Fatal("recent report was pruned")
	}
	if _, ok := s.snapshots["sr"]; !ok {
		t.Fatal("recent snapshot was pruned")
	}
}

// TestRunRetentionBoundsStateFile is the H1-C size regression: with a run
// count cap the fs-mode state.json stays bounded over many runs instead of
// growing without limit, and every derived record of a pruned run goes with
// it.
func TestRunRetentionBoundsStateFile(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("tok", "tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s.RunRetention = 0 // age bound disabled
	s.MaxRetainedRuns = 5
	s.mu.Lock()
	s.runs = map[string]model.Run{}
	s.jobs = map[string]model.Job{}
	s.reports = map[string]model.TestReport{}
	s.snapshots = map[string]model.SnapshotRecord{}
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("run-%02d", i)
		jobID := fmt.Sprintf("job-%02d", i)
		repID := fmt.Sprintf("rep-%02d", i)
		snapID := fmt.Sprintf("snap-%02d", i)
		at := now.Add(-time.Duration(i) * time.Minute)
		s.runs[id] = model.Run{ID: id, Status: model.StatusSuccess, CreatedAt: at, FinishedAt: &at}
		s.jobs[jobID] = model.Job{ID: jobID, RunID: id, Status: model.StatusSuccess, FinishedAt: &at}
		s.reports[repID] = model.TestReport{ID: repID, RunID: id}
		s.snapshots[snapID] = model.SnapshotRecord{ID: snapID, RunID: id}
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	before, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	stats := s.GC(context.Background(), now)
	if stats.RunsRemoved != 55 {
		t.Fatalf("RunsRemoved = %d, want 55", stats.RunsRemoved)
	}
	s.mu.Lock()
	runs, jobs, reports, snaps := len(s.runs), len(s.jobs), len(s.reports), len(s.snapshots)
	s.mu.Unlock()
	if runs != 5 || jobs != 5 || reports != 5 || snaps != 5 {
		t.Fatalf("after retention: runs=%d jobs=%d reports=%d snapshots=%d, want 5 each", runs, jobs, reports, snaps)
	}
	after, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() >= before.Size() {
		t.Fatalf("state.json did not shrink: before=%d after=%d", before.Size(), after.Size())
	}
}

// TestRunRetentionKeepsDependentsAndQuotaConsistent is the H1-C consistency
// regression: pruning a run drops its schedule occurrence claim, completion
// receipt and usage contribution in the SAME pass, so no index or quota
// window points at a run that no longer exists.
func TestRunRetentionKeepsDependentsAndQuotaConsistent(t *testing.T) {
	now := time.Now().UTC()
	s := New("tok")
	s.RunRetention = time.Hour
	s.MaxRetainedRuns = 0
	at := now.Add(-2 * time.Hour)
	s.mu.Lock()
	s.runs = map[string]model.Run{"r1": {ID: "r1", Status: model.StatusSuccess, CreatedAt: at, FinishedAt: &at}}
	s.jobs = map[string]model.Job{"j1": {ID: "j1", RunID: "r1", Status: model.StatusSuccess, FinishedAt: &at, UsageRecorded: true, Cost: 7}}
	s.occurrences = map[string]map[int64]string{"sched-1": {now.Truncate(time.Second).Unix(): "r1"}}
	recKey := completionReceiptKey("j1", 1, "runner-1")
	s.completions = map[string]model.CompletionReceipt{recKey: {JobID: "j1", Generation: 1, RunnerID: "runner-1"}}
	s.completionReceiptAt = map[string]time.Time{recKey: now}
	s.usageMu.Lock()
	s.usage = []usageEntry{{FinishedAt: now, Cost: 7}}
	s.usageMu.Unlock()
	s.mu.Unlock()

	if stats := s.GC(context.Background(), now); stats.RunsRemoved != 1 {
		t.Fatalf("RunsRemoved = %d, want 1", stats.RunsRemoved)
	}
	s.mu.Lock()
	if len(s.jobs) != 0 {
		t.Fatalf("jobs after retention = %d, want 0", len(s.jobs))
	}
	if len(s.occurrences) != 0 {
		t.Fatalf("occurrence claims after retention = %v, want none", s.occurrences)
	}
	if len(s.completions) != 0 {
		t.Fatalf("completion receipts after retention = %d, want 0", len(s.completions))
	}
	s.mu.Unlock()
	s.usageMu.Lock()
	usage := len(s.usage)
	s.usageMu.Unlock()
	if usage != 0 {
		t.Fatalf("quota usage window after retention = %d entries, want 0", usage)
	}
}
