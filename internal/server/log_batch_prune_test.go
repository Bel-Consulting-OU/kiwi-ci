package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// appendServerLogBatch writes one 3-line fs batch for runID directly through
// the server's fs Repository (the retention hook is what is under test, not
// the HTTP transport).
func appendServerLogBatch(t *testing.T, s *Server, runID string) {
	t.Helper()
	now := time.Now().UTC()
	entries := make([]model.LogEntry, 0, 3)
	for i := 0; i < 3; i++ {
		entries = append(entries, model.LogEntry{
			Seq: int64(i + 1), RunID: runID, JobID: "job-" + runID, JobKey: "build", Step: "run",
			Line: fmt.Sprintf("%s-%d", runID, i), CreatedAt: now,
		})
	}
	if err := s.store.AppendLogBatch(storage.LogBatchIdentity{JobID: "job-" + runID, Generation: 1, BatchID: "batch-1"}, entries); err != nil {
		t.Fatalf("append fs log batch for %s: %v", runID, err)
	}
}

// TestPruneDeadRunLogBatchesOnlyAgedTerminalRuns pins the retention contract
// the fs reclamation hook enforces: only TERMINAL runs whose FinishedAt is
// older than logBatchRetention are pruned, so an active run, a recently
// finished run and a terminal run with no finish timestamp keep their logs
// (their streams can still be read). The call is idempotent.
func TestPruneDeadRunLogBatchesOnlyAgedTerminalRuns(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-31 * 24 * time.Hour)
	recent := now.Add(-time.Hour)
	for _, id := range []string{"run-active", "run-recent", "run-dead", "run-nil-finish"} {
		appendServerLogBatch(t, s, id)
	}
	s.mu.Lock()
	s.runs["run-active"] = model.Run{ID: "run-active", Status: model.StatusRunning}
	s.runs["run-recent"] = model.Run{ID: "run-recent", Status: model.StatusSuccess, FinishedAt: &recent}
	s.runs["run-dead"] = model.Run{ID: "run-dead", Status: model.StatusFailure, FinishedAt: &old}
	s.runs["run-nil-finish"] = model.Run{ID: "run-nil-finish", Status: model.StatusCancelled}
	s.mu.Unlock()

	s.pruneDeadRunLogBatches(now)
	s.pruneDeadRunLogBatches(now) // multi-call safe: no error, no further effect

	for _, id := range []string{"run-active", "run-recent", "run-nil-finish"} {
		logs, err := s.store.ReadLogs(id, 0, 100)
		if err != nil || len(logs) != 3 {
			t.Fatalf("logs for %s after sweep = %d, %v; want the 3 lines kept", id, len(logs), err)
		}
	}
	logs, err := s.store.ReadLogs("run-dead", 0, 100)
	if err != nil || len(logs) != 0 {
		t.Fatalf("logs for the aged terminal run = %d, %v; want reclaimed", len(logs), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "logbatches", "committed", "run-dead")); !os.IsNotExist(err) {
		t.Fatalf("aged run directory survived the sweep: %v", err)
	}
}

// TestMaintainPrunesAgedRunLogBatchesAtLifecyclePoint proves the hook is
// wired into Maintain's fs-mode tick (the lifecycle point where runs are
// housekept), not just callable: a real Maintain loop reclaims the aged
// terminal run's batch records.
func TestMaintainPrunesAgedRunLogBatchesAtLifecyclePoint(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-31 * 24 * time.Hour)
	appendServerLogBatch(t, s, "run-dead")
	s.mu.Lock()
	s.runs["run-dead"] = model.Run{ID: "run-dead", Status: model.StatusSuccess, FinishedAt: &old}
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Maintain(ctx)

	deadline := time.Now().Add(8 * time.Second)
	for {
		logs, err := s.store.ReadLogs("run-dead", 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(logs) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Maintain tick did not prune the aged terminal run's log batches")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestPruneDeadRunLogBatchesSkipsMemoryAndDBMode proves the missing-contract
// guard: an in-memory server has no batch store and must be a no-op, and a
// server switched to DB mode must not touch the abandoned fs batch store (the
// SQL store owns log retention there).
func TestPruneDeadRunLogBatchesSkipsMemoryAndDBMode(t *testing.T) {
	t.Run("memory mode", func(t *testing.T) {
		s := New("token")
		s.pruneDeadRunLogBatches(time.Now().UTC()) // must not panic with a nil store
	})

	t.Run("db mode leaves the fs store alone", func(t *testing.T) {
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		old := time.Now().UTC().Add(-31 * 24 * time.Hour)
		appendServerLogBatch(t, s, "run-dead")
		s.mu.Lock()
		s.runs["run-dead"] = model.Run{ID: "run-dead", Status: model.StatusSuccess, FinishedAt: &old}
		s.mu.Unlock()
		if err := s.SwitchToDB(newDBFakeStore()); err != nil {
			t.Fatal(err)
		}
		s.pruneDeadRunLogBatches(time.Now().UTC())
		logs, err := s.store.ReadLogs("run-dead", 0, 100)
		if err != nil || len(logs) != 3 {
			t.Fatalf("DB mode must not prune the fs batch store: %d lines, %v", len(logs), err)
		}
	})
}
