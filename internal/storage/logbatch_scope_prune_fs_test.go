package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// appendScopedBatch appends one n-line batch for (runID, jobID) whose first
// Seq is seqBase. Every line carries the same run so the per-run scoping
// invariant holds.
func appendScopedBatch(t *testing.T, repo *Repository, runID, jobID, batchID string, seqBase int64, n int) {
	t.Helper()
	now := time.Now().UTC()
	entries := make([]model.LogEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, model.LogEntry{
			Seq: seqBase + int64(i), RunID: runID, JobID: jobID, JobKey: "build", Step: "run",
			Line: batchID, CreatedAt: now,
		})
	}
	if err := repo.AppendLogBatch(LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: batchID}, entries); err != nil {
		t.Fatalf("append batch %s/%s: %v", runID, batchID, err)
	}
}

// corruptCommittedBatch overwrites one committed record with invalid JSON and
// returns its path, so a reader that decodes the run is proven to fail on it.
func corruptCommittedBatch(t *testing.T, repo *Repository, runID string) string {
	t.Helper()
	dir := filepath.Join(repo.logBatchCommittedDir(), runID)
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("committed records for %s: %v (%d entries)", runID, err, len(ents))
	}
	path := filepath.Join(dir, ents[0].Name())
	if err := os.WriteFile(path, []byte("{not a log batch record"), 0o600); err != nil {
		t.Fatalf("corrupt %s: %v", path, err)
	}
	return path
}

// TestFSReadLogsScopedToRunAndIsolatedFromCorruptOtherRuns proves the
// per-run committed layout: ReadLogs(run-A) never decodes run-B's files, so
// run-B can be corrupt (or huge) without affecting run-A's reads. The
// run-B read is asserted to fail on the same corruption, proving the corrupt
// file really is on run-B's read path and not merely ignored.
func TestFSReadLogsScopedToRunAndIsolatedFromCorruptOtherRuns(t *testing.T) {
	repo := New(t.TempDir())
	appendScopedBatch(t, repo, "run-A", "job-A", "a-1", 1, 3)
	appendScopedBatch(t, repo, "run-B", "job-B", "b-1", 1, 3)
	appendScopedBatch(t, repo, "run-B", "job-B", "b-2", 4, 3)
	corruptCommittedBatch(t, repo, "run-B")

	got, err := repo.ReadLogs("run-A", 0, 100)
	if err != nil {
		t.Fatalf("ReadLogs(run-A) with a corrupt run-B record = %v, want nil (run-B must not be decoded)", err)
	}
	if len(got) != 3 || got[0].Line != "a-1" {
		t.Fatalf("ReadLogs(run-A) = %+v, want run-A's 3 lines", got)
	}
	if _, err := repo.ReadLogs("run-B", 0, 100); err == nil {
		t.Fatal("ReadLogs(run-B) must fail on its corrupt record (corruption fixture is on run-B's path)")
	}
}

// TestFSReadLogsScalingIgnoresOtherRuns is the scaling regression: 500
// batches of history in run-B must not add any decode work to a run-A read.
// A single corrupt run-B record makes any residual all-batches scan fail
// loudly instead of merely slow, and the run-A directory is asserted to hold
// exactly its own one record.
func TestFSReadLogsScalingIgnoresOtherRuns(t *testing.T) {
	repo := New(t.TempDir())
	for i := 0; i < 500; i++ {
		appendScopedBatch(t, repo, "run-B", "job-B", fmt.Sprintf("b-%d", i), int64(i*2+1), 1)
	}
	appendScopedBatch(t, repo, "run-A", "job-A", "a-1", 1, 1)
	corruptCommittedBatch(t, repo, "run-B")

	aDir := filepath.Join(repo.logBatchCommittedDir(), "run-A")
	ents, err := os.ReadDir(aDir)
	if err != nil || len(ents) != 1 {
		t.Fatalf("run-A committed entries = %d, %v; want exactly its own 1", len(ents), err)
	}
	got, err := repo.ReadLogs("run-A", 0, 100)
	if err != nil || len(got) != 1 || got[0].Line != "a-1" {
		t.Fatalf("ReadLogs(run-A) beside 500 run-B batches = %+v, %v; want 1 line and no decode of run-B", got, err)
	}
	if _, err := repo.ReadLogs("run-B", 0, 100); err == nil {
		t.Fatal("ReadLogs(run-B) must fail on the corrupt fixture")
	}
}

// TestFSMaxLogSeqIndexLifecycle pins the high-water contract: MaxLogSeq
// reflects publishes, survives a restart via the durable index, rebuilds
// when the index file is missing (the crash window), and never moves
// backwards after a prune removes the batches it was built from.
func TestFSMaxLogSeqIndexLifecycle(t *testing.T) {
	root := t.TempDir()
	repo := New(root)
	appendScopedBatch(t, repo, "run-A", "job-A", "a-1", 5, 1)
	appendScopedBatch(t, repo, "run-A", "job-A", "a-2", 42, 1)

	maxSeq, err := repo.MaxLogSeq()
	if err != nil || maxSeq != 42 {
		t.Fatalf("MaxLogSeq after publish = %d, %v; want 42", maxSeq, err)
	}
	if _, err := os.Stat(repo.logBatchMaxSeqPath()); err != nil {
		t.Fatalf("durable max-seq index missing after publish: %v", err)
	}

	// Restart: a fresh Repository for the same root reads the durable index.
	restarted := New(root)
	if maxSeq, err = restarted.MaxLogSeq(); err != nil || maxSeq != 42 {
		t.Fatalf("MaxLogSeq after restart = %d, %v; want 42", maxSeq, err)
	}

	// Crash with a missing maxseq file: the next call rebuilds the index from
	// the durable records (one-time scan) and re-persists it.
	if err := os.Remove(repo.logBatchMaxSeqPath()); err != nil {
		t.Fatal(err)
	}
	if maxSeq, err = restarted.MaxLogSeq(); err != nil || maxSeq != 42 {
		t.Fatalf("MaxLogSeq with missing index = %d, %v; want rebuilt 42", maxSeq, err)
	}
	if _, err := os.Stat(repo.logBatchMaxSeqPath()); err != nil {
		t.Fatalf("rebuilt max-seq index not persisted: %v", err)
	}

	// Prune removes the records; the watermark is monotone and stays at least
	// as high, so a restarted server never reuses a durable sequence.
	if err := restarted.PruneLogBatches("run-A"); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if maxSeq, err = restarted.MaxLogSeq(); err != nil || maxSeq < 42 {
		t.Fatalf("MaxLogSeq after prune = %d, %v; want >= 42 (monotone high-water)", maxSeq, err)
	}
}

// TestFSPruneLogBatchesReclaimsOnlyThatRun covers the retention contract's
// mechanics: committed records of the pruned run disappear, other runs and
// the global sequence are unaffected, re-publishing the same identity after
// the prune works (the record is truly gone, not conflict-marked), and the
// call is idempotent, multi-call and validation-safe.
func TestFSPruneLogBatchesReclaimsOnlyThatRun(t *testing.T) {
	repo := New(t.TempDir())
	appendScopedBatch(t, repo, "run-A", "job-A", "a-1", 1, 3)
	appendScopedBatch(t, repo, "run-A", "job-A", "a-2", 4, 3)
	appendScopedBatch(t, repo, "run-B", "job-B", "b-1", 100, 3)

	if err := repo.PruneLogBatches("run-A"); err != nil {
		t.Fatalf("prune run-A: %v", err)
	}
	got, err := repo.ReadLogs("run-A", 0, 100)
	if err != nil || len(got) != 0 {
		t.Fatalf("logs after prune = %d, %v; want empty", len(got), err)
	}
	if _, err := os.Stat(filepath.Join(repo.logBatchCommittedDir(), "run-A")); !os.IsNotExist(err) {
		t.Fatalf("run-A committed directory survived the prune: %v", err)
	}
	got, err = repo.ReadLogs("run-B", 0, 100)
	if err != nil || len(got) != 3 || got[0].Line != "b-1" {
		t.Fatalf("run-B logs after pruning run-A = %+v, %v; want intact", got, err)
	}

	// Re-publishing the same identity after the prune is a fresh append: the
	// removed record cannot conflict with (or dedupe) the new one.
	appendScopedBatch(t, repo, "run-A", "job-A", "a-1", 1, 3)
	if got, err = repo.ReadLogs("run-A", 0, 100); err != nil || len(got) != 3 {
		t.Fatalf("re-publish after prune = %d, %v; want 3", len(got), err)
	}

	if err := repo.PruneLogBatches("run-A"); err != nil {
		t.Fatalf("second prune must be an idempotent nil: %v", err)
	}
	if err := repo.PruneLogBatches("never-existed"); err != nil {
		t.Fatalf("prune of an unknown run must be a nil no-op: %v", err)
	}
	if err := repo.PruneLogBatches(""); err == nil {
		t.Fatal("empty run id must be rejected")
	}
	if err := repo.PruneLogBatches("../escape"); err == nil {
		t.Fatal("unsafe run id must be rejected")
	}
}

// TestFSPruneLogBatchesCoversInterruptedAndLegacyState proves a prune also
// reclaims data that is not yet in the new committed layout: an interrupted
// pending journal for the run is republished by recovery and then removed
// with the run directory, and a legacy flat committed record is migrated
// into the run directory before it is removed.
func TestFSPruneLogBatchesCoversInterruptedAndLegacyState(t *testing.T) {
	t.Run("pending journal", func(t *testing.T) {
		repo := New(t.TempDir())
		id := LogBatchIdentity{JobID: "job-A", Generation: 1, BatchID: "a-1"}
		entries := wave1BatchEntries("run-A", "job-A")
		rec, _ := json.Marshal(logBatchRecord{RunID: "run-A", Identity: id, Digest: LogBatchPayloadDigest(id, entries), Entries: entries})
		name := logBatchKey(id) + ".json"
		if err := AtomicWriteFile(filepath.Join(repo.logBatchPendingDir(), name), rec, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := repo.PruneLogBatches("run-A"); err != nil {
			t.Fatalf("prune with a pending journal: %v", err)
		}
		if _, err := os.Stat(filepath.Join(repo.logBatchPendingDir(), name)); !os.IsNotExist(err) {
			t.Fatalf("pending journal survived the prune: %v", err)
		}
		if _, err := os.Stat(filepath.Join(repo.logBatchCommittedDir(), "run-A")); !os.IsNotExist(err) {
			t.Fatalf("recovered run directory survived the prune: %v", err)
		}
		if got, err := repo.ReadLogs("run-A", 0, 100); err != nil || len(got) != 0 {
			t.Fatalf("logs after pruning a recovered journal = %d, %v; want empty", len(got), err)
		}
	})

	t.Run("legacy flat record", func(t *testing.T) {
		repo := New(t.TempDir())
		id := LogBatchIdentity{JobID: "job-A", Generation: 1, BatchID: "a-1"}
		entries := wave1BatchEntries("run-A", "job-A")
		// Old-format record: no run_id field, run only inside the entries.
		rec, _ := json.Marshal(logBatchRecord{Identity: id, Digest: LogBatchPayloadDigest(id, entries), Entries: entries})
		name := logBatchKey(id) + ".json"
		if err := AtomicWriteFile(filepath.Join(repo.logBatchCommittedDir(), name), rec, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := repo.PruneLogBatches("run-A"); err != nil {
			t.Fatalf("prune with a legacy flat record: %v", err)
		}
		if _, err := os.Stat(filepath.Join(repo.logBatchCommittedDir(), name)); !os.IsNotExist(err) {
			t.Fatalf("legacy flat record survived the prune: %v", err)
		}
		if got, err := repo.ReadLogs("run-A", 0, 100); err != nil || len(got) != 0 {
			t.Fatalf("logs after pruning a legacy record = %d, %v; want empty", len(got), err)
		}
	})
}

// TestFSPruneLogBatchesPartialRemovalStaysConsistent simulates a crash in
// the middle of RemoveAll: one record is already gone. Reads stay consistent
// (whole records only, no decode error), the sequence high-water is unchanged
// (no dangling index entry), and a repeated prune finishes the reclamation.
func TestFSPruneLogBatchesPartialRemovalStaysConsistent(t *testing.T) {
	repo := New(t.TempDir())
	appendScopedBatch(t, repo, "run-A", "job-A", "a-1", 1, 3)
	appendScopedBatch(t, repo, "run-A", "job-A", "a-2", 4, 3)
	maxSeq, err := repo.MaxLogSeq()
	if err != nil || maxSeq != 6 {
		t.Fatalf("MaxLogSeq before partial removal = %d, %v; want 6", maxSeq, err)
	}

	dir := filepath.Join(repo.logBatchCommittedDir(), "run-A")
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 2 {
		t.Fatalf("run-A entries = %d, %v; want 2", len(ents), err)
	}
	if err := os.Remove(filepath.Join(dir, ents[0].Name())); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ReadLogs("run-A", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("logs after an interrupted remove = %d, %v; want the remaining 3 without error", len(got), err)
	}
	if maxSeq, err = repo.MaxLogSeq(); err != nil || maxSeq != 6 {
		t.Fatalf("MaxLogSeq after an interrupted remove = %d, %v; want 6 (no dangling index)", maxSeq, err)
	}
	if err := repo.PruneLogBatches("run-A"); err != nil {
		t.Fatalf("resumed prune: %v", err)
	}
	if got, err = repo.ReadLogs("run-A", 0, 100); err != nil || len(got) != 0 {
		t.Fatalf("logs after resumed prune = %d, %v; want empty", len(got), err)
	}
}

// TestFSLogBatchLegacyFlatLayoutMigrated proves a store written by the
// pre-per-run layout keeps working: flat committed records and an old-format
// pending journal are recovered/migrated into run directories on the next
// load, stay idempotent for redeliveries, and contribute to MaxLogSeq.
func TestFSLogBatchLegacyFlatLayoutMigrated(t *testing.T) {
	root := t.TempDir()
	repo := New(root)
	now := time.Now().UTC()
	recA := logBatchRecord{
		Identity: LogBatchIdentity{JobID: "job-A", Generation: 1, BatchID: "a-1"},
		Entries:  []model.LogEntry{{Seq: 7, RunID: "run-A", JobID: "job-A", JobKey: "build", Step: "run", Line: "legacy-committed", CreatedAt: now}},
	}
	recA.Digest = LogBatchPayloadDigest(recA.Identity, recA.Entries)
	nameA := logBatchKey(recA.Identity) + ".json"
	bA, _ := json.Marshal(recA) // no run_id field: the old on-disk format
	if err := AtomicWriteFile(filepath.Join(repo.logBatchCommittedDir(), nameA), bA, 0o600); err != nil {
		t.Fatal(err)
	}
	recB := logBatchRecord{
		Identity: LogBatchIdentity{JobID: "job-B", Generation: 1, BatchID: "b-1"},
		Entries:  []model.LogEntry{{Seq: 9, RunID: "run-B", JobID: "job-B", JobKey: "build", Step: "run", Line: "legacy-pending", CreatedAt: now}},
	}
	recB.Digest = LogBatchPayloadDigest(recB.Identity, recB.Entries)
	nameB := logBatchKey(recB.Identity) + ".json"
	bB, _ := json.Marshal(recB)
	if err := AtomicWriteFile(filepath.Join(repo.logBatchPendingDir(), nameB), bB, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Load(); err != nil {
		t.Fatalf("Load over a legacy store: %v", err)
	}
	if ents, err := os.ReadDir(repo.logBatchCommittedDir()); err != nil {
		t.Fatal(err)
	} else {
		for _, ent := range ents {
			if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".json") {
				t.Fatalf("legacy flat record not migrated: %s", ent.Name())
			}
		}
	}
	got, err := repo.ReadLogs("run-A", 0, 100)
	if err != nil || len(got) != 1 || got[0].Line != "legacy-committed" {
		t.Fatalf("run-A after migration = %+v, %v", got, err)
	}
	got, err = repo.ReadLogs("run-B", 0, 100)
	if err != nil || len(got) != 1 || got[0].Line != "legacy-pending" {
		t.Fatalf("run-B recovered pending after migration = %+v, %v", got, err)
	}
	if maxSeq, err := repo.MaxLogSeq(); err != nil || maxSeq != 9 {
		t.Fatalf("MaxLogSeq after migration = %d, %v; want 9", maxSeq, err)
	}
	// A redelivery of the migrated batch is still an idempotent no-op.
	if err := repo.AppendLogBatch(recA.Identity, recA.Entries); err != nil {
		t.Fatalf("redelivery after migration = %v, want nil", err)
	}
}

// TestFSAppendLogBatchRejectsMixedAndUnsafeRuns proves the per-run layout
// cannot be tricked: a batch mixing runs is refused and nothing is written,
// and run ids that would escape the store root are refused too.
func TestFSAppendLogBatchRejectsMixedAndUnsafeRuns(t *testing.T) {
	repo := New(t.TempDir())
	mixed := []model.LogEntry{
		{Seq: 1, RunID: "run-A", JobID: "job-1", Line: "one"},
		{Seq: 2, RunID: "run-B", JobID: "job-1", Line: "two"},
	}
	err := repo.AppendLogBatch(LogBatchIdentity{JobID: "job-1", BatchID: "b-1"}, mixed)
	if err == nil || !strings.Contains(err.Error(), "mixes runs") {
		t.Fatalf("mixed-run batch = %v, want a mixes-runs rejection", err)
	}
	if _, err := os.Stat(repo.logBatchPendingDir()); !os.IsNotExist(err) {
		t.Fatalf("rejected batch staged a journal: %v", err)
	}
	unsafe := []model.LogEntry{{Seq: 1, RunID: "../escape", JobID: "job-1", Line: "one"}}
	if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "job-1", BatchID: "b-2"}, unsafe); err == nil {
		t.Fatal("unsafe run id must be rejected")
	}
	empty := []model.LogEntry{{Seq: 1, JobID: "job-1", Line: "one"}}
	if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "job-1", BatchID: "b-3"}, empty); err == nil {
		t.Fatal("an entry without a run id must be rejected")
	}
}
