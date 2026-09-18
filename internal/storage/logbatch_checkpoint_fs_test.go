package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// checkpointWriteCount reads the durable-checkpoint write counter (the
// amortization seam) under the repository lock.
func checkpointWriteCount(r *Repository) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logBatchCheckpointWrites
}

// readCheckpointValue reads and parses the durable max-seq checkpoint.
func readCheckpointValue(t *testing.T, r *Repository) int64 {
	t.Helper()
	b, err := os.ReadFile(r.logBatchMaxSeqPath())
	if err != nil {
		t.Fatalf("read max-seq checkpoint: %v", err)
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatalf("parse max-seq checkpoint %q: %v", b, err)
	}
	return v
}

// TestFSLogBatchCheckpointCrashLostRecovery proves the crash-lost checkpoint
// contract: with the checkpoint flush schedule effectively disabled, publishes
// advance only the in-memory watermark, so the persisted checkpoint is behind
// the committed records; dropping it and reloading recovers the exact
// high-water mark from the committed run directories, re-persists the
// corrected value, and the next publishes continue above the recovered
// sequence (no sequence is ever reused after a restart).
func TestFSLogBatchCheckpointCrashLostRecovery(t *testing.T) {
	root := t.TempDir()
	repo := New(root)
	repo.checkpointEvery = 1_000_000
	const batches = 6
	for i := 0; i < batches; i++ {
		appendScopedBatch(t, repo, "run-A", "job-A", fmt.Sprintf("a-%d", i), int64(i*3+1), 3)
	}
	const want = int64(batches * 3)

	if got, err := repo.MaxLogSeq(); err != nil || got != want {
		t.Fatalf("MaxLogSeq in-process = %d, %v; want %d", got, err, want)
	}
	if persisted := readCheckpointValue(t, repo); persisted >= want {
		t.Fatalf("checkpoint %d is not behind the records (%d); the crash-lost case is not exercised", persisted, want)
	}

	// A restart with the stale checkpoint still present must take the maximum
	// of the checkpoint and the listing: the checkpoint alone is behind, so
	// only the scan can recover the exact value, and it repairs the file.
	stale := New(root)
	if got, err := stale.MaxLogSeq(); err != nil || got != want {
		t.Fatalf("MaxLogSeq with a stale checkpoint = %d, %v; want %d from the listing", got, err, want)
	}
	if persisted := readCheckpointValue(t, stale); persisted != want {
		t.Fatalf("stale checkpoint after load = %d, want the corrected %d", persisted, want)
	}

	// Crash: the durable checkpoint is dropped entirely (its advance was
	// never flushed). The listing alone must reconstruct the value.
	if err := os.Remove(repo.logBatchMaxSeqPath()); err != nil {
		t.Fatalf("drop checkpoint: %v", err)
	}
	restarted := New(root)
	got, err := restarted.MaxLogSeq()
	if err != nil || got != want {
		t.Fatalf("MaxLogSeq after a lost checkpoint = %d, %v; want %d recovered from the directories", got, err, want)
	}
	// The load scan persisted the corrected checkpoint.
	if persisted := readCheckpointValue(t, restarted); persisted != want {
		t.Fatalf("recovered checkpoint = %d, want %d persisted on load", persisted, want)
	}

	// A restart from the corrected state does not regress, and new publishes
	// allocate beyond the recovered sequence: every durable Seq stays unique.
	again := New(root)
	if got, err := again.MaxLogSeq(); err != nil || got != want {
		t.Fatalf("MaxLogSeq after recovery restart = %d, %v; want %d", got, err, want)
	}
	appendScopedBatch(t, again, "run-A", "job-A", "a-next", want+1, 3)
	logs, err := again.ReadLogs("run-A", 0, 10_000)
	if err != nil {
		t.Fatalf("ReadLogs after recovery: %v", err)
	}
	if len(logs) != (batches+1)*3 {
		t.Fatalf("recovered logs = %d lines, want %d", len(logs), (batches+1)*3)
	}
	seen := map[int64]bool{}
	var trueMax int64
	for _, e := range logs {
		if seen[e.Seq] {
			t.Fatalf("sequence %d was reused after the lost checkpoint", e.Seq)
		}
		seen[e.Seq] = true
		if e.Seq > trueMax {
			trueMax = e.Seq
		}
	}
	if trueMax != want+3 {
		t.Fatalf("durable max seq after recovery = %d, want %d", trueMax, want+3)
	}
	if got, err := again.MaxLogSeq(); err != nil || got != trueMax {
		t.Fatalf("MaxLogSeq after recovery publish = %d, %v; want %d", got, err, trueMax)
	}
}

// TestFSLogBatchCheckpointScanIncludesPendingJournal proves the load scan
// counts an interrupted pending journal even before recovery republishes it:
// its sequences were already allocated, so a restart must not hand them out
// again.
func TestFSLogBatchCheckpointScanIncludesPendingJournal(t *testing.T) {
	repo := New(t.TempDir())
	id := LogBatchIdentity{JobID: "job-A", Generation: 1, BatchID: "a-1"}
	entries := []model.LogEntry{
		{Seq: 40, RunID: "run-A", JobID: "job-A", JobKey: "build", Step: "run", Line: "journaled", CreatedAt: time.Now().UTC()},
		{Seq: 77, RunID: "run-A", JobID: "job-A", JobKey: "build", Step: "run", Line: "journaled-max", CreatedAt: time.Now().UTC()},
	}
	rec, err := json.Marshal(logBatchRecord{RunID: "run-A", Identity: id, Digest: LogBatchPayloadDigest(id, entries), Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	name := logBatchKey(id) + ".json"
	if err := AtomicWriteFile(filepath.Join(repo.logBatchPendingDir(), name), rec, 0o600); err != nil {
		t.Fatalf("stage pending journal: %v", err)
	}
	if scanned, err := repo.scanLogBatchMaxSeqLocked(); err != nil || scanned != 77 {
		t.Fatalf("scan with a pending journal = %d, %v; want 77", scanned, err)
	}
	if got, err := repo.MaxLogSeq(); err != nil || got != 77 {
		t.Fatalf("MaxLogSeq with a pending journal = %d, %v; want 77", got, err)
	}
	restarted := New(repo.Root)
	if got, err := restarted.MaxLogSeq(); err != nil || got != 77 {
		t.Fatalf("MaxLogSeq after recovery committed the journal = %d, %v; want 77", got, err)
	}
}

// TestFSLogBatchCheckpointAmortization is the cost regression: over K
// publishes with a small checkpoint interval the durable checkpoint is written
// a bounded, small number of times (never once per publish), while every
// published batch stays readable and the recovered high-water mark is exact
// across a restart.
func TestFSLogBatchCheckpointAmortization(t *testing.T) {
	const k = 256
	const interval = 16
	const lines = 2
	root := t.TempDir()
	repo := New(root)
	repo.checkpointEvery = interval

	start := time.Now()
	for i := 0; i < k; i++ {
		appendScopedBatch(t, repo, "run-A", "job-A", fmt.Sprintf("a-%d", i), int64(i*lines+1), lines)
	}
	elapsed := time.Since(start)
	const want = int64(k * lines)

	writes := checkpointWriteCount(repo)
	if maxWrites := k/interval + 2; writes > maxWrites {
		t.Fatalf("checkpoint writes = %d for %d publishes (interval %d), want <= %d", writes, k, interval, maxWrites)
	}
	if writes >= k {
		t.Fatalf("checkpoint writes = %d for %d publishes, want amortized (<< K)", writes, k)
	}
	t.Logf("publishes=%d checkpoint-writes=%d per-publish=%v", k, writes, elapsed/time.Duration(k))

	if got, err := repo.MaxLogSeq(); err != nil || got != want {
		t.Fatalf("MaxLogSeq in-process = %d, %v; want %d", got, err, want)
	}

	// Every published batch is still recoverable after a restart, the load
	// scan repairs any checkpoint lag, and the value remains exact.
	restarted := New(root)
	logs, err := restarted.ReadLogs("run-A", 0, 10_000)
	if err != nil {
		t.Fatalf("ReadLogs after restart: %v", err)
	}
	if len(logs) != k*lines {
		t.Fatalf("recovered lines = %d, want %d (no batch lost to the amortized checkpoint)", len(logs), k*lines)
	}
	for i, e := range logs {
		if e.Seq != int64(i+1) {
			t.Fatalf("recovered line %d has seq %d, want %d", i, e.Seq, i+1)
		}
	}
	if got, err := restarted.MaxLogSeq(); err != nil || got != want {
		t.Fatalf("MaxLogSeq after restart = %d, %v; want %d", got, err, want)
	}
	if persisted := readCheckpointValue(t, restarted); persisted != want {
		t.Fatalf("restored checkpoint = %d, want %d", persisted, want)
	}

	t.Run("sequence delta bounds the lag", func(t *testing.T) {
		repo := New(t.TempDir())
		repo.checkpointEvery = 1_000_000
		repo.checkpointDelta = 10
		for i := 0; i < 6; i++ {
			appendScopedBatch(t, repo, "run-A", "job-A", fmt.Sprintf("a-%d", i), int64(i*3+1), 3)
		}
		if writes := checkpointWriteCount(repo); writes > 3 {
			t.Fatalf("delta-triggered checkpoint writes = %d for 6 publishes, want <= 3", writes)
		}
		if got, err := repo.MaxLogSeq(); err != nil || got != 18 {
			t.Fatalf("MaxLogSeq with a delta trigger = %d, %v; want 18", got, err)
		}
		if persisted := readCheckpointValue(t, repo); 18-persisted > int64(10+3) {
			t.Fatalf("checkpoint lag = %d, want bounded by the delta threshold plus one batch", 18-persisted)
		}
	})
}

// TestFSLogBatchCheckpointRestartAfterAdvance is the restart regression: once
// a checkpoint flush has happened, a restart reports the same (or higher)
// high-water mark, never a lower one, and the stream stays monotone across a
// further publish and restart.
func TestFSLogBatchCheckpointRestartAfterAdvance(t *testing.T) {
	root := t.TempDir()
	repo := New(root)
	repo.checkpointEvery = 4
	// 5 publishes force the scheduled flush after the 4th advancing publish;
	// the first publish also creates the initially missing checkpoint.
	for i := 0; i < 5; i++ {
		appendScopedBatch(t, repo, "run-A", "job-A", fmt.Sprintf("a-%d", i), int64(i*3+1), 3)
	}
	const flushed = int64(5 * 3)
	if persisted := readCheckpointValue(t, repo); persisted > flushed {
		t.Fatalf("checkpoint %d advanced beyond the records %d", persisted, flushed)
	}

	restarted := New(root)
	got, err := restarted.MaxLogSeq()
	if err != nil || got != flushed {
		t.Fatalf("MaxLogSeq after restart = %d, %v; want %d (no regression)", got, err, flushed)
	}
	if persisted := readCheckpointValue(t, restarted); persisted < got {
		t.Fatalf("checkpoint after restart = %d, below the reported high-water %d", persisted, got)
	}

	// Continue the stream and restart again: monotone, no reuse.
	appendScopedBatch(t, restarted, "run-A", "job-A", "a-next", flushed+1, 3)
	if got, err := restarted.MaxLogSeq(); err != nil || got != flushed+3 {
		t.Fatalf("MaxLogSeq after continuing = %d, %v; want %d", got, err, flushed+3)
	}
	third := New(root)
	if got, err := third.MaxLogSeq(); err != nil || got != flushed+3 {
		t.Fatalf("MaxLogSeq after the second restart = %d, %v; want %d", got, err, flushed+3)
	}
}

// TestFSLogBatchCheckpointPruneThenReloadMonotone proves prune stays
// compatible with the amortized checkpoint and the reload scan: pruning a run
// removes its records but never lowers the watermark, the opportunistic prune
// flush persists the raised value, a reload keeps at least that value, and a
// new publish continues above it.
func TestFSLogBatchCheckpointPruneThenReloadMonotone(t *testing.T) {
	root := t.TempDir()
	repo := New(root)
	repo.checkpointEvery = 2
	for i := 0; i < 3; i++ {
		appendScopedBatch(t, repo, "run-A", "job-A", fmt.Sprintf("a-%d", i), int64(i*3+1), 3)
	}
	const want = int64(9)
	if got, err := repo.MaxLogSeq(); err != nil || got != want {
		t.Fatalf("MaxLogSeq before prune = %d, %v; want %d", got, err, want)
	}
	if err := repo.PruneLogBatches("run-A"); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if persisted := readCheckpointValue(t, repo); persisted < want {
		t.Fatalf("checkpoint after prune = %d, want >= %d (watermark never lowered)", persisted, want)
	}

	restarted := New(root)
	got, err := restarted.MaxLogSeq()
	if err != nil || got < want {
		t.Fatalf("MaxLogSeq after prune + reload = %d, %v; want >= %d", got, err, want)
	}
	appendScopedBatch(t, restarted, "run-B", "job-B", "b-1", want+1, 3)
	final := New(root)
	if got, err := final.MaxLogSeq(); err != nil || got != want+3 {
		t.Fatalf("MaxLogSeq after prune, reload and a new run = %d, %v; want %d", got, err, want+3)
	}
}

// BenchmarkFSAppendLogBatchCheckpointAmortized is the reproducible
// steady-state cost harness: it publishes b.N batches and reports the number
// of durable checkpoint writes, so the amortized cost is visible next to the
// per-publish journal write (for example -benchtime 2000x should show ~63
// checkpoint writes, i.e. one initial flush plus one per 32 publishes, and no
// per-publish checkpoint cost). It runs only under -bench.
func BenchmarkFSAppendLogBatchCheckpointAmortized(b *testing.B) {
	repo := New(b.TempDir())
	now := time.Now().UTC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := int64(i*4 + 1)
		entries := make([]model.LogEntry, 4)
		for j := range entries {
			entries[j] = model.LogEntry{Seq: seq + int64(j), RunID: "run", JobID: "job", JobKey: "build", Step: "run", Line: "line", CreatedAt: now}
		}
		if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "job", Generation: 1, BatchID: fmt.Sprintf("b-%d", i)}, entries); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	writes := checkpointWriteCount(repo)
	b.ReportMetric(float64(writes), "checkpoint-writes")
	b.ReportMetric(float64(writes)/float64(b.N), "checkpoint-writes/op")
}
