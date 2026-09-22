package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestFSAppendLogBatchIdempotentAndConflict proves the fs batch API's core
// contract: identical identity+payload is a no-op even when the redelivery
// carries a fresh CreatedAt and re-allocated Seq values, a reused identity
// with different lines fails closed, and the committed original is untouched.
func TestFSAppendLogBatchIdempotentAndConflict(t *testing.T) {
	repo := New(t.TempDir())
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")

	if err := repo.AppendLogBatch(id, entries); err != nil {
		t.Fatalf("first append: %v", err)
	}
	replay := redeliverBatchEntries(entries, 100, time.Minute)
	if err := repo.AppendLogBatch(id, replay); err != nil {
		t.Fatalf("identical replay with a fresh arrival time = %v, want nil", err)
	}
	got, err := repo.ReadLogs("run-1", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("logs after replay = %d, %v; want 3", len(got), err)
	}

	conflict := wave1BatchEntries("run-1", "job-1")
	conflict[1].Line = "changed"
	if err := repo.AppendLogBatch(id, conflict); !errors.Is(err, ErrLogBatchConflict) {
		t.Fatalf("conflicting payload = %v, want ErrLogBatchConflict", err)
	}
	got, _ = repo.ReadLogs("run-1", 0, 100)
	if len(got) != 3 || got[1].Line != "two" {
		t.Fatalf("conflict mutated the committed batch: %+v", got)
	}

	if err := repo.AppendLogBatch(LogBatchIdentity{}, entries); err == nil {
		t.Fatal("empty identity must fail")
	}
	if err := repo.AppendLogBatch(id, nil); err == nil {
		t.Fatal("empty payload must fail")
	}
}

// TestFSAppendLogBatchRetryAcrossRestartSingleCopy proves the digest is a
// pure function of the logical lines: a fresh Repository over the same root
// (no in-memory memo can survive it) recognizes a redelivery with a new
// arrival time and new Seq values as the already-committed batch.
func TestFSAppendLogBatchRetryAcrossRestartSingleCopy(t *testing.T) {
	root := t.TempDir()
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")
	repo := New(root)
	if err := repo.AppendLogBatch(id, entries); err != nil {
		t.Fatalf("first append: %v", err)
	}

	restarted := New(root)
	if _, err := restarted.Load(); err != nil {
		t.Fatalf("Load after restart: %v", err)
	}
	replay := redeliverBatchEntries(entries, 9000, 12*time.Hour)
	if err := restarted.AppendLogBatch(id, replay); err != nil {
		t.Fatalf("retry across restart = %v, want an idempotent nil", err)
	}
	got, err := restarted.ReadLogs("run-1", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("logs after across-restart retry = %d, %v; want exactly 3", len(got), err)
	}
	if got[0].Line != "one" || got[2].Line != "three" {
		t.Fatalf("retry altered the committed lines: %+v", got)
	}
	// The committed copy keeps the FIRST delivery's timestamps, not the
	// retry's: idempotency must not rewrite durable entries.
	if got[0].CreatedAt.Equal(replay[0].CreatedAt) {
		t.Fatalf("retry overwrote the committed arrival time: %v", got[0].CreatedAt)
	}
}

// TestFSAppendLogBatchJournalWriteFailureRetrySingleCopy injects a failure in
// the journal's AtomicWriteFile (the fsutil file Sync seam). Nothing may be
// exposed as durable, and the retry must leave exactly one copy of every line.
func TestFSAppendLogBatchJournalWriteFailureRetrySingleCopy(t *testing.T) {
	repo := New(t.TempDir())
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")

	restoreSync := fsutil.SetHooks(fsutil.Hooks{FileSync: func(*os.File) error {
		return errors.New("injected journal sync failure")
	}})
	if err := repo.AppendLogBatch(id, entries); err == nil {
		t.Fatal("append must fail when the journal cannot be made durable")
	}
	restoreSync()
	t.Cleanup(restoreSync)

	got, err := repo.ReadLogs("run-1", 0, 100)
	if err != nil || len(got) != 0 {
		t.Fatalf("interrupted journal exposed as durable: %d lines, %v", len(got), err)
	}
	if err := repo.AppendLogBatch(id, redeliverBatchEntries(entries, 10, time.Second)); err != nil {
		t.Fatalf("retry after a failed journal write: %v", err)
	}
	got, err = repo.ReadLogs("run-1", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("retry copies = %d, %v; want exactly 3", len(got), err)
	}
}

// TestFSAppendLogBatchPublishFsyncFailureRetrySingleCopy injects a directory
// fsync failure on the PUBLICATION step: the rename has already happened, so
// the batch is durable, and the retry must recognize it instead of writing a
// second copy. The injected failure targets the committed run directory's
// sync by path (the per-run layout plus the max-seq index write add other
// directory fsyncs).
func TestFSAppendLogBatchPublishFsyncFailureRetrySingleCopy(t *testing.T) {
	repo := New(t.TempDir())
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")

	// Layout adaptation: the max-seq index write adds directory fsyncs of its
	// own, so the injected failure is targeted at the committed RUN
	// directory's sync (the publication step, after the rename) instead of
	// relying on the ordinal call count. The dir-sync seam now lives in
	// fsutil; the hook delegates to fsutil.RealSyncDir for every other
	// directory.
	failed := 0
	restoreDir := fsutil.SetHooks(fsutil.Hooks{DirSync: func(dir string) error {
		if filepath.Base(filepath.Dir(dir)) == filepath.Base(repo.logBatchCommittedDir()) {
			failed++
			return errors.New("injected publication dir fsync failure")
		}
		return fsutil.RealSyncDir(dir)
	}})
	err := repo.AppendLogBatch(id, entries)
	restoreDir()
	t.Cleanup(restoreDir)
	if err == nil {
		t.Fatal("append must surface the publication fsync failure")
	}
	if failed == 0 {
		t.Fatal("publication dir fsync did not run")
	}
	got, rerr := repo.ReadLogs("run-1", 0, 100)
	if rerr != nil || len(got) != 3 {
		t.Fatalf("published batch lines = %d, %v; want exactly 3", len(got), rerr)
	}
	// The retry is an idempotent no-op against the already-committed record,
	// even though it carries a fresh arrival time and new Seq values (the
	// lost-204 redelivery this digest scope exists for).
	if err := repo.AppendLogBatch(id, redeliverBatchEntries(entries, 10, time.Minute)); err != nil {
		t.Fatalf("retry after publication fsync failure: %v", err)
	}
	got, _ = repo.ReadLogs("run-1", 0, 100)
	if len(got) != 3 {
		t.Fatalf("retry duplicated lines: %d, want 3", len(got))
	}
}

// TestFSAppendLogBatchRecoveryReconcilesJournal proves that Load reconciles
// an interrupted batch: a complete pending journal is published exactly once,
// and a journal whose batch already committed is dropped.
//
// Layout adaptation: committed records now live in
// logbatches/committed/<runID>/<key>.json (per-run scoping), so the
// committed-path assertions below name the run directory; the pending journal
// path is unchanged and the recovery semantics are identical.
func TestFSAppendLogBatchRecoveryReconcilesJournal(t *testing.T) {
	repo := New(t.TempDir())
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")
	key := logBatchKey(id)
	name := key + ".json"
	rec, err := json.Marshal(logBatchRecord{Identity: id, Digest: LogBatchPayloadDigest(id, entries), Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	committedPath := filepath.Join(repo.logBatchCommittedDir(), "run-1", name)
	if err := AtomicWriteFile(filepath.Join(repo.logBatchPendingDir(), name), rec, 0o600); err != nil {
		t.Fatalf("stage interrupted journal: %v", err)
	}
	if _, err := os.Stat(committedPath); !os.IsNotExist(err) {
		t.Fatalf("batch committed before recovery: %v", err)
	}
	if _, err := repo.Load(); err != nil {
		t.Fatalf("Load recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo.logBatchPendingDir(), name)); !os.IsNotExist(err) {
		t.Fatalf("pending journal survived recovery: %v", err)
	}
	if _, err := os.Stat(committedPath); err != nil {
		t.Fatalf("recovery did not publish into the run directory: %v", err)
	}
	got, err := repo.ReadLogs("run-1", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("recovered lines = %d, %v; want exactly 3", len(got), err)
	}

	// A stale journal whose batch is already committed is dropped, and the
	// committed copy stays single.
	if err := AtomicWriteFile(filepath.Join(repo.logBatchPendingDir(), name), rec, 0o600); err != nil {
		t.Fatalf("stage stale journal: %v", err)
	}
	if _, err := repo.Load(); err != nil {
		t.Fatalf("Load second recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo.logBatchPendingDir(), name)); !os.IsNotExist(err) {
		t.Fatalf("stale journal survived recovery: %v", err)
	}
	got, _ = repo.ReadLogs("run-1", 0, 100)
	if len(got) != 3 {
		t.Fatalf("recovery duplicated lines: %d, want 3", len(got))
	}
}

// TestFSAppendLogBatchInterruptedJournalConflict: a crashed journal for
// payload A must not be silently replaced by a retry carrying payload B.
func TestFSAppendLogBatchInterruptedJournalConflict(t *testing.T) {
	repo := New(t.TempDir())
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entriesA := wave1BatchEntries("run-1", "job-1")
	entriesB := wave1BatchEntries("run-1", "job-1")
	entriesB[0].Line = "changed"
	key := logBatchKey(id)
	rec, _ := json.Marshal(logBatchRecord{Identity: id, Digest: LogBatchPayloadDigest(id, entriesA), Entries: entriesA})
	if err := AtomicWriteFile(filepath.Join(repo.logBatchPendingDir(), key+".json"), rec, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendLogBatch(id, entriesB); !errors.Is(err, ErrLogBatchConflict) {
		t.Fatalf("payload B over an interrupted payload A = %v, want ErrLogBatchConflict", err)
	}
	// Payload A publishes its staged journal unchanged; the retry may carry a
	// later arrival time because CreatedAt is not part of the digest.
	if err := repo.AppendLogBatch(id, redeliverBatchEntries(entriesA, 7, time.Hour)); err != nil {
		t.Fatalf("payload A retry: %v", err)
	}
	got, _ := repo.ReadLogs("run-1", 0, 100)
	if len(got) != 3 || got[0].Line != "one" {
		t.Fatalf("staged payload = %+v, want A", got)
	}
}

// TestFSAppendLogBatchConcurrentIdenticalAppends proves repeated concurrent
// deliveries of one identity stay a single copy.
func TestFSAppendLogBatchConcurrentIdenticalAppends(t *testing.T) {
	repo := New(t.TempDir())
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")

	const workers = 8
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each delivery carries its own arrival time and Seq block; all
			// of them are the same logical payload.
			errs <- repo.AppendLogBatch(id, redeliverBatchEntries(entries, int64(i)*100, time.Duration(i)*time.Second))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}
	got, err := repo.ReadLogs("run-1", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("concurrent copies = %d, %v; want exactly 3", len(got), err)
	}
}

// TestFSAppendLogBatchMergesWithSingleLineStream covers the read-path merge:
// committed batch lines and single-line appends are ordered by Seq, and
// MaxLogSeq includes the batch entries.
func TestFSAppendLogBatchMergesWithSingleLineStream(t *testing.T) {
	repo := New(t.TempDir())
	batchID := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	batch := []model.LogEntry{
		{Seq: 3, RunID: "run-1", JobID: "job-1", Line: "three"},
		{Seq: 4, RunID: "run-1", JobID: "job-1", Line: "four"},
	}
	if err := repo.AppendLog(model.LogEntry{Seq: 1, RunID: "run-1", JobID: "job-1", Line: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendLogBatch(batchID, batch); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendLog(model.LogEntry{Seq: 2, RunID: "run-1", JobID: "job-1", Line: "two"}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ReadLogs("run-1", 0, 100)
	if err != nil || len(got) != 4 {
		t.Fatalf("merged logs = %d, %v; want 4", len(got), err)
	}
	for i, want := range []int64{1, 2, 3, 4} {
		if got[i].Seq != want {
			t.Fatalf("merged order[%d] = %d, want %d (%+v)", i, got[i].Seq, want, got)
		}
	}
	maxSeq, err := repo.MaxLogSeq()
	if err != nil || maxSeq != 4 {
		t.Fatalf("MaxLogSeq = %d, %v; want 4 (batch lines included)", maxSeq, err)
	}
}
