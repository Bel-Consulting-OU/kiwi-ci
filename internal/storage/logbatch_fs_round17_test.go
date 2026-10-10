package storage

// Coverage round: filesystem log-batch corrupt-state and durability arms. The
// tests build real on-disk journals/committed records and assert the
// fail-closed errors; no sleeps and no mocks of the filesystem.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func itWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func itRecord(runID, jobID, batchID, digest string, entries []model.LogEntry) logBatchRecord {
	return logBatchRecord{
		RunID:    runID,
		Identity: LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: batchID},
		Digest:   digest,
		Entries:  entries,
	}
}

// TestReadLogBatchRecordCorruptStates covers every decode refusal: unreadable
// file, malformed JSON, incomplete record, unsafe run id and a run id that
// disagrees with the entries.
func TestReadLogBatchRecordCorruptStates(t *testing.T) {
	dir := t.TempDir()

	unreadable := filepath.Join(dir, "unreadable.json")
	if err := os.WriteFile(unreadable, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readLogBatchRecord(unreadable); err == nil {
		t.Fatal("unreadable record was accepted")
	}

	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readLogBatchRecord(corrupt); err == nil || !strings.Contains(err.Error(), "decode log batch record") {
		t.Fatalf("corrupt record = %v, want a decode error", err)
	}

	incomplete := filepath.Join(dir, "incomplete.json")
	itWriteJSON(t, incomplete, logBatchRecord{Identity: LogBatchIdentity{JobID: "j", BatchID: "b"}})
	if _, _, err := readLogBatchRecord(incomplete); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete record = %v, want an incomplete error", err)
	}

	unsafe := filepath.Join(dir, "unsafe.json")
	itWriteJSON(t, unsafe, itRecord("../escape", "j", "b", "d", nil))
	if _, _, err := readLogBatchRecord(unsafe); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe record = %v, want an unsafe run id error", err)
	}

	mismatch := filepath.Join(dir, "mismatch.json")
	itWriteJSON(t, mismatch, itRecord("run-1", "j", "b", "d", []model.LogEntry{{RunID: "run-2"}}))
	if _, _, err := readLogBatchRecord(mismatch); err == nil || !strings.Contains(err.Error(), "does not match its entries") {
		t.Fatalf("mismatched record = %v, want a run id mismatch", err)
	}

	// A valid record still decodes: the guard is not over-broad.
	valid := filepath.Join(dir, "valid.json")
	itWriteJSON(t, valid, itRecord("run-1", "j", "b", "d", []model.LogEntry{{RunID: "run-1", Seq: 4}}))
	if rec, ok, err := readLogBatchRecord(valid); err != nil || !ok || rec.RunID != "run-1" {
		t.Fatalf("valid record = (%+v, %v, %v)", rec, ok, err)
	}
}

// TestLogBatchRunIDEmpty covers the empty-batch refusal on the shared helper.
func TestLogBatchRunIDEmpty(t *testing.T) {
	if _, err := logBatchRunID(nil); err == nil {
		t.Fatal("empty batch was accepted")
	}
	if _, err := recordRunID(logBatchRecord{RunID: "..", Digest: "d", Identity: LogBatchIdentity{JobID: "j", BatchID: "b"}}); err == nil {
		t.Fatal("unsafe persisted run id was accepted")
	}
}

// TestMigrateLegacyLogBatchesArms covers the legacy flat-layout migration's
// failure returns: an obstructed run directory, a rename refusal and a
// directory-fsync refusal. The watermark is raised before the first move, so
// none of these may be silently ignored.
func TestMigrateLegacyLogBatchesArms(t *testing.T) {
	t.Run("run directory obstructed by a file", func(t *testing.T) {
		repo := New(t.TempDir())
		root := repo.logBatchCommittedDir()
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		itWriteJSON(t, filepath.Join(root, "legacy.json"), itRecord("run-1", "j", "b", "d", []model.LogEntry{{RunID: "run-1", Seq: 1}}))
		if err := os.WriteFile(filepath.Join(root, "run-1"), []byte("blocker"), 0o600); err != nil {
			t.Fatal(err)
		}
		repo.mu.Lock()
		err := repo.migrateLegacyLogBatchesLocked()
		repo.mu.Unlock()
		if err == nil {
			t.Fatal("migration over an obstructed run directory succeeded")
		}
	})

	t.Run("corrupt legacy record", func(t *testing.T) {
		repo := New(t.TempDir())
		root := repo.logBatchCommittedDir()
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "legacy.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		repo.mu.Lock()
		err := repo.migrateLegacyLogBatchesLocked()
		repo.mu.Unlock()
		if err == nil {
			t.Fatal("migration over a corrupt legacy record succeeded")
		}
	})

	t.Run("parent fsync refused after the move", func(t *testing.T) {
		repo := New(t.TempDir())
		root := repo.logBatchCommittedDir()
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		itWriteJSON(t, filepath.Join(root, "legacy.json"), itRecord("run-1", "j", "b", "d", []model.LogEntry{{RunID: "run-1", Seq: 1}}))
		restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(dir string) error {
			if dir == root {
				return errors.New("legacy fsync refused")
			}
			return fsutil.RealSyncDir(dir)
		}})
		defer restore()
		repo.mu.Lock()
		err := repo.migrateLegacyLogBatchesLocked()
		repo.mu.Unlock()
		if err == nil {
			t.Fatal("migration with a refused parent fsync succeeded")
		}
	})
}

// TestRecoverLogBatchesArms covers interrupted-append recovery refusals: an
// unreadable pending directory, a corrupt pending journal, an unremovable
// stale journal and a committed path that cannot be stat'd.
func TestRecoverLogBatchesArms(t *testing.T) {
	t.Run("pending path is a file", func(t *testing.T) {
		repo := New(t.TempDir())
		pending := repo.logBatchPendingDir()
		if err := os.MkdirAll(filepath.Dir(pending), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pending, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "j", BatchID: "b"}, []model.LogEntry{{RunID: "run-1", Seq: 1}}); err == nil {
			t.Fatal("append over an unreadable pending directory succeeded")
		}
	})

	t.Run("corrupt pending journal", func(t *testing.T) {
		repo := New(t.TempDir())
		pending := repo.logBatchPendingDir()
		if err := os.MkdirAll(pending, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pending, "deadbeef.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "j", BatchID: "b"}, []model.LogEntry{{RunID: "run-1", Seq: 1}}); err == nil {
			t.Fatal("append over a corrupt pending journal succeeded")
		}
	})

	t.Run("stale journal cannot be removed", func(t *testing.T) {
		repo := New(t.TempDir())
		pending := repo.logBatchPendingDir()
		committed := repo.logBatchCommittedDir()
		key := logBatchKey(LogBatchIdentity{JobID: "j", Generation: 1, BatchID: "b"})
		rec := itRecord("run-1", "j", "b", "d", []model.LogEntry{{RunID: "run-1", Seq: 1}})
		if err := os.MkdirAll(pending, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(committed, "run-1"), 0o700); err != nil {
			t.Fatal(err)
		}
		itWriteJSON(t, filepath.Join(pending, key+".json"), rec)
		itWriteJSON(t, filepath.Join(committed, "run-1", key+".json"), rec)
		if os.Geteuid() == 0 {
			t.Skip("root ignores a read-only directory")
		}
		if err := os.Chmod(pending, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(pending, 0o755) })
		if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "j", Generation: 1, BatchID: "b"}, []model.LogEntry{{RunID: "run-1", Seq: 1}}); err == nil {
			t.Fatal("append with an unremovable stale journal succeeded")
		}
	})

	t.Run("committed path is obstructed", func(t *testing.T) {
		repo := New(t.TempDir())
		pending := repo.logBatchPendingDir()
		committed := repo.logBatchCommittedDir()
		key := logBatchKey(LogBatchIdentity{JobID: "j", Generation: 1, BatchID: "b"})
		rec := itRecord("run-1", "j", "b", "d", []model.LogEntry{{RunID: "run-1", Seq: 1}})
		if err := os.MkdirAll(pending, 0o700); err != nil {
			t.Fatal(err)
		}
		itWriteJSON(t, filepath.Join(pending, key+".json"), rec)
		if err := os.MkdirAll(committed, 0o700); err != nil {
			t.Fatal(err)
		}
		// A FILE where the run directory belongs makes Stat fail with ENOTDIR.
		if err := os.WriteFile(filepath.Join(committed, "run-1"), []byte("blocker"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "j", Generation: 1, BatchID: "b"}, []model.LogEntry{{RunID: "run-1", Seq: 1}}); err == nil {
			t.Fatal("append with an obstructed committed path succeeded")
		}
	})
}

// TestCommittedLogBatchEntriesArms covers the per-run reader's refusals: an
// unsafe run id, an obstructed run directory and a corrupt committed record.
func TestCommittedLogBatchEntriesArms(t *testing.T) {
	t.Run("unsafe run id", func(t *testing.T) {
		repo := New(t.TempDir())
		if _, err := repo.committedLogBatchEntriesLocked("../escape", 0); err == nil {
			t.Fatal("reader accepted an unsafe run id")
		}
	})

	t.Run("run directory is a file", func(t *testing.T) {
		repo := New(t.TempDir())
		dir := filepath.Join(repo.logBatchCommittedDir(), "run-1")
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.committedLogBatchEntriesLocked("run-1", 0); err == nil {
			t.Fatal("reader over a file-shaped run directory succeeded")
		}
	})

	t.Run("corrupt committed record", func(t *testing.T) {
		repo := New(t.TempDir())
		dir := filepath.Join(repo.logBatchCommittedDir(), "run-1")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.committedLogBatchEntriesLocked("run-1", 0); err == nil {
			t.Fatal("reader over a corrupt committed record succeeded")
		}
	})
}

// TestAppendLogBatchFSArms covers the append's corrupt-committed read and its
// staged-journal write/publish refusals.
func TestAppendLogBatchFSArms(t *testing.T) {
	identity := LogBatchIdentity{JobID: "j", Generation: 1, BatchID: "b"}
	entries := []model.LogEntry{{RunID: "run-1", Seq: 1, Line: "hello"}}

	t.Run("corrupt committed record at the identity", func(t *testing.T) {
		repo := New(t.TempDir())
		key := logBatchKey(identity)
		dir := filepath.Join(repo.logBatchCommittedDir(), "run-1")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, key+".json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := repo.AppendLogBatch(identity, entries); err == nil {
			t.Fatal("append over a corrupt committed record succeeded")
		}
	})

	t.Run("pending journal write refused", func(t *testing.T) {
		repo := New(t.TempDir())
		pending := repo.logBatchPendingDir()
		restore := fsutil.SetHooks(fsutil.Hooks{Rename: func(oldpath, newpath string) error {
			if strings.HasPrefix(newpath, pending) {
				return errors.New("pending journal rename refused")
			}
			return os.Rename(oldpath, newpath)
		}})
		defer restore()
		if err := repo.AppendLogBatch(identity, entries); err == nil {
			t.Fatal("append with a refused pending journal write succeeded")
		}
	})

	t.Run("publish rename refused", func(t *testing.T) {
		repo := New(t.TempDir())
		dir := filepath.Join(repo.logBatchCommittedDir(), "run-1")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() == 0 {
			t.Skip("root ignores a read-only directory")
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		if err := repo.AppendLogBatch(identity, entries); err == nil {
			t.Fatal("append with a refused publish rename succeeded")
		}
	})

	t.Run("read logs over a corrupt pending journal", func(t *testing.T) {
		repo := New(t.TempDir())
		pending := repo.logBatchPendingDir()
		if err := os.MkdirAll(pending, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pending, "deadbeef.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.ReadLogs("run-1", 0, 10); err == nil {
			t.Fatal("read over a corrupt pending journal succeeded")
		}
	})
}

// TestRepositoryLoadCorruptStateArms covers Load's fail-closed state arms: a
// corrupt log-batch checkpoint, a corrupt execution-event journal and an
// unreadable state.json.
func TestRepositoryLoadCorruptStateArms(t *testing.T) {
	t.Run("corrupt log batch checkpoint", func(t *testing.T) {
		dir := t.TempDir()
		repo := New(dir)
		if err := os.MkdirAll(filepath.Dir(repo.logBatchMaxSeqPath()), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(repo.logBatchMaxSeqPath(), []byte("not-a-number"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Load(); err == nil {
			t.Fatal("load over a corrupt log batch checkpoint succeeded")
		}
	})

	t.Run("corrupt execution event journal", func(t *testing.T) {
		dir := t.TempDir()
		repo := New(dir)
		if err := os.WriteFile(filepath.Join(dir, executionEventsFile), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Load(); err == nil {
			t.Fatal("load over a corrupt execution event journal succeeded")
		}
	})

	t.Run("unreadable state file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file permissions")
		}
		dir := t.TempDir()
		repo := New(dir)
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}"), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Load(); err == nil {
			t.Fatal("load over an unreadable state file succeeded")
		}
	})
}
