package runner

// Cleanup-debt and terminal-removal state-machine regressions for the durable
// log journal: a failed unlink must never erase the journal's knowledge of a
// still-charged physical file, and a failed terminal removal must stay
// retryable instead of reporting success forever.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// journalTestBatch is one identified batch for direct journal manipulation.
func journalTestBatch(sequence int64, id, line string) logBatch {
	return logBatch{Sequence: sequence, ID: id, Lines: []logLine{{Job: "build", Step: "step", Line: line}}}
}

// journalTestAck appends and acks one batch, leaving the reclaim to the
// caller's flush.
func journalTestAck(t *testing.T, j *logJournal, sequence int64, id string) {
	t.Helper()
	if err := j.append(journalTestBatch(sequence, id, "line")); err != nil {
		t.Fatalf("append %d: %v", sequence, err)
	}
	if err := j.ack(sequence, id); err != nil {
		t.Fatalf("ack %d: %v", sequence, err)
	}
}

// TestLogJournalAckUnlinkFailureRemainsRetryable pins the cleanup debt: a
// failed unlink after an ack keeps the (path, size) entry so a later flush
// retries it, and the retry releases the charge exactly once.
func TestLogJournalAckUnlinkFailureRemainsRetryable(t *testing.T) {
	stateDir := t.TempDir()
	j := openTestJournal(t, stateDir, "job-debt", 1)
	oldRemove := journalRemove
	journalRemove = func(string) error { return errors.New("injected unlink failure") }
	t.Cleanup(func() { journalRemove = oldRemove })

	journalTestAck(t, j, 1, "batch-1")
	if err := j.flushAcks(); err != nil {
		t.Fatalf("flush with a failing unlink must be cleanup lag, got %v", err)
	}
	j.mu.Lock()
	debt, tracked := j.pendingCleanup[1]
	charged := j.bytes
	seqs := len(j.paths)
	j.mu.Unlock()
	if !tracked || debt.path == "" || debt.size <= 0 {
		t.Fatalf("failed unlink did not retain cleanup debt: %+v (tracked=%t)", debt, tracked)
	}
	if charged != debt.size {
		t.Fatalf("disk bytes charged = %d, want the orphaned record size %d", charged, debt.size)
	}
	if seqs != 0 {
		t.Fatal("acked record still occupies the replay map")
	}
	if _, err := os.Stat(debt.path); err != nil {
		t.Fatalf("orphaned record vanished: %v", err)
	}

	// Retry (the next flush) reclaims it and releases the charge.
	journalRemove = oldRemove
	if err := j.flushAcks(); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	j.mu.Lock()
	left := len(j.pendingCleanup)
	chargedAfter := j.bytes
	j.mu.Unlock()
	if left != 0 || chargedAfter != 0 {
		t.Fatalf("after retry: debt=%d bytes=%d, want 0/0", left, chargedAfter)
	}
	if _, err := os.Stat(debt.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned record still present after retry: %v", err)
	}
}

// TestLogJournalAckUnlinkFailureKeepsDiskBytesCharged proves the disk bound
// stays truthful: while an undeletable acked record exists, the budget
// rejects a batch that would exceed asyncJournalBytes.
func TestLogJournalAckUnlinkFailureKeepsDiskBytesCharged(t *testing.T) {
	stateDir := t.TempDir()
	j := openTestJournal(t, stateDir, "job-bound", 1)
	oldRemove := journalRemove
	journalRemove = func(string) error { return errors.New("injected unlink failure") }
	t.Cleanup(func() { journalRemove = oldRemove })

	journalTestAck(t, j, 1, "batch-1")
	if err := j.flushAcks(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	j.mu.Lock()
	charged := j.bytes
	j.mu.Unlock()
	if charged <= 0 {
		t.Fatal("failed unlink released the disk charge")
	}
	oldBudget := asyncJournalBytes
	asyncJournalBytes = charged
	t.Cleanup(func() { asyncJournalBytes = oldBudget })
	if err := j.append(journalTestBatch(2, "batch-2", "more")); !errors.Is(err, errLogJournalOverflow) {
		t.Fatalf("append with an undeletable orphan = %v, want errLogJournalOverflow", err)
	}

	// Once the unlink succeeds, the charge is released and the append fits.
	journalRemove = oldRemove
	if err := j.flushAcks(); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	if err := j.append(journalTestBatch(2, "batch-2", "more")); err != nil {
		t.Fatalf("append after reclaim: %v", err)
	}
}

// TestLogJournalRestartAccountsCoveredRecordWhoseDeleteStillFails pins the
// startup path: a watermark-covered record whose unlink fails is NOT silently
// ignored; its physical bytes are charged as cleanup debt (so the bound is
// truthful after a crash) without ever scheduling it for replay.
func TestLogJournalRestartAccountsCoveredRecordWhoseDeleteStillFails(t *testing.T) {
	stateDir := t.TempDir()
	jA := openTestJournal(t, stateDir, "job-restart", 1)
	oldRemove := journalRemove
	journalRemove = func(string) error { return errors.New("injected unlink failure") }
	t.Cleanup(func() { journalRemove = oldRemove })
	journalTestAck(t, jA, 1, "batch-1")
	if err := jA.flushAcks(); err != nil { // watermark durable, file stays
		t.Fatalf("flush A: %v", err)
	}
	path := filepath.Join(jA.dir, journalRecordName(1, "batch-1"))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture record missing: %v", err)
	}

	jB := openTestJournal(t, stateDir, "job-restart", 1)
	if got := jB.pendingBatches(); len(got) != 0 {
		t.Fatalf("covered record scheduled for replay: %+v", got)
	}
	jB.mu.Lock()
	debt, tracked := jB.pendingCleanup[1]
	charged := jB.bytes
	jB.mu.Unlock()
	if !tracked || charged != debt.size || charged <= 0 {
		t.Fatalf("restart did not charge the undeletable covered record: tracked=%t bytes=%d debt=%+v", tracked, charged, debt)
	}

	// The next flush retries and clears the debt.
	journalRemove = oldRemove
	if err := jB.flushAcks(); err != nil {
		t.Fatalf("restart retry flush: %v", err)
	}
	jB.mu.Lock()
	left, chargedAfter := len(jB.pendingCleanup), jB.bytes
	jB.mu.Unlock()
	if left != 0 || chargedAfter != 0 {
		t.Fatalf("after restart retry: debt=%d bytes=%d, want 0/0", left, chargedAfter)
	}
}

// TestLogJournalRestartCannotBypassDiskBudgetWithUndeletableAckedFiles pins
// the bound across many orphans: every undeletable covered record counts, so
// the reopened journal cannot admit new batches beyond asyncJournalBytes.
func TestLogJournalRestartCannotBypassDiskBudgetWithUndeletableAckedFiles(t *testing.T) {
	stateDir := t.TempDir()
	jA := openTestJournal(t, stateDir, "job-many", 1)
	oldRemove := journalRemove
	journalRemove = func(string) error { return errors.New("injected unlink failure") }
	t.Cleanup(func() { journalRemove = oldRemove })
	for i := int64(1); i <= 3; i++ {
		journalTestAck(t, jA, i, "batch-"+string(rune('a'+i-1)))
	}
	if err := jA.flushAcks(); err != nil {
		t.Fatalf("flush A: %v", err)
	}
	jA.mu.Lock()
	orphanBytes := jA.bytes
	jA.mu.Unlock()
	if orphanBytes <= 0 {
		t.Fatal("fixture did not keep any orphaned bytes")
	}

	jB := openTestJournal(t, stateDir, "job-many", 1)
	jB.mu.Lock()
	charged := jB.bytes
	debtCount := len(jB.pendingCleanup)
	jB.mu.Unlock()
	if debtCount != 3 || charged != orphanBytes {
		t.Fatalf("restart accounting = %d debts / %d bytes, want 3 / %d", debtCount, charged, orphanBytes)
	}
	oldBudget := asyncJournalBytes
	asyncJournalBytes = charged
	t.Cleanup(func() { asyncJournalBytes = oldBudget })
	if err := jB.append(journalTestBatch(4, "batch-d", "more")); !errors.Is(err, errLogJournalOverflow) {
		t.Fatalf("append beyond the orphan-charged budget = %v, want errLogJournalOverflow", err)
	}
}

// TestLogJournalRemoveFailureIsRetryable pins the terminal state machine: a
// failed RemoveAll does not mark the journal removed, leaves a marker, and a
// retry finishes the cleanup.
func TestLogJournalRemoveFailureIsRetryable(t *testing.T) {
	stateDir := t.TempDir()
	j := openTestJournal(t, stateDir, "job-remove", 1)
	journalTestAck(t, j, 1, "batch-1")

	oldRemoveAll := journalRemoveAll
	journalRemoveAll = func(string) error { return errors.New("injected RemoveAll failure") }
	t.Cleanup(func() { journalRemoveAll = oldRemoveAll })
	if err := j.remove(); err == nil {
		t.Fatal("remove with a failing RemoveAll = nil")
	}
	j.mu.Lock()
	removed, closed := j.removed, j.closed
	j.mu.Unlock()
	if removed {
		t.Fatal("failed terminal remove marked the journal removed")
	}
	if !closed {
		t.Fatal("failed terminal remove left the journal logically open")
	}
	if _, err := os.Stat(j.dir); err != nil {
		t.Fatalf("failed terminal remove lost the directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(j.dir, terminalJournalMarker)); err != nil {
		t.Fatalf("failed terminal remove left no cleanup marker: %v", err)
	}

	journalRemoveAll = oldRemoveAll
	if err := j.remove(); err != nil {
		t.Fatalf("retry remove: %v", err)
	}
	j.mu.Lock()
	removed = j.removed
	j.mu.Unlock()
	if !removed {
		t.Fatal("successful retry did not mark the journal removed")
	}
	if _, err := os.Stat(j.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal directory still present after retry: %v", err)
	}
}

// TestLogJournalSuccessfulRetryMarksRemoved pins the success path: a direct
// remove marks removed and leaves nothing behind.
func TestLogJournalSuccessfulRetryMarksRemoved(t *testing.T) {
	stateDir := t.TempDir()
	j := openTestJournal(t, stateDir, "job-remove-ok", 1)
	journalTestAck(t, j, 1, "batch-1")
	if err := j.remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	j.mu.Lock()
	removed := j.removed
	j.mu.Unlock()
	if !removed {
		t.Fatal("successful remove did not mark the journal removed")
	}
	if err := j.remove(); err != nil {
		t.Fatalf("replayed remove: %v", err)
	}
	if _, err := os.Stat(j.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal directory still present: %v", err)
	}
}

// TestLogJournalRemoveDirSyncFailureHasExplicitState pins the phase-aware
// terminal state: when RemoveAll succeeded but the parent fsync failed, the
// directory is physically absent yet removed stays false (durability
// uncertain), and a retry that syncs successfully marks removed.
func TestLogJournalRemoveDirSyncFailureHasExplicitState(t *testing.T) {
	stateDir := t.TempDir()
	j := openTestJournal(t, stateDir, "job-sync", 1)
	journalTestAck(t, j, 1, "batch-1")

	oldSync := journalDirSync
	journalDirSync = func(string) error { return errors.New("injected dir sync failure") }
	t.Cleanup(func() { journalDirSync = oldSync })
	err := j.remove()
	if err == nil {
		t.Fatal("remove with a failing directory fsync = nil")
	}
	j.mu.Lock()
	removed := j.removed
	j.mu.Unlock()
	if removed {
		t.Fatal("unsynced removal marked the journal removed")
	}
	if _, serr := os.Stat(j.dir); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("directory should be physically absent after RemoveAll: %v", serr)
	}

	journalDirSync = oldSync
	if err := j.remove(); err != nil {
		t.Fatalf("retry remove after sync recovers: %v", err)
	}
	j.mu.Lock()
	removed = j.removed
	j.mu.Unlock()
	if !removed {
		t.Fatal("retry did not mark the journal removed")
	}
}

// TestLogJournalTerminalCleanupFailureDoesNotLeakAcrossJobs pins the sweep:
// a terminal cleanup that failed leaves a marked directory, and opening the
// next job's journal reclaims it instead of leaking it forever.
func TestLogJournalTerminalCleanupFailureDoesNotLeakAcrossJobs(t *testing.T) {
	stateDir := t.TempDir()
	jA := openTestJournal(t, stateDir, "job-a", 1)
	journalTestAck(t, jA, 1, "batch-1")
	dirA := jA.dir

	oldRemoveAll := journalRemoveAll
	journalRemoveAll = func(path string) error {
		if path == dirA {
			return errors.New("injected RemoveAll failure")
		}
		return oldRemoveAll(path)
	}
	if err := jA.remove(); err == nil {
		t.Fatal("remove A with an injected failure = nil")
	}
	if _, err := os.Stat(dirA); err != nil {
		t.Fatalf("failed cleanup lost the directory: %v", err)
	}

	// The next job's open sweeps the marked directory (with removal healthy
	// again, as it would be after the transient condition clears).
	journalRemoveAll = oldRemoveAll
	_ = openTestJournal(t, stateDir, "job-b", 1)
	if _, err := os.Stat(dirA); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marked terminal journal leaked across jobs: %v", err)
	}
}
