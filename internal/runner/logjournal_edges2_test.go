package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func edgeBatch(seq int64, id string) logBatch {
	return logBatch{Sequence: seq, ID: id, Lines: []logLine{{Job: "j", Step: "s", Line: "hello"}}}
}

// TestReadLogJournalWatermarkBranches drives every rejection arm of the
// watermark reader directly.
func TestReadLogJournalWatermarkBranches(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if seq, format, err := readLogJournalWatermark(missing, "job", 1); err != nil || seq != 0 || format != logJournalFormat {
		t.Fatalf("missing watermark = (%d,%d,%v)", seq, format, err)
	}
	if _, _, err := readLogJournalWatermark(dir, "job", 1); err == nil {
		t.Fatal("directory watermark was accepted")
	}
	writeWM := func(name string, wm logJournalWatermark) string {
		p := filepath.Join(dir, name)
		b, _ := json.Marshal(wm)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	notJSON := filepath.Join(dir, "notjson")
	if err := os.WriteFile(notJSON, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readLogJournalWatermark(notJSON, "job", 1); err == nil {
		t.Fatal("invalid JSON watermark accepted")
	}
	wrong := writeWM("wrong", logJournalWatermark{JobID: "other", Generation: 1, Format: logJournalFormat})
	if _, _, err := readLogJournalWatermark(wrong, "job", 1); err == nil {
		t.Fatal("foreign watermark accepted")
	}
	neg := writeWM("neg", logJournalWatermark{JobID: "job", Generation: 1, Sequence: -1, Format: logJournalFormat})
	if _, _, err := readLogJournalWatermark(neg, "job", 1); err == nil {
		t.Fatal("negative watermark accepted")
	}
	future := writeWM("future", logJournalWatermark{JobID: "job", Generation: 1, Sequence: 3, Format: logJournalFormat + 1})
	if _, _, err := readLogJournalWatermark(future, "job", 1); err == nil {
		t.Fatal("future-format watermark accepted")
	}
	ok := writeWM("ok", logJournalWatermark{JobID: "job", Generation: 1, Sequence: 3, Format: logJournalFormat})
	if seq, format, err := readLogJournalWatermark(ok, "job", 1); err != nil || seq != 3 || format != logJournalFormat {
		t.Fatalf("valid watermark = (%d,%d,%v)", seq, format, err)
	}
}

// TestOpenLogJournalGuards covers the disabled, mkdir-failure and load-failure
// arms.
func TestOpenLogJournalGuards(t *testing.T) {
	if j, err := openLogJournal("", "job", 1, nil); j != nil || err != nil {
		t.Fatalf("empty root = (%v,%v)", j, err)
	}
	if j, err := openLogJournal(t.TempDir(), "", 1, nil); j != nil || err != nil {
		t.Fatalf("empty job = (%v,%v)", j, err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogJournal(file, "job", 1, nil); err == nil {
		t.Fatal("open under a file root succeeded")
	}
	// A corrupt record under the target (job, generation) is a hard error.
	root := t.TempDir()
	badDir := filepath.Join(root, logJournalKey("job"), "gen-1")
	if err := os.MkdirAll(badDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "1-bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogJournal(root, "job", 1, nil); err == nil {
		t.Fatal("corrupt record was accepted")
	}
}

// TestAppendGuardsAndBudgets covers append's refusal arms and budget limits.
func TestAppendGuardsAndBudgets(t *testing.T) {
	root := t.TempDir()
	j := openTestJournal(t, root, "job", 1)

	if err := j.append(logBatch{}); err == nil {
		t.Fatal("identity-less batch was journaled")
	}
	if err := j.append(edgeBatch(1, "b1")); err != nil {
		t.Fatal(err)
	}
	if err := j.append(edgeBatch(1, "b1")); err == nil {
		t.Fatal("duplicate sequence was accepted")
	}
	if err := j.ack(1, "b1"); err != nil {
		t.Fatal(err)
	}
	if err := j.append(edgeBatch(1, "b1")); err == nil {
		t.Fatal("append past an acked sequence was accepted")
	}

	oldDisk := asyncJournalBytes
	asyncJournalBytes = 1
	t.Cleanup(func() { asyncJournalBytes = oldDisk })
	if err := j.append(edgeBatch(2, "b2")); !errors.Is(err, errLogJournalOverflow) {
		t.Fatalf("disk budget = %v, want errLogJournalOverflow", err)
	}
	asyncJournalBytes = oldDisk

	oldSpool := asyncSpoolBytes
	asyncSpoolBytes = 1
	t.Cleanup(func() { asyncSpoolBytes = oldSpool })
	if err := j.append(edgeBatch(3, "b3")); !errors.Is(err, errLogJournalMemoryOverflow) {
		t.Fatalf("memory budget = %v, want errLogJournalMemoryOverflow", err)
	}
	asyncSpoolBytes = oldSpool

	oldSync := journalFileSync
	journalFileSync = func(*os.File) error { return errors.New("injected record sync failure") }
	t.Cleanup(func() { journalFileSync = oldSync })
	if err := j.append(edgeBatch(4, "b4")); err == nil {
		t.Fatal("record durable-write failure was ignored")
	}
	journalFileSync = oldSync

	if err := j.append(edgeBatch(5, "b5")); err != nil {
		t.Fatal(err)
	}
	if got := j.residentBytes(); got <= 0 {
		t.Fatalf("residentBytes = %d, want > 0", got)
	}
	if got := j.maxSequence(); got < 5 {
		t.Fatalf("maxSequence = %d, want >= 5", got)
	}
	if pending := j.pendingBatches(); len(pending) == 0 {
		t.Fatal("pendingBatches is empty")
	}
	taken := j.takePendingBatches()
	if len(taken) == 0 || len(j.pendingBatches()) != 0 {
		t.Fatalf("takePendingBatches = %d, remaining %d", len(taken), len(j.pendingBatches()))
	}

	if err := j.remove(); err != nil {
		t.Fatal(err)
	}
	if err := j.append(edgeBatch(6, "b6")); err == nil {
		t.Fatal("append to a removed journal was accepted")
	}
}

// TestAckAndFlushArms covers the watermark and flush ordering arms.
func TestAckAndFlushArms(t *testing.T) {
	root := t.TempDir()
	j := openTestJournal(t, root, "job", 1)

	if err := j.ack(99, "nope"); err != nil {
		t.Fatalf("ack of an unknown sequence = %v, want nil", err)
	}
	if err := j.append(edgeBatch(1, "b1")); err != nil {
		t.Fatal(err)
	}
	if err := j.append(edgeBatch(2, "b2")); err != nil {
		t.Fatal(err)
	}
	if err := j.ack(2, "b2"); err == nil {
		t.Fatal("ack past an unconsumed sequence was accepted")
	}
	if err := j.ack(1, "wrong-id"); err == nil {
		t.Fatal("ack with a mismatched batch id was accepted")
	}

	oldEvery := journalAckFlushEvery
	journalAckFlushEvery = 1
	t.Cleanup(func() { journalAckFlushEvery = oldEvery })

	oldSync := journalFileSync
	journalFileSync = func(*os.File) error { return errors.New("injected watermark sync failure") }
	if err := j.ack(1, "b1"); err == nil {
		t.Fatal("watermark write failure was ignored")
	}
	journalFileSync = oldSync

	// The failed flush left the record unconsumed; a healthy flush now
	// reclaims it.
	if err := j.ack(1, "b1"); err != nil {
		t.Fatalf("healthy flush = %v", err)
	}
	if err := j.ack(2, "b2"); err != nil {
		t.Fatalf("second flush = %v", err)
	}
}

// TestReclaimAndRemoveArms covers the reclaim guards and removal failure.
func TestReclaimAndRemoveArms(t *testing.T) {
	root := t.TempDir()
	j := openTestJournal(t, root, "job", 1)
	if err := j.append(edgeBatch(1, "b1")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.reclaimCoveredLocked(99); err != nil {
		t.Fatalf("reclaim of an unknown sequence = %v", err)
	}
	if _, err := j.reclaimCoveredLocked(1); err == nil {
		t.Fatal("reclaim above the watermark was accepted")
	}
	j.watermark = 1
	oldRemove := journalRemove
	journalRemove = func(string) error { return errors.New("injected unlink failure") }
	if dirty, err := j.reclaimCoveredLocked(1); err != nil || dirty {
		t.Fatalf("unlink failure = (dirty %v, err %v), want (false, nil)", dirty, err)
	}
	journalRemove = oldRemove

	// remove is idempotent; a root fsync failure is surfaced.
	if err := j.remove(); err != nil {
		t.Fatal(err)
	}
	if err := j.remove(); err != nil {
		t.Fatalf("second remove = %v, want nil", err)
	}

	j2 := openTestJournal(t, t.TempDir(), "job2", 1)
	if err := j2.append(edgeBatch(1, "b1")); err != nil {
		t.Fatal(err)
	}
	oldDirSync := journalDirSync
	journalDirSync = func(string) error { return errors.New("injected root fsync failure") }
	if err := j2.remove(); err == nil {
		t.Fatal("remove root-fsync failure was ignored")
	}
	journalDirSync = oldDirSync
}

// TestDurableWriteJournalRecordArms covers the sync, rename and directory
// fsync failure arms, plus the directory-open arm of syncJournalDir.
func TestDurableWriteJournalRecordArms(t *testing.T) {
	dir := t.TempDir()

	oldSync := journalFileSync
	journalFileSync = func(*os.File) error { return errors.New("injected record sync failure") }
	if err := durableWriteJournalRecord(filepath.Join(dir, "a.json"), []byte("x")); err == nil {
		t.Fatal("record sync failure was ignored")
	}
	journalFileSync = oldSync

	// Rename onto an existing directory fails.
	if err := os.Mkdir(filepath.Join(dir, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := durableWriteJournalRecord(filepath.Join(dir, "target"), []byte("x")); err == nil {
		t.Fatal("rename onto a directory succeeded")
	}

	oldDirSync := journalDirSync
	journalDirSync = func(string) error { return errors.New("injected dir sync failure") }
	if err := durableWriteJournalRecord(filepath.Join(dir, "b.json"), []byte("x")); err == nil {
		t.Fatal("record dir-sync failure was ignored")
	}
	journalDirSync = oldDirSync

	if err := syncJournalDir(filepath.Join(dir, "missing-dir")); err == nil {
		t.Fatal("syncJournalDir on a missing directory succeeded")
	}
}
