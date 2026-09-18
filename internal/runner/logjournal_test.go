package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// openTestJournal opens the durable journal for a test.
func openTestJournal(t *testing.T, root, jobID string, generation int64) *logJournal {
	t.Helper()
	j, err := openLogJournal(root, jobID, generation, nil)
	if err != nil {
		t.Fatalf("openLogJournal(%s, %d): %v", jobID, generation, err)
	}
	return j
}

// batchLineStrings renders a batch's ordered lines as "step: line".
func batchLineStrings(batch logBatch) []string {
	out := make([]string, 0, len(batch.Lines))
	for _, l := range batch.Lines {
		out = append(out, l.Step+": "+l.Line)
	}
	return out
}

// orderedAttempts returns the first observed attempt of every distinct batch
// id, ordered by sequence.
func orderedAttempts(attempts []batchDeliveryAttempt) []batchDeliveryAttempt {
	first := map[string]batchDeliveryAttempt{}
	for _, a := range attempts {
		if prev, ok := first[a.BatchID]; !ok || a.Sequence < prev.Sequence {
			first[a.BatchID] = a
		}
	}
	out := make([]batchDeliveryAttempt, 0, len(first))
	for _, a := range first {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

// T1: the batch is journaled and the process dies before any POST reaches
// the control plane; a fresh sink for the same (job, generation) replays the
// identical batch id and sequence, and the server holds exactly one copy.
func TestLogSpoolJournalCrashBeforeSendReplays(t *testing.T) {
	stateDir := t.TempDir()
	rsrv := newBatchReceiptServer()
	ts := httptest.NewServer(rsrv)
	defer ts.Close()

	// Process A: the delivery callback never reaches the stub (simulating a
	// crash in the window between the durable journal record and the first
	// POST attempt).
	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, func(context.Context, logBatch) error {
		return PermanentDeliveryError(errors.New("control plane unreachable"))
	}, jA)
	sinkA.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "the batch to be journaled", func() bool {
		return len(jA.pendingBatches()) == 1
	})
	outA := sinkA.Finish(2 * time.Second)
	if outA.Err == nil {
		t.Fatalf("process A reported a clean outcome despite the failed delivery: %+v", outA)
	}
	persisted := jA.pendingBatches()
	if len(persisted) != 1 || persisted[0].ID == "" || persisted[0].Sequence <= 0 {
		t.Fatalf("journal records = %+v, want exactly one identified batch", persisted)
	}
	if attempts, store := rsrv.snapshot(); len(attempts) != 0 || len(store) != 0 {
		t.Fatalf("process A reached the control plane before the crash: attempts=%v store=%v", attempts, store)
	}

	// Process B: fresh sink, same journal, same lease generation.
	r := testRunnerFor(t, ts, Config{})
	jB := openTestJournal(t, stateDir, "job-1", 3)
	sinkB := newJournaledAsyncLogSink(nil, r.logBatchPost(basicTask(payloadPipeline), &secrets.Masker{}), jB)
	waitUntil(t, 10*time.Second, "the replayed batch to be committed", func() bool {
		_, store := rsrv.snapshot()
		return len(store) == 1
	})
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("replay outcome = %+v, want a clean stop", outB)
	}

	attempts, store := rsrv.snapshot()
	if len(store) != 1 {
		t.Fatalf("server store holds %d batches, want exactly 1", len(store))
	}
	for id, lines := range store {
		if id != persisted[0].ID {
			t.Fatalf("committed batch id = %q, want the journaled %q", id, persisted[0].ID)
		}
		if len(lines) != 1 || lines[0] != "step: line-1" {
			t.Fatalf("committed lines = %v, want exactly one copy of line-1", lines)
		}
	}
	if len(attempts) == 0 {
		t.Fatal("no replay attempt was recorded")
	}
	for _, a := range attempts {
		if a.ID != persisted[0].ID || a.Sequence != persisted[0].Sequence {
			t.Fatalf("replay attempt carried (%s, %d), want the original (%s, %d)", a.ID, a.Sequence, persisted[0].ID, persisted[0].Sequence)
		}
	}
}

// T2: the server committed the batch but the acknowledgement was dropped and
// the process died before the journal record could be acked. The restart
// replays the same identity, the receipt dedupes it, and exactly one copy
// exists. Cancellation must also form no new batch.
func TestLogSpoolJournalCrashAfterSendBeforeAckDedupes(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane()
	cp.dropFirst = true
	cp.parking = true
	cp.park = make(chan struct{})
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)

	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jA)
	sinkA.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "the committed first delivery with its response dropped", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) == 1
	})
	waitUntil(t, 10*time.Second, "the parked retry", func() bool {
		attempts, _ := cp.snapshot()
		return len(attempts) >= 2
	})
	// A line drained after the committed batch: cancellation must not form
	// a new batch from it, and the committed record must survive unacked.
	sinkA.WriteLine("build", "step", "line-2")
	outA := sinkA.Finish(50 * time.Millisecond)
	if outA.Err == nil && outA.Remaining == 0 && outA.Stopped {
		t.Fatalf("parked sink reported a clean stop: %+v", outA)
	}
	persisted := jA.pendingBatches()
	if len(persisted) != 1 {
		t.Fatalf("journal records after the crash = %d, want exactly the one committed batch", len(persisted))
	}
	if attempts, store := cp.snapshot(); len(attempts) != 2 || countCommittedBatches(store) != 1 {
		t.Fatalf("cancellation formed a new batch: attempts=%v store=%v", attempts, store)
	}
	cp.startRestartPhase()

	// Restart: replay the identical identity; the receipt answers 204
	// without a second commit.
	jB := openTestJournal(t, stateDir, "job-1", 3)
	sinkB := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jB)
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}
	attempts, store := cp.snapshot()
	if countCommittedBatches(store) != 1 {
		t.Fatalf("committed batches after replay = %d, want exactly 1", countCommittedBatches(store))
	}
	if got := flattenCommittedLines(store); strings.Join(got, "|") != "step: line-1" {
		t.Fatalf("committed lines = %v, want exactly one copy of line-1", got)
	}
	for _, a := range attempts {
		if a.BatchID != persisted[0].ID || a.Sequence != persisted[0].Sequence {
			t.Fatalf("attempt carried (%s, %d), want the original (%s, %d)", a.BatchID, a.Sequence, persisted[0].ID, persisted[0].Sequence)
		}
	}
}

// T3: the server ack is durable (the ack watermark is written) but the
// record cleanup was skipped by a crash. The surviving record is recognized
// as consumed on restart — it is never replayed, so the server still holds
// strictly one copy — and the new batch continues after the persisted
// sequence (no regression).
func TestLogSpoolJournalCrashAfterAckBeforeCleanup(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane() // first delivery commits and answers 204
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)

	// Inject the skipped cleanup: the ack watermark is durable, the unlink
	// fails.
	oldRemove := journalRemove
	journalRemove = func(string) error { return errBoom() }
	t.Cleanup(func() { journalRemove = oldRemove })

	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jA)
	sinkA.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "the committed line", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) == 1
	})
	outA := sinkA.Finish(10 * time.Second)
	if outA.Err != nil {
		t.Fatalf("a durable ack with a skipped cleanup must not fail the job: %+v", outA)
	}
	journalRemove = oldRemove
	ackedSeq := jA.maxSequence()
	if ackedSeq <= 0 {
		t.Fatalf("acked sequence = %d, want a positive persisted maximum", ackedSeq)
	}
	// The skipped unlink left the record file on disk.
	genDir := jA.dir
	records, err := filepath.Glob(filepath.Join(genDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record files after the skipped cleanup = %v, want exactly 1", records)
	}
	wmBytes, err := os.ReadFile(filepath.Join(genDir, "ack-watermark"))
	if err != nil {
		t.Fatalf("ack watermark missing: %v", err)
	}
	var wm logJournalWatermark
	if err := json.Unmarshal(wmBytes, &wm); err != nil || wm.Sequence != ackedSeq {
		t.Fatalf("ack watermark = %s (%v), want sequence %d", wmBytes, err, ackedSeq)
	}

	// Restart: the watermark covers the surviving record, so it is reclaimed
	// without a replay, and the new line continues the sequence.
	jB := openTestJournal(t, stateDir, "job-1", 3)
	if got := jB.pendingBatches(); len(got) != 0 {
		t.Fatalf("acked record was scheduled for replay: %+v", got)
	}
	if got := jB.maxSequence(); got != ackedSeq {
		t.Fatalf("persisted maximum after the skipped cleanup = %d, want %d", got, ackedSeq)
	}
	if got, _ := filepath.Glob(filepath.Join(genDir, "*.json")); len(got) != 0 {
		t.Fatalf("consumed record was not reclaimed on open: %v", got)
	}
	sinkB := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jB)
	sinkB.WriteLine("build", "step", "line-2")
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}

	attempts, store := cp.snapshot()
	if countCommittedBatches(store) != 2 {
		t.Fatalf("committed batches = %d, want 2", countCommittedBatches(store))
	}
	if got := flattenCommittedLines(store); strings.Join(got, "|") != "step: line-1|step: line-2" {
		t.Fatalf("committed lines = %v, want exactly one copy of each line", got)
	}
	ordered := orderedAttempts(attempts)
	if len(ordered) != 2 {
		t.Fatalf("distinct batches = %d, want 2 (no replay of the acked record): %v", len(ordered), ordered)
	}
	if ordered[0].Sequence != ackedSeq {
		t.Fatalf("acked batch was replayed at sequence %d after the watermark %d", ordered[0].Sequence, ackedSeq)
	}
	if attemptsForID := countAttemptsFor(attempts, ordered[0].BatchID); attemptsForID != 1 {
		t.Fatalf("acked batch %s was sent %d time(s), want 1", ordered[0].BatchID, attemptsForID)
	}
	if ordered[1].Sequence != ackedSeq+1 {
		t.Fatalf("new batch sequence = %d, want %d (no regression)", ordered[1].Sequence, ackedSeq+1)
	}
	if ordered[1].BatchID == ordered[0].BatchID {
		t.Fatal("new batch reused the acked batch id")
	}
}

// countAttemptsFor counts the delivery attempts of one batch id.
func countAttemptsFor(attempts []batchDeliveryAttempt, batchID string) int {
	n := 0
	for _, a := range attempts {
		if a.BatchID == batchID {
			n++
		}
	}
	return n
}

// The durable ack watermark preserves the sequence maximum across a CLEAN
// ack + cleanup: a fresh same-generation sink must continue after it, so a
// new batch can never reuse an already-acked batch id (which the server
// would silently answer as a duplicate).
func TestLogSpoolNoSequenceRegressionAfterCleanAck(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)

	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jA)
	sinkA.WriteLine("build", "step", "line-1")
	outA := sinkA.Finish(10 * time.Second)
	if outA.Err != nil || outA.Dropped != 0 || outA.Remaining != 0 || !outA.Stopped {
		t.Fatalf("first delivery outcome = %+v, want a clean stop", outA)
	}
	ackedSeq := jA.maxSequence()
	if ackedSeq <= 0 {
		t.Fatalf("acked sequence = %d, want a positive persisted maximum", ackedSeq)
	}
	if got := jA.pendingBatches(); len(got) != 0 {
		t.Fatalf("acked batch still pending: %+v", got)
	}

	jB := openTestJournal(t, stateDir, "job-1", 3)
	if got := jB.maxSequence(); got != ackedSeq {
		t.Fatalf("persisted maximum after the clean ack = %d, want %d", got, ackedSeq)
	}
	sinkB := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jB)
	// The SAME line content: the new batch must still get a new identity,
	// never the acked batch's id.
	sinkB.WriteLine("build", "step", "line-1")
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}

	attempts, store := cp.snapshot()
	if countCommittedBatches(store) != 2 {
		t.Fatalf("committed batches = %d, want 2 (the new batch must not be silently deduped)", countCommittedBatches(store))
	}
	ordered := orderedAttempts(attempts)
	if len(ordered) != 2 {
		t.Fatalf("distinct batches = %d, want 2: %v", len(ordered), ordered)
	}
	if ordered[1].Sequence != ackedSeq+1 {
		t.Fatalf("new batch sequence = %d, want %d (sequence regressed past the durable watermark)", ordered[1].Sequence, ackedSeq+1)
	}
	if ordered[1].BatchID == ordered[0].BatchID {
		t.Fatal("new batch reused an acked batch id")
	}
}

// T4: the old restart gap scenario — a restart with different drain
// boundaries. The journaled lines now replay as the ORIGINAL persisted
// batches (identity and boundary copied verbatim), so re-batching the same
// lines under a different boundary is impossible and each line is committed
// exactly once. Lines that were never journaled may be re-emitted by the new
// process (the accepted boundary) and form new batches.
func TestLogSpoolRestartDifferentDrainBoundariesNoDuplication(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)

	// Original process: line-1/line-2 are journaled but the delivery never
	// confirms; the process dies.
	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, func(context.Context, logBatch) error {
		return PermanentDeliveryError(errors.New("control plane unreachable"))
	}, jA)
	sinkA.WriteLine("build", "step", "line-1")
	sinkA.WriteLine("build", "step", "line-2")
	if pending := sinkA.Flush(5 * time.Second); pending != 0 {
		t.Fatalf("original spool did not drain: %d pending", pending)
	}
	sinkA.Finish(2 * time.Second)
	persisted := jA.pendingBatches()
	if len(persisted) == 0 {
		t.Fatal("nothing was journaled by the original process")
	}
	if got := strings.Join(flattenPersistedLines(persisted), "|"); got != "step: line-1|step: line-2" {
		t.Fatalf("persisted lines = %q, want line-1 and line-2", got)
	}

	// Restart: the journal is replayed with the persisted boundaries; only
	// genuinely new lines form new batches.
	jB := openTestJournal(t, stateDir, "job-1", 3)
	sinkB := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jB)
	waitUntil(t, 10*time.Second, "the persisted batches to be replayed", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) == len(persisted)
	})
	sinkB.WriteLine("build", "step", "line-3")
	sinkB.WriteLine("build", "step", "line-4")
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}

	_, store := cp.snapshot()
	got := flattenCommittedLines(store)
	want := []string{"step: line-1", "step: line-2", "step: line-3", "step: line-4"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("committed lines = %v, want exactly %v (no boundary-based duplicates)", got, want)
	}
	// Every persisted batch was replayed with its exact identity AND its
	// exact ordered lines: the boundary cannot change across the restart.
	attempts, _ := cp.snapshot()
	bySequence := map[int64]batchDeliveryAttempt{}
	for _, a := range attempts {
		if _, ok := bySequence[a.Sequence]; !ok {
			bySequence[a.Sequence] = a
		}
	}
	for _, p := range persisted {
		a, ok := bySequence[p.Sequence]
		if !ok || a.BatchID != p.ID {
			t.Fatalf("persisted batch (seq %d, id %s) was not replayed verbatim: %+v", p.Sequence, p.ID, a)
		}
		if strings.Join(a.Lines, "|") != strings.Join(batchLineStrings(p), "|") {
			t.Fatalf("replayed boundary = %v, want the persisted %v", a.Lines, batchLineStrings(p))
		}
	}
}

// flattenPersistedLines renders journaled batches in sequence order.
func flattenPersistedLines(batches []logBatch) []string {
	var out []string
	for _, b := range batches {
		out = append(out, batchLineStrings(b)...)
	}
	return out
}

// T5: terminal job completion removes the journal; no stale records remain.
func TestLogSpoolJournalCleanupOnCompletion(t *testing.T) {
	cp := newLeaseCompletionControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()
	task := cp.acquire("job-1", "runner-1", payloadPipeline)

	r := testRunnerFor(t, ts, Config{})
	r.Cfg.StateDir = t.TempDir()
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), task)

	journalDir := filepath.Join(r.Cfg.StateDir, "log-journal", logJournalKey("job-1"), "gen-5")
	if _, err := os.Stat(journalDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal directory survived terminal completion: stat err = %v", err)
	}
	var stale []string
	root := filepath.Join(r.Cfg.StateDir, "log-journal")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		stale = append(stale, path)
		return nil
	})
	if len(stale) != 0 {
		t.Fatalf("stale journal records after completion: %v", stale)
	}
}

// T6: new lines after replay get strictly increasing sequences and distinct
// ids, and ordering across the restart is preserved.
func TestLogSpoolSequenceContinuesAfterRestart(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)

	// Original process: one journaled batch per drained line, none
	// delivered.
	sent := make(chan struct{}, 8)
	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, func(_ context.Context, _ logBatch) error {
		sent <- struct{}{}
		return PermanentDeliveryError(errors.New("control plane unreachable"))
	}, jA)
	for _, line := range []string{"line-1", "line-2"} {
		sinkA.WriteLine("build", "step", line)
		select {
		case <-sent:
		case <-time.After(5 * time.Second):
			t.Fatalf("batch for %s was not journaled and attempted", line)
		}
	}
	if pending := sinkA.Flush(5 * time.Second); pending != 0 {
		t.Fatalf("original spool did not drain: %d pending", pending)
	}
	sinkA.Finish(2 * time.Second)
	persisted := jA.pendingBatches()
	if len(persisted) != 2 {
		t.Fatalf("journaled batches = %d, want 2", len(persisted))
	}

	// Restart: replay both records, then two new lines.
	jB := openTestJournal(t, stateDir, "job-1", 3)
	sinkB := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jB)
	waitUntil(t, 10*time.Second, "both persisted batches to be replayed", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) == 2
	})
	sinkB.WriteLine("build", "step", "line-3")
	sinkB.WriteLine("build", "step", "line-4")
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}

	attempts, store := cp.snapshot()
	ordered := orderedAttempts(attempts)
	if len(ordered) < 3 {
		t.Fatalf("distinct batches = %d, want at least 3: %v", len(ordered), ordered)
	}
	var lines []string
	ids := map[string]bool{}
	for i, a := range ordered {
		if a.BatchID == "" || ids[a.BatchID] {
			t.Fatalf("batch id %q is empty or reused", a.BatchID)
		}
		ids[a.BatchID] = true
		if i > 0 && a.Sequence <= ordered[i-1].Sequence {
			t.Fatalf("sequence regressed across the restart: %d after %d", a.Sequence, ordered[i-1].Sequence)
		}
		lines = append(lines, a.Lines...)
	}
	if ordered[0].BatchID != persisted[0].ID || ordered[1].BatchID != persisted[1].ID {
		t.Fatalf("replay identities = (%s, %s), want the persisted (%s, %s)", ordered[0].BatchID, ordered[1].BatchID, persisted[0].ID, persisted[1].ID)
	}
	if ordered[0].Sequence != persisted[0].Sequence || ordered[1].Sequence != persisted[1].Sequence {
		t.Fatalf("replay sequences = (%d, %d), want the persisted (%d, %d)", ordered[0].Sequence, ordered[1].Sequence, persisted[0].Sequence, persisted[1].Sequence)
	}
	if ordered[len(ordered)-1].Sequence <= persisted[len(persisted)-1].Sequence {
		t.Fatalf("new batches did not continue after the persisted maximum: %d <= %d", ordered[len(ordered)-1].Sequence, persisted[len(persisted)-1].Sequence)
	}
	want := []string{"step: line-1", "step: line-2", "step: line-3", "step: line-4"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("delivery order across the restart = %v, want %v", lines, want)
	}
	if got := flattenCommittedLines(store); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("committed lines = %v, want exactly %v", got, want)
	}
}

// T7: a journal write failure fails the job explicitly: the batch is never
// posted (no ack without durability), no line is silently dropped, and the
// in-memory budget stays exactly consistent with the retained lines.
func TestLogSpoolJournalWriteFailureFailsJobWithoutAck(t *testing.T) {
	stateDir := t.TempDir()
	rsrv := newBatchReceiptServer()
	ts := httptest.NewServer(rsrv)
	defer ts.Close()

	oldSync := journalFileSync
	journalFileSync = func(*os.File) error { return errBoom() }
	t.Cleanup(func() { journalFileSync = oldSync })

	r := testRunnerFor(t, ts, Config{})
	jA := openTestJournal(t, stateDir, "job-1", 3)
	sink := newJournaledAsyncLogSink(nil, r.logBatchPost(basicTask(payloadPipeline), &secrets.Masker{}), jA)
	sink.WriteLine("build", "step", "line-1")
	out := sink.Finish(5 * time.Second)
	if out.Err == nil {
		t.Fatalf("journal write failure was not surfaced: %+v", out)
	}
	if !strings.Contains(out.Err.Error(), "log journal") {
		t.Fatalf("journal failure error = %v, want a log journal error", out.Err)
	}
	if out.Dropped != 0 {
		t.Fatalf("journal failure dropped lines (must fail, never drop): %+v", out)
	}
	if out.Remaining == 0 {
		t.Fatalf("lines were neither delivered nor retained: %+v", out)
	}
	if attempts, store := rsrv.snapshot(); len(attempts) != 0 || len(store) != 0 {
		t.Fatalf("an unjournaled batch was posted: attempts=%v store=%v", attempts, store)
	}
	if recs := jA.pendingBatches(); len(recs) != 0 {
		t.Fatalf("failed journal write left records on disk: %+v", recs)
	}

	sink.mu.Lock()
	tracked := sink.spoolBytes
	var stored int64
	for _, l := range sink.spool {
		stored += l.spoolCost
	}
	sink.mu.Unlock()
	if tracked != stored {
		t.Fatalf("in-memory budget drifted after the journal failure: tracked=%d stored=%d", tracked, stored)
	}
	if want := int64(len("build") + len("step") + len("line-1")); tracked != want {
		t.Fatalf("tracked bytes = %d, want the retained line's cost %d", tracked, want)
	}
}

// The disk budget bounds the journal exactly like the memory budget bounds
// the spool: overflow fails the job explicitly instead of silently dropping
// lines, and the unjournaled batch is never posted.
func TestLogSpoolJournalDiskBudgetOverflowFailsJob(t *testing.T) {
	stateDir := t.TempDir()
	rsrv := newBatchReceiptServer()
	ts := httptest.NewServer(rsrv)
	defer ts.Close()

	oldBudget := asyncJournalBytes
	asyncJournalBytes = 1
	t.Cleanup(func() { asyncJournalBytes = oldBudget })

	r := testRunnerFor(t, ts, Config{})
	jA := openTestJournal(t, stateDir, "job-1", 3)
	sink := newJournaledAsyncLogSink(nil, r.logBatchPost(basicTask(payloadPipeline), &secrets.Masker{}), jA)
	sink.WriteLine("build", "step", "line-1")
	out := sink.Finish(5 * time.Second)
	if out.Err == nil || !errors.Is(out.Err, errLogJournalOverflow) {
		t.Fatalf("overflow error = %v, want errLogJournalOverflow", out.Err)
	}
	if out.Dropped != 0 {
		t.Fatalf("disk overflow dropped lines (must fail, never drop): %+v", out)
	}
	if out.Remaining == 0 {
		t.Fatalf("overflowed lines were neither delivered nor retained: %+v", out)
	}
	if attempts, store := rsrv.snapshot(); len(attempts) != 0 || len(store) != 0 {
		t.Fatalf("an unjournaled batch was posted on overflow: attempts=%v store=%v", attempts, store)
	}
	if recs := jA.pendingBatches(); len(recs) != 0 {
		t.Fatalf("overflow left records on disk: %+v", recs)
	}
}
