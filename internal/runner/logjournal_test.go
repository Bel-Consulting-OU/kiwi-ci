package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
// boundaries. The journaled lines replay as the ORIGINAL persisted batches
// (identity and boundary copied verbatim), so re-batching the same lines
// under a different boundary is impossible and each line is committed
// exactly once. Lines that were never journaled (spooled only after the
// sender stopped on the failed batch) are the documented loss boundary; the
// recovery path re-executes them under a new lease, not the log sink.
func TestLogSpoolRestartDifferentDrainBoundariesNoDuplication(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)

	// Original process: line-1 is journaled, but the delivery fails
	// permanently and the sender stops (fail closed). line-2 is spooled only
	// after that failure and is therefore never journaled.
	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, func(context.Context, logBatch) error {
		return PermanentDeliveryError(errors.New("control plane unreachable"))
	}, jA)
	sinkA.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "line-1 to be journaled", func() bool {
		return len(jA.pendingBatches()) == 1
	})
	sinkA.WriteLine("build", "step", "line-2")
	outA := sinkA.Finish(2 * time.Second)
	if outA.Err == nil {
		t.Fatalf("original process reported a clean outcome despite the failed delivery: %+v", outA)
	}
	persisted := jA.pendingBatches()
	if len(persisted) != 1 {
		t.Fatalf("persisted batches = %+v, want only the failed journaled batch", persisted)
	}
	if got := strings.Join(flattenPersistedLines(persisted), "|"); got != "step: line-1" {
		t.Fatalf("persisted lines = %q, want line-1", got)
	}

	// Restart: the journal is replayed with the persisted boundaries; only
	// genuinely new lines form new batches.
	jB := openTestJournal(t, stateDir, "job-1", 3)
	sinkB := newJournaledAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}), jB)
	waitUntil(t, 10*time.Second, "the persisted batch to be replayed", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) == 1
	})
	sinkB.WriteLine("build", "step", "line-3")
	sinkB.WriteLine("build", "step", "line-4")
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}

	_, store := cp.snapshot()
	got := flattenCommittedLines(store)
	want := []string{"step: line-1", "step: line-3", "step: line-4"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("committed lines = %v, want exactly %v (no boundary-based duplicates; line-2 was never journaled)", got, want)
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
// ids, and ordering across the restart is preserved. The original process
// delivered its batches but died BEFORE the batched ack watermark could be
// flushed, so the restart replays the persisted identities idempotently
// (server dedupe) and continues the sequence after the persisted maximum.
func TestLogSpoolSequenceContinuesAfterRestart(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)
	post := r.logBatchPost(task, &secrets.Masker{})

	// Original process: one journaled+committed batch per drained line. The
	// process crashes without Finish, so no ack flush ever runs.
	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, post, jA)
	for i, line := range []string{"line-1", "line-2"} {
		sinkA.WriteLine("build", "step", line)
		want := i + 1
		waitUntil(t, 10*time.Second, "line to be journaled", func() bool {
			return len(jA.pendingBatches()) == want
		})
	}
	crashLogSink(sinkA)
	persisted := jA.pendingBatches()
	if len(persisted) != 2 {
		t.Fatalf("journaled batches = %d, want 2", len(persisted))
	}

	// Restart: replay both records, then two new lines.
	jB := openTestJournal(t, stateDir, "job-1", 3)
	sinkB := newJournaledAsyncLogSink(nil, post, jB)
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

// --- FB-1: watermark vs sequence gap --------------------------------------

// crashLogSink stops a sink the way a process crash does: without the
// Finish-time ack flush. It wakes the waiting sender so the goroutine exits.
func crashLogSink(s *asyncLogSink) {
	s.cancel()
	s.WriteLine("crash", "wake", "wake")
	<-s.done
}

// waitSinkDrained waits until the spool is empty AND every formed batch has
// finished its ack (inFlight is decremented only after ack returns).
func waitSinkDrained(t *testing.T, s *asyncLogSink) {
	t.Helper()
	waitUntil(t, 10*time.Second, "the sink to drain fully", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.spool) == 0 && s.inFlight == 0
	})
}

// durableWatermarkSequence reads the persisted ack watermark (0 when absent).
func durableWatermarkSequence(t *testing.T, dir string) int64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "ack-watermark"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("read ack watermark: %v", err)
	}
	var wm logJournalWatermark
	if err := json.Unmarshal(b, &wm); err != nil {
		t.Fatalf("decode ack watermark %s: %v", b, err)
	}
	return wm.Sequence
}

// oneLineBatch builds an identified single-line batch for the given sequence.
func oneLineBatch(sequence int64, line string) logBatch {
	b := logBatch{Sequence: sequence, Lines: []logLine{{Job: "build", Step: "step", Line: line}}}
	b.ID = logBatchID(b.Sequence, b.Lines)
	return b
}

// FB-1 regression: the pre-amortization sender could advance the watermark
// past a batch whose delivery failed permanently (it kept sending later
// batches, acked one of them, and the single watermark covered the failed
// sequence). On restart that record must be REPLAYED, never reclaimed as
// consumed; the later committed batch must not be re-sent (its record was
// unlinked and the server dedupes anyway); and the sequence must continue
// after the persisted maximum.
//
// This test FAILS before the fix: load reclaimed record 1 because its
// sequence was <= the format-1 watermark 2.
func TestLogJournalLegacyWatermarkGapReplaysFailedBatch(t *testing.T) {
	stateDir := t.TempDir()
	cp := newRestartLogControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)
	post := r.logBatchPost(task, &secrets.Masker{})

	// Phase A (legacy process): batch 1 failed permanently and was never
	// committed; batch 2 was delivered and committed. The legacy sender
	// still acked batch 2, writing watermark=2 (format 1: no format field)
	// and unlinking record 2 while record 1 stayed on disk.
	jA := openTestJournal(t, stateDir, "job-1", 3)
	b1 := oneLineBatch(1, "line-1")
	b2 := oneLineBatch(2, "line-2")
	if err := jA.append(b1); err != nil {
		t.Fatalf("journal batch 1: %v", err)
	}
	if err := jA.append(b2); err != nil {
		t.Fatalf("journal batch 2: %v", err)
	}
	if err := post(context.Background(), b2); err != nil {
		t.Fatalf("commit batch 2: %v", err)
	}
	legacyWM := []byte(`{"job_id":"job-1","generation":3,"sequence":2}`)
	if err := os.WriteFile(filepath.Join(jA.dir, "ack-watermark"), legacyWM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(jA.dir, journalRecordName(2, b2.ID))); err != nil {
		t.Fatalf("legacy ack did not unlink record 2: %v", err)
	}
	// jA is abandoned: this is the crash.

	// Phase B (fixed process): the format-1 watermark must NOT cause record 1
	// to be reclaimed; it has to replay.
	jB := openTestJournal(t, stateDir, "job-1", 3)
	pending := jB.pendingBatches()
	if len(pending) != 1 || pending[0].Sequence != 1 || pending[0].ID != b1.ID {
		t.Fatalf("after the legacy-watermark restart pending = %+v, want the failed batch (seq 1, id %s)", pending, b1.ID)
	}

	sinkB := newJournaledAsyncLogSink(nil, post, jB)
	sinkB.WriteLine("build", "step", "line-3")
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}

	attempts, store := cp.snapshot()
	if countCommittedBatches(store) != 3 {
		t.Fatalf("committed batches = %d, want 3 (batch 1 replayed once, batch 2 deduped, line-3 new)", countCommittedBatches(store))
	}
	got := flattenCommittedLines(store)
	want := []string{"step: line-1", "step: line-2", "step: line-3"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("committed lines = %v, want exactly %v (one copy each)", got, want)
	}
	if n := countAttemptsFor(attempts, b2.ID); n != 1 {
		t.Fatalf("committed batch 2 was sent %d time(s), want exactly 1 (deduped, not replayed)", n)
	}
	if n := countAttemptsFor(attempts, b1.ID); n != 1 {
		t.Fatalf("failed batch 1 replay attempts = %d, want exactly 1", n)
	}
	// No sequence regression: the new line gets sequence 3 (> persisted max 2).
	var newSeq int64
	for _, a := range attempts {
		if len(a.Lines) == 1 && a.Lines[0] == "step: line-3" {
			newSeq = a.Sequence
		}
	}
	if newSeq != 3 {
		t.Fatalf("new batch sequence = %d, want 3 (no regression past the persisted maximum)", newSeq)
	}
}

// FB-1 sender-side regression: a permanent delivery failure stops the
// sender. No later batch may be formed or acked, so the durable watermark
// can never advance past the failed sequence; Finish surfaces the failure
// and the restart replays the failed batch under its original identity while
// the sequence continues after the persisted maximum.
func TestLogSinkStopsOnSendFailureBeforeAckingPast(t *testing.T) {
	stateDir := t.TempDir()
	var mu sync.Mutex
	var failFirst atomic.Bool
	failFirst.Store(true)
	attempts := map[int64]int{}
	committed := map[string][]string{}
	post := func(_ context.Context, batch logBatch) error {
		mu.Lock()
		attempts[batch.Sequence]++
		mu.Unlock()
		if failFirst.Load() && batch.Sequence == 1 {
			return PermanentDeliveryError(errors.New("rejected permanently"))
		}
		mu.Lock()
		if _, ok := committed[batch.ID]; !ok {
			committed[batch.ID] = batchLineStrings(batch)
		}
		mu.Unlock()
		return nil
	}

	jA := openTestJournal(t, stateDir, "job-1", 3)
	sinkA := newJournaledAsyncLogSink(nil, post, jA)
	sinkA.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "the permanent failure of batch 1", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return attempts[1] > 0
	})
	// Only now is line-2 spooled: after the failure the sender must not form
	// or post another batch.
	sinkA.WriteLine("build", "step", "line-2")
	outA := sinkA.Finish(10 * time.Second)
	if outA.Err == nil {
		t.Fatalf("the failed delivery was not surfaced: %+v", outA)
	}
	mu.Lock()
	for seq := range attempts {
		if seq != 1 {
			mu.Unlock()
			t.Fatalf("batch %d was attempted after the permanent failure", seq)
		}
	}
	for id := range committed {
		mu.Unlock()
		t.Fatalf("batch %s was committed after the permanent failure", id)
	}
	mu.Unlock()
	if outA.Dropped != 0 {
		t.Fatalf("dropped = %d, want 0 (the spooled line is retained and reported)", outA.Dropped)
	}
	if outA.Remaining != 1 {
		t.Fatalf("remaining = %d, want the spooled line-2 reported", outA.Remaining)
	}
	if got := jA.maxSequence(); got != 1 {
		t.Fatalf("maxSequence = %d, want 1 (no later batch was formed)", got)
	}
	if recs := jA.pendingBatches(); len(recs) != 1 || recs[0].Sequence != 1 {
		t.Fatalf("journal records = %+v, want only the failed batch 1", recs)
	}

	// Restart: batch 1 replays exactly once; the sequence continues after the
	// persisted maximum. The endpoint recovers, so the replay succeeds.
	failFirst.Store(false)
	jB := openTestJournal(t, stateDir, "job-1", 3)
	recs := jB.pendingBatches()
	if len(recs) != 1 || recs[0].Sequence != 1 {
		t.Fatalf("after restart pending = %+v, want the failed batch 1 replayed (not discarded)", recs)
	}
	sinkB := newJournaledAsyncLogSink(nil, post, jB)
	sinkB.WriteLine("build", "step", "line-3")
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restart outcome = %+v, want a clean stop", outB)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(committed) != 2 {
		t.Fatalf("committed batches = %d, want 2 (replayed batch 1 and the new batch)", len(committed))
	}
	if got := attempts[1]; got != 2 {
		t.Fatalf("batch 1 attempts = %d, want 2 (permanent failure + replay)", got)
	}
	if got := attempts[2]; got != 1 {
		t.Fatalf("new batch attempts = %d, want 1", got)
	}
	var lines []string
	for _, l := range committed {
		lines = append(lines, l...)
	}
	sort.Strings(lines)
	if strings.Join(lines, "|") != "step: line-1|step: line-3" {
		t.Fatalf("committed lines = %v, want line-1 and line-3 exactly once", lines)
	}
}

// --- FB-2: amortized ack watermark -----------------------------------------

// FB-2 regression: a burst of K acked batches performs FEWER than K durable
// watermark writes (counted through the seam, never timing), and a crash at
// any flush point leaves every un-acked record replayable and every acked
// record either reclaimed or idempotently replayed, with exactly one
// committed copy of every line and no sequence regression.
func TestLogJournalAmortizedAckFlushBurst(t *testing.T) {
	oldEvery := journalAckFlushEvery
	journalAckFlushEvery = 4
	t.Cleanup(func() { journalAckFlushEvery = oldEvery })

	for _, k := range []int{1, 3, 4, 8, 11} {
		t.Run(fmt.Sprintf("crash_after_%d_batches", k), func(t *testing.T) {
			stateDir := t.TempDir()
			oldWrites := journalWatermarkWrites.Swap(0)
			t.Cleanup(func() { journalWatermarkWrites.Store(oldWrites) })

			// In-process delivery stub: commit once per batch identity.
			var mu sync.Mutex
			committed := map[string][]string{}
			attempts := map[int64]int{}
			post := func(_ context.Context, batch logBatch) error {
				mu.Lock()
				attempts[batch.Sequence]++
				if _, ok := committed[batch.ID]; !ok {
					committed[batch.ID] = batchLineStrings(batch)
				}
				mu.Unlock()
				return nil
			}

			jA := openTestJournal(t, stateDir, "job-1", 3)
			sinkA := newJournaledAsyncLogSink(nil, post, jA)
			for i := 0; i < k; i++ {
				sinkA.WriteLine("build", "step", fmt.Sprintf("line-%d", i))
				want := i + 1
				waitUntil(t, 10*time.Second, fmt.Sprintf("%d committed batches", want), func() bool {
					mu.Lock()
					defer mu.Unlock()
					return len(committed) == want
				})
			}
			waitSinkDrained(t, sinkA)
			writes := journalWatermarkWrites.Load()
			if writes == 0 && k >= journalAckFlushEvery {
				t.Fatalf("no ack watermark reached disk across %d acks (flush boundary %d)", k, journalAckFlushEvery)
			}
			if writes >= int64(k) {
				t.Fatalf("watermark writes = %d for %d acked batches; the ack side was not amortized", writes, k)
			}
			// Crash WITHOUT Finish: no final flush runs.
			crashLogSink(sinkA)

			durableWM := durableWatermarkSequence(t, jA.dir)
			if durableWM < 0 || durableWM > int64(k) {
				t.Fatalf("durable watermark = %d for %d batches", durableWM, k)
			}
			if k >= journalAckFlushEvery && durableWM == 0 {
				t.Fatal("no ack flush reached disk within the burst")
			}

			// Restart: exactly the records above the durable watermark are
			// pending; nothing at or below it is replayed (acked batches stay
			// deduped) and nothing above it is skipped.
			jB := openTestJournal(t, stateDir, "job-1", 3)
			pending := jB.pendingBatches()
			if want := int64(k) - durableWM; int64(len(pending)) != want {
				t.Fatalf("pending records after restart = %d, want %d (durable watermark %d)", len(pending), want, durableWM)
			}
			for i, b := range pending {
				if wantSeq := durableWM + 1 + int64(i); b.Sequence != wantSeq {
					t.Fatalf("pending[%d].Sequence = %d, want %d", i, b.Sequence, wantSeq)
				}
			}
			if got := jB.maxSequence(); got != int64(k) {
				t.Fatalf("maxSequence after restart = %d, want %d (no sequence regression)", got, k)
			}

			sinkB := newJournaledAsyncLogSink(nil, post, jB)
			sinkB.WriteLine("build", "step", "line-new")
			outB := sinkB.Finish(10 * time.Second)
			if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
				t.Fatalf("restart outcome = %+v, want a clean stop", outB)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(committed) != k+1 {
				t.Fatalf("committed batches = %d, want %d", len(committed), k+1)
			}
			var lines []string
			for _, l := range committed {
				lines = append(lines, l...)
			}
			sort.Strings(lines)
			want := make([]string, 0, k+1)
			for i := 0; i < k; i++ {
				want = append(want, fmt.Sprintf("step: line-%d", i))
			}
			want = append(want, "step: line-new")
			sort.Strings(want)
			if strings.Join(lines, "|") != strings.Join(want, "|") {
				t.Fatalf("committed lines = %v, want exactly one copy of each of %v", lines, want)
			}
			if got := attempts[int64(k)+1]; got != 1 {
				t.Fatalf("new batch attempts = %d, want 1 (sequence %d is new)", got, k+1)
			}
			for _, b := range pending {
				if got := attempts[b.Sequence]; got != 2 {
					t.Fatalf("replayed batch %d attempts = %d, want 2 (crash + idempotent replay)", b.Sequence, got)
				}
			}
		})
	}
}

// --- FB-3: unified memory accounting ---------------------------------------

// FB-3 regression: loading a journal backlog whose resident bytes exceed the
// shared in-memory budget fails explicitly and leaves every durable record
// in place (never a silent truncation/drop). Before the fix the backlog was
// retained in memory up to the 128 MiB DISK budget, unbudgeted.
func TestLogJournalMemoryBudgetRejectsOverBudgetBacklog(t *testing.T) {
	stateDir := t.TempDir()
	jA := openTestJournal(t, stateDir, "job-1", 3)
	line := strings.Repeat("x", 1024)
	for seq := int64(1); seq <= 8; seq++ {
		if err := jA.append(oneLineBatch(seq, line)); err != nil {
			t.Fatalf("append batch %d: %v", seq, err)
		}
	}
	records, err := filepath.Glob(filepath.Join(jA.dir, "*.json"))
	if err != nil || len(records) != 8 {
		t.Fatalf("journaled records = %v (%v), want 8", records, err)
	}

	oldBytes := asyncSpoolBytes
	asyncSpoolBytes = 2048
	t.Cleanup(func() { asyncSpoolBytes = oldBytes })

	jB, err := openLogJournal(stateDir, "job-1", 3, nil)
	if err == nil {
		t.Fatal("loading an over-budget backlog succeeded; resident memory is not bounded by the documented budget")
	}
	if !strings.Contains(err.Error(), "memory budget") {
		t.Fatalf("load error = %v, want an explicit memory budget error", err)
	}
	if jB != nil {
		t.Fatalf("failed load returned a journal: %+v", jB)
	}
	// No silent drop: the failed open left every record durably in place.
	records, err = filepath.Glob(filepath.Join(jA.dir, "*.json"))
	if err != nil || len(records) != 8 {
		t.Fatalf("records after the failed load = %v (%v), want 8 preserved", records, err)
	}
}

// FB-3: journal-resident bytes are charged against the shared budget with an
// explicit rejection at the boundary and released by the ack flush; the
// charge never exceeds the documented bound.
func TestLogJournalMemoryBudgetAccountingBound(t *testing.T) {
	stateDir := t.TempDir()
	oldBytes := asyncSpoolBytes
	asyncSpoolBytes = 8192
	t.Cleanup(func() { asyncSpoolBytes = oldBytes })

	j := openTestJournal(t, stateDir, "job-1", 3)
	line := strings.Repeat("x", 1024)
	var accepted []logBatch
	for seq := int64(1); seq <= 100; seq++ {
		b := oneLineBatch(seq, line)
		if err := j.append(b); err != nil {
			if !errors.Is(err, errLogJournalMemoryOverflow) {
				t.Fatalf("append %d error = %v, want errLogJournalMemoryOverflow", seq, err)
			}
			break
		}
		accepted = append(accepted, b)
		if got := j.residentBytes(); got > asyncSpoolBytes {
			t.Fatalf("resident bytes = %d exceed the %d byte budget", got, asyncSpoolBytes)
		}
		if got := j.residentBytes(); got <= 0 {
			t.Fatalf("accepted record %d is not charged to the shared budget", seq)
		}
	}
	if len(accepted) == 0 || len(accepted) >= 100 {
		t.Fatalf("accepted = %d batches, want an explicit mid-burst rejection", len(accepted))
	}
	if got := len(j.pendingBatches()); got != len(accepted) {
		t.Fatalf("pending = %d, want the %d accepted records", got, len(accepted))
	}
	if _, ok := j.paths[int64(len(accepted)+1)]; ok {
		t.Fatal("the rejected sequence left a path entry behind")
	}
	// The ack flush releases the reclaimed records' charge.
	before := j.residentBytes()
	if err := j.ack(accepted[0].Sequence, accepted[0].ID); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := j.flushAcks(); err != nil {
		t.Fatalf("flushAcks: %v", err)
	}
	if after := j.residentBytes(); after >= before {
		t.Fatalf("ack+flush released no resident bytes: %d -> %d", before, after)
	}
	if got := j.residentBytes(); got > asyncSpoolBytes {
		t.Fatalf("resident bytes = %d exceed the %d byte budget after the flush", got, asyncSpoolBytes)
	}
}

// --- FB-4: explicit state-dir failures -------------------------------------

// FB-4: the production entry path fails closed when no durable state
// directory can be resolved instead of silently running journal-less.
func TestRunFailsWhenStateDirCannotBeResolved(t *testing.T) {
	t.Setenv("HOME", "")
	r := &Runner{Cfg: Config{Server: "http://127.0.0.1:1"}}
	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("Run silently accepted an unresolvable state directory")
	}
	if !strings.Contains(err.Error(), "state directory") {
		t.Fatalf("Run error = %v, want a state-directory error", err)
	}
}

// FB-4: direct execute callers may run journal-less ONLY through the
// explicit opt-out seam; without it openJobLogJournal fails closed, and a
// configured but unusable state directory is always an error.
func TestOpenJobLogJournalRequiresExplicitOptOut(t *testing.T) {
	r := &Runner{}
	if j, err := r.openJobLogJournal("job-1", 1, nil); err == nil || j != nil {
		t.Fatalf("openJobLogJournal without a state dir = (%v, %v), want an explicit error", j, err)
	}
	// The seam is the only journal-less path.
	rOptOut := &Runner{journalOptOut: true}
	if j, err := rOptOut.openJobLogJournal("job-1", 1, nil); j != nil || err != nil {
		t.Fatalf("openJobLogJournal with journalOptOut = (%v, %v), want (nil, nil)", j, err)
	}
	// A resolved state directory always opens the journal.
	r.Cfg.StateDir = t.TempDir()
	j, err := r.openJobLogJournal("job-1", 1, nil)
	if err != nil || j == nil {
		t.Fatalf("openJobLogJournal with a state dir = (%v, %v), want a journal", j, err)
	}
}

// FB-4: an unusable (read-only) state directory is fail-closed: the journal
// cannot be created and the error is surfaced rather than silently ignored.
func TestOpenJobLogJournalReadOnlyStateDirFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	r := &Runner{Cfg: Config{StateDir: dir}}
	if j, err := r.openJobLogJournal("job-1", 1, nil); err == nil || j != nil {
		t.Fatalf("openJobLogJournal on a read-only state dir = (%v, %v), want an explicit error", j, err)
	}
}
