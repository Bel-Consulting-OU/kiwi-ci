package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func wave1BatchEntries(runID, jobID string) []model.LogEntry {
	now := time.Now().UTC()
	return []model.LogEntry{
		{Seq: 1, RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "one", CreatedAt: now},
		{Seq: 2, RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "two", CreatedAt: now},
		{Seq: 3, RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "three", CreatedAt: now},
	}
}

// redeliverBatchEntries returns a copy of entries as a retransmission would
// build them: the per-delivery Seq values and CreatedAt timestamps are
// re-allocated (a later arrival time and a fresh counter block) while the
// logical line content stays byte-identical.
func redeliverBatchEntries(entries []model.LogEntry, seqDelta int64, atDelta time.Duration) []model.LogEntry {
	out := append([]model.LogEntry(nil), entries...)
	for i := range out {
		out[i].Seq += seqDelta
		out[i].CreatedAt = out[i].CreatedAt.Add(atDelta)
	}
	return out
}

func TestLogBatchPayloadDigestCanonical(t *testing.T) {
	id := LogBatchIdentity{JobID: "job-1", Generation: 2, BatchID: "b1"}
	entries := wave1BatchEntries("run-1", "job-1")
	digest := LogBatchPayloadDigest(id, entries)
	if len(digest) != 64 {
		t.Fatalf("digest = %q, want 64 hex chars", digest)
	}
	if again := LogBatchPayloadDigest(id, entries); again != digest {
		t.Fatalf("digest is not deterministic: %q then %q", digest, again)
	}
	// Seq AND CreatedAt are per-delivery, not payload identity: a retry with
	// newly allocated Seq values and a fresh arrival time must digest equal,
	// or the lost-204 retry would look like a conflict.
	retry := redeliverBatchEntries(entries, 1000, time.Hour)
	if got := LogBatchPayloadDigest(id, retry); got != digest {
		t.Fatal("Seq/CreatedAt must not participate in the batch payload digest")
	}
	// Changing ONLY CreatedAt must not change the digest either.
	recreated := append([]model.LogEntry(nil), entries...)
	for i := range recreated {
		recreated[i].CreatedAt = recreated[i].CreatedAt.Add(-72 * time.Hour)
	}
	if got := LogBatchPayloadDigest(id, recreated); got != digest {
		t.Fatal("CreatedAt must not participate in the batch payload digest")
	}
	// Ordered lines: swapping two entries is a different payload.
	swapped := append([]model.LogEntry(nil), entries...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if got := LogBatchPayloadDigest(id, swapped); got == digest {
		t.Fatal("entry order must change the digest")
	}
	// Changed line content is a different payload.
	changed := append([]model.LogEntry(nil), entries...)
	changed[1].Line = "two!"
	if got := LogBatchPayloadDigest(id, changed); got == digest {
		t.Fatal("line content must change the digest")
	}
	// Length prefixes make neighboring field boundaries unambiguous.
	shifted := append([]model.LogEntry(nil), entries...)
	shifted[0].Step = "r"
	shifted[0].Line = "unone"
	if got := LogBatchPayloadDigest(id, shifted); got == digest {
		t.Fatal("ambiguous concatenation: shifted field bytes kept the digest")
	}
	// The digest is bound to the receipt identity.
	other := id
	other.BatchID = "b2"
	if got := LogBatchPayloadDigest(other, entries); got == digest {
		t.Fatal("identity must participate in the digest")
	}
}

func TestMemAppendLogBatchIdempotentAndConflict(t *testing.T) {
	m := newMemStore()
	seedRunningJob(m)
	ctx := context.Background()
	id := LogBatchIdentity{JobID: testJob.ID, Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries(testRun.ID, testJob.ID)

	inserted, err := m.AppendLogBatch(ctx, testRunner.ID, entries, id)
	if err != nil || !inserted {
		t.Fatalf("first append = inserted=%v err=%v, want true, nil", inserted, err)
	}
	// The replay carries a fresh CreatedAt and re-allocated Seq values: it
	// must still be recognized as a duplicate of the same logical batch.
	inserted, err = m.AppendLogBatch(ctx, testRunner.ID, redeliverBatchEntries(entries, 500, time.Minute), id)
	if err != nil || inserted {
		t.Fatalf("identical replay = inserted=%v err=%v, want false, nil", inserted, err)
	}
	got, err := m.ReadLogs(ctx, testRun.ID, 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("logs after replay = %d, %v; want 3 (no duplicates)", len(got), err)
	}

	conflict := wave1BatchEntries(testRun.ID, testJob.ID)
	conflict[0].Line = "changed"
	if _, err := m.AppendLogBatch(ctx, testRunner.ID, conflict, id); !errors.Is(err, ErrLogBatchConflict) {
		t.Fatalf("conflicting payload = %v, want ErrLogBatchConflict", err)
	}
	got, _ = m.ReadLogs(ctx, testRun.ID, 0, 100)
	if len(got) != 3 || got[0].Line != "one" {
		t.Fatalf("conflict mutated the stored batch: %+v", got)
	}

	if _, err := m.AppendLogBatch(ctx, testRunner.ID, entries, LogBatchIdentity{}); err == nil {
		t.Fatal("empty batch identity must fail")
	}
	if _, err := m.AppendLogBatch(ctx, testRunner.ID, nil, id); err == nil {
		t.Fatal("empty batch payload must fail")
	}
}

// TestMemAppendLogBatchLeaseFence proves the in-memory batch commit is fenced
// by the live lease: a generation that is no longer held (revoked holder or
// superseded generation) is refused with ErrLeaseLost for BOTH a fresh batch
// and a replay of an already-receipted one, so there is no post-expiry
// idempotent ack. The predicate is evaluated before the receipt and inserts
// nothing.
func TestMemAppendLogBatchLeaseFence(t *testing.T) {
	m := newMemStore()
	seedRunningJob(m)
	ctx := context.Background()
	id := LogBatchIdentity{JobID: testJob.ID, Generation: 1, BatchID: "batch-fence"}
	entries := wave1BatchEntries(testRun.ID, testJob.ID)
	if inserted, err := m.AppendLogBatch(ctx, testRunner.ID, entries, id); err != nil || !inserted {
		t.Fatalf("live append = inserted=%v err=%v", inserted, err)
	}
	// Revoke the lease out from under the batch: the same identity and the
	// identical payload must now be refused, not acked.
	m.mu.Lock()
	j := m.jobs[testJob.ID]
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	m.jobs[testJob.ID] = j
	m.mu.Unlock()
	if _, err := m.AppendLogBatch(ctx, testRunner.ID, entries, id); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale replay = %v, want ErrLeaseLost", err)
	}
	fresh := LogBatchIdentity{JobID: testJob.ID, Generation: 1, BatchID: "batch-fence-fresh"}
	if _, err := m.AppendLogBatch(ctx, testRunner.ID, freshEntries(entries), fresh); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale fresh batch = %v, want ErrLeaseLost", err)
	}
	got, _ := m.ReadLogs(ctx, testRun.ID, 0, 100)
	if len(got) != 3 {
		t.Fatalf("stale batch persisted lines: %d", len(got))
	}
}

// freshEntries clones a batch payload with different line text so a refused
// append cannot be mistaken for a dedupe of the earlier payload.
func freshEntries(entries []model.LogEntry) []model.LogEntry {
	out := append([]model.LogEntry(nil), entries...)
	for i := range out {
		out[i].Line += "!"
	}
	return out
}

// TestMemAppendLogForLeaseFenceAndIdentity proves the in-memory single-line
// commit applies the same predicate and identity binding as PostgreSQL:
// a live lease appends an allocated seq, a revoked lease is ErrLeaseLost,
// and a run/job identity that disagrees with the locked job is refused
// without persisting.
func TestMemAppendLogForLeaseFenceAndIdentity(t *testing.T) {
	m := newMemStore()
	seedRunningJob(m)
	ctx := context.Background()
	e := model.LogEntry{RunID: testRun.ID, JobID: testJob.ID, JobKey: testJob.Key, Step: "run", Line: "one", CreatedAt: time.Now().UTC()}
	if err := m.AppendLogForLease(ctx, testJob.ID, testRunner.ID, 1, e); err != nil {
		t.Fatalf("live append: %v", err)
	}
	got, _ := m.ReadLogs(ctx, testRun.ID, 0, 10)
	if len(got) != 1 || got[0].Seq != 1 || got[0].LeaseGeneration != 1 {
		t.Fatalf("stored line = %+v", got)
	}
	// Identity disagreements are refused and persist nothing.
	if err := m.AppendLogForLease(ctx, testJob.ID, testRunner.ID, 1, model.LogEntry{RunID: "dddddddddddddddddddddddddddddddd", Line: "x"}); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("foreign run = %v, want ErrLeaseIdentityMismatch", err)
	}
	if err := m.AppendLogForLease(ctx, testJob.ID, testRunner.ID, 1, model.LogEntry{RunID: testRun.ID, JobKey: "other", Line: "x"}); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("foreign key = %v, want ErrLeaseIdentityMismatch", err)
	}
	if err := m.AppendLogForLease(ctx, testJob.ID, testRunner.ID, 2, model.LogEntry{RunID: testRun.ID, Line: "x"}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale generation = %v, want ErrLeaseLost", err)
	}
	if got, _ := m.ReadLogs(ctx, testRun.ID, 0, 10); len(got) != 1 {
		t.Fatalf("refused lines persisted: %d", len(got))
	}
}

// TestFaultyStoreLogBatchConflictPassThrough proves the wrapper never masks
// or rewrites the inner store's conflict sentinel.
func TestFaultyStoreLogBatchConflictPassThrough(t *testing.T) {
	f := &FaultyStore{Inner: newMemStore()}
	seedRunningJob(f.Inner.(*memStore))
	ctx := context.Background()
	id := LogBatchIdentity{JobID: testJob.ID, Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries(testRun.ID, testJob.ID)
	if _, err := f.AppendLogBatch(ctx, testRunner.ID, entries, id); err != nil {
		t.Fatalf("first append: %v", err)
	}
	conflict := wave1BatchEntries(testRun.ID, testJob.ID)
	conflict[2].Line = "other"
	if _, err := f.AppendLogBatch(ctx, testRunner.ID, conflict, id); !errors.Is(err, ErrLogBatchConflict) {
		t.Fatalf("wrapper conflict = %v, want ErrLogBatchConflict", err)
	}
	// An injected fault still wins over the pass-through.
	injected := errors.New("injected append failure")
	f.FailAfter = 1
	f.Err = injected
	if _, err := f.AppendLogBatch(ctx, testRunner.ID, entries, id); !errors.Is(err, injected) {
		t.Fatalf("injected fault = %v, want %v", err, injected)
	}
}
