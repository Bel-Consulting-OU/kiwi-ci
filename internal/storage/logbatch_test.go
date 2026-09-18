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
	ctx := context.Background()
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")

	inserted, err := m.AppendLogBatch(ctx, entries, id)
	if err != nil || !inserted {
		t.Fatalf("first append = inserted=%v err=%v, want true, nil", inserted, err)
	}
	// The replay carries a fresh CreatedAt and re-allocated Seq values: it
	// must still be recognized as a duplicate of the same logical batch.
	inserted, err = m.AppendLogBatch(ctx, redeliverBatchEntries(entries, 500, time.Minute), id)
	if err != nil || inserted {
		t.Fatalf("identical replay = inserted=%v err=%v, want false, nil", inserted, err)
	}
	got, err := m.ReadLogs(ctx, "run-1", 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("logs after replay = %d, %v; want 3 (no duplicates)", len(got), err)
	}

	conflict := wave1BatchEntries("run-1", "job-1")
	conflict[0].Line = "changed"
	if _, err := m.AppendLogBatch(ctx, conflict, id); !errors.Is(err, ErrLogBatchConflict) {
		t.Fatalf("conflicting payload = %v, want ErrLogBatchConflict", err)
	}
	got, _ = m.ReadLogs(ctx, "run-1", 0, 100)
	if len(got) != 3 || got[0].Line != "one" {
		t.Fatalf("conflict mutated the stored batch: %+v", got)
	}

	if _, err := m.AppendLogBatch(ctx, entries, LogBatchIdentity{}); err == nil {
		t.Fatal("empty batch identity must fail")
	}
	if _, err := m.AppendLogBatch(ctx, nil, id); err == nil {
		t.Fatal("empty batch payload must fail")
	}
}

// TestFaultyStoreLogBatchConflictPassThrough proves the wrapper never masks
// or rewrites the inner store's conflict sentinel.
func TestFaultyStoreLogBatchConflictPassThrough(t *testing.T) {
	f := &FaultyStore{Inner: newMemStore()}
	ctx := context.Background()
	id := LogBatchIdentity{JobID: "job-1", Generation: 1, BatchID: "batch-1"}
	entries := wave1BatchEntries("run-1", "job-1")
	if _, err := f.AppendLogBatch(ctx, entries, id); err != nil {
		t.Fatalf("first append: %v", err)
	}
	conflict := wave1BatchEntries("run-1", "job-1")
	conflict[2].Line = "other"
	if _, err := f.AppendLogBatch(ctx, conflict, id); !errors.Is(err, ErrLogBatchConflict) {
		t.Fatalf("wrapper conflict = %v, want ErrLogBatchConflict", err)
	}
	// An injected fault still wins over the pass-through.
	injected := errors.New("injected append failure")
	f.FailAfter = 1
	f.Err = injected
	if _, err := f.AppendLogBatch(ctx, entries, id); !errors.Is(err, injected) {
		t.Fatalf("injected fault = %v, want %v", err, injected)
	}
}
