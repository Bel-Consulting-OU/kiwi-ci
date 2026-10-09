package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestRepositoryExecutionEventsAppendListRestart proves the fs journal is
// durable, monotonic across restarts and paged oldest-first from a cursor
// (unlike readJSONL's keep-the-newest semantics, which would skip backlog).
func TestRepositoryExecutionEventsAppendListRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := New(dir)

	for i := 1; i <= 5; i++ {
		run := "run-a"
		if i%2 == 1 {
			run = "run-b"
		}
		if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{
			RunID: run, JobID: "j", Type: "job.queued", ToStatus: "queued",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Load (startup) recovers the watermark from the journal.
	if _, err := repo.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	// A restart appends after the recovered watermark, never reusing a seq.
	repo2 := New(dir)
	if _, err := repo2.Load(); err != nil {
		t.Fatalf("load second: %v", err)
	}
	if err := repo2.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-a", Type: "job.running", ToStatus: "running"}); err != nil {
		t.Fatalf("append after restart: %v", err)
	}
	all, cursor, err := repo2.ListExecutionEvents(ctx, 0, 100, "")
	if err != nil || len(all) != 6 || cursor != 6 {
		t.Fatalf("after restart = %d events cursor %d err %v, want 6/6", len(all), cursor, err)
	}
	if all[5].Seq != 6 || all[5].Type != "job.running" {
		t.Fatalf("restart event = %+v, want seq 6 job.running", all[5])
	}
	// The first page is the OLDEST matching events, not the newest.
	page, cur, err := repo2.ListExecutionEvents(ctx, 0, 2, "")
	if err != nil || len(page) != 2 || page[0].Seq != 1 || page[1].Seq != 2 || cur != 2 {
		t.Fatalf("oldest-first page = %+v cursor %d err %v", page, cur, err)
	}
	// Run filter and cursor combination.
	filtered, cur, err := repo2.ListExecutionEvents(ctx, 1, 10, "run-b")
	if err != nil || len(filtered) != 2 {
		t.Fatalf("run filter = %d cursor %d err %v", len(filtered), cur, err)
	}
	for _, e := range filtered {
		if e.RunID != "run-b" {
			t.Fatalf("run filter leaked %q", e.RunID)
		}
	}
	// A missing journal is an empty page, not an error.
	empty := New(t.TempDir())
	if got, cur, err := empty.ListExecutionEvents(ctx, 0, 10, ""); err != nil || len(got) != 0 || cur != 0 {
		t.Fatalf("missing journal = %d cursor %d err %v", len(got), cur, err)
	}
}

// TestRepositoryExecutionEventsMissingFileLoad proves startup tolerates an
// absent journal (the normal pre-feature data dir).
func TestRepositoryExecutionEventsMissingFileLoad(t *testing.T) {
	snap, err := New(t.TempDir()).Load()
	if err != nil {
		t.Fatalf("load without journal: %v", err)
	}
	if snap.Runs == nil {
		t.Fatal("load returned a nil runs map")
	}
}

// TestRepositoryExecutionEventsCorruptJournalFailsClosed proves a corrupt
// record fails startup and append: the store cannot prove which seq values
// are published, so continuing could reuse a cursor.
func TestRepositoryExecutionEventsCorruptJournalFailsClosed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, executionEventsFile), []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir).Load(); err == nil {
		t.Fatal("corrupt journal must fail Load")
	}
	if err := New(dir).AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "run.queued"}); err == nil {
		t.Fatal("corrupt journal must fail append")
	}
}

// TestRepositoryExecutionEventsAppendFailureConsumesSeq proves a failed
// append may skip a seq but can never regress or duplicate one: the cursor
// stays monotonic across a write failure.
func TestRepositoryExecutionEventsAppendFailureConsumesSeq(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := New(dir)
	if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "run.queued", ToStatus: "queued"}); err != nil {
		t.Fatal(err)
	}
	// A directory at the journal path makes the next append fail.
	path := filepath.Join(dir, executionEventsFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "job.queued"}); err == nil {
		t.Fatal("append onto a directory must fail")
	}
	// Restore the journal and append again: the new seq is strictly greater
	// than the failed append's (no regression, no duplicate).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "job.running", ToStatus: "running"}); err != nil {
		t.Fatal(err)
	}
	events, _, err := repo.ListExecutionEvents(ctx, 0, 100, "")
	if err != nil || len(events) != 2 {
		t.Fatalf("events = %d err %v, want 2", len(events), err)
	}
	if events[1].Seq <= events[0].Seq {
		t.Fatalf("seq regressed across a failed append: %d -> %d", events[0].Seq, events[1].Seq)
	}
}

// TestRepositoryExecutionEventsCreatedAtAndSchemaDefaulted proves a zero
// event is stamped with the schema version and a time, so consumers never
// see a zero timestamp.
func TestRepositoryExecutionEventsCreatedAtAndSchemaDefaulted(t *testing.T) {
	ctx := context.Background()
	repo := New(t.TempDir())
	before := time.Now().UTC().Add(-time.Second)
	if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "run.queued"}); err != nil {
		t.Fatal(err)
	}
	events, _, err := repo.ListExecutionEvents(ctx, 0, 10, "")
	if err != nil || len(events) != 1 {
		t.Fatalf("events = %d err %v", len(events), err)
	}
	if events[0].SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", events[0].SchemaVersion)
	}
	if events[0].CreatedAt.Before(before) {
		t.Fatalf("created_at not stamped: %v", events[0].CreatedAt)
	}
}

// TestRepositoryExecutionEventsRetentionAtomicRead proves the fs atomic
// retention read and the monotonic latest watermark: the page, watermark and
// latest cursor are returned from one lock critical section, pruning the
// whole journal does not regress latest (the seq watermark is recovered from
// the durable retained file on restart), and the expiry boundary is exactly
// after < retainedFrom.
func TestRepositoryExecutionEventsRetentionAtomicRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := New(dir)
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-a", Type: "job.queued", CreatedAt: now.Add(-48 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	page, cursor, retained, latest, err := repo.ReadExecutionEventsRetention(ctx, 0, 100, "")
	if err != nil || len(page) != 4 || cursor != 4 || retained != 0 || latest != 4 {
		t.Fatalf("initial atomic read = %d cursor %d retained %d latest %d err %v", len(page), cursor, retained, latest, err)
	}
	pruned, retained, err := repo.PruneExecutionEvents(ctx, now.Add(time.Hour), 100)
	if err != nil || pruned != 4 || retained != 4 {
		t.Fatalf("prune all = %d/%d err %v, want 4/4", pruned, retained, err)
	}
	// after == retainedFrom stays valid; the page is empty and latest does
	// not regress.
	page, cursor, retained, latest, err = repo.ReadExecutionEventsRetention(ctx, 4, 100, "")
	if err != nil || len(page) != 0 || cursor != 4 || retained != 4 || latest != 4 {
		t.Fatalf("all-pruned atomic read = %d cursor %d retained %d latest %d err %v", len(page), cursor, retained, latest, err)
	}
	if !ExecutionEventCursorExpired(3, retained) || ExecutionEventCursorExpired(4, retained) {
		t.Fatalf("fs expiry boundary at retained %d disagrees", retained)
	}
	// A restart recovers the watermark from the retained file (the journal is
	// empty), so the next append continues at 5 and never reuses a seq.
	repo2 := New(dir)
	if _, err := repo2.Load(); err != nil {
		t.Fatal(err)
	}
	if latest, err := repo2.LatestExecutionEventSeq(ctx); err != nil || latest != 4 {
		t.Fatalf("reloaded latest = %d err %v, want 4", latest, err)
	}
	if err := repo2.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-a", Type: "run.succeeded"}); err != nil {
		t.Fatal(err)
	}
	page, _, _, latest, err = repo2.ReadExecutionEventsRetention(ctx, 4, 100, "")
	if err != nil || len(page) != 1 || page[0].Seq != 5 || latest != 5 {
		t.Fatalf("post-restart page = %+v latest %d err %v, want seq 5", page, latest, err)
	}
}

// TestRepositoryLatestLogSeqParity proves the fs LatestLogSeq is the ADDRESSED
// RUN's durable high-water (single-line journal plus batch lines): for one run
// it equals MaxLogSeq, and another run's higher sequence never leaks into the
// per-run value.
func TestRepositoryLatestLogSeqParity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := New(dir)
	if err := repo.AppendLog(model.LogEntry{Seq: 7, RunID: "run-a", Line: "line"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendLogBatch(LogBatchIdentity{JobID: "job-a", Generation: 1, BatchID: "b1"}, []model.LogEntry{
		{Seq: 8, RunID: "run-a", JobID: "job-a", Line: "batch-1"},
		{Seq: 9, RunID: "run-a", JobID: "job-a", Line: "batch-2"},
	}); err != nil {
		t.Fatal(err)
	}
	latest, err := repo.LatestLogSeq(ctx, "run-a")
	if err != nil || latest != 9 {
		t.Fatalf("LatestLogSeq = %d err %v, want 9", latest, err)
	}
	if max, err := repo.MaxLogSeq(); err != nil || max != latest {
		t.Fatalf("MaxLogSeq = %d err %v, want LatestLogSeq %d", max, err, latest)
	}
	// Another run's higher sequence is invisible to run-a's per-run latest
	// (the process-global watermark still reports it).
	if err := repo.AppendLog(model.LogEntry{Seq: 10, RunID: "run-b", Line: "other"}); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.LatestLogSeq(ctx, "run-a"); err != nil || got != 9 {
		t.Fatalf("LatestLogSeq(run-a) = %d err %v, want 9 (not the global max)", got, err)
	}
	if got, err := repo.LatestLogSeq(ctx, "run-b"); err != nil || got != 10 {
		t.Fatalf("LatestLogSeq(run-b) = %d err %v, want 10", got, err)
	}
	if max, err := repo.MaxLogSeq(); err != nil || max != 10 {
		t.Fatalf("MaxLogSeq = %d err %v, want 10", max, err)
	}
}
