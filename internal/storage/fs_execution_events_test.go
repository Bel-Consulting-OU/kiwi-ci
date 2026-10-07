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
