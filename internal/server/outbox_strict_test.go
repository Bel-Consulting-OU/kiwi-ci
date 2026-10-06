package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// mustNewOutboxForTest keeps ordinary tests terse: a nil or healthy store
// never fails construction. Corruption tests call NewOutbox directly.
func mustNewOutboxForTest(store *storage.Repository) *Outbox {
	o, err := NewOutbox(store)
	if err != nil {
		panic(err)
	}
	return o
}

// Filesystem outbox crash matrix: a durable outbox must never silently start
// empty. Corrupt pending records, truncated tails and corrupt ACK records all
// fail construction with the journal bytes preserved for repair.

func writeJournal(t *testing.T, dir, name string, lines []string) string {
	t.Helper()
	root := dir
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func pendingLine(t *testing.T, id string) string {
	t.Helper()
	b, err := json.Marshal(forge.OutboxItem{ID: id, Kind: "forge.check", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func doneLine(t *testing.T, id string) string {
	t.Helper()
	b, err := json.Marshal(outboxDoneRecord{ID: id})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPersistentOutboxCorruptPendingJournalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeJournal(t, dir, outboxFile, []string{pendingLine(t, "ok-1"), "{this is not json"})
	if _, err := NewOutbox(storage.New(dir)); err == nil {
		t.Fatal("corrupt pending journal started an empty outbox")
	}
	// The journal bytes are untouched (repair keeps every valid prefix item).
	b, err := os.ReadFile(filepath.Join(dir, outboxFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "ok-1") {
		t.Fatal("valid prefix item lost during the failed construction")
	}
}

func TestPersistentOutboxTruncatedTailDoesNotStartEmpty(t *testing.T) {
	line := pendingLine(t, "tail-1")
	for cut := 1; cut < len(line); cut++ {
		dir := t.TempDir()
		raw := line[:cut]
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, outboxFile), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewOutbox(storage.New(dir)); err == nil {
			t.Fatalf("truncation at byte %d started an empty outbox", cut)
		}
	}
}

func TestCorruptDoneRecordDoesNotSilentlyStart(t *testing.T) {
	dir := t.TempDir()
	writeJournal(t, dir, outboxFile, []string{pendingLine(t, "p-1")})
	writeJournal(t, dir, outboxDoneFile, []string{doneLine(t, "p-1"), `{"id": "brok`})
	if _, err := NewOutbox(storage.New(dir)); err == nil {
		t.Fatal("corrupt acknowledgment record was silently skipped")
	}
}

func TestHealthyOutboxJournalLoads(t *testing.T) {
	dir := t.TempDir()
	writeJournal(t, dir, outboxFile, []string{pendingLine(t, "live-1"), pendingLine(t, "done-1")})
	writeJournal(t, dir, outboxDoneFile, []string{doneLine(t, "done-1")})
	o, err := NewOutbox(storage.New(dir))
	if err != nil {
		t.Fatalf("healthy journal: %v", err)
	}
	if len(o.items) != 1 || o.items[0].ID != "live-1" {
		t.Fatalf("items = %+v, want only the unfinished intent", o.items)
	}
}

// TestFSOutboxRejectsOversizedJournal pins the byte bound of the fs pending
// journal: startup decodes the journal in full, so a journal over
// outboxFSMaxBytes must fail construction (naming the file for repair)
// instead of materializing unbounded memory or silently truncating.
func TestFSOutboxRejectsOversizedJournal(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, outboxFile)
	if err := os.WriteFile(path, []byte(pendingLine(t, "ok-1")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Only the stat size is checked before decoding, so a sparse file keeps
	// the test fast while genuinely exceeding the bound.
	if err := os.Truncate(path, outboxFSMaxBytes+1); err != nil {
		t.Fatal(err)
	}
	_, err := NewOutbox(storage.New(dir))
	if err == nil {
		t.Fatal("oversized pending journal started an outbox")
	}
	if !strings.Contains(err.Error(), outboxFile) {
		t.Fatalf("error must name the journal for repair, got %v", err)
	}
}

// TestFSOutboxRejectsTooManyItems pins the entry bound of the fs pending
// journal: many tiny valid lines stay below the byte cap, so the item count
// must fail construction (naming the file for repair) rather than decoding an
// unbounded number of entries.
func TestFSOutboxRejectsTooManyItems(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// "{}" is a valid (empty) outbox record; outboxFSMaxItems+1 of them are a
	// few hundred kilobytes, far below outboxFSMaxBytes.
	journal := bytes.Repeat([]byte("{}\n"), outboxFSMaxItems+1)
	path := filepath.Join(dir, outboxFile)
	if err := os.WriteFile(path, journal, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewOutbox(storage.New(dir))
	if err == nil {
		t.Fatal("pending journal with too many entries started an outbox")
	}
	if !strings.Contains(err.Error(), outboxFile) {
		t.Fatalf("error must name the journal for repair, got %v", err)
	}
}
