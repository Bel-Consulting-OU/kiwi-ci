package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCompactedReceiptKeysArrayAndJournal covers both on-disk forms
// compactedReceiptKeysLocked understands: the legacy JSON array (with
// duplicates and blanks) and the append-only journal (adds, deletes and
// duplicate re-adds preserve most-recent order).
func TestCompactedReceiptKeysArrayAndJournal(t *testing.T) {
	s := &Server{}
	dir := t.TempDir()

	arrayPath := filepath.Join(dir, "array.json")
	if err := os.WriteFile(arrayPath, []byte(`["a","b","","a","c"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.compactedReceiptKeysLocked(arrayPath)
	if err != nil {
		t.Fatalf("array compact: %v", err)
	}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("array compact = %v, want [a b c]", got)
	}

	journalPath := filepath.Join(dir, "journal.jsonl")
	lines := []string{
		`{"key":"a"}`,
		``,
		`{"key":"b"}`,
		`{"key":"a","del":true}`,
		`{"key":""}`,
		`{"key":"c"}`,
		`{"key":"a"}`,
	}
	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(journalPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = s.compactedReceiptKeysLocked(journalPath)
	if err != nil {
		t.Fatalf("journal compact: %v", err)
	}
	if len(got) != 3 || got[0] != "b" || got[1] != "c" || got[2] != "a" {
		t.Fatalf("journal compact = %v, want [b c a]", got)
	}
}

// TestCompactedReceiptKeysErrors covers the corrupt-journal and non-ENOENT
// read-error arms.
func TestCompactedReceiptKeysErrors(t *testing.T) {
	s := &Server{}
	dir := t.TempDir()

	corrupt := filepath.Join(dir, "corrupt.jsonl")
	if err := os.WriteFile(corrupt, []byte("{not json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactedReceiptKeysLocked(corrupt); err == nil {
		t.Fatal("corrupt journal compact succeeded")
	}

	// A legacy array with invalid JSON is rejected too.
	badArray := filepath.Join(dir, "badarray.json")
	if err := os.WriteFile(badArray, []byte("[not-an-array"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactedReceiptKeysLocked(badArray); err == nil {
		t.Fatal("corrupt legacy array compact succeeded")
	}

	// A directory in place of the file is a non-ENOENT read error.
	dirPath := filepath.Join(dir, "isdir")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactedReceiptKeysLocked(dirPath); err == nil {
		t.Fatal("read error was not surfaced")
	}
}

// TestCompactedReceiptKeysNoFileUsesMemory covers the in-memory fallback when
// the journal does not exist.
func TestCompactedReceiptKeysNoFileUsesMemory(t *testing.T) {
	s := &Server{secretReceipts: map[string]bool{"in-memory": true}}
	got, err := s.compactedReceiptKeysLocked(filepath.Join(t.TempDir(), "missing.jsonl"))
	if err != nil || len(got) != 1 || got[0] != "in-memory" {
		t.Fatalf("in-memory compact = %v, %v", got, err)
	}
}

// TestLoadSecretReceiptsEdges covers the empty-file, corrupt-array and
// journal-replay arms.
func TestLoadSecretReceiptsEdges(t *testing.T) {
	dir := t.TempDir()

	empty := &Server{}
	emptyPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := empty.loadSecretReceipts(dir); err != nil {
		t.Fatalf("empty receipts file: %v", err)
	}

	bad := &Server{}
	if err := os.WriteFile(filepath.Join(dir, secretReceiptsFile), []byte("[bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bad.loadSecretReceipts(dir); err == nil {
		t.Fatal("corrupt legacy array was accepted")
	}

	// Journal replay ignores blank lines and empty keys, applies deletes.
	journal := &Server{}
	var buf bytes.Buffer
	for _, rec := range []secretReceiptRecord{{Key: "x"}, {Key: ""}, {Key: "x", Del: true}, {Key: "y"}} {
		b, _ := json.Marshal(rec)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	buf.WriteString("\n")
	if err := os.WriteFile(filepath.Join(dir, secretReceiptsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := journal.loadSecretReceipts(dir); err != nil {
		t.Fatalf("journal replay: %v", err)
	}
	if journal.secretReceipts["x"] || !journal.secretReceipts["y"] {
		t.Fatalf("journal replay set = %v, want only y", journal.secretReceipts)
	}

	if (&Server{}).replaySecretReceiptsJournalLocked([]byte("{bad}\n")) == nil {
		t.Fatal("corrupt journal line was accepted")
	}
}

// TestPersistSecretReceiptsNoDataDir covers the no-op arm.
func TestPersistSecretReceiptsNoDataDir(t *testing.T) {
	s := &Server{}
	if err := s.persistSecretReceiptsLocked(); err != nil {
		t.Fatalf("persist with no data dir = %v", err)
	}
}
