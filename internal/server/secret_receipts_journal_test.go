package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeReceiptJournal(t *testing.T, path string, keys []string) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, k := range keys {
		if err := enc.Encode(secretReceiptRecord{Key: k}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSecretReceiptCompactionBounds is the G2-F regression half one: an
// oversized append-only receipt journal is compacted to a bounded live set
// (memory and file), keeping the most recent receipts.
func TestSecretReceiptCompactionBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, secretReceiptsFile)
	total := secretReceiptsMaxEntries + 500
	keys := make([]string, 0, total)
	for i := 0; i < total; i++ {
		keys = append(keys, fmt.Sprintf("k%06d", i))
	}
	writeReceiptJournal(t, path, keys)

	s := New("t")
	s.dataDir = dir
	if err := s.loadSecretReceipts(dir); err != nil {
		t.Fatal(err)
	}
	if len(s.secretReceipts) != total {
		t.Fatalf("loaded %d receipts, want %d", len(s.secretReceipts), total)
	}
	s.mu.Lock()
	err := s.persistSecretReceiptsLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.secretReceipts) > secretReceiptsMaxEntries {
		t.Fatalf("live receipts = %d, want <= %d", len(s.secretReceipts), secretReceiptsMaxEntries)
	}
	if lines := countJournalLines(t, path); lines > secretReceiptsMaxEntries {
		t.Fatalf("journal has %d records, want <= %d", lines, secretReceiptsMaxEntries)
	}
	if !s.secretReceipts[keys[len(keys)-1]] {
		t.Fatal("most recent receipt was compacted away")
	}
	if s.secretReceipts[keys[0]] {
		t.Fatal("oldest receipt survived the bounded window")
	}
}

// TestSecretReceiptAppendOnlyAndRelease covers the append-only journal half:
// each delivery appends one line (no full-file rewrite), a replay writes
// nothing, and a release appends a tombstone that removes the receipt on
// reload.
func TestSecretReceiptAppendOnlyAndRelease(t *testing.T) {
	dir := t.TempDir()
	s := New("t")
	s.dataDir = dir
	s.secretReceipts = map[string]bool{}
	if ok, err := s.markSecretDelivered("a"); err != nil || !ok {
		t.Fatalf("mark a = %v,%v", ok, err)
	}
	size1 := fileSize(t, filepath.Join(dir, secretReceiptsFile))
	if ok, err := s.markSecretDelivered("a"); err != nil || ok {
		t.Fatalf("replay a = %v,%v", ok, err)
	}
	if got := fileSize(t, filepath.Join(dir, secretReceiptsFile)); got != size1 {
		t.Fatalf("replay rewrote the journal: %d -> %d", size1, got)
	}
	if ok, err := s.markSecretDelivered("b"); err != nil || !ok {
		t.Fatalf("mark b = %v,%v", ok, err)
	}
	size2 := fileSize(t, filepath.Join(dir, secretReceiptsFile))
	if size2 <= size1 || size2-size1 > 128 {
		t.Fatalf("append grew the journal by %d bytes, want one small line", size2-size1)
	}
	if err := s.releaseSecretReceipt("a"); err != nil {
		t.Fatal(err)
	}
	s2 := New("t")
	if err := s2.loadSecretReceipts(dir); err != nil {
		t.Fatal(err)
	}
	if s2.secretReceipts["a"] {
		t.Fatal("released receipt survived a restart")
	}
	if !s2.secretReceipts["b"] {
		t.Fatal("unrelated receipt lost across restart")
	}
}

// TestSecretReceiptLegacyArrayMigration pins backward compatibility: a
// pre-journal JSON array loads and is rewritten in the journal form so later
// appends cannot mix formats.
func TestSecretReceiptLegacyArrayMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, secretReceiptsFile)
	if err := os.WriteFile(path, []byte(`["a|1|tok","b|2|tok"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New("t")
	if err := s.loadSecretReceipts(dir); err != nil {
		t.Fatal(err)
	}
	if !s.secretReceipts["a|1|tok"] || !s.secretReceipts["b|2|tok"] {
		t.Fatalf("legacy receipts not loaded: %v", s.secretReceipts)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		t.Fatal("legacy array was not migrated to journal form")
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}
