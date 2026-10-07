package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCompactedReceiptRecordsArrayAndJournal covers both on-disk forms
// compactedReceiptRecordsLocked understands: the legacy JSON array (with
// duplicates and blanks) and the append-only journal (adds, deletes and
// duplicate re-adds preserve most-recent order, coalesced to the latest state
// per key).
func TestCompactedReceiptRecordsArrayAndJournal(t *testing.T) {
	s := &Server{}
	dir := t.TempDir()

	arrayPath := filepath.Join(dir, "array.json")
	if err := os.WriteFile(arrayPath, []byte(`["a","b","","a","c"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.compactedReceiptRecordsLocked(arrayPath)
	if err != nil {
		t.Fatalf("array compact: %v", err)
	}
	if keys := recordKeys(got); len(keys) != 3 || keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Fatalf("array compact = %v, want [a b c]", keys)
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
	got, err = s.compactedReceiptRecordsLocked(journalPath)
	if err != nil {
		t.Fatalf("journal compact: %v", err)
	}
	if keys := recordKeys(got); len(keys) != 3 || keys[0] != "b" || keys[1] != "c" || keys[2] != "a" {
		t.Fatalf("journal compact = %v, want [b c a]", keys)
	}
}

// recordKeys extracts the ordered keys of compacted records for assertions.
func recordKeys(records []secretReceiptRecord) []string {
	keys := make([]string, 0, len(records))
	for _, rec := range records {
		keys = append(keys, rec.Key)
	}
	return keys
}

// TestCompactedReceiptsLifecycleRetention pins the finding-6 rule: a receipt
// whose job is still live (same generation, non-terminal, unexpired lease) is
// never evicted to satisfy the cap, while terminal/absent keys are trimmed
// oldest first. Once the job turns terminal the live receipt becomes
// evictable.
func TestCompactedReceiptsLifecycleRetention(t *testing.T) {
	s := &Server{}
	dir := t.TempDir()
	exp := time.Now().UTC().Add(time.Hour)
	s.jobs = map[string]model.Job{
		"live-job": {ID: "live-job", Status: model.StatusRunning, LeaseGeneration: 3, LeaseExpiresAt: &exp},
	}
	liveKey := secretReceiptKey("live-job", 3, "tok")

	// One live receipt plus more evictable receipts than the cap allows.
	records := []secretReceiptRecord{{Key: liveKey, RecipientPublic: []byte("pub"), Ciphertext: []byte("ct")}}
	for i := 0; i < secretReceiptsMaxEntries; i++ {
		records = append(records, secretReceiptRecord{Key: fmt.Sprintf("dead-job|1|s%06d", i)})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "lifecycle.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.compactedReceiptRecordsLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > secretReceiptsMaxEntries {
		t.Fatalf("compacted records = %d, want <= %d", len(got), secretReceiptsMaxEntries)
	}
	kept := map[string]bool{}
	for _, rec := range got {
		kept[rec.Key] = true
	}
	if !kept[liveKey] {
		t.Fatal("live receipt was evicted to satisfy the cap")
	}
	if kept[records[1].Key] {
		t.Fatal("oldest evictable receipt survived the bounded window")
	}
	if !kept[records[len(records)-1].Key] {
		t.Fatal("newest evictable receipt was dropped")
	}

	// Generation advance makes the previously live receipt evictable.
	s.jobs["live-job"] = model.Job{ID: "live-job", Status: model.StatusRunning, LeaseGeneration: 4, LeaseExpiresAt: &exp}
	got, err = s.compactedReceiptRecordsLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range got {
		if rec.Key == liveKey {
			t.Fatal("receipt of a superseded generation was retained")
		}
	}

	// Terminal status makes it evictable too.
	s.jobs["live-job"] = model.Job{ID: "live-job", Status: model.StatusSuccess, LeaseGeneration: 3, LeaseExpiresAt: &exp}
	got, err = s.compactedReceiptRecordsLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range got {
		if rec.Key == liveKey {
			t.Fatal("receipt of a terminal job was retained")
		}
	}

	// A live set larger than the cap is retained in full (documented
	// overshoot): live claims must never be evicted.
	s.jobs = map[string]model.Job{}
	liveTotal := secretReceiptsMaxEntries + 10
	var liveBuf bytes.Buffer
	liveEnc := json.NewEncoder(&liveBuf)
	for i := 0; i < liveTotal; i++ {
		jobID := fmt.Sprintf("live-%06d", i)
		s.jobs[jobID] = model.Job{ID: jobID, Status: model.StatusRunning, LeaseGeneration: 1, LeaseExpiresAt: &exp}
		if err := liveEnc.Encode(secretReceiptRecord{Key: secretReceiptKey(jobID, 1, "tok")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, liveBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = s.compactedReceiptRecordsLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != liveTotal {
		t.Fatalf("live set compaction = %d records, want the full %d (overshoot allowed)", len(got), liveTotal)
	}
}

// TestCompactedReceiptRecordsErrors covers the corrupt-journal and non-ENOENT
// read-error arms.
func TestCompactedReceiptRecordsErrors(t *testing.T) {
	s := &Server{}
	dir := t.TempDir()

	corrupt := filepath.Join(dir, "corrupt.jsonl")
	if err := os.WriteFile(corrupt, []byte("{not json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactedReceiptRecordsLocked(corrupt); err == nil {
		t.Fatal("corrupt journal compact succeeded")
	}

	// A legacy array with invalid JSON is rejected too.
	badArray := filepath.Join(dir, "badarray.json")
	if err := os.WriteFile(badArray, []byte("[not-an-array"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactedReceiptRecordsLocked(badArray); err == nil {
		t.Fatal("corrupt legacy array compact succeeded")
	}

	// A directory in place of the file is a non-ENOENT read error.
	dirPath := filepath.Join(dir, "isdir")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.compactedReceiptRecordsLocked(dirPath); err == nil {
		t.Fatal("read error was not surfaced")
	}
}

// TestCompactedReceiptRecordsNoFileUsesMemory covers the in-memory fallback
// when the journal does not exist.
func TestCompactedReceiptRecordsNoFileUsesMemory(t *testing.T) {
	s := &Server{secretReceipts: map[string]secretReceipt{"in-memory": {}}}
	got, err := s.compactedReceiptRecordsLocked(filepath.Join(t.TempDir(), "missing.jsonl"))
	if err != nil || len(got) != 1 || got[0].Key != "in-memory" {
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
	if _, x := journal.secretReceipts["x"]; x {
		t.Fatalf("journal replay set = %v, want only y", journal.secretReceipts)
	}
	if _, y := journal.secretReceipts["y"]; !y {
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
