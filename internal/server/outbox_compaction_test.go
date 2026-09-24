package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func countJournalLines(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// TestOutboxDoneJournalCompactionBoundsRestartLoad is the G2-E regression: an
// oversized append-only done journal is compacted by the flush path so a
// restart loads a bounded done set, while the most recent acked IDs stay acked
// (re-enqueue is a no-op) and acked pending-journal lines are dropped.
func TestOutboxDoneJournalCompactionBoundsRestartLoad(t *testing.T) {
	root := t.TempDir()
	total := outboxDoneMaxIDs + 100

	// Seed an oversized append-only done journal plus the acked lines it
	// covers in the pending journal, exactly the shape the old design left
	// behind (no per-ack fsync needed to reproduce it).
	var done bytes.Buffer
	var pending bytes.Buffer
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("id-%06d", i)
		if err := json.NewEncoder(&done).Encode(outboxDoneRecord{ID: id}); err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(&pending).Encode(forge.OutboxItem{ID: id, Kind: forge.OutboxKindWebhookCall, Payload: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, outboxDoneFile), done.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, outboxFile), pending.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	o := NewOutbox(storage.New(root))
	// The flush path triggers compaction even with an empty queue.
	if _, err := o.Flush(context.Background(), func(context.Context, forge.OutboxItem) error { return nil }); err != nil {
		t.Fatal(err)
	}

	if got := countJournalLines(t, filepath.Join(root, outboxDoneFile)); got > outboxDoneMaxIDs {
		t.Fatalf("done journal has %d records, want <= %d after compaction", got, outboxDoneMaxIDs)
	}
	if got := countJournalLines(t, filepath.Join(root, outboxFile)); got != 0 {
		t.Fatalf("pending journal still holds %d acked lines after compaction", got)
	}

	// A restart loads a bounded done set.
	o2 := NewOutbox(storage.New(root))
	o2.mu.Lock()
	loaded := len(o2.done)
	o2.mu.Unlock()
	if loaded > outboxDoneMaxIDs {
		t.Fatalf("restart loaded %d done ids, want <= %d", loaded, outboxDoneMaxIDs)
	}
	// The most recent acked ID is still acked: re-enqueue is a no-op.
	lastID := fmt.Sprintf("id-%06d", total-1)
	if err := o2.Enqueue(context.Background(), forge.OutboxItem{ID: lastID, Kind: forge.OutboxKindWebhookCall, Payload: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("re-enqueue acked id: %v", err)
	}
	for _, it := range o2.Pending() {
		if it.ID == lastID {
			t.Fatal("acked id was re-queued after restart")
		}
	}
}
