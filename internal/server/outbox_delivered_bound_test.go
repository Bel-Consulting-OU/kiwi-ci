package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// noSyncAppendJSONL keeps the production append shape (one JSON line against
// the durable journal) without the per-record fsync. The delivered-bound
// tests create more than outboxDeliveredMaxKeys distinct keys through the
// public MarkDelivered path; thousands of fsyncs would only slow the suite
// without changing the bound under test, while the journal bytes still land
// on disk for the restart assertions.
func noSyncAppendJSONL(t *testing.T) {
	t.Helper()
	old := appendOutboxJSONL
	appendOutboxJSONL = func(o *Outbox, name string, v any) error {
		if o.store == nil {
			return nil
		}
		if err := os.MkdirAll(o.store.Root, 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(o.store.Root, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		return json.NewEncoder(f).Encode(v)
	}
	t.Cleanup(func() { appendOutboxJSONL = old })
}

// TestOutboxDeliveredWatermarkBoundFSRestartLoad is the finding-10
// regression: more than outboxDeliveredMaxKeys distinct logical keys were
// delivered through the public MarkDelivered path, so the in-memory
// watermark map must stay bounded (newest kept, oldest evicted), compaction
// must rewrite the done journal to at most the cap watermark lines, and a
// restart from that journal must load a bounded watermark.
func TestOutboxDeliveredWatermarkBoundFSRestartLoad(t *testing.T) {
	noSyncAppendJSONL(t)
	root := t.TempDir()
	o := mustNewOutboxForTest(storage.New(root))
	total := outboxDeliveredMaxKeys + 64
	newestKey := fmt.Sprintf("lk-%06d", total-1)
	for i := 0; i < total; i++ {
		if err := o.MarkDelivered(fmt.Sprintf("lk-%06d", i), int64(i+1)); err != nil {
			t.Fatalf("MarkDelivered(%d): %v", i, err)
		}
	}

	o.mu.Lock()
	inMem := len(o.delivered)
	order := len(o.deliveredOrder)
	_, oldest := o.delivered["lk-000000"]
	_, newest := o.delivered[newestKey]
	o.mu.Unlock()
	if inMem > outboxDeliveredMaxKeys {
		t.Fatalf("in-memory delivered = %d, want <= %d", inMem, outboxDeliveredMaxKeys)
	}
	if order != inMem {
		t.Fatalf("deliveredOrder = %d, want %d (map and order must stay in sync)", order, inMem)
	}
	if oldest {
		t.Fatal("oldest watermark survived the eager eviction")
	}
	if !newest {
		t.Fatal("newest watermark was evicted")
	}

	// The flush-path rewrite bounds the journal: at most the cap watermark
	// lines remain (doneOrder is empty here, so no done-ID lines).
	if err := o.compactLocked(); err != nil {
		t.Fatal(err)
	}
	watermarks, doneIDs := countJournalRecords(t, filepath.Join(root, outboxDoneFile))
	if watermarks > outboxDeliveredMaxKeys {
		t.Fatalf("done journal holds %d watermark lines, want <= %d", watermarks, outboxDeliveredMaxKeys)
	}
	if doneIDs != 0 {
		t.Fatalf("done journal holds %d unexpected done-ID lines", doneIDs)
	}

	// A restart loads the bounded watermark and keeps the newest keys.
	o2 := mustNewOutboxForTest(storage.New(root))
	o2.mu.Lock()
	loaded := len(o2.delivered)
	loadedOrder := len(o2.deliveredOrder)
	_, oldGone := o2.delivered["lk-000000"]
	_, newestLoaded := o2.delivered[newestKey]
	o2.mu.Unlock()
	if loaded > outboxDeliveredMaxKeys {
		t.Fatalf("restart loaded %d delivered keys, want <= %d", loaded, outboxDeliveredMaxKeys)
	}
	if loadedOrder != loaded {
		t.Fatalf("restart deliveredOrder = %d, want %d", loadedOrder, loaded)
	}
	if oldGone {
		t.Fatal("restart resurrected the oldest watermark")
	}
	if !newestLoaded {
		t.Fatal("restart lost the newest watermark")
	}
}

// countJournalRecords returns the (watermark, done-ID) record counts of a
// done journal.
func countJournalRecords(t *testing.T, path string) (watermarks, doneIDs int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0
		}
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var rec outboxDoneRecord
		if err := dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode done journal: %v", err)
		}
		if rec.LogicalKey != "" {
			watermarks++
		} else if rec.ID != "" {
			doneIDs++
		}
	}
	return watermarks, doneIDs
}

// TestOutboxDeliveredWatermarkBoundDBMode pins the DB-mode half of finding 10:
// flushDBBatch accumulates delivered watermarks for the whole process
// lifetime, so the same eager recency eviction must bound the map with no fs
// journal involved. recordDeliveredLocked is exactly the call flushDBBatch
// makes after a successful ACK.
func TestOutboxDeliveredWatermarkBoundDBMode(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	o := s.outbox
	total := outboxDeliveredMaxKeys + 64
	for i := 0; i < total; i++ {
		o.recordDeliveredLocked(forge.OutboxItem{LogicalKey: fmt.Sprintf("db-lk-%05d", i), StateVersion: 1})
	}
	o.mu.Lock()
	got := len(o.delivered)
	order := len(o.deliveredOrder)
	_, oldest := o.delivered["db-lk-00000"]
	_, newest := o.delivered[fmt.Sprintf("db-lk-%05d", total-1)]
	o.mu.Unlock()
	if got > outboxDeliveredMaxKeys {
		t.Fatalf("DB-mode delivered = %d, want <= %d", got, outboxDeliveredMaxKeys)
	}
	if order != got {
		t.Fatalf("DB-mode deliveredOrder = %d, want %d", order, got)
	}
	if oldest {
		t.Fatal("DB-mode oldest watermark survived the eager eviction")
	}
	if !newest {
		t.Fatal("DB-mode newest watermark was evicted")
	}
}
