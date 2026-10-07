package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// noopOutboxDispatch acknowledges every intent without an external effect.
func noopOutboxDispatch(context.Context, forge.OutboxItem) error { return nil }

// deliverVersionedFS enqueues one versioned item and flushes it with the no-op
// dispatcher, leaving BOTH a delivered watermark and a retained versioned
// done-ID record ("key#version") in the outbox, exactly like a real delivery.
func deliverVersionedFS(t *testing.T, o *Outbox, key string, version int64) {
	t.Helper()
	id := fmt.Sprintf("%s#%d", key, version)
	if err := o.Enqueue(context.Background(), forge.OutboxItem{
		ID: id, Kind: "test-versioned", LogicalKey: key, StateVersion: version,
	}); err != nil {
		t.Fatalf("Enqueue(%s): %v", id, err)
	}
	n, err := o.Flush(context.Background(), noopOutboxDispatch)
	if err != nil || n != 1 {
		t.Fatalf("Flush = %d, %v; want one delivery", n, err)
	}
}

// fabricateOrder returns a delivered map/order pair one entry over the cap
// with key as the OLDEST watermark, plus fill keys.
func fabricateOrder(key string) (map[string]int64, []string) {
	delivered := map[string]int64{key: 5}
	order := []string{key}
	for i := 0; i < outboxDeliveredMaxKeys+1; i++ {
		fill := fmt.Sprintf("fill-%06d", i)
		delivered[fill] = 1
		order = append(order, fill)
	}
	return delivered, order
}

// TestOutboxWatermarkEvictionSkipsEvidencedKeys is finding-2 test (a): a key
// with a retained versioned done-ID or with a pending queued item is never
// evicted, even when the cap demands an eviction and the key is the oldest.
func TestOutboxWatermarkEvictionSkipsEvidencedKeys(t *testing.T) {
	t.Run("retained done id", func(t *testing.T) {
		o := mustNewOutboxForTest(nil)
		o.done["evidenced#7"] = true
		o.doneOrder = []string{"evidenced#7"}
		delivered, order := fabricateOrder("evidenced")
		trimmed := o.trimDeliveredOrderLocked(delivered, order)
		if _, ok := delivered["evidenced"]; !ok {
			t.Fatal("watermark with a retained versioned done ID was evicted")
		}
		if len(trimmed) != outboxDeliveredMaxKeys {
			t.Fatalf("trimmed order = %d, want %d (blocked key kept, eligible fill evicted)", len(trimmed), outboxDeliveredMaxKeys)
		}
	})
	t.Run("pending item", func(t *testing.T) {
		o := mustNewOutboxForTest(nil)
		if err := o.Enqueue(context.Background(), forge.OutboxItem{
			ID: "evidenced#9", Kind: "test-versioned", LogicalKey: "evidenced", StateVersion: 9,
		}); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		delivered, order := fabricateOrder("evidenced")
		trimmed := o.trimDeliveredOrderLocked(delivered, order)
		if _, ok := delivered["evidenced"]; !ok {
			t.Fatal("watermark referenced by a pending item was evicted")
		}
		if len(trimmed) != outboxDeliveredMaxKeys {
			t.Fatalf("trimmed order = %d, want %d", len(trimmed), outboxDeliveredMaxKeys)
		}
	})
	t.Run("fs delivery keeps done-id evidence", func(t *testing.T) {
		noSyncAppendJSONL(t)
		o := mustNewOutboxForTest(storage.New(t.TempDir()))
		deliverVersionedFS(t, o, "keep-evidenced", 7)
		for i := 0; i < outboxDeliveredMaxKeys+32; i++ {
			if err := o.MarkDelivered(fmt.Sprintf("fill-%06d", i), 1); err != nil {
				t.Fatalf("MarkDelivered(%d): %v", i, err)
			}
		}
		o.mu.Lock()
		version, kept := o.delivered["keep-evidenced"]
		size := len(o.delivered)
		o.mu.Unlock()
		if !kept || version != 7 {
			t.Fatalf("delivered[keep-evidenced] = %d, %t; want 7, true", version, kept)
		}
		if size > outboxDeliveredMaxKeys+1 {
			t.Fatalf("delivered grew to %d, want the cap plus at most the evidenced key", size)
		}
		if !o.Superseded("keep-evidenced", 3) {
			t.Fatal("lower version accepted while the watermark evidence is retained")
		}
	})
}

// TestOutboxWatermarkEvictionResumesAfterEvidenceRemoved is finding-2 test
// (b): once the retained done ID and the pending item are gone (as a
// compaction/ack leaves them), the key becomes evictable again and the
// oldest-first eviction resumes.
func TestOutboxWatermarkEvictionResumesAfterEvidenceRemoved(t *testing.T) {
	o := mustNewOutboxForTest(nil)
	o.done["evidenced#7"] = true
	o.doneOrder = []string{"evidenced#7"}
	o.items = []forge.OutboxItem{{ID: "evidenced#9", LogicalKey: "evidenced", StateVersion: 9}}
	delivered, order := fabricateOrder("evidenced")

	trimmed := o.trimDeliveredOrderLocked(delivered, order)
	if _, ok := delivered["evidenced"]; !ok {
		t.Fatal("watermark evicted while evidence existed")
	}
	// Evidence removed: compact drops the retained done ID and the ack/pop
	// removes the pending item. A new delivery pushes the order over the cap
	// again, and the now-eligible oldest key is evicted.
	delete(o.done, "evidenced#7")
	o.doneOrder = nil
	o.items = nil
	delivered["newest"] = 1
	trimmed = append(trimmed, "newest")
	trimmed = o.trimDeliveredOrderLocked(delivered, trimmed)
	if _, ok := delivered["evidenced"]; ok {
		t.Fatal("watermark stayed after its evidence was removed; eviction did not resume")
	}
	if len(trimmed) != outboxDeliveredMaxKeys {
		t.Fatalf("trimmed order = %d, want %d", len(trimmed), outboxDeliveredMaxKeys)
	}

	// The same resumption through the real ack/trim path: trimDoneLocked
	// drops an aged-out done ID, then the bound pass evicts its watermark.
	mem := mustNewOutboxForTest(nil)
	mem.done["aged#3"] = true
	mem.doneOrder = []string{"aged#3"}
	mem.setDeliveredLocked("aged", 3)
	for i := 0; i < outboxDoneMaxIDs+1; i++ {
		id := fmt.Sprintf("newer-%d", i)
		mem.done[id] = true
		mem.doneOrder = append(mem.doneOrder, id)
	}
	for i := 0; i < outboxDeliveredMaxKeys+1; i++ {
		mem.setDeliveredLocked(fmt.Sprintf("later-%06d", i), 1)
	}
	mem.mu.Lock()
	mem.trimDoneLocked()
	mem.mu.Unlock()
	// The trim dropped the aged done ID; the next delivery pushes the order
	// over the cap and the now-eligible oldest watermark is evicted.
	mem.setDeliveredLocked("after-trim", 1)
	mem.mu.Lock()
	_, survived := mem.delivered["aged"]
	mem.mu.Unlock()
	if survived {
		t.Fatal("watermark survived the done-ID trim that removed its evidence")
	}
}

// TestOutboxLowerVersionRejectedWhileEvidenceHeld is finding-2 test (c): a
// lower version injected while the evidenced watermark is still held must be
// rejected, so a stable forge check cannot regress success -> running.
func TestOutboxLowerVersionRejectedWhileEvidenceHeld(t *testing.T) {
	noSyncAppendJSONL(t)
	o := mustNewOutboxForTest(storage.New(t.TempDir()))
	deliverVersionedFS(t, o, "stable-key", 9)
	for i := 0; i < outboxDeliveredMaxKeys+16; i++ {
		if err := o.MarkDelivered(fmt.Sprintf("pressure-%06d", i), 1); err != nil {
			t.Fatalf("MarkDelivered(%d): %v", i, err)
		}
	}
	if err := o.Enqueue(context.Background(), forge.OutboxItem{
		ID: "stable-key#4", Kind: "test-versioned", LogicalKey: "stable-key", StateVersion: 4,
	}); err != nil {
		t.Fatalf("Enqueue lower version: %v", err)
	}
	if o.HasIntent("stable-key#4") {
		t.Fatal("lower version was queued despite the retained watermark")
	}
	if !o.Superseded("stable-key", 4) {
		t.Fatal("Superseded(4) = false, want the retained watermark to reject it")
	}
	o.mu.Lock()
	version := o.delivered["stable-key"]
	o.mu.Unlock()
	if version != 9 {
		t.Fatalf("delivered[stable-key] = %d, want 9", version)
	}
}

// TestOutboxRestartLoadKeepsRetainedWatermarkMonotonic is finding-2 test (d):
// a restart reloads an over-cap watermark journal, keeps the keys whose
// evidence is retained (a versioned done ID and a pending item), evicts only
// the eligible oldest keys, and still rejects a lower version afterwards.
func TestOutboxRestartLoadKeepsRetainedWatermarkMonotonic(t *testing.T) {
	root := t.TempDir()
	var done bytes.Buffer
	enc := json.NewEncoder(&done)
	// Oldest record: a retained versioned done ID is durable evidence.
	if err := enc.Encode(outboxDoneRecord{ID: "restart-key#5"}); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(outboxDoneRecord{LogicalKey: "pending-key", StateVersion: 2}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < outboxDeliveredMaxKeys+64; i++ {
		if err := enc.Encode(outboxDoneRecord{LogicalKey: fmt.Sprintf("rk-%06d", i), StateVersion: int64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, outboxDoneFile), done.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var pending bytes.Buffer
	if err := json.NewEncoder(&pending).Encode(forge.OutboxItem{
		ID: "pending-key#9", Kind: "test-versioned", LogicalKey: "pending-key", StateVersion: 9,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, outboxFile), pending.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	o := mustNewOutboxForTest(storage.New(root))
	o.mu.Lock()
	restart, hasRestart := o.delivered["restart-key"]
	pendingWM, hasPending := o.delivered["pending-key"]
	size := len(o.delivered)
	_, oldestEvicted := o.delivered["rk-000000"]
	o.mu.Unlock()
	if !hasRestart || restart != 5 {
		t.Fatalf("restart-key watermark = %d, %t; want 5, true", restart, hasRestart)
	}
	if !hasPending || pendingWM != 2 {
		t.Fatalf("pending-key watermark = %d, %t; want 2, true", pendingWM, hasPending)
	}
	if size > outboxDeliveredMaxKeys+2 {
		t.Fatalf("restart loaded %d watermarks, want the cap plus at most the two evidenced keys", size)
	}
	if oldestEvicted {
		t.Fatal("oldest eligible rk-000000 watermark survived the load bound")
	}
	if !o.Superseded("restart-key", 1) {
		t.Fatal("lower version accepted after restart although the done ID was retained")
	}
	if err := o.Enqueue(context.Background(), forge.OutboxItem{
		ID: "restart-key#2", Kind: "test-versioned", LogicalKey: "restart-key", StateVersion: 2,
	}); err != nil {
		t.Fatalf("Enqueue lower version after restart: %v", err)
	}
	if o.HasIntent("restart-key#2") {
		t.Fatal("lower version was queued after restart despite the retained watermark")
	}
}
