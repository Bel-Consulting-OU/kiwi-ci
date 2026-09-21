package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestOutboxFSVersionedRetirementFailureNeverPublishesOlder is the P2
// regression for enqueueVersionedLocked's fs ordering. The new version's
// JSONL line is appended durably, but the retirement (done) append of the
// older pending version fails. Without a restart, the old version must never
// reach the dispatcher even though the newer version was absent from the
// in-memory queue in the defect state: the flush's newer-version guard must
// see the durably accepted version, and the subsequent successful flush must
// publish exactly the new version once.
func TestOutboxFSVersionedRetirementFailureNeverPublishesOlder(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := storage.New(dir)
	o := NewOutbox(store)
	key := forgeCheckLogicalKey("github.com", "run-retire", "Pipeline")
	oldItem := forge.OutboxItem{
		ID: forgeCheckRowID(key, 1), Kind: forge.OutboxKindGitHubCheck,
		Payload: []byte(`{"state":"queued"}`), LogicalKey: key, StateVersion: 1,
	}
	if err := o.Enqueue(ctx, oldItem); err != nil {
		t.Fatalf("baseline enqueue: %v", err)
	}

	// Arm the fs append seam so the new line lands durably and the FIRST
	// retirement (done) append fails: the exact defect window.
	seamErr := errors.New("injected: first retirement append failed")
	restore := appendOutboxJSONL
	t.Cleanup(func() { appendOutboxJSONL = restore })
	doneAppends := 0
	appendOutboxJSONL = func(ob *Outbox, name string, v any) error {
		if name == outboxDoneFile {
			doneAppends++
			if doneAppends == 1 {
				return seamErr
			}
		}
		return restore(ob, name, v)
	}
	newItem := forge.OutboxItem{
		ID: forgeCheckRowID(key, 2), Kind: forge.OutboxKindGitHubCheck,
		Payload: []byte(`{"state":"completed"}`), LogicalKey: key, StateVersion: 2,
	}
	err := o.Enqueue(ctx, newItem)
	appendOutboxJSONL = restore // seam cleared for the flushes below
	if !errors.Is(err, seamErr) {
		t.Fatalf("enqueue = %v, want the injected retirement append failure", err)
	}
	if doneAppends != 1 {
		t.Fatalf("retirement appends attempted = %d, want the injected first attempt", doneAppends)
	}
	// The newer line IS durable even though the enqueue failed.
	items, rerr := o.readItems()
	if rerr != nil {
		t.Fatalf("read durable journal: %v", rerr)
	}
	durable := false
	for _, it := range items {
		if it.ID == newItem.ID {
			durable = true
		}
	}
	if !durable {
		t.Fatal("newer version line is not durable after the failed retirement append")
	}

	// Flush WITHOUT a restart, with the remote failing: the old payload must
	// never even be attempted. In the defect ordering the queue still holds
	// only the old version, so this flush dispatches it first.
	remoteDown := errors.New("remote forge unavailable")
	var attempted []string
	n, ferr := o.Flush(ctx, func(_ context.Context, it forge.OutboxItem) error {
		attempted = append(attempted, it.ID)
		return remoteDown
	})
	if !errors.Is(ferr, remoteDown) {
		t.Fatalf("flush = %v, want the injected remote failure", ferr)
	}
	if n != 0 {
		t.Fatalf("failed flush dispatched %d intent(s), want 0", n)
	}
	for _, id := range attempted {
		if id == oldItem.ID {
			t.Fatalf("superseded version %s was dispatched after a newer version was durably accepted", id)
		}
	}
	if len(attempted) != 1 || attempted[0] != newItem.ID {
		t.Fatalf("dispatch attempts = %v, want only the newer version %s", attempted, newItem.ID)
	}

	// The subsequent successful flush publishes exactly the new version; the
	// old payload is never dispatched or acked.
	var published []string
	n, ferr = o.Flush(ctx, func(_ context.Context, it forge.OutboxItem) error {
		published = append(published, it.ID)
		return nil
	})
	if ferr != nil {
		t.Fatalf("recovery flush: %v", ferr)
	}
	if n != 1 || len(published) != 1 || published[0] != newItem.ID {
		t.Fatalf("recovery flush = n=%d published=%v, want exactly the newer version %s", n, published, newItem.ID)
	}
	if pending := o.Pending(); len(pending) != 0 {
		t.Fatalf("queue after the recovery flush = %+v, want empty", pending)
	}
	// A retry of the deterministic enqueue converges to a no-op.
	if err := o.Enqueue(ctx, newItem); err != nil {
		t.Fatalf("post-delivery retry = %v, want a converged no-op", err)
	}
	// The newer ack (with its versioned identity) is durable in the done
	// journal; a restart drops the superseded journal line.
	done, rerr := os.ReadFile(filepath.Join(dir, outboxDoneFile))
	if rerr != nil {
		t.Fatalf("read done journal: %v", rerr)
	}
	if !strings.Contains(string(done), newItem.ID) {
		t.Fatalf("done journal lacks the newer version's ack: %s", done)
	}
	o2 := NewOutbox(store)
	if pending := o2.Pending(); len(pending) != 0 {
		t.Fatalf("restart replayed %+v, want nothing (the newer watermark retires the old line)", pending)
	}
}
