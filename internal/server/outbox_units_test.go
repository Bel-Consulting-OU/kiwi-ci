package server

// Direct branch coverage for the outbox's small pure helpers and fallbacks:
// semantic content comparison, the delivered-watermark bookkeeping (mark,
// set, bound), supersede checks, done-set marking, the retry fallback ladder
// and the journal load failures. These are exercised without any forge API.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestSameOutboxContentSemantics(t *testing.T) {
	base := forge.OutboxItem{Kind: "github_check", Payload: []byte(`{}`)}
	other := base
	other.Kind = "gitlab_check"
	if sameOutboxContent(base, other) {
		t.Fatal("different kinds compared equal")
	}
	other = base
	other.LogicalKey = "lk"
	if sameOutboxContent(base, other) {
		t.Fatal("different logical keys compared equal")
	}
	other = base
	other.StateVersion = 2
	if sameOutboxContent(base, other) {
		t.Fatal("different state versions compared equal")
	}
	empty := forge.OutboxItem{Kind: "github_check"}
	if !sameOutboxContent(empty, forge.OutboxItem{Kind: "github_check"}) {
		t.Fatal("two empty payloads must normalize to the same content")
	}
	if !sameOutboxContent(forge.OutboxItem{Kind: "k", Payload: []byte(`{"a":1}`)}, forge.OutboxItem{Kind: "k", Payload: []byte("{\n\"a\": 1}")}) {
		t.Fatal("semantically equal payloads must compare equal")
	}
	if sameOutboxContent(forge.OutboxItem{Kind: "k", Payload: []byte(`{`)}, forge.OutboxItem{Kind: "k", Payload: []byte(`{}`)}) {
		t.Fatal("undecodable payload compared equal")
	}
}

func TestOutboxDeliveredWatermarkBookkeeping(t *testing.T) {
	o, err := NewOutbox(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.MarkDelivered("", 1); err != nil {
		t.Fatalf("empty key mark = %v, want nil", err)
	}
	if err := o.MarkDelivered("k", 0); err != nil {
		t.Fatalf("non-positive version mark = %v, want nil", err)
	}
	if err := o.MarkDelivered("k", 2); err != nil {
		t.Fatal(err)
	}
	if err := o.MarkDelivered("k", 1); err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	watermark := o.delivered["k"]
	o.mu.Unlock()
	if watermark != 2 {
		t.Fatalf("watermark = %d, want 2 (never lowered)", watermark)
	}
	if o.Superseded("", 0) {
		t.Fatal("empty identity reported superseded")
	}
	if !o.Superseded("k", 1) {
		t.Fatal("delivered watermark must supersede an older version")
	}
	if o.Superseded("k", 3) {
		t.Fatal("newer version reported superseded")
	}
	// A newer pending item supersedes an older legacy publication.
	o.mu.Lock()
	o.items = append(o.items, forge.OutboxItem{ID: "newer", LogicalKey: "pending", StateVersion: 5})
	o.mu.Unlock()
	if !o.Superseded("pending", 4) {
		t.Fatal("newer pending item did not supersede an older version")
	}

	// setDeliveredLocked ignores empty identities, re-initializes a nil map
	// and never lowers an existing watermark.
	o.mu.Lock()
	o.delivered = nil
	o.setDeliveredLocked("", 1)
	o.setDeliveredLocked("fresh", 0)
	o.setDeliveredLocked("fresh", 3)
	o.setDeliveredLocked("fresh", 1)
	if o.delivered["fresh"] != 3 || len(o.delivered) != 1 {
		t.Fatalf("delivered map = %v", o.delivered)
	}

	// boundDeliveredLocked drops empty/duplicate order entries and
	// non-positive watermarks, and appends unordered live keys.
	o.delivered = map[string]int64{"": 7, "a": 3, "zero": 0, "b": 4}
	o.deliveredOrder = []string{"", "a", "a", "missing"}
	o.boundDeliveredLocked()
	seen := map[string]bool{}
	for _, k := range o.deliveredOrder {
		if k == "" || k == "zero" || k == "missing" {
			t.Fatalf("boundDeliveredLocked kept a bogus key: %v", o.deliveredOrder)
		}
		if seen[k] {
			t.Fatalf("boundDeliveredLocked kept a duplicate: %v", o.deliveredOrder)
		}
		seen[k] = true
		if _, ok := o.delivered[k]; !ok {
			t.Fatalf("order key %q has no watermark", k)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("order = %v, want a and b", o.deliveredOrder)
	}
	if _, ok := o.delivered["zero"]; ok {
		t.Fatal("non-positive watermark not dropped")
	}
	o.mu.Unlock()

	// markDoneLocked: empty ids are ignored, repeats are idempotent.
	o.mu.Lock()
	o.markDoneLocked("")
	o.done = nil
	o.markDoneLocked("id-1")
	o.markDoneLocked("id-1")
	o.markDoneLocked("id-2")
	if !o.done["id-1"] || !o.done["id-2"] || len(o.doneOrder) != 2 {
		t.Fatalf("done set = %v order=%v", o.done, o.doneOrder)
	}
	o.mu.Unlock()

	if o.HasIntent("") {
		t.Fatal("empty intent id reported present")
	}
	if o.HasIntent("id-1") {
		t.Fatal("done id reported as a queued intent")
	}
	o.mu.Lock()
	o.items = append(o.items, forge.OutboxItem{ID: "queued-1"})
	o.mu.Unlock()
	if !o.HasIntent("queued-1") {
		t.Fatal("queued intent reported absent")
	}
}

// narrowOutboxStore exposes exactly the storage.OutboxStore contract, hiding
// the optional versioned/retry capabilities of the wrapped fake.
type narrowOutboxStore struct{ storage.OutboxStore }

// legacyRetryStore adds ONLY the legacy unguarded OutboxRetry method.
type legacyRetryStore struct{ storage.OutboxStore }

func (legacyRetryStore) OutboxRetry(context.Context, string, error, int) error { return nil }

func TestOutboxRetryFallbackLadder(t *testing.T) {
	ctx := context.Background()
	item := forge.OutboxItem{ID: "row-1", Kind: "github_check"}

	o, _ := NewOutbox(nil)
	// No store at all: nothing to record, no error.
	if err := o.retryOutboxRow(ctx, item, errors.New("boom")); err != nil {
		t.Fatalf("nil-store retry = %v, want nil", err)
	}
	// Claim-guarded store: the fake records the retry.
	f := newDBFakeStore()
	o.db = f
	if err := o.retryOutboxRow(ctx, item, errors.New("boom")); err != nil {
		t.Fatalf("claim-guarded retry = %v", err)
	}
	// Legacy fallback: only the unguarded method exists.
	o.db = legacyRetryStore{OutboxStore: newDBFakeStore()}
	if err := o.retryOutboxRow(ctx, item, errors.New("boom")); err != nil {
		t.Fatalf("legacy retry = %v", err)
	}
	// Neither method exists: a clean no-op.
	o.db = narrowOutboxStore{OutboxStore: newDBFakeStore()}
	if err := o.retryOutboxRow(ctx, item, errors.New("boom")); err != nil {
		t.Fatalf("capability-less retry = %v, want nil", err)
	}
	// An internal completion-effect kind disables the dead-letter cap; the
	// call still reaches the store without error.
	internal := forge.OutboxItem{ID: "row-2", Kind: storage.OutboxKindExecutionAttest}
	o.db = f
	if err := o.retryOutboxRow(ctx, internal, errors.New("boom")); err != nil {
		t.Fatalf("internal retry = %v", err)
	}
}

func TestOutboxEnqueueAndVersionedGuards(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOutbox(nil)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := o.Enqueue(canceled, forge.OutboxItem{ID: "x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled enqueue = %v, want context.Canceled", err)
	}
	// An empty ID is generated and the intent is queued.
	if err := o.Enqueue(ctx, forge.OutboxItem{Kind: "github_check", Payload: []byte(`{}`)}); err != nil {
		t.Fatalf("enqueue with generated id = %v", err)
	}
	o.mu.Lock()
	n := len(o.items)
	o.mu.Unlock()
	if n != 1 {
		t.Fatalf("queued items = %d, want 1", n)
	}

	// enqueueVersionedLocked: canceled context, then a store hiding the
	// versioned contract fails closed.
	o.mu.Lock()
	err := o.enqueueVersionedLocked(canceled, forge.OutboxItem{ID: "v", LogicalKey: "lk", StateVersion: 1})
	o.mu.Unlock()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled versioned enqueue = %v", err)
	}
	o.db = narrowOutboxStore{OutboxStore: newDBFakeStore()}
	o.mu.Lock()
	err = o.enqueueVersionedLocked(ctx, forge.OutboxItem{ID: "v", LogicalKey: "lk", StateVersion: 1})
	o.mu.Unlock()
	if err == nil {
		t.Fatal("versioned enqueue without the contract succeeded")
	}
}

func TestOutboxJournalLoadFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, outboxFile), []byte("{not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOutbox(storage.New(root)); err == nil {
		t.Fatal("corrupt pending journal was accepted at startup")
	}
	// A missing journal is simply an empty outbox.
	empty := t.TempDir()
	o, err := NewOutbox(storage.New(empty))
	if err != nil {
		t.Fatalf("missing journal = %v, want nil", err)
	}
	if o == nil {
		t.Fatal("nil outbox")
	}
	// compactLocked is a no-op without an fs store or with a DB store.
	if err := o.compactLocked(); err != nil {
		t.Fatalf("compact without store = %v", err)
	}
}
