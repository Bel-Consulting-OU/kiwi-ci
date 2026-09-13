package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kiwici/kiwi/internal/forge"
	"github.com/kiwici/kiwi/internal/storage"
)

func testOutboxItem(t *testing.T, kind, payload string) forge.OutboxItem {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	return forge.OutboxItem{ID: id, Kind: kind, Payload: json.RawMessage(payload)}
}

func TestOutboxFlushDispatchesAndEmpties(t *testing.T) {
	o := NewOutbox(nil)
	a := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{"repo_full_name":"octocat/hello-world","sha":"s"}`)
	b := testOutboxItem(t, forge.OutboxKindGitHubStatus, `{"repo_full_name":"octocat/hello-world","sha":"s"}`)
	if err := o.Enqueue(a); err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(b); err != nil {
		t.Fatal(err)
	}
	var order []string
	n, err := o.Flush(context.Background(), func(_ context.Context, it forge.OutboxItem) error {
		order = append(order, it.ID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(o.Pending()) != 0 {
		t.Fatalf("flush did not drain queue: n=%d pending=%d", n, len(o.Pending()))
	}
	if order[0] != a.ID || order[1] != b.ID {
		t.Fatalf("FIFO order violated: %v", order)
	}
}

func TestOutboxFlushStopsOnFailure(t *testing.T) {
	o := NewOutbox(nil)
	a := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{}`)
	b := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{}`)
	_ = o.Enqueue(a)
	_ = o.Enqueue(b)
	boom := errors.New("api down")
	var calls int
	n, err := o.Flush(context.Background(), func(_ context.Context, it forge.OutboxItem) error {
		calls++
		if it.ID == a.ID {
			return boom
		}
		return nil
	})
	if err != boom {
		t.Fatalf("want dispatch error, got %v", err)
	}
	if n != 0 {
		t.Fatalf("no items should have dispatched, got %d", n)
	}
	if calls != 1 {
		t.Fatalf("dispatch must stop at first failure: %d calls", calls)
	}
	if pending := o.Pending(); len(pending) != 2 {
		t.Fatalf("failed flush must keep items: %d", len(pending))
	}
	// A later flush that succeeds drains everything.
	n, err = o.Flush(context.Background(), func(_ context.Context, it forge.OutboxItem) error { return nil })
	if err != nil || n != 2 || len(o.Pending()) != 0 {
		t.Fatalf("retry flush: n=%d err=%v pending=%d", n, err, len(o.Pending()))
	}
}

func TestOutboxRestartReplay(t *testing.T) {
	dir := t.TempDir()
	store := storage.New(dir)
	o1 := NewOutbox(store)
	a := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{"repo_full_name":"r"}`)
	b := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{"repo_full_name":"r"}`)
	c := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{"repo_full_name":"r"}`)
	if err := o1.Enqueue(a); err != nil {
		t.Fatal(err)
	}
	if err := o1.Enqueue(b); err != nil {
		t.Fatal(err)
	}
	// Flush a only; b stays queued (simulates crash after a dispatch).
	if _, err := o1.Flush(context.Background(), func(_ context.Context, it forge.OutboxItem) error {
		if it.ID == a.ID {
			return nil
		}
		return errors.New("crash before dispatch")
	}); err == nil {
		t.Fatal("expected error")
	}
	if err := o1.Enqueue(c); err != nil {
		t.Fatal(err)
	}

	// A restarted control plane replays the unflushed intents (b, c) and
	// skips the processed one (a).
	o2 := NewOutbox(store)
	pending := o2.Pending()
	if len(pending) != 2 {
		t.Fatalf("replay loaded %d items, want 2", len(pending))
	}
	ids := map[string]bool{}
	for _, it := range pending {
		ids[it.ID] = true
	}
	if ids[a.ID] || !ids[b.ID] || !ids[c.ID] {
		t.Fatalf("replay set wrong: %v", ids)
	}
	var dispatched []string
	if _, err := o2.Flush(context.Background(), func(_ context.Context, it forge.OutboxItem) error {
		dispatched = append(dispatched, it.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(dispatched) != 2 || len(o2.Pending()) != 0 {
		t.Fatalf("replayed flush: %v pending=%d", dispatched, len(o2.Pending()))
	}

	// A second restart finds an empty queue: done markers filtered
	// everything.
	o3 := NewOutbox(store)
	if len(o3.Pending()) != 0 {
		t.Fatalf("post-restart queue not empty: %d", len(o3.Pending()))
	}
}

func TestOutboxInMemoryPersistenceOptional(t *testing.T) {
	o := NewOutbox(nil)
	it := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{}`)
	if err := o.Enqueue(it); err != nil {
		t.Fatalf("in-memory enqueue must not fail: %v", err)
	}
	if len(o.Pending()) != 1 {
		t.Fatal("item not queued")
	}
}
