package server

import (
	"context"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestOutboxDBRoundTrip(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	item := forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{"name":"Pipeline"}`)}
	if err := s.outbox.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	queued := s.outbox.Pending()
	if len(queued) != 1 || queued[0].ID == "" {
		t.Fatalf("pending after enqueue = %+v", queued)
	}
	f.mu.Lock()
	stored := len(f.outboxItems)
	f.mu.Unlock()
	if stored != 1 {
		t.Fatalf("OutboxAppend items = %d, want 1", stored)
	}

	// Dispatch succeeds → the item is acked.
	dispatched := 0
	n, err := s.outbox.Flush(context.Background(), func(ctx context.Context, it forge.OutboxItem) error {
		dispatched++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || dispatched != 1 {
		t.Fatalf("flush n=%d dispatched=%d", n, dispatched)
	}
	f.mu.Lock()
	remaining := len(f.outboxItems)
	acked := len(f.outboxAcked)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("pending after flush = %d, want 0", remaining)
	}
	if acked != 1 {
		t.Fatalf("OutboxAck calls = %d, want 1", acked)
	}

	// A failed dispatch keeps the item queued and unacked.
	if err := s.outbox.Enqueue(forge.OutboxItem{Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	_, err = s.outbox.Flush(context.Background(), func(ctx context.Context, it forge.OutboxItem) error {
		return context.Canceled
	})
	if err == nil {
		t.Fatal("flush must propagate dispatch errors")
	}
	if got := len(s.outbox.Pending()); got != 1 {
		t.Fatalf("pending after failed dispatch = %d, want 1", got)
	}
}

func TestOutboxReplayDBOnStartup(t *testing.T) {
	f := newDBFakeStore()
	if err := f.OutboxAppend(context.Background(), storage.OutboxItem{ID: "pending-1", Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	pending := s.outbox.Pending()
	if len(pending) != 1 || pending[0].ID != "pending-1" {
		t.Fatalf("replayed pending = %+v", pending)
	}
}
