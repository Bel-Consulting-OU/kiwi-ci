package server

import (
	"context"
	"errors"
	"testing"
	"time"

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
	// Durable-first retry contract: the local queue is a wake-up cache; the
	// FAILED intent stays as a durable row (with attempts/backoff recorded)
	// and is re-claimed when next_attempt_at is due. The error is returned
	// AFTER the batch so unrelated rows still processed.
	if got := len(s.outbox.Pending()); got != 0 {
		t.Fatalf("local pending after failed dispatch = %d, want 0 (durable row owns the retry)", got)
	}
	f.mu.Lock()
	remaining = len(f.outboxItems)
	f.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("durable rows after failed dispatch = %d, want 1", remaining)
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

// outboxAckFailStore fails OutboxAck for one row id, so a flush stops at the
// middle claimed row with the later claimed rows untouched.
type outboxAckFailStore struct {
	*dbFakeStore
	failID string
}

func (s *outboxAckFailStore) OutboxAck(ctx context.Context, id string) error {
	if id == s.failID {
		return errors.New("synthetic outbox ack failure")
	}
	return s.dbFakeStore.OutboxAck(ctx, id)
}

// outboxPendingIDSet returns the local queue's IDs as a set.
func outboxPendingIDSet(o *Outbox) map[string]bool {
	ids := map[string]bool{}
	for _, it := range o.Pending() {
		ids[it.ID] = true
	}
	return ids
}

// TestOutboxFlushDBReleasesUndispatchedClaimsOnAckError pins J2-2: when the
// ack of one claimed row fails, every other claimed row this flush never
// dispatched must have its claim released immediately — the batch invariant
// is "every claimed row ends the call ACKed or released" — so another replica
// can claim it in the same tick instead of waiting out OutboxClaimTTL.
func TestOutboxFlushDBReleasesUndispatchedClaimsOnAckError(t *testing.T) {
	base := time.Now().UTC().Add(-time.Minute)
	f := &outboxAckFailStore{dbFakeStore: newDBFakeStore(), failID: "b"}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i, id := range []string{"a", "b", "c"} {
		if err := f.OutboxAppend(ctx, storage.OutboxItem{
			ID: id, Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	var dispatched []string
	if _, err := s.outbox.Flush(ctx, func(_ context.Context, it forge.OutboxItem) error {
		dispatched = append(dispatched, it.ID)
		return nil
	}); err == nil {
		t.Fatal("flush must propagate the ack error")
	}
	if len(dispatched) != 2 || dispatched[0] != "a" || dispatched[1] != "b" {
		t.Fatalf("dispatch order = %v, want [a b] (the flush stops at the failed ack)", dispatched)
	}
	f.mu.Lock()
	_, aClaimed := f.outboxClaims["a"]
	_, bClaimed := f.outboxClaims["b"]
	_, cClaimed := f.outboxClaims["c"]
	f.mu.Unlock()
	if aClaimed {
		t.Fatal("ACKed row kept its claim")
	}
	if bClaimed {
		t.Fatal("failed-ACK row kept its claim after the flush returned")
	}
	if cClaimed {
		t.Fatal("undispatched claimed row kept its claim until OutboxClaimTTL (J2-2)")
	}
	reclaimed, err := f.ClaimOutbox(ctx, "other-replica", 10)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, it := range reclaimed {
		ids[it.ID] = true
	}
	if !ids["b"] || !ids["c"] {
		t.Fatalf("same-tick re-claim = %+v, want b and c (claims not released)", reclaimed)
	}
}

// TestOutboxReplayDBMirrorsOnlyDueRows pins J2-3: o.items holds only
// currently-due, non-dead intents. A delayed row (future next_attempt_at) is
// NOT resident after ReplayDB and becomes claimable when due; a dead letter
// is never resident and stays visible only through the dead-letter API; prune
// uses the same due-only active set.
func TestOutboxReplayDBMirrorsOnlyDueRows(t *testing.T) {
	f := newDBFakeStore()
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id string, created time.Time) storage.OutboxItem {
		return storage.OutboxItem{ID: id, Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{}`), CreatedAt: created}
	}
	if err := f.OutboxAppend(ctx, mk("due", now.Add(-2*time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := f.OutboxAppend(ctx, mk("delayed", now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := f.OutboxAppend(ctx, mk("dead", now)); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.outboxMeta["delayed"] = fakeOutboxMeta{attempts: 1, lastError: "boom", nextAt: now.Add(time.Hour)}
	f.outboxMeta["dead"] = fakeOutboxMeta{attempts: maxOutboxAttempts, lastError: "retired", deadAt: now}
	f.mu.Unlock()

	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ids := outboxPendingIDSet(s.outbox)
	if !ids["due"] || ids["delayed"] || ids["dead"] {
		t.Fatalf("resident after ReplayDB = %v, want only the due row", ids)
	}
	if dead, err := f.OutboxDeadLetters(ctx); err != nil || len(dead) != 1 || dead[0].ID != "dead" {
		t.Fatalf("dead letter operator visibility = %+v, %v", dead, err)
	}

	// The backoff elapses: the row is claimable again, and the claim path
	// mirrors it (ReplayDB would too).
	f.mu.Lock()
	meta := f.outboxMeta["delayed"]
	meta.nextAt = time.Time{}
	f.outboxMeta["delayed"] = meta
	f.mu.Unlock()
	claimed, err := f.ClaimOutbox(ctx, "other-replica", 10)
	if err != nil {
		t.Fatal(err)
	}
	claimedIDs := map[string]bool{}
	for _, it := range claimed {
		claimedIDs[it.ID] = true
	}
	if !claimedIDs["due"] || !claimedIDs["delayed"] {
		t.Fatalf("claim once due = %+v, want due and delayed", claimed)
	}
	if err := s.outbox.ReplayDB(ctx); err != nil {
		t.Fatal(err)
	}
	ids = outboxPendingIDSet(s.outbox)
	if !ids["due"] || !ids["delayed"] || ids["dead"] {
		t.Fatalf("resident after due replay = %v, want due and delayed only", ids)
	}

	// prune uses the same due-only set: a local copy of a row whose retry is
	// deferred (or that was dead-lettered) is dropped, local-only items stay.
	f.mu.Lock()
	f.outboxMeta["delayed"] = fakeOutboxMeta{attempts: 2, lastError: "boom", nextAt: time.Now().UTC().Add(time.Hour)}
	f.mu.Unlock()
	s.outbox.mu.Lock()
	s.outbox.items = append(s.outbox.items,
		forge.OutboxItem{ID: "delayed", Kind: forge.OutboxKindGitHubCheck},
		forge.OutboxItem{ID: "delayed-2", Kind: forge.OutboxKindGitHubCheck},
		forge.OutboxItem{ID: "local-only", Kind: "local_kind"})
	s.outbox.localOnly["local-only"] = true
	s.outbox.mu.Unlock()
	f.mu.Lock()
	f.outboxMeta["delayed-2"] = fakeOutboxMeta{attempts: maxOutboxAttempts, lastError: "retired", deadAt: time.Now().UTC()}
	f.mu.Unlock()
	s.outbox.pruneDB(ctx)
	ids = outboxPendingIDSet(s.outbox)
	if ids["delayed"] || ids["delayed-2"] {
		t.Fatalf("prune kept non-due/dead local copies resident: %v", ids)
	}
	if !ids["local-only"] {
		t.Fatalf("prune dropped a local-only item: %v", ids)
	}
}

// TestOutboxEnqueueSameIDConflictDB pins J2-4 for the DB-backed queue: the
// local fast path is an idempotent success only for identical content, a
// different payload under the same ID is the typed invariant conflict, and a
// durable-first replay (local copy gone) mirrors OutboxAppend's semantics.
func TestOutboxEnqueueSameIDConflictDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	first := forge.OutboxItem{ID: "db-fixed-intent", Kind: forge.OutboxKindGitHubStatus, Payload: []byte(`{"a":1}`)}
	if err := s.outbox.Enqueue(first); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if err := s.outbox.Enqueue(first); err != nil {
		t.Fatalf("same-payload replay must be a success: %v", err)
	}
	if err := s.outbox.Enqueue(forge.OutboxItem{ID: "db-fixed-intent", Kind: forge.OutboxKindGitHubStatus, Payload: []byte(`{"a":2}`)}); !errors.Is(err, ErrOutboxIDConflict) {
		t.Fatalf("different payload error = %v, want ErrOutboxIDConflict", err)
	}
	f.mu.Lock()
	rows := len(f.outboxItems)
	f.mu.Unlock()
	if rows != 1 || len(s.outbox.Pending()) != 1 {
		t.Fatalf("conflict mutated the durable/local intent: rows=%d pending=%d", rows, len(s.outbox.Pending()))
	}

	// Durable-first replay (as after a restart where the local mirror is
	// rebuilt): the SAME content converges on the existing row...
	s.outbox.mu.Lock()
	s.outbox.removeLocked(first.ID)
	s.outbox.mu.Unlock()
	if err := s.outbox.Enqueue(first); err != nil {
		t.Fatalf("same-content durable replay must be a success: %v", err)
	}
	// ...while different content under the same durable ID is rejected.
	s.outbox.mu.Lock()
	s.outbox.removeLocked(first.ID)
	s.outbox.mu.Unlock()
	if err := s.outbox.Enqueue(forge.OutboxItem{ID: "db-fixed-intent", Kind: forge.OutboxKindGitHubStatus, Payload: []byte(`{"a":3}`)}); err == nil {
		t.Fatal("durable same-ID/different-content enqueue must fail")
	}
}
