package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
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
	if err := s.outbox.Enqueue(context.Background(), item); err != nil {
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
	if err := s.outbox.Enqueue(context.Background(), forge.OutboxItem{Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{}")}); err != nil {
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

// outboxCancelCtxStore mirrors PostgresStore's context coupling for the
// statements a flush performs AFTER a successful dispatch: pgx refuses an
// already-cancelled context before the statement reaches PostgreSQL, so the
// ACK and the claim-release UPDATE fail once the flush context dies. The
// context-blind dbFakeStore shortcut cannot reproduce the stranding defect;
// this wrapper can.
type outboxCancelCtxStore struct{ *dbFakeStore }

func (s *outboxCancelCtxStore) OutboxAck(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.dbFakeStore.OutboxAck(ctx, id)
}

func (s *outboxCancelCtxStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.dbFakeStore.ReleaseOutboxClaim(ctx, id, claimer)
}

// TestOutboxFlushDBCancelledContextReleasesClaims pins the P2 outbox-claim
// stranding defect: claim cleanup must NOT ride the dispatch context. The
// flush context is cancelled while the dispatch of "b" is in flight (the
// Maintain 2-minute bound expiring mid-batch); the ACK of "b" then fails on
// the dead context and the flush returns early, leaving "c" and "d" claimed
// but never dispatched. With cleanup on the dispatch context the release
// UPDATEs are refused too (and the errors discarded), so b/c/d stay invisible
// to every other replica until OutboxClaimTTL (5 minutes). With a cleanup
// context derived via context.WithoutCancel they are claimable immediately.
func TestOutboxFlushDBCancelledContextReleasesClaims(t *testing.T) {
	f := &outboxCancelCtxStore{dbFakeStore: newDBFakeStore()}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	for i, id := range []string{"a", "b", "c", "d"} {
		if err := f.OutboxAppend(ctx, storage.OutboxItem{
			ID: id, Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}

	flushCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var dispatched []string
	n, err := s.outbox.Flush(flushCtx, func(_ context.Context, it forge.OutboxItem) error {
		dispatched = append(dispatched, it.ID)
		if it.ID == "b" {
			// The flush bound expires while this dispatch is in flight: the
			// forge call completed, but every later store statement would run
			// on a dead context.
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("the ACK of b on the cancelled context must fail the flush")
	}
	if n != 1 || len(dispatched) != 2 || dispatched[0] != "a" || dispatched[1] != "b" {
		t.Fatalf("flush = n=%d dispatched=%v, want a ACKed and b dispatched but unACKed", n, dispatched)
	}

	// The failed ACK released b with a cleanup context of its own, and the
	// deferred cleanup released the never-dispatched c and d.
	f.mu.Lock()
	_, aClaimed := f.outboxClaims["a"]
	_, bClaimed := f.outboxClaims["b"]
	_, cClaimed := f.outboxClaims["c"]
	_, dClaimed := f.outboxClaims["d"]
	f.mu.Unlock()
	if aClaimed || bClaimed || cClaimed || dClaimed {
		t.Fatalf("claims after flush: a=%v b=%v c=%v d=%v, want every claim released", aClaimed, bClaimed, cClaimed, dClaimed)
	}

	// A second replica must be able to claim the remaining rows RIGHT NOW,
	// not after OutboxClaimTTL.
	reclaimed, cerr := f.ClaimOutbox(ctx, "replica-2", 10)
	if cerr != nil {
		t.Fatal(cerr)
	}
	ids := map[string]bool{}
	for _, it := range reclaimed {
		ids[it.ID] = true
	}
	if !ids["b"] || !ids["c"] || !ids["d"] {
		t.Fatalf("immediately reclaimable rows = %v, want b, c and d (claims stranded until OutboxClaimTTL)", ids)
	}
	if ids["a"] {
		t.Fatalf("ACKed row was claimable again: %v", ids)
	}
}

// outboxReleaseFailStore fails every ReleaseOutboxClaim while recording the
// attempted IDs: claim cleanup errors must be logged (row ID + error) and
// must never abort or panic the flush.
type outboxReleaseFailStore struct {
	*dbFakeStore
	releaseErr error
	released   []string
}

func (s *outboxReleaseFailStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	s.released = append(s.released, id)
	if s.releaseErr != nil {
		return s.releaseErr
	}
	return s.dbFakeStore.ReleaseOutboxClaim(ctx, id, claimer)
}

// TestOutboxFlushDBReleaseFailureLoggedAndFlushContinues pins the cleanup
// error contract: a failing ReleaseOutboxClaim is logged with the item ID and
// the error (never silently discarded) and the batch keeps dispatching and
// ACKing its remaining rows.
func TestOutboxFlushDBReleaseFailureLoggedAndFlushContinues(t *testing.T) {
	f := &outboxReleaseFailStore{dbFakeStore: newDBFakeStore(), releaseErr: errors.New("release update down")}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	for i, id := range []string{"a", "b", "c"} {
		if err := f.OutboxAppend(ctx, storage.OutboxItem{
			ID: id, Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevLog)

	var dispatched []string
	n, err := s.outbox.Flush(ctx, func(_ context.Context, it forge.OutboxItem) error {
		dispatched = append(dispatched, it.ID)
		if it.ID == "a" {
			return errors.New("dispatch down")
		}
		return nil
	})
	if err == nil {
		t.Fatal("the per-row dispatch failure must still be returned after the batch")
	}
	if n != 2 || strings.Join(dispatched, ",") != "a,b,c" {
		t.Fatalf("flush n=%d dispatched=%v, want [a b c] with 2 ACKs (the release failure must not stop the batch)", n, dispatched)
	}
	logged := buf.String()
	if !strings.Contains(logged, "release claim for a") || !strings.Contains(logged, "release update down") {
		t.Fatalf("release failure not logged with item ID and error: %q", logged)
	}
	if len(f.released) == 0 {
		t.Fatal("release was never attempted")
	}
	f.mu.Lock()
	var remaining []string
	for _, it := range f.outboxItems {
		remaining = append(remaining, it.ID)
	}
	f.mu.Unlock()
	if strings.Join(remaining, ",") != "a" {
		t.Fatalf("durable rows = %v, want only the failed-dispatch row a (b and c ACKed)", remaining)
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
	if err := s.outbox.Enqueue(context.Background(), first); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if err := s.outbox.Enqueue(context.Background(), first); err != nil {
		t.Fatalf("same-payload replay must be a success: %v", err)
	}
	if err := s.outbox.Enqueue(context.Background(), forge.OutboxItem{ID: "db-fixed-intent", Kind: forge.OutboxKindGitHubStatus, Payload: []byte(`{"a":2}`)}); !errors.Is(err, ErrOutboxIDConflict) {
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
	if err := s.outbox.Enqueue(context.Background(), first); err != nil {
		t.Fatalf("same-content durable replay must be a success: %v", err)
	}
	// ...while different content under the same durable ID is rejected.
	s.outbox.mu.Lock()
	s.outbox.removeLocked(first.ID)
	s.outbox.mu.Unlock()
	if err := s.outbox.Enqueue(context.Background(), forge.OutboxItem{ID: "db-fixed-intent", Kind: forge.OutboxKindGitHubStatus, Payload: []byte(`{"a":3}`)}); err == nil {
		t.Fatal("durable same-ID/different-content enqueue must fail")
	}
}
