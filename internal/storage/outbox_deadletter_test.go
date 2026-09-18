package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func wave1OutboxItem(id string) OutboxItem {
	return OutboxItem{ID: id, Kind: "integration", Payload: []byte(`{"id":"` + id + `"}`), CreatedAt: time.Now().UTC()}
}

// TestMemOutboxDeadLetterLifecycle proves the mem mirror of the dead-letter
// contract: retirement after maxAttempts, exclusion from OutboxPending and
// ClaimOutbox, operator listing with context, requeue back to dispatchable,
// and delete.
func TestMemOutboxDeadLetterLifecycle(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	if err := m.OutboxAppend(ctx, wave1OutboxItem("o1")); err != nil {
		t.Fatal(err)
	}
	if err := m.OutboxAppend(ctx, wave1OutboxItem("o2")); err != nil {
		t.Fatal(err)
	}

	// One failure below the cap stays active with a deferred next attempt.
	if err := m.OutboxRetry(ctx, "o1", errors.New("boom-1"), 2); err != nil {
		t.Fatal(err)
	}
	pending, err := m.OutboxPending(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending after first failure = %d, %v; want 2", len(pending), err)
	}
	if claims, err := m.ClaimOutbox(ctx, "flusher", 10); err != nil || len(claims) != 1 || claims[0].ID != "o2" {
		t.Fatalf("claims after backoff = %+v, %v; want only o2 (o1 deferred)", claims, err)
	}
	if err := m.ReleaseOutboxClaim(ctx, "o2", "flusher"); err != nil {
		t.Fatal(err)
	}

	// The second failure retires o1.
	if err := m.OutboxRetry(ctx, "o1", errors.New("boom-2"), 2); err != nil {
		t.Fatal(err)
	}
	pending, _ = m.OutboxPending(ctx)
	if len(pending) != 1 || pending[0].ID != "o2" {
		t.Fatalf("pending after retirement = %+v, want only o2", pending)
	}
	dead, err := m.OutboxDeadLetters(ctx)
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead letters = %+v, %v; want one", dead, err)
	}
	if dead[0].ID != "o1" || dead[0].Attempts != 2 || dead[0].LastError != "boom-2" || dead[0].DeadLetteredAt.IsZero() {
		t.Fatalf("dead letter context = %+v", dead[0])
	}
	if claims, err := m.ClaimOutbox(ctx, "flusher-2", 10); err != nil || len(claims) != 1 || claims[0].ID != "o2" {
		t.Fatalf("claims must skip dead letters: %+v, %v", claims, err)
	}
	if err := m.ReleaseOutboxClaim(ctx, "o2", "flusher-2"); err != nil {
		t.Fatal(err)
	}

	// Requeue clears the retirement and makes the row claimable again.
	if err := m.OutboxRequeue(ctx, "o1"); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if dead, _ := m.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after requeue = %+v", dead)
	}
	pending, _ = m.OutboxPending(ctx)
	if len(pending) != 2 {
		t.Fatalf("pending after requeue = %+v, want both rows", pending)
	}
	claims, err := m.ClaimOutbox(ctx, "flusher-3", 10)
	if err != nil || len(claims) != 2 {
		t.Fatalf("reclaimed after requeue = %+v, %v; want both rows", claims, err)
	}
	claimed := map[string]bool{}
	for _, it := range claims {
		claimed[it.ID] = true
	}
	if !claimed["o1"] {
		t.Fatalf("requeued row not claimable again: %+v", claims)
	}
	// A live row cannot be requeued or deleted through the dead-letter API.
	if err := m.OutboxRequeue(ctx, "o2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("requeue live row = %v, want ErrNotFound", err)
	}
	if err := m.OutboxDelete(ctx, "o2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete live row = %v, want ErrNotFound", err)
	}

	// Retire o1 again with a one-attempt budget, then delete it.
	if err := m.OutboxRetry(ctx, "o1", errors.New("boom-3"), 1); err != nil {
		t.Fatal(err)
	}
	if err := m.OutboxDelete(ctx, "o1"); err != nil {
		t.Fatalf("delete dead letter: %v", err)
	}
	if dead, _ := m.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after delete = %+v", dead)
	}
	pending, _ = m.OutboxPending(ctx)
	if len(pending) != 1 || pending[0].ID != "o2" {
		t.Fatalf("pending after delete = %+v, want only o2", pending)
	}
	if err := m.OutboxDelete(ctx, "o1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing = %v, want ErrNotFound", err)
	}
}

// TestFaultyStoreOutboxDeadLetterWiring proves the wrapper delegates the new
// dead-letter methods and still honors injected faults on the mutating ones.
func TestFaultyStoreOutboxDeadLetterWiring(t *testing.T) {
	f := &FaultyStore{Inner: newMemStore()}
	ctx := context.Background()
	if err := f.OutboxAppend(ctx, wave1OutboxItem("o1")); err != nil {
		t.Fatal(err)
	}
	if err := f.OutboxRetry(ctx, "o1", errors.New("boom"), 1); err != nil {
		t.Fatal(err)
	}
	dead, err := f.OutboxDeadLetters(ctx)
	if err != nil || len(dead) != 1 || dead[0].ID != "o1" {
		t.Fatalf("wrapped dead letters = %+v, %v", dead, err)
	}
	if err := f.OutboxRequeue(ctx, "o1"); err != nil {
		t.Fatalf("wrapped requeue: %v", err)
	}
	if err := f.OutboxRetry(ctx, "o1", errors.New("boom-again"), 1); err != nil {
		t.Fatal(err)
	}
	if err := f.OutboxDelete(ctx, "o1"); err != nil {
		t.Fatalf("wrapped delete: %v", err)
	}
	if dead, _ := f.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after delete = %+v", dead)
	}
	// Injected faults surface on the mutating dead-letter calls.
	injected := errors.New("injected outbox failure")
	f.FailAfter = f.Mutations() + 1
	f.Err = injected
	if err := f.OutboxRequeue(ctx, "o1"); !errors.Is(err, injected) {
		t.Fatalf("injected requeue fault = %v, want %v", err, injected)
	}
	f.FailAfter = f.Mutations() + 1
	if err := f.OutboxDelete(ctx, "o1"); !errors.Is(err, injected) {
		t.Fatalf("injected delete fault = %v, want %v", err, injected)
	}
}
