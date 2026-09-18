package storage

import (
	"context"
	"errors"
	"testing"
)

// TestPostgresIntegrationOutboxDeadLetterVisibility proves the S-C fix
// against real PostgreSQL: dead-lettered rows disappear from OutboxPending
// (and OutboxDue), stay visible through the operator listing with their
// failure context, become claimable again after requeue, and can be deleted.
func TestPostgresIntegrationOutboxDeadLetterVisibility(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	item1 := OutboxItem{ID: pgITNewID(t), Kind: "integration", Payload: []byte(`{"n":1}`)}
	item2 := OutboxItem{ID: pgITNewID(t), Kind: "integration", Payload: []byte(`{"n":2}`)}
	for _, it := range []OutboxItem{item1, item2} {
		if err := st.OutboxAppend(ctx, it); err != nil {
			t.Fatalf("append %s: %v", it.ID, err)
		}
	}

	// One failed attempt is below the cap: still pending, not due yet.
	if err := st.OutboxRetry(ctx, item1.ID, errors.New("attempt-1"), 2); err != nil {
		t.Fatalf("retry 1: %v", err)
	}
	pending, err := st.OutboxPending(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending after first failure = %d, %v; want 2", len(pending), err)
	}

	// The second failure retires item1.
	if err := st.OutboxRetry(ctx, item1.ID, errors.New("attempt-2"), 2); err != nil {
		t.Fatalf("retry 2: %v", err)
	}
	pending, err = st.OutboxPending(ctx)
	if err != nil || len(pending) != 1 || pending[0].ID != item2.ID {
		t.Fatalf("pending after retirement = %+v, %v; want only item2", pending, err)
	}
	due, err := st.OutboxDue(ctx)
	if err != nil || len(due) != 1 || due[0].ID != item2.ID {
		t.Fatalf("due after retirement = %+v, %v; want only item2", due, err)
	}
	dead, err := st.OutboxDeadLetters(ctx)
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead letters = %+v, %v; want one", dead, err)
	}
	if dead[0].ID != item1.ID || dead[0].Attempts != 2 || dead[0].LastError != "attempt-2" || dead[0].DeadLetteredAt.IsZero() {
		t.Fatalf("dead letter context = %+v", dead[0])
	}

	// Claims never pick a dead letter.
	claims, err := st.ClaimOutbox(ctx, "wave1-claimer", 10)
	if err != nil || len(claims) != 1 || claims[0].ID != item2.ID {
		t.Fatalf("claims = %+v, %v; want only item2", claims, err)
	}
	if err := st.ReleaseOutboxClaim(ctx, item2.ID, "wave1-claimer"); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Requeue clears the retirement and the row is immediately claimable.
	if err := st.OutboxRequeue(ctx, item1.ID); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if dead, _ := st.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after requeue = %+v", dead)
	}
	claims, err = st.ClaimOutbox(ctx, "wave1-claimer-2", 10)
	if err != nil || len(claims) != 2 {
		t.Fatalf("claims after requeue = %+v, %v; want both rows", claims, err)
	}
	if err := st.OutboxRequeue(ctx, item1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("requeue of a live row = %v, want ErrNotFound", err)
	}

	// Retire again with a one-attempt budget, then delete.
	if err := st.OutboxRetry(ctx, item1.ID, errors.New("attempt-3"), 1); err != nil {
		t.Fatalf("retry 3: %v", err)
	}
	if dead, _ := st.OutboxDeadLetters(ctx); len(dead) != 1 || dead[0].ID != item1.ID {
		t.Fatalf("dead letters before delete = %+v", dead)
	}
	if err := st.OutboxDelete(ctx, item1.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if dead, _ := st.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after delete = %+v", dead)
	}
	var rows int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id=$1`, item1.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("deleted row count = %d, %v; want 0", rows, err)
	}
	if err := st.OutboxDelete(ctx, item1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of a missing row = %v, want ErrNotFound", err)
	}
	// The live row is untouched by the dead-letter operator API.
	if err := st.OutboxDelete(ctx, item2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of a live row = %v, want ErrNotFound", err)
	}
}
