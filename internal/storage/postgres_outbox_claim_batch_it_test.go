package storage

// Real-PostgreSQL integration coverage for the batch outbox claim release
// (OutboxClaimBatchStore.ReleaseOutboxClaims): one aggregate statement clears
// exactly the rows still claimed by the caller, leaves another flusher's rows
// untouched, reports the affected count, and is safe against a concurrent
// re-claim because the claimer match is part of the UPDATE predicate.

import (
	"context"
	"testing"
)

func TestPostgresIntegrationOutboxClaimBatchRelease(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	pgITArmFence(t, st)
	ctx := context.Background()

	for _, id := range []string{"claim-batch-a", "claim-batch-b", "claim-batch-c"} {
		if err := st.OutboxAppend(ctx, OutboxItem{ID: id, Kind: "test"}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	claimed, err := st.ClaimOutbox(ctx, "flusher-a", 2)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claim a = %d/%v", len(claimed), err)
	}
	rest, err := st.ClaimOutbox(ctx, "flusher-b", 10)
	if err != nil || len(rest) != 1 {
		t.Fatalf("claim b = %d/%v", len(rest), err)
	}
	aIDs := []string{claimed[0].ID, claimed[1].ID}
	bID := rest[0].ID

	// One aggregate release clears exactly flusher-a's rows, even though the
	// batch also names flusher-b's id; the count reflects only matches.
	n, err := st.ReleaseOutboxClaims(ctx, append(append([]string{}, aIDs...), bID, "missing"), "flusher-a")
	if err != nil || n != 2 {
		t.Fatalf("batch release = %d/%v, want 2/nil", n, err)
	}
	assertOutboxClaimState := func(id, wantClaimer string) {
		t.Helper()
		var claimer *string
		if err := st.pool.QueryRow(ctx, `SELECT claimed_by FROM outbox WHERE id=$1`, id).Scan(&claimer); err != nil {
			t.Fatalf("read claim %s: %v", id, err)
		}
		got := ""
		if claimer != nil {
			got = *claimer
		}
		if got != wantClaimer {
			t.Fatalf("claim on %s = %q, want %q", id, got, wantClaimer)
		}
	}
	assertOutboxClaimState(aIDs[0], "")
	assertOutboxClaimState(aIDs[1], "")
	assertOutboxClaimState(bID, "flusher-b")

	// Idempotent replay: nothing left to release.
	if n, err := st.ReleaseOutboxClaims(ctx, aIDs, "flusher-a"); err != nil || n != 0 {
		t.Fatalf("replayed batch release = %d/%v, want 0/nil", n, err)
	}

	// Concurrent re-claim: flusher-b reclaims one row (as after the claim
	// TTL) while flusher-a's cleanup is in flight; the claimer mismatch must
	// leave the NEW claim intact and not count it.
	if _, err := st.pool.Exec(ctx, `UPDATE outbox SET claimed_at=now(), claimed_by='flusher-b' WHERE id=$1`, aIDs[0]); err != nil {
		t.Fatalf("simulate reclaim: %v", err)
	}
	if n, err := st.ReleaseOutboxClaims(ctx, aIDs, "flusher-a"); err != nil || n != 0 {
		t.Fatalf("release after reclaim = %d/%v, want 0/nil", n, err)
	}
	assertOutboxClaimState(aIDs[0], "flusher-b")

	// The reclaiming flusher can release it, proving ownership moved.
	if n, err := st.ReleaseOutboxClaims(ctx, []string{aIDs[0]}, "flusher-b"); err != nil || n != 1 {
		t.Fatalf("flusher-b release = %d/%v, want 1/nil", n, err)
	}
	assertOutboxClaimState(aIDs[0], "")

	// Empty inputs are explicit no-ops / wiring errors.
	if n, err := st.ReleaseOutboxClaims(ctx, nil, "flusher-a"); err != nil || n != 0 {
		t.Fatalf("empty batch = %d/%v, want 0/nil", n, err)
	}
	if _, err := st.ReleaseOutboxClaims(ctx, aIDs, "  "); err == nil {
		t.Fatal("empty claimer must fail closed")
	}
}
