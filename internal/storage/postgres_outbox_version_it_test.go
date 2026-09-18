package storage

// Real-PostgreSQL integration tests for the versioned forge-delivery outbox
// (migration 0018): supersede, the delivered watermark, the dispatcher guard
// and the dead-letter operator lifecycle, plus concurrent enqueues from two
// replicas over the same tables. Gated on KIWI_TEST_POSTGRES_URL like the
// other integration tests.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// pgITVersionedItem builds one versioned outbox row for the integration
// store. The ID follows the production logicalKey#version shape.
func pgITVersionedItem(t *testing.T, key string, version int64) OutboxItem {
	t.Helper()
	return OutboxItem{
		ID: key + "#" + itoaVersion(version), Kind: "github_check",
		Payload: []byte(fmt.Sprintf(`{"n":%d}`, version)), CreatedAt: time.Now().UTC(),
		LogicalKey: key, StateVersion: version,
	}
}

// TestPostgresIntegrationOutboxVersionedLifecycle proves the durable
// versioned contract: newer enqueues supersede older PENDING rows (including
// an out-of-order older enqueue arriving after a newer one), the ACK advances
// the delivered watermark in the same statement, the guard rejects delivered
// and superseded rows, and the dead-letter operator lifecycle round-trips.
func TestPostgresIntegrationOutboxVersionedLifecycle(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	key := "pg-version-key-" + pgITNewID(t)

	// v1 inserts; v2 supersedes it atomically (one row for the key).
	if outcome, err := st.OutboxEnqueueVersioned(ctx, pgITVersionedItem(t, key, 1)); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue v1 = %v, %v", outcome, err)
	}
	if outcome, err := st.OutboxEnqueueVersioned(ctx, pgITVersionedItem(t, key, 2)); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue v2 = %v, %v", outcome, err)
	}
	var rows int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE logical_key=$1`, key).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("rows for key after supersede = %d, %v; want 1", rows, err)
	}
	var pendingVersion int64
	if err := st.pool.QueryRow(ctx, `SELECT state_version FROM outbox WHERE logical_key=$1`, key).Scan(&pendingVersion); err != nil || pendingVersion != 2 {
		t.Fatalf("pending version = %d, %v; want 2", pendingVersion, err)
	}
	// Out-of-order older enqueue while v2 is pending is rejected.
	if outcome, err := st.OutboxEnqueueVersioned(ctx, pgITVersionedItem(t, key, 1)); err != nil || outcome != VersionedSuperseded {
		t.Fatalf("out-of-order v1 = %v, %v; want superseded", outcome, err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE logical_key=$1`, key).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("rows after out-of-order enqueue = %d, %v; want 1", rows, err)
	}

	// Guard: the pending v2 may publish; v1 (even if it were present) may not.
	if publish, err := st.OutboxVersionGuard(ctx, key+"#2", key, 2); err != nil || !publish {
		t.Fatalf("guard for pending v2 = %v, %v; want publish", publish, err)
	}
	if publish, err := st.OutboxVersionGuard(ctx, key+"#1", key, 1); err != nil || publish {
		t.Fatalf("guard for older v1 = %v, %v; want skip", publish, err)
	}

	// ACK v2: the row disappears and the watermark advances in one statement.
	if err := st.OutboxAck(ctx, key+"#2"); err != nil {
		t.Fatal(err)
	}
	var delivered int64
	if err := st.pool.QueryRow(ctx, `SELECT delivered_version FROM forge_check_state WHERE logical_key=$1`, key).Scan(&delivered); err != nil || delivered != 2 {
		t.Fatalf("delivered watermark = %d, %v; want 2", delivered, err)
	}
	// A delivered version can never be re-enqueued or pass the guard, and a
	// newer version still inserts.
	if outcome, err := st.OutboxEnqueueVersioned(ctx, pgITVersionedItem(t, key, 2)); err != nil || outcome != VersionedSuperseded {
		t.Fatalf("re-enqueue delivered v2 = %v, %v", outcome, err)
	}
	if publish, err := st.OutboxVersionGuard(ctx, key+"#2", key, 2); err != nil || publish {
		t.Fatalf("guard for delivered v2 = %v, %v; want skip", publish, err)
	}
	if outcome, err := st.OutboxEnqueueVersioned(ctx, pgITVersionedItem(t, key, 3)); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue v3 = %v, %v", outcome, err)
	}

	// Dead-letter lifecycle on a second key.
	deadKey := "pg-dead-key-" + pgITNewID(t)
	deadItem := pgITVersionedItem(t, deadKey, 1)
	if outcome, err := st.OutboxEnqueueVersioned(ctx, deadItem); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue dead letter candidate = %v, %v", outcome, err)
	}
	for i := 0; i < 2; i++ {
		if err := st.OutboxRetry(ctx, deadItem.ID, errors.New("forge down"), 2); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	pending, err := st.OutboxPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range pending {
		if it.ID == deadItem.ID {
			t.Fatalf("dead letter still pending: %+v", it)
		}
	}
	claims, err := st.ClaimOutbox(ctx, "dead-letter-claimer", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range claims {
		if it.ID == deadItem.ID {
			t.Fatalf("dead letter claimed: %+v", it)
		}
	}
	dead, err := st.OutboxDeadLetters(ctx)
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead letters = %+v, %v; want one", dead, err)
	}
	if dead[0].ID != deadItem.ID || dead[0].LogicalKey != deadKey || dead[0].StateVersion != 1 || dead[0].Attempts != 2 {
		t.Fatalf("dead letter context = %+v", dead[0])
	}
	// Requeue: claimable, guard passes, delivery acks the watermark.
	if err := st.OutboxRequeue(ctx, deadItem.ID); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if err := st.ReleaseOutboxClaim(ctx, deadItem.ID, "dead-letter-claimer"); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimOutbox(ctx, "requeue-claimer", 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range claimed {
		if it.ID == deadItem.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("requeued row not claimable: %+v", claimed)
	}
	if publish, err := st.OutboxVersionGuard(ctx, deadItem.ID, deadKey, 1); err != nil || !publish {
		t.Fatalf("guard after requeue = %v, %v; want publish", publish, err)
	}
	if err := st.OutboxAck(ctx, deadItem.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT delivered_version FROM forge_check_state WHERE logical_key=$1`, deadKey).Scan(&delivered); err != nil || delivered != 1 {
		t.Fatalf("dead-letter watermark = %d, %v; want 1", delivered, err)
	}
	// Delete a retired row.
	second := pgITVersionedItem(t, "pg-delete-key-"+pgITNewID(t), 1)
	if _, err := st.OutboxEnqueueVersioned(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := st.OutboxRetry(ctx, second.ID, errors.New("boom"), 1); err != nil {
		t.Fatal(err)
	}
	if err := st.OutboxDelete(ctx, second.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := st.OutboxDelete(ctx, second.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of missing dead letter = %v, want ErrNotFound", err)
	}
}

// TestPostgresIntegrationOutboxVersionedConcurrentReplicas proves two
// replicas enqueueing versions N and N+1 concurrently leave exactly the
// newest pending (the per-key advisory lock serializes supersede+insert), and
// two concurrent ACKs of one logical key leave the watermark at the maximum
// version.
func TestPostgresIntegrationOutboxVersionedConcurrentReplicas(t *testing.T) {
	env := pgITSetup(t)
	stA := env.open(t)
	env.migrate(t, stA)
	stB := env.open(t)
	ctx := context.Background()
	key := "pg-race-key-" + pgITNewID(t)

	// Concurrent v1/v2 enqueues from two pools. Whichever commits first, the
	// supersede/max-pending rule leaves exactly v2.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := stA.OutboxEnqueueVersioned(ctx, pgITVersionedItem(t, key, 1)); err != nil {
			errs <- err
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := stB.OutboxEnqueueVersioned(ctx, pgITVersionedItem(t, key, 2)); err != nil {
			errs <- err
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent enqueue: %v", err)
	}
	var rows int
	var version int64
	if err := stA.pool.QueryRow(ctx, `SELECT count(*), COALESCE(MAX(state_version),0) FROM outbox WHERE logical_key=$1`, key).Scan(&rows, &version); err != nil || rows != 1 || version != 2 {
		t.Fatalf("pending after concurrent enqueue = %d rows v%d, %v; want 1/v2", rows, version, err)
	}
	if publish, err := stA.OutboxVersionGuard(ctx, key+"#2", key, 2); err != nil || !publish {
		t.Fatalf("guard for v2 = %v, %v; want publish", publish, err)
	}

	// Concurrent ACKs of versions 1 and 2 of one key leave the watermark at
	// 2 (GREATEST, same statement as the delete). Insert both rows directly:
	// the versioned enqueue would supersede v1.
	if _, err := stA.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at, logical_key, state_version) VALUES ($1,'github_check','{}'::jsonb,now(),$2,1), ($3,'github_check','{}'::jsonb,now(),$2,2) ON CONFLICT (id) DO NOTHING`,
		key+"#1", key, key+"#2"); err != nil {
		t.Fatalf("seed ack rows: %v", err)
	}
	var wg2 sync.WaitGroup
	errs2 := make(chan error, 2)
	for _, pair := range []struct {
		st *PostgresStore
		id string
	}{{stA, key + "#1"}, {stB, key + "#2"}} {
		wg2.Add(1)
		go func(st *PostgresStore, id string) {
			defer wg2.Done()
			if err := st.OutboxAck(ctx, id); err != nil {
				errs2 <- err
			}
		}(pair.st, pair.id)
	}
	wg2.Wait()
	close(errs2)
	for err := range errs2 {
		t.Fatalf("concurrent ack: %v", err)
	}
	var delivered int64
	if err := stA.pool.QueryRow(ctx, `SELECT delivered_version FROM forge_check_state WHERE logical_key=$1`, key).Scan(&delivered); err != nil || delivered != 2 {
		t.Fatalf("watermark after concurrent acks = %d, %v; want 2", delivered, err)
	}
	if err := stA.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE logical_key=$1`, key).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rows after concurrent acks = %d, %v; want 0", rows, err)
	}
}
