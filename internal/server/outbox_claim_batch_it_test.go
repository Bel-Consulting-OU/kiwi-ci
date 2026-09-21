package server

// Real-PostgreSQL integration coverage for the aggregate outbox claim cleanup:
// a canceled flush must release the whole claimed-but-unACKed batch through
// ONE ReleaseOutboxClaims statement (PostgresStore implements
// storage.OutboxClaimBatchStore, so the per-row fallback must never run), so a
// second replica can re-claim every released row immediately. Gated on
// KIWI_TEST_POSTGRES_URL like the other integration tests in this package.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// outboxBatchCallCounter wraps a real store and counts claim-release calls, so
// the IT can distinguish the aggregate path from the per-row fallback.
type outboxBatchCallCounter struct {
	*storage.PostgresStore
	mu          sync.Mutex
	batchCalls  int
	perRowCalls int
	batchIDs    int
}

func (c *outboxBatchCallCounter) ReleaseOutboxClaims(ctx context.Context, ids []string, claimer string) (int, error) {
	c.mu.Lock()
	c.batchCalls++
	c.batchIDs += len(ids)
	c.mu.Unlock()
	return c.PostgresStore.ReleaseOutboxClaims(ctx, ids, claimer)
}

func (c *outboxBatchCallCounter) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	c.mu.Lock()
	c.perRowCalls++
	c.mu.Unlock()
	return c.PostgresStore.ReleaseOutboxClaim(ctx, id, claimer)
}

func (c *outboxBatchCallCounter) counts() (batch, perRow, batchIDs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.batchCalls, c.perRowCalls, c.batchIDs
}

// TestPostgresIntegrationOutboxCancelledFlushBatchRelease is the real-PG
// regression for the per-row cleanup pathology: a full OutboxClaimBatch is
// claimed, the flush context is cancelled mid-batch (the Maintain bound
// expiring), the ACK fails on the dead context, and the deferred sweep must
// release every unACKed claim in ONE aggregate statement — not 64 detached
// per-row statements. The second replica then re-claims the whole released
// batch in a single ClaimOutbox statement, proving no claim was stranded for
// OutboxClaimTTL.
func TestPostgresIntegrationOutboxCancelledFlushBatchRelease(t *testing.T) {
	env := pgITServerSetup(t)
	stA := env.open(t)
	stB := env.open(t)
	pgITSrvArmFence(t, stA)
	pgITSrvArmFence(t, stB)
	ctx := context.Background()
	created := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < storage.OutboxClaimBatch; i++ {
		id := fmt.Sprintf("pg-batch-%02d", i)
		if err := stA.OutboxAppend(ctx, storage.OutboxItem{
			ID: id, Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`),
			CreatedAt: created.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}

	counter := &outboxBatchCallCounter{PostgresStore: stA}
	o := NewOutbox(nil)
	o.AttachDB(counter)

	flushCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var dispatched []string
	n, err := o.Flush(flushCtx, func(_ context.Context, it forge.OutboxItem) error {
		dispatched = append(dispatched, it.ID)
		if len(dispatched) == 2 {
			// The flush bound expires while the second dispatch is in
			// flight: the ACK and every later statement on this context are
			// refused by pgx.
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("the ACK on the cancelled context must fail the flush")
	}
	if n != 1 || len(dispatched) != 2 {
		t.Fatalf("flush = n=%d dispatched=%v, want the first row ACKed and the second dispatched but unACKed", n, dispatched)
	}

	batch, perRow, batchIDs := counter.counts()
	if batch != 1 || perRow != 0 {
		t.Fatalf("claim cleanup calls = batch %d / per-row %d, want 1/0 (Postgres must take the aggregate branch)", batch, perRow)
	}
	if batchIDs != storage.OutboxClaimBatch-1 {
		t.Fatalf("aggregate release ids = %d, want %d (every claimed row except the ACKed one)", batchIDs, storage.OutboxClaimBatch-1)
	}

	// The second replica (separate pool) re-claims the released batch RIGHT
	// NOW in ONE statement: exactly the unACKed rows, never the ACKed one. A
	// stranded claim would make ClaimOutbox skip the row until
	// OutboxClaimTTL.
	reclaimed, cerr := stB.ClaimOutbox(ctx, "replica-2", storage.OutboxClaimBatch)
	if cerr != nil {
		t.Fatalf("second-pool claim: %v", cerr)
	}
	if len(reclaimed) != storage.OutboxClaimBatch-1 {
		t.Fatalf("second-pool reclaim = %d rows, want %d (every unACKed claim must be free)", len(reclaimed), storage.OutboxClaimBatch-1)
	}
	ids := map[string]bool{}
	for _, it := range reclaimed {
		ids[it.ID] = true
	}
	if ids[dispatched[0]] {
		t.Fatalf("the ACKed row %s was reclaimable by the second pool", dispatched[0])
	}
	if !ids[dispatched[1]] {
		t.Fatalf("the unACKed row %s was not immediately reclaimable (claim stranded until OutboxClaimTTL)", dispatched[1])
	}
}
