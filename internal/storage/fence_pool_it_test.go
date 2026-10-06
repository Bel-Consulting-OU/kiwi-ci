package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPostgresIntegrationDigestFenceAtTotalBudget6 is the pool-deadlock
// regression under the TOTAL-budget semantics: WithMaxConnections(6) leaves
// exactly ONE operational connection (6 - 4 advisory - 1 leader), and a
// fenced writer MUST still be able to perform ordinary DB work inside its
// fence. Holding the advisory lock on the operational pool would stall here
// forever.
func TestPostgresIntegrationDigestFenceAtTotalBudget6(t *testing.T) {
	dsn := pgITSetup(t).base
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := NewPostgresOpt(ctx, dsn, WithMaxConnections(6))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if got := st.OperationalMaxConns(); got != 1 {
		t.Fatalf("OperationalMaxConns = %d, want 1 (6 total - 4 advisory - 1 leader)", got)
	}
	op, adv := st.PoolStats()
	if !op.Present || op.Max != 1 || !adv.Present || adv.Max != advisoryPoolMaxConns {
		t.Fatalf("pool stats accounting = operational %+v, advisory %+v", op, adv)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	done := make(chan error, 1)
	go func() {
		done <- st.WithDigestFence(ctx, digest, func() error {
			// Ordinary DB work inside the fence, through the OPERATIONAL pool.
			return st.PutCheckRun(ctx, "run-1|Pipeline", "42")
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("fenced DB work at total max_connections=6: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: fenced operation at total max_connections=6 never completed")
	}
}

// TestPostgresIntegrationDigestFenceConcurrentWritersAtTotalBudget7:
// two concurrent fenced writers with a 2-connection operational pool (the
// remainder of a 7-connection TOTAL budget) must both complete; the advisory
// locks live on the dedicated pool.
func TestPostgresIntegrationDigestFenceConcurrentWritersAtTotalBudget7(t *testing.T) {
	dsn := pgITSetup(t).base
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := NewPostgresOpt(ctx, dsn, WithMaxConnections(7))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if got := st.OperationalMaxConns(); got != 2 {
		t.Fatalf("OperationalMaxConns = %d, want 2 (7 total - 4 advisory - 1 leader)", got)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, digest := range []string{strings.Repeat("b", 64), strings.Repeat("c", 64)} {
		wg.Add(1)
		go func(i int, digest string) {
			defer wg.Done()
			errs <- st.WithDigestFence(ctx, digest, func() error {
				return st.PutCheckRun(ctx, "run-conc|"+digest[:1], "id")
			})
		}(i, digest)
	}
	waitDone := make(chan struct{})
	go func() { wg.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: concurrent fenced writers never completed")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent fenced writer: %v", err)
		}
	}
}

// TestPostgresIntegrationCollectorLeaseAndFenceAndReferences proves the
// collector's full lock stack (lease + digest fence + reference reads)
// coexists within a 7-connection TOTAL budget (2 operational connections
// plus the dedicated advisory pool).
func TestPostgresIntegrationCollectorLeaseAndFenceAndReferences(t *testing.T) {
	dsn := pgITSetup(t).base
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := NewPostgresOpt(ctx, dsn, WithMaxConnections(7))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	pgITArmFence(t, st)

	lease, held, err := st.TryAcquireCASGCLease(ctx, "kiwi-cas-gc")
	if err != nil || !held {
		t.Fatalf("collector lease: held=%v err=%v", held, err)
	}
	defer lease.Release(context.Background())

	digest := strings.Repeat("d", 64)
	done := make(chan error, 1)
	go func() {
		done <- st.WithDigestFence(ctx, digest, func() error {
			// The reference set read a collector performs under the fence.
			_, err := st.ListRuns(ctx, 10)
			return err
		})
	}()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatalf("collector fence + references at total max_connections=7: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: collector lock stack never completed")
	}
}

// TestPostgresIntegrationTotalConnectionBudget is the finding-11 accounting
// regression: with WithMaxConnections(6) the store opens, migrates, holds ONE
// leadership direct connection and completes concurrent fenced operations
// without exhausting the total budget. The operational pool may only use
// 6 - advisoryPoolMaxConns - leaderConnReserve = 1 connection; if any Kiwi
// component drew outside its share the fenced operations would stall.
func TestPostgresIntegrationTotalConnectionBudget(t *testing.T) {
	dsn := pgITSetup(t).base
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := NewPostgresOpt(ctx, dsn, WithMaxConnections(6))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// The leader holds one direct connection, accounted as leaderConnReserve.
	held, err := st.TryAcquireLeadership(ctx, "kiwi-it-total-budget", time.Minute)
	if err != nil || !held {
		t.Fatalf("TryAcquireLeadership: held=%v err=%v", held, err)
	}
	if !st.LeaderSessionHeld() {
		t.Fatal("LeaderSessionHeld = false after a successful acquisition")
	}

	// Concurrent fenced writers: up to advisoryPoolMaxConns advisory
	// connections are held at once while every writer serializes through the
	// single operational connection.
	const writers = 6
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			digest := fmt.Sprintf("%064x", i+1)
			errs <- st.WithDigestFence(ctx, digest, func() error {
				return st.PutCheckRun(ctx, fmt.Sprintf("run-budget-%d|Pipeline", i), "42")
			})
		}(i)
	}
	waitDone := make(chan struct{})
	go func() { wg.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(45 * time.Second):
		t.Fatal("total-budget exhaustion: concurrent fenced operations never completed")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("fenced writer under the total budget: %v", err)
		}
	}

	// Accounting: operational + advisory + the held leader session must fit
	// inside the 6-connection total ceiling.
	op, adv := st.PoolStats()
	if !op.Present || op.Max != 1 {
		t.Fatalf("operational pool = %+v, want Present with Max=1", op)
	}
	if !adv.Present || adv.Max != advisoryPoolMaxConns {
		t.Fatalf("advisory pool = %+v, want Present with Max=%d", adv, advisoryPoolMaxConns)
	}
	total := int(op.Max) + int(adv.Max)
	if st.LeaderSessionHeld() {
		total += leaderConnReserve
	}
	if total > 6 {
		t.Fatalf("Kiwi-owned connection budget = %d, over the WithMaxConnections(6) ceiling", total)
	}
	if st.OperationalMaxConns() != 1 {
		t.Fatalf("OperationalMaxConns = %d, want 1", st.OperationalMaxConns())
	}
}
