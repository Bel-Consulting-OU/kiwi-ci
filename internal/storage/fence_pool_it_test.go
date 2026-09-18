package storage

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fenceTestDSN is the integration DSN; the tests skip without it.
func fenceTestDSN(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("integration-skip: KIWI_TEST_POSTGRES_URL not set")
	}
	return dsn
}

// TestPostgresIntegrationDigestFenceAtMaxConnections1 is the pool-deadlock
// regression: with max_connections=1 a fenced writer MUST still be able to
// perform ordinary DB work inside its fence. Holding the advisory lock on
// the operational pool would stall here forever.
func TestPostgresIntegrationDigestFenceAtMaxConnections1(t *testing.T) {
	dsn := fenceTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := NewPostgresOpt(ctx, dsn, WithMaxConnections(1))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
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
			t.Fatalf("fenced DB work at max_connections=1: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: fenced operation at max_connections=1 never completed")
	}
}

// TestPostgresIntegrationDigestFenceConcurrentWritersAtMaxConnections2:
// two concurrent fenced writers with a 2-connection operational pool must
// both complete; the advisory locks live on the dedicated pool.
func TestPostgresIntegrationDigestFenceConcurrentWritersAtMaxConnections2(t *testing.T) {
	dsn := fenceTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := NewPostgresOpt(ctx, dsn, WithMaxConnections(2))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
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
// coexists at max_connections=2.
func TestPostgresIntegrationCollectorLeaseAndFenceAndReferences(t *testing.T) {
	dsn := fenceTestDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := NewPostgresOpt(ctx, dsn, WithMaxConnections(2))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

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
			t.Fatalf("collector fence + references at max_connections=2: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: collector lock stack never completed")
	}
}
