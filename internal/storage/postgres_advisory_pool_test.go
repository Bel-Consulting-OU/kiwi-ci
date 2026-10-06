package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresIntegrationAdvisoryPoolHonorsStartupCancellation proves the
// eager advisory-pool initialization uses the startup context:
// NewPostgresOpt with an already-canceled ctx must return promptly with a
// context error instead of connecting (the old code opened and pinged the
// advisory pool on context.Background() and could hang through the startup
// budget). It needs a real server only to prove the canceled call returns
// BEFORE any connection is attempted; the Integration name puts it in the
// PostgreSQL lane.
func TestPostgresIntegrationAdvisoryPoolHonorsStartupCancellation(t *testing.T) {
	dsn := pgITDSN(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	st, err := NewPostgresOpt(ctx, dsn)
	elapsed := time.Since(start)
	if err == nil {
		_ = st.Close()
		t.Fatal("NewPostgresOpt with a canceled startup context must fail")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startup error = %v, want a context error", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("canceled startup took %v; it must abort promptly", elapsed)
	}
}

// TestAdvisoryPoolFailedInitRetries proves a failed first advisoryPool(ctx)
// does not latch: the pool stays uninitialized and the next call retries with
// its own context (the previous sync.Once latched the first failure forever,
// so a canceled startup attempt permanently poisoned every fenced operation).
// The connect seam fails once and then succeeds; a canceled first attempt is
// also exercised and must not consume the retry.
func TestAdvisoryPoolFailedInitRetries(t *testing.T) {
	// A lazy pool against a port nobody listens on: pgxpool.New parses and
	// constructs without connecting (MinConns defaults to 0), so no server is
	// needed for the seam to return a valid *pgxpool.Pool.
	base, err := pgxpool.New(context.Background(), "postgres://kiwi:kiwi@127.0.0.1:1/kiwi?sslmode=disable")
	if err != nil {
		t.Fatalf("base pool: %v", err)
	}
	t.Cleanup(base.Close)
	st := NewPostgresFromPool(base)

	oldConnect := advisoryPoolConnect
	t.Cleanup(func() { advisoryPoolConnect = oldConnect })

	attempts := 0
	failure := errors.New("synthetic first advisory-pool attempt failure")
	advisoryPoolConnect = func(ctx context.Context, cfg *pgxpool.Config) (*pgxpool.Pool, error) {
		attempts++
		if attempts == 1 {
			return nil, failure
		}
		return base, nil
	}

	// A canceled first attempt aborts before the seam and must not latch.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if pool, err := st.advisoryPool(canceled); !errors.Is(err, context.Canceled) || pool != nil {
		t.Fatalf("canceled first advisoryPool = %v, %v; want a context error", pool, err)
	}
	if attempts != 0 {
		t.Fatalf("canceled attempt reached the connect seam %d time(s)", attempts)
	}

	// A failed connect attempt must be retried (not latched).
	if pool, err := st.advisoryPool(context.Background()); err == nil || pool != nil || !errors.Is(err, failure) {
		t.Fatalf("first live advisoryPool = %v, %v; want the injected failure", pool, err)
	}
	pool, err := st.advisoryPool(context.Background())
	if err != nil {
		t.Fatalf("retry after a failed first attempt: %v (a failed attempt must not latch)", err)
	}
	if pool != base {
		t.Fatalf("retry returned %p, want the seam pool %p", pool, base)
	}
	if attempts != 2 {
		t.Fatalf("connect attempts = %d, want 2 (failed attempt then retry)", attempts)
	}
	// The successful pool is cached: a later caller reuses it.
	again, err := st.advisoryPool(context.Background())
	if err != nil || again != base || attempts != 2 {
		t.Fatalf("cached advisoryPool = %v, %v (attempts=%d); want the seam pool without another connect", again, err, attempts)
	}
}
