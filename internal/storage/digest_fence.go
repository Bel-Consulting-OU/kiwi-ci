package storage

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fenceReleaseTimeout bounds the advisory-unlock round-trip on the release
// path, and fenceCloseTimeout bounds the session close performed when the
// unlock fails or times out. They are vars only so tests can shrink the hard
// bounds; production never reassigns them (same seam convention as
// randReader/leaderProbeFn).
var (
	fenceReleaseTimeout = 5 * time.Second
	fenceCloseTimeout   = 2 * time.Second
)

// fenceReleaseFn performs the unlock round-trip on the acquired session. It
// is a var so a test can simulate a wedged session whose call blocks until
// the bound expires; production never reassigns it.
var fenceReleaseFn = func(ctx context.Context, conn *pgxpool.Conn, key int64) error {
	_, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, key)
	return err
}

// fenceCloseFn closes the underlying session (which releases every
// session-level advisory lock it holds). It is a var for the same test seam
// reason: a test blocks it to prove the close carries its OWN bound.
var fenceCloseFn = func(ctx context.Context, conn *pgx.Conn) error {
	return conn.Close(ctx)
}

// fenceReleaseContext derives the bounded context for the release round-trip.
// The origin context may already be canceled — the request that acquired the
// fence is gone by the time the release runs — so cancellation is stripped
// (WithoutCancel) while values survive, and a FRESH timeout imposes the hard
// bound. A bare Background at this call site is the defect this helper exists
// to prevent: a wedged connection would pin the request goroutine and its
// dedicated advisory-pool slot forever.
func fenceReleaseContext(origin context.Context, bound time.Duration) (context.Context, context.CancelFunc) {
	if origin == nil {
		origin = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(origin), bound)
}

// releaseFenceConn releases one acquired advisory-fence session under hard
// bounds: the unlock runs under fenceReleaseTimeout, and if it fails or times
// out the session is CLOSED under its own fenceCloseTimeout — closing the
// PostgreSQL session releases the advisory lock deterministically even when
// the protocol round-trip cannot complete. The pool slot is always returned
// (pgxpool discards a closed connection and replaces it), so neither the
// goroutine nor the dedicated advisory connection can leak. Callers wrap this
// in a sync.Once, so a second release is a no-op.
func releaseFenceConn(origin context.Context, conn *pgxpool.Conn, key int64) {
	uctx, cancel := fenceReleaseContext(origin, fenceReleaseTimeout)
	err := fenceReleaseFn(uctx, conn, key)
	cancel()
	if err != nil {
		cctx, ccancel := fenceReleaseContext(origin, fenceCloseTimeout)
		_ = fenceCloseFn(cctx, conn.Conn())
		ccancel()
	}
	conn.Release()
}

// DigestFenceStore is the cross-replica form of the CAS digest fence: a
// transaction-scoped Postgres advisory lock on a key derived from the digest
// serializes writers ("publish object + commit reference") against the
// garbage collector ("re-read references + delete") on every replica.
//
// The lock lives on a dedicated transaction so it never shares the pooled
// connection used by the scheduler leadership claim, and it is released by
// the transaction ending even if the process dies.
type DigestFenceStore interface {
	WithDigestFence(ctx context.Context, digest string, fn func() error) error
	// AcquireDigestFence takes the lock and returns an idempotent release.
	AcquireDigestFence(ctx context.Context, digest string) (release func(), err error)
	// AcquireNamedFence is the general form for other distributed
	// uniqueness scopes (e.g. per-logical-check GitHub publication):
	// namespace + key, same dedicated advisory pool.
	AcquireNamedFence(ctx context.Context, namespace, key string) (release func(), err error)
}

var digestFenceRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

var _ DigestFenceStore = (*PostgresStore)(nil)

// WithDigestFence takes the digest's advisory lock, runs fn, and releases the
// lock when the transaction commits or rolls back. fn errors are returned
// as-is (the lock is still released).
func (s *PostgresStore) WithDigestFence(ctx context.Context, digest string, fn func() error) error {
	if fn == nil {
		return fmt.Errorf("storage: digest fence requires a function")
	}
	release, err := s.AcquireDigestFence(ctx, digest)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// AcquireNamedFence takes a session advisory lock for an arbitrary
// namespace/key pair on the dedicated lock pool (never the operational
// pool). The release is idempotent and hard-bounded: it unlocks under
// fenceReleaseTimeout and, if that fails or times out, closes the session
// under fenceCloseTimeout (closing releases the lock), so a crashed or wedged
// holder can never pin the caller or the advisory-pool slot.
func (s *PostgresStore) AcquireNamedFence(ctx context.Context, namespace, key string) (func(), error) {
	namespace = strings.TrimSpace(namespace)
	key = strings.TrimSpace(key)
	if namespace == "" || key == "" || len(namespace)+len(key) > 512 {
		return nil, fmt.Errorf("storage: named fence requires a namespace and key")
	}
	pool, err := s.advisoryPool()
	if err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	lockKey := advisoryLockKey("kiwi-fence-"+namespace, key)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		conn.Release()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() { releaseFenceConn(ctx, conn, lockKey) })
	}, nil
}

// AcquireDigestFence opens a transaction, takes the digest's advisory lock,
// and returns an idempotent release that commits (releasing the lock). The
// lock outlives individual store calls, which is what lets a writer hold it
// across "publish object + commit reference" without funnelling every store
// operation through one transaction.
func (s *PostgresStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	if !digestFenceRE.MatchString(digest) {
		return nil, fmt.Errorf("storage: digest fence requires a lowercase-hex sha256 digest")
	}
	// The lock lives on the DEDICATED advisory pool: the fenced operation
	// itself performs ordinary reads/writes through the operational pool,
	// and holding the lock on that pool would deadlock as soon as it is
	// exhausted (max_connections=1 stalls immediately).
	pool, err := s.advisoryPool()
	if err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	key := advisoryLockKey("kiwi-cas-digest", digest)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		conn.Release()
		return nil, err
	}
	var once sync.Once
	return func() {
		// The release is idempotent (sync.Once) and hard-bounded: a wedged
		// session cannot pin the caller or the advisory-pool slot.
		once.Do(func() { releaseFenceConn(ctx, conn, key) })
	}, nil
}
