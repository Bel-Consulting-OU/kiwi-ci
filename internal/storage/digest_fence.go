package storage

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

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
// pool). The release is idempotent and drops the session if the unlock
// fails, so a crashed holder can never wedge the fence.
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
		once.Do(func() {
			if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey); err != nil {
				_ = conn.Conn().Close(context.Background())
			}
			conn.Release()
		})
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
		once.Do(func() {
			// Unlock on the same session, then return the connection; a
			// failed unlock drops the session (and with it the lock).
			if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
				_ = conn.Conn().Close(context.Background())
			}
			conn.Release()
		})
	}, nil
}
