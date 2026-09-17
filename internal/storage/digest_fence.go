package storage

import (
	"context"
	"fmt"
	"regexp"
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
}

var digestFenceRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

var _ DigestFenceStore = (*PostgresStore)(nil)

// WithDigestFence takes the digest's advisory lock, runs fn, and releases the
// lock when the transaction commits or rolls back. fn errors are returned
// as-is (the lock is still released).
func (s *PostgresStore) WithDigestFence(ctx context.Context, digest string, fn func() error) error {
	if !digestFenceRE.MatchString(digest) {
		return fmt.Errorf("storage: digest fence requires a lowercase-hex sha256 digest")
	}
	if fn == nil {
		return fmt.Errorf("storage: digest fence requires a function")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey("kiwi-cas-digest", digest)); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	// Commit to release the transaction-scoped lock deterministically before
	// the deferred rollback would.
	return tx.Commit(ctx)
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey("kiwi-cas-digest", digest)); err != nil {
		_ = tx.Rollback(context.Background())
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = tx.Commit(context.Background()) })
	}, nil
}
