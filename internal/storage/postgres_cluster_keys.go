package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ClusterKeyBlobStore is the durable shared cluster-key-material contract
// backing the server's DB cluster key store (HA deployments). Every signing
// material (lease HMAC key, OIDC ring, provenance key, cache signing key,
// web session secret, runner CA) is stored as one opaque blob per kind, so
// every replica loads identical material from PostgreSQL instead of minting
// node-local keys.
//
// Create is create-if-absent and returns the WINNING bytes: two replicas
// racing to create the same kind both receive the same material (the loser
// of the insert re-reads the winner). Put is the explicit rotation write and
// bumps the row version. Acquiring the rotation fence serializes
// reload/re-check/rotate/persist across replicas so two replicas can never
// publish different replacements for the same expired key.
type ClusterKeyBlobStore interface {
	EnsureClusterKeySchema(ctx context.Context) error
	GetClusterKey(ctx context.Context, kind string) ([]byte, bool, error)
	CreateClusterKey(ctx context.Context, kind string, data []byte) ([]byte, bool, error)
	PutClusterKey(ctx context.Context, kind string, data []byte) error
	WithClusterKeyRotationFence(ctx context.Context, kind string, fn func() error) error
	// ClusterKeyVersion reports the rotation counter for kind (0/false when
	// the kind has never been created). Tests and operators use it to
	// confirm that concurrent rotation attempts produced exactly one write.
	ClusterKeyVersion(ctx context.Context, kind string) (int64, bool, error)
}

var _ ClusterKeyBlobStore = (*PostgresStore)(nil)

// clusterKeySchemaSQL creates the shared key-material table. The table is
// deliberately outside the numbered migrations: it is additive, created
// idempotently at startup by EnsureClusterKeySchema before any replica loads
// keys, and carries no foreign keys. version is the rotation counter (each
// successful Put increments it), which makes "exactly one rotation" directly
// observable.
const clusterKeySchemaSQL = `
CREATE TABLE IF NOT EXISTS cluster_keys (
    kind       text PRIMARY KEY,
    data       bytea NOT NULL,
    version    bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
)`

// requireClusterKeyPool guards the cluster-key methods against a closed or
// never-opened store (fault-injection wrappers and misconfiguration).
func (s *PostgresStore) requireClusterKeyPool() error {
	if s.pool == nil {
		return errors.New("storage: cluster key store requires an open pool")
	}
	return nil
}

// EnsureClusterKeySchema creates the cluster_keys table when absent. It runs
// against the operational pool so the table lands in the same schema as the
// rest of the store (the integration tests' per-test search_path included).
//
// The CREATE is wrapped in a transaction that holds the SAME transaction-
// scoped advisory lock Migrate uses. CREATE TABLE IF NOT EXISTS resolves the
// catalog BEFORE inserting its own catalog rows, so two replicas bootstrapping
// simultaneously (or a bootstrap racing a migration) can both miss the check
// and then collide on the catalog insert with SQLSTATE 23505, aborting one
// startup with a raw duplicate-key error. The advisory lock serializes the
// bootstrap instead: the waiting replica's statement sees the committed table
// and becomes a no-op. The lock is the established serialization primitive in
// this package (per-migration and cross-replica), it also orders the bootstrap
// against schema migrations, and it removes the race outright instead of
// retrying on a raw SQLSTATE that could have other causes.
func (s *PostgresStore) EnsureClusterKeySchema(ctx context.Context) error {
	if err := s.requireClusterKeyPool(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('kiwi_schema_migrations'))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, clusterKeySchemaSQL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetClusterKey reads one kind's blob. found=false with a nil error means the
// kind has never been created.
func (s *PostgresStore) GetClusterKey(ctx context.Context, kind string) ([]byte, bool, error) {
	if kind == "" {
		return nil, false, errors.New("storage: empty cluster key kind")
	}
	if err := s.requireClusterKeyPool(); err != nil {
		return nil, false, err
	}
	var data []byte
	if err := s.pool.QueryRow(ctx, `SELECT data FROM cluster_keys WHERE kind = $1`, kind).Scan(&data); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

// ClusterKeyVersion reports the kind's rotation counter. found=false means
// the row does not exist.
func (s *PostgresStore) ClusterKeyVersion(ctx context.Context, kind string) (int64, bool, error) {
	if kind == "" {
		return 0, false, errors.New("storage: empty cluster key kind")
	}
	if err := s.requireClusterKeyPool(); err != nil {
		return 0, false, err
	}
	var version int64
	if err := s.pool.QueryRow(ctx, `SELECT version FROM cluster_keys WHERE kind = $1`, kind).Scan(&version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return version, true, nil
}

// CreateClusterKey inserts data for kind when absent and returns the stored
// bytes plus whether this caller's insert won. The insert is the CAS
// primitive: a concurrent creator's insert conflicts and the winner's
// material is re-read, so freshly generated material is NEVER returned when
// the table already holds a value for the kind.
func (s *PostgresStore) CreateClusterKey(ctx context.Context, kind string, data []byte) ([]byte, bool, error) {
	if kind == "" {
		return nil, false, errors.New("storage: empty cluster key kind")
	}
	if len(data) == 0 {
		return nil, false, errors.New("storage: empty cluster key material")
	}
	if err := s.requireClusterKeyPool(); err != nil {
		return nil, false, err
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO cluster_keys (kind, data) VALUES ($1, $2) ON CONFLICT (kind) DO NOTHING`,
		kind, data)
	if err != nil {
		return nil, false, err
	}
	stored, found, err := s.GetClusterKey(ctx, kind)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, fmt.Errorf("storage: cluster key %q disappeared after insert", kind)
	}
	return stored, tag.RowsAffected() == 1, nil
}

// PutClusterKey overwrites the kind's blob (OIDC rotation) and increments the
// row version. The write supersedes the previous material for every replica;
// callers must hold the rotation fence so concurrent rotations cannot both
// observe an expired key and overwrite each other's replacement.
func (s *PostgresStore) PutClusterKey(ctx context.Context, kind string, data []byte) error {
	if kind == "" {
		return errors.New("storage: empty cluster key kind")
	}
	if len(data) == 0 {
		return errors.New("storage: empty cluster key material")
	}
	if err := s.requireClusterKeyPool(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO cluster_keys (kind, data) VALUES ($1, $2)
		ON CONFLICT (kind) DO UPDATE
		SET data = EXCLUDED.data, version = cluster_keys.version + 1, updated_at = now()`,
		kind, data)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("storage: cluster key %q was not stored", kind)
	}
	return nil
}

// WithClusterKeyRotationFence takes the cross-replica rotation lock for kind
// on the dedicated advisory-lock pool, runs fn, and releases the lock. The
// lock is session-scoped and hard-bounded on release (a wedged session is
// closed, which releases it), so a crashed rotator never wedges the next
// rotation. Contention is bounded by ctx: a caller with a deadline gives up
// and must keep serving the current published key rather than rotate without
// the fence.
func (s *PostgresStore) WithClusterKeyRotationFence(ctx context.Context, kind string, fn func() error) error {
	if fn == nil {
		return errors.New("storage: cluster key rotation fence requires a function")
	}
	if kind == "" {
		return errors.New("storage: cluster key rotation fence requires a kind")
	}
	release, err := s.AcquireNamedFence(ctx, "cluster-key-rotation", kind)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}
