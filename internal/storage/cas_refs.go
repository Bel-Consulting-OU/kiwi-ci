package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// CASReferenceStore enumerates every durable digest reference the
// reference-aware CAS garbage collector must treat as live. It is a
// read-only extension of the Store contract: any persistence failure makes
// the collector fail closed (collect nothing) rather than risk deleting a
// referenced blob.
//
// The reads are full-table by design. A bounded read (for example one page
// of artifacts) could silently omit a live reference and the collector
// would then delete the referenced object, so no listing is truncated.
type CASReferenceStore interface {
	// ListAllArtifacts returns every artifact record, including the
	// provenance/SBOM/sigstore digests it carries.
	ListAllArtifacts(ctx context.Context) ([]model.ArtifactRecord, error)
	// ListAllSnapshots returns every workspace snapshot record.
	ListAllSnapshots(ctx context.Context) ([]model.SnapshotRecord, error)
	// ListAllCacheManifests returns every signed shared-cache manifest row.
	ListAllCacheManifests(ctx context.Context) ([]CacheManifestRecord, error)
	// ListAllPendingSidecarDigests returns every digest referenced by the
	// durable pending-sidecar rows (the upload window between a sidecar
	// upload and its artifact payload).
	ListAllPendingSidecarDigests(ctx context.Context) ([]string, error)
}

var _ CASReferenceStore = (*PostgresStore)(nil)

// CASGCLease is one held collector lease. Release releases the underlying
// Postgres transaction (and with it the transaction-scoped advisory lock);
// it is idempotent and safe to call from a defer.
type CASGCLease interface {
	Release(ctx context.Context) error
}

// CASGCLeaseStore is the store-mediated HA lease for the CAS garbage
// collector. It is deliberately separate from the scheduler leadership
// claim (TryAcquireLeadership): that claim owns one shared connection per
// store, so taking it under a second key would evict the scheduler's lock
// and flap leadership on every collection pass. The collector lease uses a
// transaction-scoped advisory lock on a dedicated pooled connection, held
// for the duration of the pass and released by the transaction ending (or
// by the process dying).
type CASGCLeaseStore interface {
	// TryAcquireCASGCLease takes the collector lease for key. ok=false
	// means another replica holds it and the caller must skip the pass.
	TryAcquireCASGCLease(ctx context.Context, key string) (CASGCLease, bool, error)
}

var _ CASGCLeaseStore = (*PostgresStore)(nil)

// pgCASGCLease holds the open transaction that owns the advisory lock.
type pgCASGCLease struct {
	tx   pgx.Tx
	once sync.Once
	err  error
}

// Release rolls the transaction back, releasing the advisory lock. A
// released lease is a no-op on repeat calls and reports the first error.
func (l *pgCASGCLease) Release(ctx context.Context) error {
	l.once.Do(func() { l.err = l.tx.Rollback(ctx) })
	return l.err
}

// TryAcquireCASGCLease opens a transaction and takes a transaction-scoped
// advisory lock on a 64-bit key derived from the collector key. The lock is
// released when the returned lease is released (rollback) or when its
// connection dies, so a crashed collector never wedges the next pass.
//
// The pass is leader-only, so the transaction is FENCED first: the store's
// retained leadership epoch must still match the durable leader_fence row.
// A stale leader is rejected with ErrStaleLeader before taking the collector
// lease, so it can start no pass and delete nothing. The fence's share lock
// is held for the whole pass (the lease transaction stays open until
// Release), which also keeps a new leader from publishing its epoch until the
// in-flight pass has finished — a stale pass can therefore never overlap a
// fresh one.
func (s *PostgresStore) TryAcquireCASGCLease(ctx context.Context, key string) (CASGCLease, bool, error) {
	if key == "" {
		return nil, false, fmt.Errorf("storage: empty cas gc lease key")
	}
	pool, err := s.advisoryPool()
	if err != nil {
		return nil, false, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := s.fenceLeaderTx(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return nil, false, err
	}
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, advisoryLockKey("kiwi-cas-gc-lease", key)).Scan(&got); err != nil {
		_ = tx.Rollback(ctx)
		return nil, false, err
	}
	if !got {
		_ = tx.Rollback(ctx)
		return nil, false, nil
	}
	return &pgCASGCLease{tx: tx}, true, nil
}

// ListAllArtifacts reads every artifact payload row in a stable order.
func (s *PostgresStore) ListAllArtifacts(ctx context.Context) ([]model.ArtifactRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT payload FROM artifacts ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ArtifactRecord{}
	for rows.Next() {
		var (
			payload []byte
			a       model.ArtifactRecord
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAllSnapshots reads every workspace snapshot payload row in a stable
// order.
func (s *PostgresStore) ListAllSnapshots(ctx context.Context) ([]model.SnapshotRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT payload FROM workspace_snapshots ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SnapshotRecord{}
	for rows.Next() {
		var (
			payload []byte
			rec     model.SnapshotRecord
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ListAllCacheManifests reads every signed cache-manifest payload row in a
// stable order.
func (s *PostgresStore) ListAllCacheManifests(ctx context.Context) ([]CacheManifestRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT payload FROM cache_manifests ORDER BY created_at ASC, repo ASC, trust_domain ASC, logical_key ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CacheManifestRecord{}
	for rows.Next() {
		var (
			payload []byte
			rec     CacheManifestRecord
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &rec); err != nil {
			return nil, err
		}
		if rec.BlobSHA256 != "" {
			out = append(out, rec)
		}
	}
	return out, rows.Err()
}

// ListAllPendingSidecarDigests reads the digest column of every pending
// sidecar row in a stable order.
func (s *PostgresStore) ListAllPendingSidecarDigests(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT digest FROM artifact_pending_sidecars ORDER BY created_at ASC, job_id ASC, artifact_name ASC, kind ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, err
		}
		out = append(out, digest)
	}
	return out, rows.Err()
}
