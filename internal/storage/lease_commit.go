package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/jackc/pgx/v5"
)

// ErrLeaseLost reports that a commit-time lease predicate failed: by the time
// the metadata write would commit, the addressed job was no longer running
// under the presented (runner, generation) with an unexpired lease. It is the
// typed failure the runner-upload handlers map to HTTP 409 (the same
// semantics as a stale lease at request start) and it guarantees the
// transaction committed NOTHING: no cache manifest, no snapshot record, no
// artifact row.
var ErrLeaseLost = errors.New("storage: lease lost before commit")

// LeaseCommitStore is the transactional commit-time lease-predicate contract.
//
// The runner upload endpoints (job cache, workspace snapshot, artifact)
// authorize the lease at request start, but a multi-GB body can take long
// enough that the lease is revoked, cancelled, replaced by a new generation,
// or expires while the bytes are staged. A late handler-side re-check does not
// close that window: it is a read followed by a separate metadata write, so a
// concurrent cancel can still commit in between. These methods evaluate the
// lease predicate and perform the metadata write in the SAME transaction (and,
// for PostgreSQL, under a row lock on the job), so the metadata is committed
// only while the lease is provably live and a concurrent revocation either
// commits first (and fails the predicate) or waits for the metadata commit.
//
// A failed predicate returns an error wrapping ErrLeaseLost and writes
// nothing. The presented token is NOT re-verified here: token possession is
// checked at request start, and the predicate's job is the lease's LIFE, not
// its credential.
type LeaseCommitStore interface {
	// PutCacheManifestForLease upserts a signed cache manifest only while the
	// named job is still running under (runnerID, generation) with an
	// unexpired lease.
	PutCacheManifestForLease(ctx context.Context, jobID, runnerID string, generation int64, rec CacheManifestRecord) error
	// InsertSnapshotForLease inserts a workspace snapshot record only while
	// the named job is still running under (runnerID, generation) with an
	// unexpired lease.
	InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, rec model.SnapshotRecord) error
	// InsertArtifactOnceForLease is the lease-fenced sibling of
	// InsertArtifactOnce: it inserts the artifact row (idempotent on the
	// (job, generation, name) key) only while the named job is still running
	// under (runnerID, generation) with an unexpired lease. A lost lease
	// returns ErrLeaseLost and inserts nothing; a surviving lease behaves
	// exactly like InsertArtifactOnce (created=true, or the stored record with
	// created=false / ErrArtifactDigestConflict).
	InsertArtifactOnceForLease(ctx context.Context, jobID, runnerID string, generation int64, a model.ArtifactRecord) (model.ArtifactRecord, bool, error)
}

var (
	_ LeaseCommitStore = (*PostgresStore)(nil)
	_ LeaseCommitStore = (*memStore)(nil)
	_ LeaseCommitStore = (*FaultyStore)(nil)
)

// leaseHeldTx locks the job row FOR UPDATE and reports whether it is still
// running under (runnerID, generation) with an unexpired lease. Holding the
// row lock across the metadata write is what makes the predicate
// transactional: a concurrent cancel/recovery/replacement must wait for this
// transaction, so it can never interleave between the check and the write.
// An absent row reports false (a vanished job fails the predicate closed),
// never an error.
func (s *PostgresStore) leaseHeldTx(ctx context.Context, tx pgx.Tx, jobID, runnerID string, generation int64) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT status='running' AND COALESCE(lease_runner_id, '') = $2 AND lease_generation = $3 AND lease_expires_at IS NOT NULL AND lease_expires_at > now() FROM jobs WHERE id = $1 FOR UPDATE`,
		jobID, runnerID, generation).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ok, nil
}

// validateLeaseCommitKey is the shared input contract of the lease-fenced
// writes: the predicate addresses exactly one job by its id and needs a
// generation to compare against the live lease.
func validateLeaseCommitKey(jobID, runnerID string, generation int64) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	if err := ValidateRunnerID(runnerID); err != nil {
		return err
	}
	if generation < 0 {
		return fmt.Errorf("storage: negative lease generation %d", generation)
	}
	return nil
}

// PutCacheManifestForLease is the transactional cache-manifest commit: it
// locks the job row, re-evaluates the live-lease predicate, and only then
// upserts the manifest, all in one transaction. The stored row is byte-for-
// byte what PutCacheManifest would write.
func (s *PostgresStore) PutCacheManifestForLease(ctx context.Context, jobID, runnerID string, generation int64, rec CacheManifestRecord) error {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return err
	}
	if rec.Repo == "" || rec.TrustDomain == "" || rec.LogicalKey == "" {
		return fmt.Errorf("storage: incomplete cache manifest namespace")
	}
	if len(rec.BlobSHA256) != 64 {
		return fmt.Errorf("storage: invalid cache manifest blob digest")
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	payload, err := jsonMarshal(rec)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	held, err := s.leaseHeldTx(ctx, tx, jobID, runnerID, generation)
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: cache manifest for job %s", ErrLeaseLost, jobID)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cache_manifests (repo, trust_domain, logical_key, blob_sha256, blob_size, producer_run, producer_job, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (repo, trust_domain, logical_key) DO UPDATE SET blob_sha256=EXCLUDED.blob_sha256, blob_size=EXCLUDED.blob_size, producer_run=EXCLUDED.producer_run, producer_job=EXCLUDED.producer_job, payload=EXCLUDED.payload`,
		rec.Repo, rec.TrustDomain, rec.LogicalKey, rec.BlobSHA256, rec.BlobSize, nullText(rec.ProducerRun), nullText(rec.ProducerJob), rec.CreatedAt, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InsertSnapshotForLease is the transactional snapshot-record commit: it
// locks the job row, re-evaluates the live-lease predicate, and only then
// inserts the record, all in one transaction.
func (s *PostgresStore) InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, rec model.SnapshotRecord) error {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return err
	}
	if err := ValidateID(rec.ID); err != nil {
		return err
	}
	if err := ValidateRunID(rec.RunID); err != nil {
		return err
	}
	payload, err := jsonMarshal(rec)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	held, err := s.leaseHeldTx(ctx, tx, jobID, runnerID, generation)
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: snapshot %s for job %s", ErrLeaseLost, rec.ID, jobID)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workspace_snapshots (id, run_id, job_id, created_at, payload) VALUES ($1, $2, $3, $4, $5)`,
		rec.ID, rec.RunID, nullText(rec.JobID), rec.CreatedAt, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InsertArtifactOnceForLease is the transactional artifact commit: it locks
// the job row, re-evaluates the live-lease predicate, and only then performs
// the idempotent insert, all in one transaction. The predicate failure takes
// precedence over a conflict: a lost lease reports ErrLeaseLost and returns
// no stored record, so a revoked upload can never be acknowledged as an
// idempotent replay.
func (s *PostgresStore) InsertArtifactOnceForLease(ctx context.Context, jobID, runnerID string, generation int64, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if err := ValidateID(a.ID); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if err := ValidateRunID(a.RunID); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	payload, err := jsonMarshal(a)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	held, err := s.leaseHeldTx(ctx, tx, jobID, runnerID, generation)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if !held {
		return model.ArtifactRecord{}, false, fmt.Errorf("%w: artifact %s for job %s", ErrLeaseLost, a.Name, jobID)
	}
	ct, err := tx.Exec(ctx, `INSERT INTO artifacts (id, run_id, job_id, job_key, name, size, sha256, created_at, expires_at, job_generation, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (job_id, job_generation, name) DO NOTHING`,
		a.ID, a.RunID, nullText(a.JobID), nullText(a.JobKey), a.Name, a.Size, nullText(a.SHA256), a.CreatedAt, a.ExpiresAt, a.LeaseGeneration, payload)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if ct.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return model.ArtifactRecord{}, false, err
		}
		return a, true, nil
	}
	// A conflicting row exists (a NULL job_id never conflicts, so JobID is
	// non-empty on this path). Read it inside the same transaction and apply
	// the same digest-conflict semantics as InsertArtifactOnce.
	var existingPayload []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM artifacts WHERE job_id=$1 AND job_generation=$2 AND name=$3 LIMIT 1`,
		a.JobID, a.LeaseGeneration, a.Name).Scan(&existingPayload); err != nil {
		// The row vanished between the conflict and the read: not a conflict
		// any more, but the predicate still held, so report the plain insert
		// failure rather than a fabricated record.
		if errors.Is(err, pgx.ErrNoRows) {
			return model.ArtifactRecord{}, false, ErrNotFound
		}
		return model.ArtifactRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	var existing model.ArtifactRecord
	if err := json.Unmarshal(existingPayload, &existing); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if existing.SHA256 != a.SHA256 {
		return existing, false, ErrArtifactDigestConflict
	}
	return existing, false, nil
}

// leaseHeldLocked evaluates the same predicate as leaseHeldTx against the
// in-memory job map. The caller holds m.mu, which is this store's transaction:
// the check and the caller's metadata write are atomic with respect to every
// other memStore mutation.
func (m *memStore) leaseHeldLocked(jobID, runnerID string, generation int64, now time.Time) bool {
	j, ok := m.jobs[jobID]
	if !ok {
		return false
	}
	if j.Status != model.StatusRunning || j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now) {
		return false
	}
	return j.LeaseRunnerID == runnerID && j.LeaseGeneration == generation
}

// PutCacheManifestForLease is the in-memory mirror of the SQL transactional
// cache-manifest commit: the predicate and the write happen under one lock.
func (m *memStore) PutCacheManifestForLease(ctx context.Context, jobID, runnerID string, generation int64, rec CacheManifestRecord) error {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return err
	}
	if rec.Repo == "" || rec.TrustDomain == "" || rec.LogicalKey == "" {
		return fmt.Errorf("storage: incomplete cache manifest namespace")
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.leaseHeldLocked(jobID, runnerID, generation, time.Now().UTC()) {
		return fmt.Errorf("%w: cache manifest for job %s", ErrLeaseLost, jobID)
	}
	m.cacheMans[rec.Repo+"\x00"+rec.TrustDomain+"\x00"+rec.LogicalKey] = rec
	return nil
}

// InsertSnapshotForLease is the in-memory mirror of the SQL transactional
// snapshot-record commit.
func (m *memStore) InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, rec model.SnapshotRecord) error {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.leaseHeldLocked(jobID, runnerID, generation, time.Now().UTC()) {
		return fmt.Errorf("%w: snapshot %s for job %s", ErrLeaseLost, rec.ID, jobID)
	}
	m.snapshots = append(m.snapshots, rec)
	return nil
}

// InsertArtifactOnceForLease is the in-memory mirror of the SQL transactional
// artifact commit, with the same predicate-before-conflict precedence and the
// same (job, generation, name) idempotency.
func (m *memStore) InsertArtifactOnceForLease(ctx context.Context, jobID, runnerID string, generation int64, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.leaseHeldLocked(jobID, runnerID, generation, time.Now().UTC()) {
		return model.ArtifactRecord{}, false, fmt.Errorf("%w: artifact %s for job %s", ErrLeaseLost, a.Name, jobID)
	}
	for _, existing := range m.artifacts {
		if existing.JobID != a.JobID || existing.LeaseGeneration != a.LeaseGeneration || existing.Name != a.Name {
			continue
		}
		if existing.SHA256 != a.SHA256 {
			return existing, false, ErrArtifactDigestConflict
		}
		return existing, false, nil
	}
	m.artifacts = append(m.artifacts, a)
	return a, true, nil
}

// PutCacheManifestForLease forwards the faulted backend's inner implementation
// while injecting the configured mutation fault.
func (f *FaultyStore) PutCacheManifestForLease(ctx context.Context, jobID, runnerID string, generation int64, rec CacheManifestRecord) error {
	inner, ok := f.Inner.(LeaseCommitStore)
	if !ok {
		return errMissingInnerInterface("LeaseCommitStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.PutCacheManifestForLease(ctx, jobID, runnerID, generation, rec)
}

// InsertSnapshotForLease forwards the faulted backend's inner implementation
// while injecting the configured mutation fault.
func (f *FaultyStore) InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, rec model.SnapshotRecord) error {
	inner, ok := f.Inner.(LeaseCommitStore)
	if !ok {
		return errMissingInnerInterface("LeaseCommitStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertSnapshotForLease(ctx, jobID, runnerID, generation, rec)
}

// InsertArtifactOnceForLease forwards the faulted backend's inner
// implementation while injecting the configured mutation fault.
func (f *FaultyStore) InsertArtifactOnceForLease(ctx context.Context, jobID, runnerID string, generation int64, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	inner, ok := f.Inner.(LeaseCommitStore)
	if !ok {
		return model.ArtifactRecord{}, false, errMissingInnerInterface("LeaseCommitStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	return inner.InsertArtifactOnceForLease(ctx, jobID, runnerID, generation, a)
}
