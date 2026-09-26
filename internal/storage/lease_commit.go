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

// ErrLeaseIdentityMismatch reports that a commit-time record disagreed with
// the authoritative identity of the job whose live lease was proven: the
// record's job/run coordinates, lease generation, repository, trust domain or
// producer fields were cross-bound to another job. The lease predicate alone
// proves a lease over the addressed job; it says nothing about the record a
// malformed internal caller presents. These methods therefore LOCK the job row
// (or the in-memory job) and validate every identity-bearing field against the
// locked row before writing, returning this typed error and committing
// NOTHING on any disagreement.
var ErrLeaseIdentityMismatch = errors.New("storage: lease commit identity mismatch")

// leaseIdentityErrorf wraps ErrLeaseIdentityMismatch with the offending field
// and values. It is the one construction site so every mismatch is
// errors.Is-classifiable by callers and tests.
func leaseIdentityErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrLeaseIdentityMismatch}, args...)...)
}

// ErrSnapshotCapReached reports that a (run, job) already holds the maximum
// number of snapshot records. The cap is enforced at COMMIT time (under the
// job row lock in PostgreSQL, under the store mutex in memory), not only as a
// preflight check, so concurrent uploads cannot exceed it. The count is keyed
// to the LOCKED job's (run, job) coordinates — never to fields supplied by
// the caller.
var ErrSnapshotCapReached = errors.New("storage: snapshot cap reached")

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
// The lock is also the source of truth for the record's identity: every
// identity-bearing field (run id, job id, job key, lease generation, cache
// repository/trust domain/producer coordinates) is validated against — or, for
// fields the record may omit, constructed from — the LOCKED job row. A record
// that proves one job's lease but carries another job's identity is refused
// with ErrLeaseIdentityMismatch and commits nothing; the predicate's job is the
// lease's LIFE and its identity, not its credential. The presented token is NOT
// re-verified here: token possession is checked at request start.
type LeaseCommitStore interface {
	// PutCacheManifestForLease upserts a signed cache manifest only while the
	// named job is still running under (runnerID, generation) with an
	// unexpired lease. The namespace (repo, trust domain) and producer
	// coordinates are derived from the locked job and must agree with the
	// record's fields; a disagreement commits nothing and returns an error
	// wrapping ErrLeaseIdentityMismatch.
	PutCacheManifestForLease(ctx context.Context, jobID, runnerID string, generation int64, rec CacheManifestRecord) error
	// InsertSnapshotForLease inserts a workspace snapshot record only while
	// the named job is still running under (runnerID, generation) with an
	// unexpired lease. The record's RunID and JobID must match the locked
	// job; the per-job cap counts the locked job's records.
	InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, maxPerJob int, rec model.SnapshotRecord) error
	// InsertArtifactOnceForLease is the lease-fenced sibling of
	// InsertArtifactOnce: it inserts the artifact row (idempotent on the
	// (job, generation, name) key) only while the named job is still running
	// under (runnerID, generation) with an unexpired lease. The record's job,
	// run and lease generation must match the locked job. A lost lease
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

// leaseJobCoords is the authoritative identity of the job row a commit-time
// predicate locked. Every field comes from the locked row (PostgreSQL) or the
// in-memory job the store mutex protects (memStore); none of it is taken from
// the record the caller presented.
type leaseJobCoords struct {
	JobID       string
	RunID       string
	JobKey      string
	Generation  int64
	RepoID      string
	Trusted     bool
	TrustDomain string
}

// cacheTrustDomain maps a job's trust flag onto the cache trust-domain string.
// It mirrors the server's cacheNamespace derivation; storage derives it here
// so the persisted manifest namespace can never disagree with the locked job.
func cacheTrustDomain(trusted bool) string {
	if trusted {
		return "trusted"
	}
	return "untrusted"
}

// lockedLeaseJobTx locks the job row FOR UPDATE and reports its authoritative
// coordinates when it is still running under (runnerID, generation) with an
// unexpired lease. Holding the row lock across the metadata write is what
// makes the predicate transactional: a concurrent cancel/recovery/replacement
// must wait for this transaction, so it can never interleave between the check
// and the write. An absent row (or a row whose lease is no longer held)
// reports false (a vanished job fails the predicate closed), never an error;
// no lock is taken in that case because the caller writes nothing.
func (s *PostgresStore) lockedLeaseJobTx(ctx context.Context, tx pgx.Tx, jobID, runnerID string, generation int64) (leaseJobCoords, bool, error) {
	var (
		c            leaseJobCoords
		repoID       string
		policyRepoID string
		repoURL      string
		repoFull     string
	)
	err := tx.QueryRow(ctx, `SELECT run_id, COALESCE(key, ''),
		COALESCE(payload->>'repo_id', ''),
		COALESCE(payload->>'policy_repo_id', ''),
		COALESCE(payload->>'repo_url', ''),
		COALESCE(payload->>'repo_full_name', ''),
		CASE WHEN jsonb_typeof(payload->'trusted') = 'boolean' THEN (payload->>'trusted')::boolean ELSE FALSE END
		FROM jobs
		WHERE id = $1 AND status='running' AND COALESCE(lease_runner_id, '') = $2 AND lease_generation = $3
		  AND lease_expires_at IS NOT NULL AND lease_expires_at > now()
		FOR UPDATE`,
		jobID, runnerID, generation).Scan(&c.RunID, &c.JobKey, &repoID, &policyRepoID, &repoURL, &repoFull, &c.Trusted)
	if errors.Is(err, pgx.ErrNoRows) {
		return leaseJobCoords{}, false, nil
	}
	if err != nil {
		return leaseJobCoords{}, false, err
	}
	c.JobID = jobID
	c.Generation = generation
	// The locked row's payload carries the immutable repository identity; the
	// shared derivation (RepoIDForJob) is the same one the scheduler, policy
	// and server use, so the persisted namespace cannot drift. Trust is the
	// job's own flag, mirrored by cacheTrustDomain.
	c.RepoID = RepoIDForJob(model.Job{
		PolicyRepoID: policyRepoID,
		RepoID:       repoID,
		RepoURL:      repoURL,
		RepoFullName: repoFull,
	})
	c.TrustDomain = cacheTrustDomain(c.Trusted)
	return c, true, nil
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

// bindSnapshotLeaseIdentity validates a snapshot record against the locked
// job's coordinates. The run and job ids are REQUIRED to match: a record that
// carries another job's coordinates is cross-bound and refused. The job key is
// stamped from the locked row when the caller omitted it and validated when
// present.
func bindSnapshotLeaseIdentity(jobID string, c leaseJobCoords, rec *model.SnapshotRecord) error {
	if rec.JobID != jobID {
		return leaseIdentityErrorf("snapshot %s job id %q does not match leased job %s", rec.ID, rec.JobID, jobID)
	}
	if rec.RunID != c.RunID {
		return leaseIdentityErrorf("snapshot %s run id %q does not match leased job run %s", rec.ID, rec.RunID, c.RunID)
	}
	if rec.JobKey != "" && rec.JobKey != c.JobKey {
		return leaseIdentityErrorf("snapshot %s job key %q does not match leased job key %q", rec.ID, rec.JobKey, c.JobKey)
	}
	if rec.JobKey == "" {
		rec.JobKey = c.JobKey
	}
	return nil
}

// bindArtifactLeaseIdentity validates an artifact record against the locked
// job's coordinates. Job id, run id and lease generation are REQUIRED to
// match: the (job, generation, name) idempotency key and the durable row are
// both bound to the job whose lease was proven.
func bindArtifactLeaseIdentity(jobID string, c leaseJobCoords, generation int64, a *model.ArtifactRecord) error {
	if a.JobID != jobID {
		return leaseIdentityErrorf("artifact %s job id %q does not match leased job %s", a.Name, a.JobID, jobID)
	}
	if a.RunID != c.RunID {
		return leaseIdentityErrorf("artifact %s run id %q does not match leased job run %s", a.Name, a.RunID, c.RunID)
	}
	if a.LeaseGeneration != generation {
		return leaseIdentityErrorf("artifact %s lease generation %d does not match leased generation %d", a.Name, a.LeaseGeneration, generation)
	}
	if a.JobKey != "" && a.JobKey != c.JobKey {
		return leaseIdentityErrorf("artifact %s job key %q does not match leased job key %q", a.Name, a.JobKey, c.JobKey)
	}
	if a.JobKey == "" {
		a.JobKey = c.JobKey
	}
	return nil
}

// bindCacheManifestLeaseIdentity validates a cache manifest record against the
// locked job's coordinates and stamps the authoritative producer coordinates.
// Repository and trust domain are DERIVED from the locked job (the shared
// RepoIDForJob derivation plus the job's trust flag) and must equal the
// record's namespace: a manifest is reachable by (repo, trust, logical key), so
// a mismatched namespace would publish into another repository's cache. The
// producer run/job are always written from the locked job; a non-empty
// disagreeing value is refused.
func bindCacheManifestLeaseIdentity(jobID string, c leaseJobCoords, rec *CacheManifestRecord) error {
	if rec.Repo != c.RepoID {
		return leaseIdentityErrorf("cache manifest repo %q does not match leased job repository %q", rec.Repo, c.RepoID)
	}
	if rec.TrustDomain != c.TrustDomain {
		return leaseIdentityErrorf("cache manifest trust domain %q does not match leased job trust domain %q", rec.TrustDomain, c.TrustDomain)
	}
	if rec.ProducerJob != "" && rec.ProducerJob != jobID {
		return leaseIdentityErrorf("cache manifest producer job %q does not match leased job %s", rec.ProducerJob, jobID)
	}
	if rec.ProducerRun != "" && rec.ProducerRun != c.RunID {
		return leaseIdentityErrorf("cache manifest producer run %q does not match leased job run %s", rec.ProducerRun, c.RunID)
	}
	rec.ProducerJob = jobID
	rec.ProducerRun = c.RunID
	return nil
}

// PutCacheManifestForLease is the transactional cache-manifest commit: it
// locks the job row, re-evaluates the live-lease predicate, validates the
// record's namespace and producer identity against the locked job, and only
// then upserts the manifest, all in one transaction. The stored row is
// byte-for-byte what PutCacheManifest would write.
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	coords, held, err := s.lockedLeaseJobTx(ctx, tx, jobID, runnerID, generation)
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: cache manifest for job %s", ErrLeaseLost, jobID)
	}
	if err := bindCacheManifestLeaseIdentity(jobID, coords, &rec); err != nil {
		return err
	}
	payload, err := jsonMarshal(rec)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cache_manifests (repo, trust_domain, logical_key, blob_sha256, blob_size, producer_run, producer_job, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (repo, trust_domain, logical_key) DO UPDATE SET blob_sha256=EXCLUDED.blob_sha256, blob_size=EXCLUDED.blob_size, producer_run=EXCLUDED.producer_run, producer_job=EXCLUDED.producer_job, created_at=EXCLUDED.created_at, payload=EXCLUDED.payload`,
		rec.Repo, rec.TrustDomain, rec.LogicalKey, rec.BlobSHA256, rec.BlobSize, nullText(rec.ProducerRun), nullText(rec.ProducerJob), rec.CreatedAt, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InsertSnapshotForLease is the transactional snapshot-record commit: it
// locks the job row, re-evaluates the live-lease predicate, validates the
// record's job/run identity against the locked job, and only then inserts the
// record, all in one transaction.
// CountSnapshotsForJob is the O(1) preflight count for one (run, job) pair:
// a direct COUNT over the indexed snapshot table instead of decoding every
// snapshot in the run. The COMMIT-time cap inside InsertSnapshotForLease
// remains the enforcement point.
func (s *PostgresStore) CountSnapshotsForJob(ctx context.Context, runID, jobID string) (int, error) {
	if err := ValidateRunID(runID); err != nil {
		return 0, err
	}
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM workspace_snapshots WHERE run_id=$1 AND job_id=$2`, runID, nullText(jobID)).Scan(&n)
	return n, err
}

func (s *PostgresStore) InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, maxPerJob int, rec model.SnapshotRecord) error {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return err
	}
	if err := ValidateID(rec.ID); err != nil {
		return err
	}
	if err := ValidateRunID(rec.RunID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	coords, held, err := s.lockedLeaseJobTx(ctx, tx, jobID, runnerID, generation)
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: snapshot %s for job %s", ErrLeaseLost, rec.ID, jobID)
	}
	if err := bindSnapshotLeaseIdentity(jobID, coords, &rec); err != nil {
		return err
	}
	// Cap enforcement at COMMIT, not just as a preflight check: the job row is
	// locked, so concurrent snapshot commits for one job serialize here and
	// can never exceed the cap. The count is keyed to the LOCKED job's
	// (run, job) coordinates, never to the record's fields.
	if maxPerJob > 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace_snapshots WHERE run_id=$1 AND job_id=$2`, coords.RunID, jobID).Scan(&n); err != nil {
			return err
		}
		if n >= maxPerJob {
			return fmt.Errorf("%w: job %s already has %d snapshots (cap %d)", ErrSnapshotCapReached, jobID, n, maxPerJob)
		}
	}
	payload, err := jsonMarshal(rec)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workspace_snapshots (id, run_id, job_id, created_at, payload) VALUES ($1, $2, $3, $4, $5)`,
		rec.ID, rec.RunID, nullText(rec.JobID), rec.CreatedAt, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InsertArtifactOnceForLease is the transactional artifact commit: it locks
// the job row, re-evaluates the live-lease predicate, validates the record's
// job/run/generation identity against the locked job, and only then performs
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	defer tx.Rollback(ctx)
	coords, held, err := s.lockedLeaseJobTx(ctx, tx, jobID, runnerID, generation)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if !held {
		return model.ArtifactRecord{}, false, fmt.Errorf("%w: artifact %s for job %s", ErrLeaseLost, a.Name, jobID)
	}
	if err := bindArtifactLeaseIdentity(jobID, coords, generation, &a); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	payload, err := jsonMarshal(a)
	if err != nil {
		return model.ArtifactRecord{}, false, err
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

// leaseJobCoordsLocked evaluates the same predicate as lockedLeaseJobTx
// against the in-memory job map and returns the authoritative coordinates. The
// caller holds m.mu, which is this store's transaction: the check and the
// caller's metadata write are atomic with respect to every other memStore
// mutation, and the coordinates are read under the same lock as the write.
func (m *memStore) leaseJobCoordsLocked(jobID, runnerID string, generation int64, now time.Time) (leaseJobCoords, bool) {
	j, ok := m.jobs[jobID]
	if !ok {
		return leaseJobCoords{}, false
	}
	if j.Status != model.StatusRunning || j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now) {
		return leaseJobCoords{}, false
	}
	if j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation {
		return leaseJobCoords{}, false
	}
	return leaseJobCoords{
		JobID:       jobID,
		RunID:       j.RunID,
		JobKey:      j.Key,
		Generation:  generation,
		RepoID:      RepoIDForJob(j),
		Trusted:     j.Trusted,
		TrustDomain: cacheTrustDomain(j.Trusted),
	}, true
}

// PutCacheManifestForLease is the in-memory mirror of the SQL transactional
// cache-manifest commit: the predicate, the identity binding and the write
// happen under one lock.
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
	coords, held := m.leaseJobCoordsLocked(jobID, runnerID, generation, time.Now().UTC())
	if !held {
		return fmt.Errorf("%w: cache manifest for job %s", ErrLeaseLost, jobID)
	}
	if err := bindCacheManifestLeaseIdentity(jobID, coords, &rec); err != nil {
		return err
	}
	m.cacheMans[rec.Repo+"\x00"+rec.TrustDomain+"\x00"+rec.LogicalKey] = rec
	return nil
}

// InsertSnapshotForLease is the in-memory mirror of the SQL transactional
// snapshot-record commit.
// CountSnapshotsForJob mirrors the SQL preflight count for the in-memory
// store.
func (m *memStore) CountSnapshotsForJob(ctx context.Context, runID, jobID string) (int, error) {
	if err := ValidateRunID(runID); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, rec := range m.snapshots {
		if rec.RunID == runID && rec.JobID == jobID {
			n++
		}
	}
	return n, nil
}

func (m *memStore) InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, maxPerJob int, rec model.SnapshotRecord) error {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	coords, held := m.leaseJobCoordsLocked(jobID, runnerID, generation, time.Now().UTC())
	if !held {
		return fmt.Errorf("%w: snapshot %s for job %s", ErrLeaseLost, rec.ID, jobID)
	}
	if err := bindSnapshotLeaseIdentity(jobID, coords, &rec); err != nil {
		return err
	}
	if maxPerJob > 0 {
		n := 0
		for _, existing := range m.snapshots {
			if existing.RunID == coords.RunID && existing.JobID == jobID {
				n++
			}
		}
		if n >= maxPerJob {
			return fmt.Errorf("%w: job %s already has %d snapshots (cap %d)", ErrSnapshotCapReached, jobID, n, maxPerJob)
		}
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
	coords, held := m.leaseJobCoordsLocked(jobID, runnerID, generation, time.Now().UTC())
	if !held {
		return model.ArtifactRecord{}, false, fmt.Errorf("%w: artifact %s for job %s", ErrLeaseLost, a.Name, jobID)
	}
	if err := bindArtifactLeaseIdentity(jobID, coords, generation, &a); err != nil {
		return model.ArtifactRecord{}, false, err
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
// while injecting the configured mutation fault. Identity binding (X3-A) is
// the inner implementation's contract; the wrapper never writes anything
// itself, so a forwarding call cannot bypass it.
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
// while injecting the configured mutation fault. Identity binding (X3-A) is
// the inner implementation's contract; the wrapper never writes anything
// itself, so a forwarding call cannot bypass it.
// CountSnapshotsForJob forwards the inner store's preflight count.
func (f *FaultyStore) CountSnapshotsForJob(ctx context.Context, runID, jobID string) (int, error) {
	inner, ok := f.Inner.(interface {
		CountSnapshotsForJob(context.Context, string, string) (int, error)
	})
	if !ok {
		return 0, errMissingInnerInterface("SnapshotCountStore")
	}
	return inner.CountSnapshotsForJob(ctx, runID, jobID)
}

func (f *FaultyStore) InsertSnapshotForLease(ctx context.Context, jobID, runnerID string, generation int64, maxPerJob int, rec model.SnapshotRecord) error {
	inner, ok := f.Inner.(LeaseCommitStore)
	if !ok {
		return errMissingInnerInterface("LeaseCommitStore")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return err
	}
	return inner.InsertSnapshotForLease(ctx, jobID, runnerID, generation, maxPerJob, rec)
}

// InsertArtifactOnceForLease forwards the faulted backend's inner
// implementation while injecting the configured mutation fault. Identity
// binding (X3-A) is the inner implementation's contract; the wrapper never
// writes anything itself, so a forwarding call cannot bypass it.
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
