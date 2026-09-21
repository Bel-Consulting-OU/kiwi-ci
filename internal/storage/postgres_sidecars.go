package storage

// Artifact sidecars: the durable state that bridges an SBOM /
// Sigstore-bundle upload and the artifact record that later references it.
//
// Artifact identity in this codebase is (job_id, lease_generation,
// artifact_name): the artifacts table carries job_generation and the unique
// index artifacts_job_generation_name_idx arbitrates uploads on exactly that
// triple. A sidecar upload is only meaningful for one of those triples — a
// retry generation must never resolve, verify against, attach to, or consume
// another generation's artifact. This file therefore keeps the generation
// first-class in the pending-sidecar store contract.
//
// The pending table artifact_pending_sidecars was recreated by migration 0028
// with PRIMARY KEY (job_id, job_generation, artifact_name, kind). Rows are
// TRANSIENT pending state (they only exist between a sidecar upload and its
// artifact payload commit), so 0028 DRAINS the pre-0028 rows instead of
// guessing a generation for them: a generation-less row can never be safely
// attributed to an artifact under the new identity. Operators upgrading
// should let in-flight uploads finish (or re-upload the sidecar afterwards);
// the 7-day prune window is unchanged.
//
// The digests are content-addressed: no method here ever deletes a CAS blob,
// which may be referenced by other records.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ArtifactSidecarStore is the durable artifact-sidecar contract:
// SetArtifactSidecars updates one artifact record's sidecar references
// (SBOM/sigstore digests) after the record was created (only non-empty
// values are written), and the pending-sidecar methods persist the upload
// window between a sidecar upload and its artifact payload. Pending rows are
// keyed by the full artifact identity (job_id, generation, artifact_name,
// kind):
//
//   - RememberPendingSidecar upserts the digest (a re-upload of the same
//     kind replaces the digest) for one generation.
//   - PendingSidecar resolves it (ok=false when no row exists for that
//     generation — never a fallback to another generation).
//   - ConsumePendingSidecar deletes the row ONLY when the stored digest
//     still equals the consumed record's reference, and only for the exact
//     generation: a newer re-upload or another generation's row is never
//     dropped by a stale consumer.
//   - PrunePendingSidecars drops rows older than the cutoff (the
//     maintenance tick prunes rows past the 7-day retention window).
//
// There is deliberately no job-wide delete: a per-artifact commit consumes
// ONLY the rows its own record references, and everything else survives
// until its own commit or the 7-day prune.
type ArtifactSidecarStore interface {
	SetArtifactSidecars(ctx context.Context, artifactID, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error
	RememberPendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error
	PendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind string) (digest string, ok bool, err error)
	ConsumePendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error
	PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error)
}

// validatePendingSidecarKey checks the artifact_pending_sidecars primary-key
// components. The artifact name is the cleaned name the server addresses
// records by; the generation is the artifact's lease generation (>= 0, the
// backfilled generation of pre-0010 rows); the kind is one of the canonical
// kinds.
func validatePendingSidecarKey(jobID string, generation int64, artifactName, kind string) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	if generation < 0 {
		return fmt.Errorf("storage: invalid pending sidecar generation %d", generation)
	}
	if strings.TrimSpace(artifactName) == "" {
		return fmt.Errorf("storage: empty pending sidecar artifact name")
	}
	switch kind {
	case ArtifactSidecarKindSBOM, ArtifactSidecarKindSigstore:
		return nil
	default:
		return fmt.Errorf("storage: invalid pending sidecar kind %q", kind)
	}
}

// validatePendingSidecarDigest checks the content-addressed digest stored
// for a pending sidecar: the canonical 64 lowercase hex sha256.
func validatePendingSidecarDigest(digest string) error {
	if len(digest) != 64 {
		return fmt.Errorf("storage: invalid pending sidecar digest length %d", len(digest))
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return fmt.Errorf("storage: invalid pending sidecar digest character %q at position %d", c, i)
	}
	return nil
}

// SetArtifactSidecars updates an artifact record's sidecar references
// (non-empty values only) with one jsonb_set per field.
func (s *PostgresStore) SetArtifactSidecars(ctx context.Context, artifactID, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error {
	if err := ValidateID(artifactID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if sbomPath != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sbom_path}', to_jsonb($2::text), true) WHERE id=$1`, artifactID, sbomPath); err != nil {
			return err
		}
	}
	if sbomSHA256 != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sbom_sha256}', to_jsonb($2::text), true) WHERE id=$1`, artifactID, sbomSHA256); err != nil {
			return err
		}
	}
	if sigstorePath != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sigstore_path}', to_jsonb($2::text), true) WHERE id=$1`, artifactID, sigstorePath); err != nil {
			return err
		}
	}
	if sigstoreSHA256 != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sigstore_sha256}', to_jsonb($2::text), true) WHERE id=$1`, artifactID, sigstoreSHA256); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RememberPendingSidecar upserts the pending sidecar digest for one
// (job, generation, artifact, kind) artifact identity: a re-upload of the
// same kind replaces the digest and refreshes created_at, so the payload gate
// always resolves the latest bytes. The row is durable and shared, so any
// replica can resolve it, and generation-qualified, so a retry generation
// never overwrites the previous generation's pending state.
func (s *PostgresStore) RememberPendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error {
	if err := validatePendingSidecarKey(jobID, generation, artifactName, kind); err != nil {
		return err
	}
	if err := validatePendingSidecarDigest(digest); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO artifact_pending_sidecars (job_id, job_generation, artifact_name, kind, digest) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (job_id, job_generation, artifact_name, kind) DO UPDATE SET digest = EXCLUDED.digest, created_at = now()`,
		jobID, generation, artifactName, kind, digest)
	return err
}

// PendingSidecar resolves the pending sidecar digest uploaded for one
// (job, generation, artifact) identity, or ok=false when no row exists for
// that generation (the gate then fails closed; a row for another generation
// is never returned).
func (s *PostgresStore) PendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind string) (string, bool, error) {
	if err := validatePendingSidecarKey(jobID, generation, artifactName, kind); err != nil {
		return "", false, err
	}
	var digest string
	err := s.pool.QueryRow(ctx, `SELECT digest FROM artifact_pending_sidecars WHERE job_id=$1 AND job_generation=$2 AND artifact_name=$3 AND kind=$4`,
		jobID, generation, artifactName, kind).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return digest, true, nil
}

// ConsumePendingSidecar deletes the pending row for one
// (job, generation, artifact, kind) identity only while it still carries the
// consumed digest: a concurrent re-upload with a newer digest, and every
// other generation's rows, survive the stale consumer.
func (s *PostgresStore) ConsumePendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind, digest string) error {
	if err := validatePendingSidecarKey(jobID, generation, artifactName, kind); err != nil {
		return err
	}
	if err := validatePendingSidecarDigest(digest); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM artifact_pending_sidecars WHERE job_id=$1 AND job_generation=$2 AND artifact_name=$3 AND kind=$4 AND digest=$5`,
		jobID, generation, artifactName, kind, digest)
	return err
}

// PrunePendingSidecars deletes pending rows created before the cutoff and
// reports how many were removed. It never touches CAS blobs. This is the
// durable delete of the leader-only GC pass, so it is epoch-FENCED: a stale
// leader prunes nothing.
func (s *PostgresStore) PrunePendingSidecars(ctx context.Context, olderThan time.Time) (int, error) {
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	ct, err := tx.Exec(ctx, `DELETE FROM artifact_pending_sidecars WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}
