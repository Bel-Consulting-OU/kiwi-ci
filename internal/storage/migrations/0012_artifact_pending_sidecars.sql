-- 0012_artifact_pending_sidecars.sql — durable pending artifact sidecars.
--
-- A runner may upload an SBOM or sigstore bundle BEFORE its artifact
-- payload (the payload upload gate resolves the sidecar bytes). In DB mode
-- the bytes live in the shared CAS and this table records the
-- (job_id, artifact_name, kind) -> digest mapping, so the pending state is
-- durable and visible to every replica instead of living in one node's
-- memory:
--   * the artifact upload gate resolves the digest from here,
--   * the artifact record creation copies the digest into the record and
--     then CONSUMES the row (delete) once the record is durably written,
--   * leftover rows for a job are cleared when an artifact record commits
--     (DeletePendingSidecars),
--   * rows older than the retention window (7 days) are pruned by the
--     maintenance tick (PrunePendingSidecars).
--
-- The digest is content-addressed: consuming or pruning a row never
-- deletes the CAS blob, which may be referenced by other records.

CREATE TABLE artifact_pending_sidecars (
    job_id TEXT NOT NULL,
    artifact_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, artifact_name, kind)
);

CREATE INDEX artifact_pending_sidecars_created_at_idx ON artifact_pending_sidecars (created_at);
