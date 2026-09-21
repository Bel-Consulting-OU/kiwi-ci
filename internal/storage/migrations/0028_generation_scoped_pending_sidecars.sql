-- 0028_generation_scoped_pending_sidecars.sql — generation-qualified pending
-- artifact sidecars.
--
-- Artifact identity in kiwi-ci is (job_id, lease_generation, artifact_name):
-- the artifacts table carries job_generation and
-- artifacts_job_generation_name_idx (migration 0010) arbitrates uploads on
-- exactly that triple. Migration 0012's artifact_pending_sidecars, however,
-- was keyed by (job_id, artifact_name, kind) — it DROPPED the generation. A
-- retry generation uploading an SBOM or sigstore bundle before its artifact
-- payload could therefore resolve, verify against, attach to, or consume the
-- PREVIOUS generation's artifact record: a supply-chain gate that attests the
-- wrong bytes.
--
-- This migration recreates the table with the full artifact identity in the
-- primary key:
--
--   PRIMARY KEY (job_id, job_generation, artifact_name, kind)
--
-- and keeps the created_at prune index (the maintenance tick still drops
-- rows older than the 7-day retention window).
--
-- DRAIN-FIRST UPGRADE: artifact_pending_sidecars holds TRANSIENT state only —
-- a row exists between a sidecar upload and the artifact payload commit that
-- consumes it. A pre-0028 row carries no generation, so it cannot be safely
-- attributed to any artifact under the new identity (guessing 0 or the job's
-- current generation is exactly the cross-generation confusion this
-- migration removes). The correctness-first transition is therefore to DRAIN
-- the rows (DELETE) rather than fall back to cross-version semantics: any
-- sidecar still waiting for its payload at upgrade time is dropped, the
-- artifact payload gate then fails closed (422) for that pending sidecar
-- until the runner re-uploads it, and the runner's normal sidecar-then-payload
-- order re-creates the row. OPERATORS: let in-flight artifact/sidecar
-- uploads finish before applying this migration, and never run a mixed-version
-- fleet (a pre-0028 replica writes the generation-less column list and will
-- fail its sidecar writes against the recreated table) — drain the runners or
-- upgrade all replicas together.
--
-- DEPLOY-SAFETY (same discipline as 0021-0027): every statement in this file
-- touches ONLY artifact_pending_sidecars, whose rows are bounded by the
-- in-flight upload window and which no other relation references. No other
-- table is locked or rewritten, so there is nothing to split further: the
-- DRAIN + DROP + CREATE must stay in one migration file so the table is never
-- absent for a committed schema version. IF EXISTS keeps a replay harmless,
-- and the created_at index keeps the existing 7-day prune behavior.

DELETE FROM artifact_pending_sidecars;

DROP TABLE IF EXISTS artifact_pending_sidecars;

CREATE TABLE artifact_pending_sidecars (
    job_id TEXT NOT NULL,
    job_generation BIGINT NOT NULL,
    artifact_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, job_generation, artifact_name, kind)
);

CREATE INDEX IF NOT EXISTS artifact_pending_sidecars_created_at_idx
    ON artifact_pending_sidecars (created_at);
