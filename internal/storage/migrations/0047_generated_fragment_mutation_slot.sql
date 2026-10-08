-- 0047_generated_fragment_mutation_slot.sql — logical generator mutation slot.
--
-- 0043 made (parent_job_id, fragment_id) the receipt identity for content
-- idempotency: an identical fragment replays, a changed fragment inserts a
-- second child graph. But content identity answers "identical mutation?" and
-- not "same logical generator emission?": a nondeterministic generator retry
-- of the same emission can submit a DIFFERENT fragment digest and append a
-- SECOND child graph under one parent job.
--
-- This migration adds the logical mutation slot. Today's endpoint has exactly
-- one generated output per parent job, so every existing row is the constant
-- slot 'generated'. Receipt identity becomes (parent_job_id, mutation_slot):
-- a differing fragment digest in the same slot fails closed in the store and
-- the handler answers 409, never a second graph. The future generalization
-- (parent, mutation_key, digest) with a client-supplied key is documented on
-- the request type and deliberately not implemented yet.
--
-- Duplicates per (parent_job_id, mutation_slot) — the exact history a
-- nondeterministic retry left behind before the slot existed — are preserved
-- in generated_fragments_conflicts with reason 'nondeterministic mutation
-- retry (pre-slot upgrade)', never deleted silently. Child job rows are
-- untouched. The conflicts table is also created by the migrator's 0043
-- preflight, so CREATE TABLE IF NOT EXISTS here covers databases that
-- recorded 43 before that preflight existed.

CREATE TABLE IF NOT EXISTS generated_fragments_conflicts (
    parent_job_id TEXT NOT NULL,
    lease_generation BIGINT NOT NULL,
    fragment_id TEXT NOT NULL,
    children JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE generated_fragments ADD COLUMN IF NOT EXISTS mutation_slot TEXT NOT NULL DEFAULT 'generated';

INSERT INTO generated_fragments_conflicts (parent_job_id, lease_generation, fragment_id, children, created_at, reason)
SELECT parent_job_id, lease_generation, fragment_id, children, created_at,
       'nondeterministic mutation retry (pre-slot upgrade)'
FROM (
    SELECT parent_job_id, lease_generation, fragment_id, children, created_at,
           ROW_NUMBER() OVER (PARTITION BY parent_job_id, mutation_slot ORDER BY created_at DESC, lease_generation DESC) AS rn
    FROM generated_fragments
) ranked
WHERE rn > 1;

DELETE FROM generated_fragments gf
USING (
    SELECT parent_job_id, lease_generation, fragment_id
    FROM (
        SELECT parent_job_id, lease_generation, fragment_id,
               ROW_NUMBER() OVER (PARTITION BY parent_job_id, mutation_slot ORDER BY created_at DESC, lease_generation DESC) AS rn
        FROM generated_fragments
    ) ranked
    WHERE rn > 1
) dup
WHERE gf.parent_job_id = dup.parent_job_id
  AND gf.lease_generation = dup.lease_generation
  AND gf.fragment_id = dup.fragment_id;

CREATE UNIQUE INDEX IF NOT EXISTS generated_fragments_slot_idx
    ON generated_fragments (parent_job_id, mutation_slot);
