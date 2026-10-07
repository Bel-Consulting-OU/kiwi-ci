-- 0043_generated_fragment_mutation_key.sql — scope generated-fragment
-- idempotency by the semantic mutation identity (parent job, fragment id)
-- instead of the lease generation.
--
-- The lease generation AUTHORIZES one upload (the runner must present the
-- currently active lease) but it does not define the mutation. An
-- infrastructure retry requeues the same logical parent under a NEW
-- generation and re-submits an identical fragment: keyed by generation the
-- receipt missed, so the retry inserted a duplicate child graph with fresh
-- random child IDs. The unique index below makes (parent_job_id, fragment_id)
-- the mutation identity: an identical fragment replays the original children
-- under any generation, while a changed fragment (different fragment_id)
-- still inserts a new graph.
--
-- Backfill-free: every existing row was already unique per generation, so
-- the pair is already unique. If a duplicate pair somehow exists, CREATE
-- UNIQUE INDEX fails loudly and aborts the migration (the version is not
-- recorded), which is the intended fail-closed outcome. The existing primary
-- key stays.

CREATE UNIQUE INDEX IF NOT EXISTS generated_fragments_mutation_idx
    ON generated_fragments (parent_job_id, fragment_id);
