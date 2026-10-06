-- 0039_queued_scheduling_key.sql — materialized aged scheduling key plus
-- coarse-eligibility indexes for bounded queued-candidate selection.
--
-- The aged order (priority + floor(age/600s)) was computed at query time, so
-- no index could satisfy its ORDER BY and a LIMIT still sorted the whole
-- queued population. queue_boost materializes the wait term into a real
-- column (recomputed by the bounded idempotent PromoteQueuedJobBoosts sweep)
-- and jobs_queued_aged_idx makes the exact aged ORDER BY an index order, so
-- the page walk stops after limit+1 index entries.
--
-- The coarse-eligibility indexes let a runner's page query push runtime,
-- required-label and placement-region eligibility into the database instead
-- of paging through candidates the runner can never take. Every expression is
-- immutable (no now()), so all are valid index keys. This migration is
-- ADD-only (one column with a constant default plus new partial indexes) and
-- keeps older binaries operating unchanged.

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS queue_boost INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS jobs_queued_aged_idx
    ON jobs (((priority + queue_boost)) DESC, created_at ASC, id ASC)
    WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_boost_sweep_idx
    ON jobs (created_at ASC, queue_boost ASC, id ASC)
    WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_runtime_idx
    ON jobs ((COALESCE(NULLIF(payload->'compiled_job_payload'->'effective_job'->'job'->>'runtime',''),'native')))
    WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_labels_idx
    ON jobs USING gin ((payload->'required_labels'))
    WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_regions_idx
    ON jobs USING gin ((payload->'placement_regions'))
    WHERE status='queued';
