-- 0022_jobs_recovery_queue_deadline_backfill.sql — one-time backfill of the
-- derived queue_deadline column (see 0021).
--
-- Split out of 0021 (DEPLOY-SAFETY): the ADD COLUMN holds ACCESS EXCLUSIVE on
-- jobs, while this row-level UPDATE takes only ROW EXCLUSIVE and therefore
-- blocks neither reads nor ordinary job writes for the duration of the scan.
-- The guard keeps malformed payload values out of the cast: only string
-- values that start like an RFC3339 timestamp are converted (the canonical
-- writer marshals time.Time exactly like that), everything else stays NULL
-- and is served by the query's payload fallback instead of failing the
-- migration.
--
-- New rows are stamped by the canonical job write path. A row inserted by an
-- old binary between 0021 and 0022 that commits after this UPDATE's snapshot
-- stays NULL and is equally covered by the fallback predicate.

UPDATE jobs
SET queue_deadline = (payload->>'queue_deadline')::timestamptz
WHERE queue_deadline IS NULL
  AND jsonb_typeof(payload->'queue_deadline') = 'string'
  AND payload->>'queue_deadline' ~ '^\d{4}-\d{2}-\d{2}';
