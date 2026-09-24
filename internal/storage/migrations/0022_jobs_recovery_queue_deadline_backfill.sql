-- 0022_jobs_recovery_queue_deadline_backfill.sql — one-time backfill of the
-- derived queue_deadline column (see 0021).
--
-- Split out of 0021 (DEPLOY-SAFETY): the ADD COLUMN holds ACCESS EXCLUSIVE on
-- jobs, while this row-level UPDATE takes only ROW EXCLUSIVE and therefore
-- blocks neither reads nor ordinary job writes for the duration of the scan.
--
-- The guard keeps malformed payload values out of the cast: only a JSON STRING
-- is considered at all, and it must match a FULL RFC3339 calendar before the
-- ::timestamptz cast. The pre-fix guard checked only the '\d{4}-\d{2}-\d{2}'
-- date PREFIX, so a value like "2024-13-45T99:99:99Z" passed the filter and
-- then RAISED inside the migration transaction, aborting it and blocking every
-- subsequent startup. A bare prefix cannot be made safe: PostgreSQL also
-- rejects calendar-invalid days that a range check alone would admit
-- ("2024-02-30"), so the regex validates month/day/hour/min/sec AND the real
-- calendar, including leap years (Feb 29 only in a leap year, year 0000
-- rejected because PostgreSQL has no year zero), an optional fractional second
-- and a "Z"/±HH:MM offset within the ±15:59 PostgreSQL accepts. Every string
-- the regex admits casts without raising. Everything else stays NULL and is
-- served by the query's payload fallback instead of failing the migration.
--
-- New rows are stamped by the canonical job write path. A row inserted by an
-- old binary between 0021 and 0022 that commits after this UPDATE's snapshot
-- stays NULL and is equally covered by the fallback predicate.

UPDATE jobs
SET queue_deadline = (payload->>'queue_deadline')::timestamptz
WHERE queue_deadline IS NULL
  AND jsonb_typeof(payload->'queue_deadline') = 'string'
  AND payload->>'queue_deadline' ~ '^(?!0000)(?:[0-9]{4}-(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|[0-9]{4}-(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)|[0-9]{4}-02-(?:0[1-9]|1[0-9]|2[0-8])|(?:[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|(?:0[48]|[2468][048]|[13579][26])00)-02-29)T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|[+-](?:0[0-9]|1[0-5]):[0-5][0-9])$';
