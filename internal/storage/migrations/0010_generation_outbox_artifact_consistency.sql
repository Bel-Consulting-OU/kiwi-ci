-- 0010_generation_outbox_artifact_consistency.sql — HA consistency state for
-- generated fragments, cross-replica outbox flushing, and artifact uploads.
--
-- generated_fragments is the idempotency receipt of one runner fragment
-- upload: (parent_job_id, lease_generation, fragment_id) is the deterministic
-- key (fragment_id = sha256 hex of the canonical JSON of the parsed
-- {jobs, deps}), and children carries the created child key/ID pairs in
-- canonical sorted-key order. The receipt is inserted in the SAME transaction as the
-- child jobs, so a replay after a lost response returns the original children
-- and never duplicates a fragment.
--
-- outbox gains the cross-replica claim lease: a flusher atomically claims a
-- batch (SELECT ... FOR UPDATE SKIP LOCKED) before dispatch and acknowledges
-- (DELETE) after it, a claimed_at older than the claim TTL (5 minutes) is
-- reclaimable by another replica after a crash.
--
-- artifacts gains the job_generation column and the (job_id, job_generation,
-- name) unique index that make the database the authoritative arbiter of
-- artifact idempotency. Existing rows backfill their generation from the
-- stored payload so replays of pre-migration uploads still match.

CREATE TABLE generated_fragments (
    parent_job_id TEXT NOT NULL,
    lease_generation BIGINT NOT NULL,
    fragment_id TEXT NOT NULL,
    children JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (parent_job_id, lease_generation, fragment_id)
);

ALTER TABLE outbox ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

ALTER TABLE outbox ADD COLUMN IF NOT EXISTS claimed_by TEXT;

CREATE INDEX IF NOT EXISTS outbox_claim_idx ON outbox (claimed_at);

ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS job_generation BIGINT NOT NULL DEFAULT 0;

-- The generation backfill reads an untrusted payload. A bare cast of a
-- malformed value ("abc", a boolean, a fractional/exponent number) raises and
-- aborts the migration transaction, leaving the version unrecorded and every
-- startup blocked. The guard is the resource-reconcile pattern: jsonb_typeof
-- proves the value is a JSON number, the text must be a plain optional-sign
-- integer (PostgreSQL renders jsonb numbers in canonical decimal form, so a
-- fractional or enormous value is rejected here), and the exact numeric
-- comparison keeps the cast inside BIGINT's domain. Everything else defaults
-- the column to 0.
UPDATE artifacts SET job_generation = CASE
    WHEN jsonb_typeof(payload->'lease_generation') = 'number'
     AND (payload->>'lease_generation') ~ '^-?[0-9]+$'
     AND (payload->>'lease_generation')::numeric BETWEEN (-9223372036854775808)::numeric AND (9223372036854775807)::numeric
    THEN (payload->>'lease_generation')::bigint
    ELSE 0 END;

CREATE UNIQUE INDEX IF NOT EXISTS artifacts_job_generation_name_idx ON artifacts (job_id, job_generation, name);
