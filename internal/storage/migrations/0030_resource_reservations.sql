-- 0030_resource_reservations.sql — runner resource capacities and durable
-- per-lease resource reservations.
--
-- Runner profiles gain the four resource dimensions (max_cpu, max_memory,
-- max_disk, max_pids). A zero value means the dimension is UNCONSTRAINED:
-- that is the documented default and preserves the pre-0030 behavior
-- exactly (admission limited to the job-count capacity). Capacities live on
-- the profile only, because every scheduling decision already resolves the
-- runner's LIVE profile through cert_profile_links: a profile edit takes
-- effect on the next lease without touching the runner row.
--
-- job_resource_reservations is the durable check-and-reserve ledger: the
-- lease claim inserts the leased job's requested resources in the SAME
-- transaction that flips the job to running, and every path that ends or
-- invalidates a lease deletes the row in its own transaction (completion,
-- cancellation, supersession, lease recovery, corruption recovery, runner
-- revocation/disable, queue-timeout expiry). job_id is the primary key, so
-- a release is idempotent and a re-lease replaces the row instead of
-- double-counting. RUNNING jobs hold reservations and queued jobs hold none.
--
-- The (runner_id) index backs the in-transaction remaining-capacity SUM.

ALTER TABLE runner_profiles ADD COLUMN IF NOT EXISTS max_cpu DOUBLE PRECISION NOT NULL DEFAULT 0;

ALTER TABLE runner_profiles ADD COLUMN IF NOT EXISTS max_memory BIGINT NOT NULL DEFAULT 0;

ALTER TABLE runner_profiles ADD COLUMN IF NOT EXISTS max_disk BIGINT NOT NULL DEFAULT 0;

ALTER TABLE runner_profiles ADD COLUMN IF NOT EXISTS max_pids INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS job_resource_reservations (
    job_id TEXT NOT NULL PRIMARY KEY,
    runner_id TEXT NOT NULL,
    generation BIGINT NOT NULL DEFAULT 0,
    cpu DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory BIGINT NOT NULL DEFAULT 0,
    disk BIGINT NOT NULL DEFAULT 0,
    pids INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS job_resource_reservations_runner_idx ON job_resource_reservations (runner_id);
