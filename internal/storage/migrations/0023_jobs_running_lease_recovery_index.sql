-- 0023_jobs_running_lease_recovery_index.sql — expired running-lease discovery.
--
-- Split out of the 0021/0022 queue-deadline migration batch (DEPLOY-SAFETY):
-- the runner applies each migration file in one transaction
-- (internal/storage/postgres.go applyMigration), so this build holds only its
-- own SHARE lock on jobs instead of sharing the ADD COLUMN transaction's
-- ACCESS EXCLUSIVE lock or the backfill's row locks. The SHARE lock blocks job
-- writes for the duration of this single index build, but not reads.
--
-- ListExpiredRunningJobs filters status='running' AND (lease_expires_at <=
-- now OR lease_expires_at IS NULL) and pages in id order. The partial index
-- keeps every running row in (lease_expires_at, id) order, so the range scan
-- starts at the oldest expiries (and the IS NULL branch) instead of touching
-- the terminal history, while id is the deterministic tiebreaker/keyset that
-- the paged sweep orders by.
--
-- Non-concurrent on purpose: CREATE INDEX CONCURRENTLY cannot run inside a
-- transaction block and the runner has no non-transactional mode. Keeping
-- IF NOT EXISTS makes the file a no-op on databases that already created the
-- index.

CREATE INDEX IF NOT EXISTS jobs_running_lease_recovery_idx
    ON jobs (lease_expires_at, id)
    WHERE status = 'running';
