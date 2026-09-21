-- 0024_jobs_queue_deadline_recovery_index.sql — queue-timeout discovery.
--
-- Split out of the 0021/0022 queue-deadline migration batch (DEPLOY-SAFETY):
-- the runner applies each migration file in one transaction
-- (internal/storage/postgres.go applyMigration), so this build holds only its
-- own SHARE lock on jobs instead of sharing the ADD COLUMN transaction's
-- ACCESS EXCLUSIVE lock or the backfill's row locks. The SHARE lock blocks job
-- writes for the duration of this single index build, but not reads.
--
-- ListQueueTimedOutJobs filters the non-terminal queue states and
-- queue_deadline <= now and pages in id order. The partial index keeps only
-- those rows in (queue_deadline, id) order, so the sweep pages straight to the
-- elapsed deadlines regardless of how many older/newer runs exist, and id is
-- the deterministic tiebreaker/keyset. Legacy rows whose deadline is only
-- derivable from the compiled payload keep a NULL column and are covered by
-- the query's payload fallback predicate, not by this index.
--
-- Non-concurrent on purpose: CREATE INDEX CONCURRENTLY cannot run inside a
-- transaction block and the runner has no non-transactional mode. Keeping
-- IF NOT EXISTS makes the file a no-op on databases that already created the
-- index.

CREATE INDEX IF NOT EXISTS jobs_queue_deadline_recovery_idx
    ON jobs (queue_deadline, id)
    WHERE status IN ('queued', 'waiting_approval');
