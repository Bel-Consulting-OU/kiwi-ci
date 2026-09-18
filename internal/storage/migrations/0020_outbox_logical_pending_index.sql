-- 0020_outbox_logical_pending_index.sql — pending versioned outbox lookup.
--
-- Split out of 0018 (DEPLOY-SAFETY): the runner applies each migration file
-- in one transaction (internal/storage/postgres.go applyMigration), so this
-- build holds only its own SHARE lock on outbox instead of sharing the
-- ADD COLUMN transaction's ACCESS EXCLUSIVE lock. The SHARE lock blocks
-- outbox writes (INSERT/UPDATE/DELETE: webhook and completion enqueues) for
-- the duration of this single index build, but not reads.
--
-- Non-concurrent on purpose: CREATE INDEX CONCURRENTLY cannot run inside a
-- transaction block and the runner has no non-transactional mode. Keeping
-- IF NOT EXISTS makes the file a no-op on databases that already applied the
-- original combined 0018, where this index was created by that file.

CREATE INDEX IF NOT EXISTS outbox_logical_pending_idx
    ON outbox (logical_key, state_version)
    WHERE logical_key IS NOT NULL AND dead_lettered_at IS NULL;
