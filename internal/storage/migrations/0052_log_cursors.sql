-- 0052_log_cursors.sql — commit-ordered PostgreSQL log cursors.
--
-- log_entries.seq was a GENERATED ALWAYS AS IDENTITY column: the identity
-- sequence allocates inside the INSERT statement, BEFORE its transaction
-- commits. A consumer could therefore observe seq 12 (committed) while seq 11
-- was still in flight, advance its cursor past 11, and lose 11 forever — a
-- rollback and a late commit are indistinguishable on the log stream. It is
-- the same defect the execution event stream fixed in migration 0046.
--
-- This migration adds log_cursors (one row per run) and drops the identity
-- property of log_entries.seq, redefining the primary key as (run_id, seq)
-- (see the per-run uniqueness note below). Appends allocate through the
-- single upsert
--   INSERT INTO log_cursors (run_id, value) VALUES ($1, $n)
--   ON CONFLICT (run_id) DO UPDATE SET value = log_cursors.value + $n
--   RETURNING value
-- whose row lock is held to commit: a later append for the same run BLOCKS
-- until the earlier one commits or rolls back, so allocation order equals
-- visible order and a rollback frees its range (no holes).
--
-- The backfill seeds each run's cursor from MAX(seq), so an upgraded database
-- never reuses a sequence value that is already visible. Old binaries are
-- fenced by the default compatible-from (0052): an append path that still
-- relied on the identity default would allocate outside the cursor table.
--
-- Because the cursor is PER RUN, seq is now the commit-ordered sequence
-- WITHIN a run: two runs may both have seq 1. The primary key is redefined
-- from (seq) to (run_id, seq), which stays unique for all existing rows
-- (the identity was globally unique) and is the identity every reader
-- already uses (WHERE run_id = $1 AND seq > $2 ORDER BY seq).

CREATE TABLE IF NOT EXISTS log_cursors (
    run_id TEXT PRIMARY KEY,
    value BIGINT NOT NULL DEFAULT 0
);

INSERT INTO log_cursors (run_id, value)
SELECT run_id, MAX(seq) FROM log_entries GROUP BY run_id
ON CONFLICT (run_id) DO NOTHING;

ALTER TABLE log_entries ALTER COLUMN seq DROP IDENTITY;

ALTER TABLE log_entries DROP CONSTRAINT IF EXISTS log_entries_pkey;

ALTER TABLE log_entries ADD CONSTRAINT log_entries_pkey PRIMARY KEY (run_id, seq);
