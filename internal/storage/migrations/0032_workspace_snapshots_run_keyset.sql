-- 0032_workspace_snapshots_run_keyset.sql — per-run keyset index.
--
-- The per-run snapshot listing walks the collection with the keyset cursor
-- (created_at, id) > ($1, $2) ordered by created_at ASC, id COLLATE "C"
-- ASC (see internal/storage/postgres_snapshot_get.go). The primary key on
-- workspace_snapshots.id cannot serve that ordered walk, so without this
-- index every page is a sequential scan of the whole table filtered by
-- run_id. The composite index makes one page a bounded index range read.
--
-- Non-concurrent on purpose, matching the other index migrations: CREATE
-- INDEX CONCURRENTLY cannot run inside a transaction block and the runner
-- applies each migration file in one transaction. IF NOT EXISTS keeps the
-- file idempotent.

CREATE INDEX IF NOT EXISTS workspace_snapshots_run_keyset_idx
    ON workspace_snapshots (run_id, created_at, id COLLATE "C");
