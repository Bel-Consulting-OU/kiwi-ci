-- 0036_normalized_run_repo_identity_effective_fallback.sql — NULL-tolerant
-- authorized-page identity and the maintenance re-backfill (R3-A).
--
-- ROLLING-UPGRADE GAP: migration 0033 added repo_identity_normalized /
-- repo_full_name_normalized and 0034 backfilled them, assuming every writer
-- stamps them. A PRE-0034 replica running during a rolling upgrade writes
-- through the old INSERT/UPDATE and leaves both columns NULL. The authorized
-- collection page (RunPageAuthorizedStore) compared those columns by equality,
-- so a NULL row evaluated to NULL in every arm of the predicate and was
-- PERMANENTLY invisible — even to a global read — until an upgrade re-stamped
-- it. The predicate now reads the NULL-tolerant effective expression
--      COALESCE(<column>, kiwi_normalize_run_repo_identity(payload, 'repo'))
-- so a NULL row is still classified by the SHARED IMMUTABLE function the
-- canonical write path and the 0034 backfill use (Go<->SQL parity is pinned by
-- TestNormalizedRunRepoSQLMatchesMigrations and the run-identity corpus IT).
--
-- EXPRESSION INDEXES MUST MATCH THE PREDICATE (audit class): the page
-- predicate is no longer plain equality on the stored column, so the two
-- keyset indexes are swapped to the IDENTICAL COALESCE expression
-- (normalizedRunRepoIdentityEffectiveSQL / ...FullNameEffectiveSQL). Without
-- the swap the planner could not prove the predicate from the index and the
-- R1-B bounded index walk would regress to a filter.
--
-- MAINTENANCE RE-BACKFILL KEYED ON THE SCHEMA MARKER: the schema marker is the
-- schema_migrations version row this file records (0036). The UPDATE re-stamps
-- every row still missing either column, so legacy NULL rows are materialized
-- once and the fallback only has to serve the transient rolling-upgrade window.
-- It is the exact idempotent backfill of 0034 (same shared functions, same
-- IS NULL guard) and is safe to re-run. Rows written by a still-running
-- pre-0034 replica AFTER this migration are covered by the predicate fallback
-- until that replica is upgraded. A later operator/upgrade pass can re-run the
-- same maintenance backfill, and no row is ever invisible in the meantime.
--
-- DEPLOY-SAFETY: the re-backfill is row-level (ROW EXCLUSIVE, blocks no
-- reads). The index swap is a DROP + non-concurrent CREATE like every other
-- index migration (CREATE INDEX CONCURRENTLY cannot run inside the runner's
-- transaction), and the definition is unchanged for rows that carry the
-- columns, so the index is equivalent except that it also carries the
-- function-derived entries for NULL rows.

UPDATE runs SET repo_identity_normalized = kiwi_normalize_run_repo_identity(payload, 'repo'), repo_full_name_normalized = kiwi_normalize_run_repo_full_name(payload, 'repo') WHERE repo_identity_normalized IS NULL OR repo_full_name_normalized IS NULL;

DROP INDEX IF EXISTS runs_repo_identity_normalized_keyset_idx;

CREATE INDEX IF NOT EXISTS runs_repo_identity_normalized_keyset_idx
    ON runs (COALESCE(repo_identity_normalized, kiwi_normalize_run_repo_identity(payload, 'repo')), created_at DESC, id COLLATE "C" DESC);

DROP INDEX IF EXISTS runs_repo_full_name_normalized_keyset_idx;

CREATE INDEX IF NOT EXISTS runs_repo_full_name_normalized_keyset_idx
    ON runs (COALESCE(repo_full_name_normalized, kiwi_normalize_run_repo_full_name(payload, 'repo')), created_at DESC, id COLLATE "C" DESC);
