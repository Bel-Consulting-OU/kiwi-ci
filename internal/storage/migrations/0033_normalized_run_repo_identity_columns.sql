-- 0033_normalized_run_repo_identity_columns.sql — materialized normalized
-- repository identity columns for the authorized runs collection page.
--
-- The authorized runs collection (RunPageAuthorizedStore) pushes the
-- principal's repository visibility policy into the ordered keyset query. The
-- pre-fix predicate re-derived each run's canonical repository identity from
-- its JSONB payload inside the page WHERE clause (SUBSTRING / STRPOS / CASE /
-- LOWER / REGEXP_REPLACE), so no index could serve it and a sparse tenant
-- forced a long walk of runs_created_at_idx. These two columns materialize
-- that identity so the predicate becomes simple equality over an index.
--
--   * repo_identity_normalized is the canonical "host/full" policy repository
--     identity (RepoIDForRun) for a canonical candidate — host canonicalized
--     exactly like auth.CanonicalHost (case, one trailing dot, default-port
--     and bracketed/unbracketed IPv6 handling) — and '' for a bare identity.
--   * repo_full_name_normalized is the full name: the owner/name remainder for
--     a canonical candidate, the whole value for a bare one, '' for empty.
--
-- The columns are a DERIVED INDEX of the payload, never a second source of
-- truth: the canonical runs write path stamps both on every INSERT/UPDATE
-- through the IMMUTABLE functions migration 0034 creates, and 0034 backfills
-- every existing row. They are deliberately nullable and default-less so this
-- ADD COLUMN stays metadata-only (no table rewrite) and holds runs' ACCESS
-- EXCLUSIVE lock only for the statements themselves.
--
-- DEPLOY-SAFETY SPLIT: the function definitions, the row-level backfill and
-- the two index builds live in 0034, so the ACCESS EXCLUSIVE lock taken here
-- is released before the backfill (ROW EXCLUSIVE) and the index builds.

ALTER TABLE runs ADD COLUMN IF NOT EXISTS repo_identity_normalized TEXT;

ALTER TABLE runs ADD COLUMN IF NOT EXISTS repo_full_name_normalized TEXT;
