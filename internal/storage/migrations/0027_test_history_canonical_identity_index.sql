-- 0027_test_history_canonical_identity_index.sql — canonical policy-first
-- repository-identity expression index for test-history reads.
--
-- Migration 0026 shipped an expression index whose identity expression was
-- INCOMPLETE: it resolved runs_repo_identity_idx from stored policy_repo_id /
-- repo_id only, while every test-history read (ResolveTestHistoryRepoIDs,
-- TestReportTotals, RebuildRepoTestHistory, ListTestHistoryRepoIDs) and the
-- migration-0026 upgrade bridge select runs through the canonical
-- policy-first identity that ALSO derives a legacy row's identity from its
-- clone URL + repo_full_name. A pre-RepoID row therefore never matched the
-- 0026 index expression (and, worse, never matched a read's WHERE clause), so
-- reports uploaded before RepoID existed were silently excluded from counts,
-- totals, flakes and rebuilds.
--
-- This migration converges every database on the CANONICAL expression the
-- reads actually use:
--
--   * kiwi_canonical_repo_id(jsonb, text) is the IMMUTABLE SQL function that
--     wraps the full repo_id/clone-URL + repo_full_name derivation (the same
--     body storage.canonicalRepoIDFunctionBody renders, so the Go helper and
--     the database can never drift). The derivation cannot be inlined into
--     an expression index: its parsed expression tree exceeds the pg_index
--     catalog row limit (SQLSTATE 54000 "row is too big"), so the index
--     names the function while every query compares through the same call.
--   * runs_repo_identity_idx is recreated on the short policy-first
--     expression COALESCE(policy_repo_id, kiwi_canonical_repo_id(payload,
--     'repo')), which is EXACTLY what
--     storage.canonicalPolicyRepoIDSQLExpr("repo") renders.
--   * runs_repo_full_name_idx is recreated on the full-name expression the
--     reads compare against (r.payload->>'repo_full_name').
--
-- A database that already applied 0026 converges to the corrected
-- definitions on upgrade. 0026 itself is left untouched (its DDL was
-- shipped), and 0027 runs exactly once per database.
--
-- DEPLOY-SAFETY: creating/replacing one small SQL function and swapping two
-- expression indexes is metadata-only with respect to runs (ACCESS SHARE for
-- the index builds, no row rewritten). DROP INDEX + CREATE INDEX for the same
-- name leaves a short window without the identity index, which costs planner
-- efficiency only, never correctness.

CREATE OR REPLACE FUNCTION kiwi_canonical_repo_id(payload jsonb, url_key text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$SELECT COALESCE(NULLIF(BTRIM(payload->>'repo_id'), ''), CASE WHEN CASE WHEN BTRIM(COALESCE(payload->>'repo_full_name', '')) <> '' THEN BTRIM(COALESCE(payload->>'repo_full_name', '')) ELSE BTRIM(REGEXP_REPLACE(CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN COALESCE(SUBSTRING(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3) FROM '/(.*)$'), '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), ':') + 1) ELSE COALESCE(payload->>url_key, '') END, '\.git$', ''), '/') END = '' THEN '' WHEN CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN REGEXP_REPLACE(SPLIT_PART(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3), '/', 1), '^.*@', '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), ':', 1), '^.*@', '') ELSE REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), '/', 1), '^.*@', '') END = '' OR LEFT(CASE WHEN BTRIM(COALESCE(payload->>'repo_full_name', '')) <> '' THEN BTRIM(COALESCE(payload->>'repo_full_name', '')) ELSE BTRIM(REGEXP_REPLACE(CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN COALESCE(SUBSTRING(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3) FROM '/(.*)$'), '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), ':') + 1) ELSE COALESCE(payload->>url_key, '') END, '\.git$', ''), '/') END, LENGTH(CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN REGEXP_REPLACE(SPLIT_PART(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3), '/', 1), '^.*@', '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), ':', 1), '^.*@', '') ELSE REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), '/', 1), '^.*@', '') END) + 1) = CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN REGEXP_REPLACE(SPLIT_PART(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3), '/', 1), '^.*@', '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), ':', 1), '^.*@', '') ELSE REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), '/', 1), '^.*@', '') END || '/' THEN CASE WHEN BTRIM(COALESCE(payload->>'repo_full_name', '')) <> '' THEN BTRIM(COALESCE(payload->>'repo_full_name', '')) ELSE BTRIM(REGEXP_REPLACE(CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN COALESCE(SUBSTRING(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3) FROM '/(.*)$'), '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), ':') + 1) ELSE COALESCE(payload->>url_key, '') END, '\.git$', ''), '/') END ELSE CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN REGEXP_REPLACE(SPLIT_PART(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3), '/', 1), '^.*@', '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), ':', 1), '^.*@', '') ELSE REGEXP_REPLACE(SPLIT_PART(COALESCE(payload->>url_key, ''), '/', 1), '^.*@', '') END || '/' || CASE WHEN BTRIM(COALESCE(payload->>'repo_full_name', '')) <> '' THEN BTRIM(COALESCE(payload->>'repo_full_name', '')) ELSE BTRIM(REGEXP_REPLACE(CASE WHEN STRPOS(COALESCE(payload->>url_key, ''), '://') > 0 THEN COALESCE(SUBSTRING(SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), '://') + 3) FROM '/(.*)$'), '') WHEN STRPOS(COALESCE(payload->>url_key, ''), ':') > 0 AND (STRPOS(COALESCE(payload->>url_key, ''), '/') = 0 OR STRPOS(COALESCE(payload->>url_key, ''), '/') > STRPOS(COALESCE(payload->>url_key, ''), ':')) THEN SUBSTRING(COALESCE(payload->>url_key, '') FROM STRPOS(COALESCE(payload->>url_key, ''), ':') + 1) ELSE COALESCE(payload->>url_key, '') END, '\.git$', ''), '/') END END)$$;

DROP INDEX IF EXISTS runs_repo_identity_idx;

CREATE INDEX IF NOT EXISTS runs_repo_identity_idx
    ON runs ((COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, 'repo'))));

DROP INDEX IF EXISTS runs_repo_full_name_idx;

CREATE INDEX IF NOT EXISTS runs_repo_full_name_idx
    ON runs ((payload->>'repo_full_name'));
