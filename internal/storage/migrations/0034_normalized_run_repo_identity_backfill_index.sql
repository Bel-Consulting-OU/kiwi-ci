-- 0034_normalized_run_repo_identity_backfill_index.sql — the SQL
-- canonicalization functions, the one-time backfill and the keyset indexes
-- for the materialized run repository identity (see 0033).
--
--   * kiwi_canonical_host(text) is auth.CanonicalHost rendered as IMMUTABLE
--     SQL. It fixes the R1-A divergence: the pre-fix predicate stripped a
--     default-port suffix from EVERY unbracketed host, so an unbracketed IPv6
--     literal ending in :443/:80/:22 ("::1:443") collapsed to "::1" in SQL
--     while auth.CanonicalHost preserved it (its legacy host:port split
--     applies only to a spelling with EXACTLY ONE colon), letting the
--     collection endpoint read a run under a grant for a different forge than
--     the per-run RBAC path authorized. The body is pinned to
--     storage.canonicalHostFunctionBody by TestNormalizedRunRepoSQLMatchesMigrations.
--   * kiwi_normalize_run_repo_identity / ..._full_name derive the materialized
--     columns from the payload. They are the SAME functions the runs write
--     path calls, so a row written through any INSERT/UPDATE and a legacy row
--     backfilled here resolve identically. Bodies are pinned to
--     storage.normalizedRunRepoIdentityFunctionBody / ...FullNameFunctionBody.
--   * the UPDATE backfills every row that lacks either column (legacy rows and
--     rows written by a pre-upgrade binary between 0033 and 0034). It is
--     idempotent (IS NULL guard) and row-level, so it does not block reads.
--   * the two composite keyset indexes make one authorized page a bounded
--     index range read: equality on the normalized identity, then the
--     (created_at DESC, id COLLATE "C" DESC) keyset order the page uses. They
--     are non-concurrent deliberately, matching the other index migrations
--     (CREATE INDEX CONCURRENTLY cannot run inside the runner's transaction).
--
-- The pre-fix id-predicate plan walked runs_created_at_idx with the identity
-- expression as a per-row Filter (no index could satisfy it). With these
-- columns the plan is an Index Scan on runs_repo_identity_normalized_keyset_idx.

CREATE OR REPLACE FUNCTION kiwi_canonical_host(host text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$SELECT CASE WHEN host = '' THEN '' WHEN LEFT(host, 1) = '[' THEN CASE WHEN STRPOS(host, ']') > 0 THEN REGEXP_REPLACE(SUBSTRING(LOWER(host) FROM 2 FOR STRPOS(host, ']') - 2), '\.$', '') || CASE WHEN LEFT(SUBSTRING(LOWER(host) FROM STRPOS(host, ']') + 1), 1) <> ':' OR SUBSTRING(SUBSTRING(LOWER(host) FROM STRPOS(host, ']') + 1) FROM 2) IN ('443', '80', '22') THEN '' ELSE SUBSTRING(LOWER(host) FROM STRPOS(host, ']') + 1) END ELSE REGEXP_REPLACE(LOWER(host), '\.$', '') END ELSE CASE WHEN (LENGTH(host) - LENGTH(REPLACE(host, ':', ''))) = 1 AND STRPOS(host, ':') > 1 THEN CASE WHEN SUBSTRING(LOWER(host) FROM STRPOS(host, ':') + 1) ~ '^[+-]?[0-9]+$' THEN REGEXP_REPLACE(LEFT(LOWER(host), STRPOS(host, ':') - 1), '\.$', '') || CASE WHEN SUBSTRING(LOWER(host) FROM STRPOS(host, ':') + 1) IN ('443', '80', '22') THEN '' ELSE ':' || SUBSTRING(LOWER(host) FROM STRPOS(host, ':') + 1) END ELSE REGEXP_REPLACE(LEFT(LOWER(host), STRPOS(host, ':') - 1), '\.$', '') END ELSE REGEXP_REPLACE(LOWER(host), '\.$', '') END END$$;

CREATE OR REPLACE FUNCTION kiwi_normalize_run_repo_identity(payload jsonb, url_key text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$SELECT CASE WHEN (STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') > 0 AND STRPOS(SUBSTRING(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)) FROM STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') + 1), '/') > 0) THEN CASE WHEN kiwi_canonical_host(CASE WHEN STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') > 0 THEN LEFT(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') - 1) ELSE '' END) = '' THEN COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)) ELSE kiwi_canonical_host(CASE WHEN STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') > 0 THEN LEFT(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') - 1) ELSE '' END) || '/' || SUBSTRING(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)) FROM STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') + 1) END ELSE '' END$$;

CREATE OR REPLACE FUNCTION kiwi_normalize_run_repo_full_name(payload jsonb, url_key text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$SELECT CASE WHEN (STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') > 0 AND STRPOS(SUBSTRING(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)) FROM STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') + 1), '/') > 0) THEN SUBSTRING(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)) FROM STRPOS(COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)), '/') + 1) ELSE COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), kiwi_canonical_repo_id(payload, url_key)) END$$;

UPDATE runs SET repo_identity_normalized = kiwi_normalize_run_repo_identity(payload, 'repo'), repo_full_name_normalized = kiwi_normalize_run_repo_full_name(payload, 'repo') WHERE repo_identity_normalized IS NULL OR repo_full_name_normalized IS NULL;

CREATE INDEX IF NOT EXISTS runs_repo_identity_normalized_keyset_idx
    ON runs (repo_identity_normalized, created_at DESC, id COLLATE "C" DESC);

CREATE INDEX IF NOT EXISTS runs_repo_full_name_normalized_keyset_idx
    ON runs (repo_full_name_normalized, created_at DESC, id COLLATE "C" DESC);
