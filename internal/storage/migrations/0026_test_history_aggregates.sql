-- 0026_test_history_aggregates.sql — incremental per-repository test-history
-- aggregates.
--
-- The pre-0026 test-history path rebuilt the ENTIRE history from every durable
-- test_results row on every upload (O(total history) per report) and served
-- test-intelligence by materializing every report and resolving its run in Go.
-- This migration adds the incremental storage that replaces both:
--
--   test_history_aggregates is one row per (repo_id, suite, test_class,
--   test_name) with the same per-test aggregate the serialized history cache
--   always held (runs/passes/fails/ewma/outcomes/flake_prob/last_failure).
--   An upload upserts ONLY the keys that appear in its report, in the same
--   transaction as the report insert, so the work for report N does not grow
--   with total history. repo_id is the canonical repository identity
--   (storage.RepoIDForRun / server repoIDForRun) resolved at upload time.
--
--   test_history_repos holds one monotonically increasing version per
--   repository: replicas reload a repository's aggregates only when its
--   version advances, so a read for one repository never materializes another
--   repository's history. The legacy single-row test_history cache is left
--   untouched and remains the shape-compatible fallback.
--
-- Reads keyed by repository identity are served by the run-identity indexes:
-- the canonical identity expression mirrors storage.RepoIDFor (stored
-- policy_repo_id, then stored repo_id) and repo_full_name is the human query
-- form. test_results is joined to runs on tr.run_id, so a query never
-- materializes reports for unrelated repositories (and never parses their
-- payloads).
--
-- DEPLOY-SAFETY (same discipline as 0021-0025): this file contains only
-- metadata-only DDL — CREATE TABLE/CREATE INDEX for new relations plus
-- expression indexes on existing rows. No existing table is rewritten and no
-- existing row is locked, so there is nothing to split further. IF NOT
-- EXISTS keeps a replay harmless. The aggregates start empty, and two
-- bounded bridges repopulate a repository from its durable reports exactly
-- once: the first post-upgrade upload seeds the repository's existing
-- reports inside its own transaction, and a read of a repository with no
-- version row lazily invokes the explicit per-repository repair
-- (PostgresStore.RebuildRepoTestHistory). No path rebuilds all repositories
-- per upload.

CREATE TABLE IF NOT EXISTS test_history_aggregates (
    repo_id TEXT NOT NULL,
    suite TEXT NOT NULL DEFAULT '',
    test_class TEXT NOT NULL DEFAULT '',
    test_name TEXT NOT NULL,
    runs BIGINT NOT NULL DEFAULT 0,
    passes BIGINT NOT NULL DEFAULT 0,
    fails BIGINT NOT NULL DEFAULT 0,
    ewma DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_failure TIMESTAMPTZ,
    outcomes JSONB NOT NULL DEFAULT '[]'::jsonb,
    flake_prob DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, suite, test_class, test_name)
);

CREATE TABLE IF NOT EXISTS test_history_repos (
    repo_id TEXT PRIMARY KEY,
    version BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS runs_repo_identity_idx
    ON runs ((COALESCE(NULLIF(payload->>'policy_repo_id',''), NULLIF(payload->>'repo_id',''))));

CREATE INDEX IF NOT EXISTS runs_repo_full_name_idx
    ON runs ((payload->>'repo_full_name'));
