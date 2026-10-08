-- 0048_run_scoped_job_key_identity.sql — run-scoped logical job key identity.
--
-- Finding 7: model.Job.Key is the run-scoped logical node identity — the
-- compiled job id with its matrix/shard suffix (e.g. build[os=linux]) and
-- unique within one run — while BaseKey is grouping/display only and
-- INTENTIONALLY repeats across matrix variants. Generated fragments
-- previously checked child keys only WITHIN one fragment, so two different
-- fragments could each insert a job row with the same (run_id, key) under
-- different random ids, and jobInRun-style key lookups silently resolved the
-- first match.
--
-- This migration installs the DB-level uniqueness guard on (run_id, key),
-- but ONLY on a database whose jobs table currently has no duplicate
-- (run_id, key): CREATE UNIQUE INDEX would otherwise abort on exactly the
-- dirty databases this fix must upgrade. Duplicates are never quarantined or
-- deleted here — live job rows are untouched. On a dirty database the
-- generated-fragment admission checks remain authoritative and fail closed
-- with a typed conflict instead, and an operator who repairs the data by hand
-- may create jobs_run_key_idx manually (this migration will not re-run once
-- its version is recorded). On a clean database the index is the final
-- backstop under the admission check. Matrix variants stay distinct because
-- the suffix is part of Key, so BaseKey uniqueness is deliberately NOT
-- enforced.
--
-- Keep comments in this file semicolon-free: the migration splitter strips
-- comment-only lines after splitting, so a semicolon inside a comment would
-- cut it in half.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM jobs GROUP BY run_id, key HAVING count(*) > 1) THEN
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_run_key_idx ON jobs (run_id, key);
  ELSE
    RAISE NOTICE 'jobs_run_key_idx skipped: existing duplicate (run_id,key) rows';
  END IF;
END $$;
