-- 0053_run_key_index_repair.sql — re-run the 0048 conditional unique index.
--
-- 0048 creates jobs_run_key_idx ONLY when the database has no duplicate
-- (run_id, key) rows, and records its version row either way. A database that
-- was dirty at that moment (duplicates present) therefore never got the
-- index, even after an operator later repaired the duplicates by hand, and
-- the generated-fragment admission checks remained the only guard.
--
-- This migration re-runs the SAME conditional CREATE UNIQUE INDEX, so the
-- next migrate after a repair picks the index up. Operator repair path:
-- locate duplicate (run_id, key) job rows, cancel or remove them, then
-- re-run the migrator (or create the index manually with CREATE UNIQUE INDEX
-- jobs_run_key_idx ON jobs (run_id, key)). Readiness reports the index
-- presence until it exists.
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
