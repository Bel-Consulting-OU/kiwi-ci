-- 0055_attempt_evidence_indexes.sql — attempt-scoped evidence indexes.
--
-- The final execution attestation must bind exactly one attempt's evidence
-- (artifact records, test reports, workspace snapshots), and the emitter used
-- to load every row of the run and filter in Go, an O(n^2) walk over a run
-- with n completed jobs. The attempt is the indexed identity (job_id,
-- lease_generation), mirroring the shape the artifact table already has via
-- artifacts_job_generation_name_idx. test_results and workspace_snapshots
-- carried the generation only inside the payload JSON, so this migration
-- promotes it to a column, backfills it from the payload and indexes it.
--
-- Additive with a default: older binaries never select the column and keep
-- reading and writing the table unchanged. The queries that use the new
-- columns are the attempt-scoped evidence reads only, and the migration
-- floors default to this version so reads never run against rows written by a
-- binary that predates the column. The backfill guard is the artifact
-- generation pattern from 0010: the payload value must be a JSON number in
-- plain integer text within the BIGINT domain, everything else defaults to 0.

ALTER TABLE test_results ADD COLUMN IF NOT EXISTS lease_generation BIGINT NOT NULL DEFAULT 0;

ALTER TABLE workspace_snapshots ADD COLUMN IF NOT EXISTS lease_generation BIGINT NOT NULL DEFAULT 0;

UPDATE test_results SET lease_generation = CASE
    WHEN jsonb_typeof(payload->'lease_generation') = 'number'
     AND (payload->>'lease_generation') ~ '^-?[0-9]+$'
     AND (payload->>'lease_generation')::numeric BETWEEN (-9223372036854775808)::numeric AND (9223372036854775807)::numeric
    THEN (payload->>'lease_generation')::bigint
    ELSE 0 END
WHERE lease_generation = 0;

UPDATE workspace_snapshots SET lease_generation = CASE
    WHEN jsonb_typeof(payload->'lease_generation') = 'number'
     AND (payload->>'lease_generation') ~ '^-?[0-9]+$'
     AND (payload->>'lease_generation')::numeric BETWEEN (-9223372036854775808)::numeric AND (9223372036854775807)::numeric
    THEN (payload->>'lease_generation')::bigint
    ELSE 0 END
WHERE lease_generation = 0;

CREATE INDEX IF NOT EXISTS test_results_job_lease_generation_idx
    ON test_results (job_id, lease_generation);

CREATE INDEX IF NOT EXISTS workspace_snapshots_job_lease_generation_idx
    ON workspace_snapshots (job_id, lease_generation);
