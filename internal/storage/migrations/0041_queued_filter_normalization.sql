-- 0041_queued_filter_normalization.sql — normalized queued filter columns,
-- array GIN indexes for the list-valued dimensions, resource expression
-- indexes and extended statistics for bounded runner queue polls.
--
-- Migration 0039 pushed the runner-coarse eligibility predicates into SQL,
-- but two of them could not be served by any index:
--
--   * the label predicate (payload->'required_labels' <@ runnerLabels) uses
--     the jsonb containment operator, and the built-in jsonb GIN opclass has
--     no <@ strategy, so jobs_queued_labels_idx could never answer it
--   * the region predicate is a disjunction
--     (payload->'placement_regions' IS NULL OR length = 0 OR ?| runnerRegion)
--     and PostgreSQL cannot form a bitmap path for an OR whose arms are not
--     all indexable, so jobs_queued_regions_idx could never answer it either
--
-- Both predicates therefore degenerated into heap filters over whatever
-- index drove the scan, and a RARE filter value could examine the whole
-- queued population before the page filled.
--
-- This migration materializes the two list-valued dimensions as normalized
-- TEXT[] columns (a missing payload key stays '{}', exactly the Go model's
-- zero value) served by array GIN indexes, whose opclass implements BOTH
-- <@ (labels) and && / = (regions): the region disjunction becomes a
-- bitmap-OR of two indexable arms. The resource dimensions keep the query's
-- guarded numeric expressions (job request plus service envelope) but gain
-- expression indexes AND CREATE STATISTICS objects, because an expression
-- index alone carries no clause selectivity: without statistics the planner
-- estimates a rare `request <= capacity` filter as broadly matching and
-- prefers the aged-order walk, which then scans the whole queue when the
-- filter is rare. The job-only form (used when a job-scoped cgroup lets the
-- runner reserve the job's own request, IgnoreServiceEnvelope) gets the same
-- index+statistics pair under the _own suffix, because the combined
-- expression can never answer the job-only predicate. The runtime expression
-- gets a statistics object for the same selectivity reason (a COMMON runtime
-- must not look selective). Every new statistics object and both normalized
-- array columns are raised to statistics_target 1000: the default 100 samples
-- only ~30k rows, a 1-in-10000 label/region/request value can miss that
-- sample entirely, and the estimators then fall back to generic defaults that
-- rate a rare region as matching 0.5 percent of the queue, so the planner
-- prefers the aged walk and scans the whole queue. The 1m planner test
-- caught exactly that plan.
--
-- DEPLOY SAFETY: both ADD COLUMNs are metadata-only (constant defaults), the
-- backfills touch only queued rows and are guarded by jsonb_typeof so a
-- malformed payload can never abort the migration transaction, and the index
-- builds and the final ANALYZE follow in the same per-file transaction. The
-- old jsonb label/region GIN indexes are dropped because no query can use
-- them once the normalized predicates replace them, and the explicit ANALYZE
-- populates the statistics objects immediately instead of waiting for
-- autovacuum, so the first polls after an upgrade already plan against real
-- selectivity.

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS required_labels TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS placement_regions TEXT[] NOT NULL DEFAULT '{}';

UPDATE jobs SET required_labels = COALESCE(ARRAY(SELECT jsonb_array_elements_text(payload->'required_labels')), '{}') WHERE status='queued' AND payload ? 'required_labels' AND jsonb_typeof(payload->'required_labels') = 'array';

UPDATE jobs SET placement_regions = COALESCE(ARRAY(SELECT jsonb_array_elements_text(payload->'placement_regions')), '{}') WHERE status='queued' AND payload ? 'placement_regions' AND jsonb_typeof(payload->'placement_regions') = 'array';

CREATE INDEX IF NOT EXISTS jobs_queued_labels_arr_idx ON jobs USING gin (required_labels) WHERE status='queued';

DROP INDEX IF EXISTS jobs_queued_labels_idx;

CREATE INDEX IF NOT EXISTS jobs_queued_regions_arr_idx ON jobs USING gin (placement_regions) WHERE status='queued';

DROP INDEX IF EXISTS jobs_queued_regions_idx;

CREATE INDEX IF NOT EXISTS jobs_queued_cpu_idx ON jobs (((CASE WHEN jsonb_typeof(payload->'cpu_request') = 'number' THEN (payload->>'cpu_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'cpu') = 'number' THEN (payload->'service_envelope_request'->>'cpu')::numeric ELSE 0 END))) WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_memory_idx ON jobs (((CASE WHEN jsonb_typeof(payload->'memory_request') = 'number' THEN (payload->>'memory_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'memory') = 'number' THEN (payload->'service_envelope_request'->>'memory')::numeric ELSE 0 END))) WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_pids_idx ON jobs (((CASE WHEN jsonb_typeof(payload->'pids_request') = 'number' THEN (payload->>'pids_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'pids') = 'number' THEN (payload->'service_envelope_request'->>'pids')::numeric ELSE 0 END))) WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_disk_idx ON jobs (((CASE WHEN jsonb_typeof(payload->'disk_request') = 'number' THEN (payload->>'disk_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'disk') = 'number' THEN (payload->'service_envelope_request'->>'disk')::numeric ELSE 0 END))) WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_cpu_own_idx ON jobs ((CASE WHEN jsonb_typeof(payload->'cpu_request') = 'number' THEN (payload->>'cpu_request')::numeric ELSE 0 END)) WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_memory_own_idx ON jobs ((CASE WHEN jsonb_typeof(payload->'memory_request') = 'number' THEN (payload->>'memory_request')::numeric ELSE 0 END)) WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_pids_own_idx ON jobs ((CASE WHEN jsonb_typeof(payload->'pids_request') = 'number' THEN (payload->>'pids_request')::numeric ELSE 0 END)) WHERE status='queued';

CREATE INDEX IF NOT EXISTS jobs_queued_disk_own_idx ON jobs ((CASE WHEN jsonb_typeof(payload->'disk_request') = 'number' THEN (payload->>'disk_request')::numeric ELSE 0 END)) WHERE status='queued';

CREATE STATISTICS jobs_queued_runtime_stats ON ((COALESCE(NULLIF(payload->'compiled_job_payload'->'effective_job'->'job'->>'runtime',''),'native'))) FROM jobs;

CREATE STATISTICS jobs_queued_cpu_stats ON (((CASE WHEN jsonb_typeof(payload->'cpu_request') = 'number' THEN (payload->>'cpu_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'cpu') = 'number' THEN (payload->'service_envelope_request'->>'cpu')::numeric ELSE 0 END))) FROM jobs;

CREATE STATISTICS jobs_queued_memory_stats ON (((CASE WHEN jsonb_typeof(payload->'memory_request') = 'number' THEN (payload->>'memory_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'memory') = 'number' THEN (payload->'service_envelope_request'->>'memory')::numeric ELSE 0 END))) FROM jobs;

CREATE STATISTICS jobs_queued_pids_stats ON (((CASE WHEN jsonb_typeof(payload->'pids_request') = 'number' THEN (payload->>'pids_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'pids') = 'number' THEN (payload->'service_envelope_request'->>'pids')::numeric ELSE 0 END))) FROM jobs;

CREATE STATISTICS jobs_queued_disk_stats ON (((CASE WHEN jsonb_typeof(payload->'disk_request') = 'number' THEN (payload->>'disk_request')::numeric ELSE 0 END) + (CASE WHEN jsonb_typeof(payload->'service_envelope_request'->'disk') = 'number' THEN (payload->'service_envelope_request'->>'disk')::numeric ELSE 0 END))) FROM jobs;

CREATE STATISTICS jobs_queued_cpu_own_stats ON ((CASE WHEN jsonb_typeof(payload->'cpu_request') = 'number' THEN (payload->>'cpu_request')::numeric ELSE 0 END)) FROM jobs;

CREATE STATISTICS jobs_queued_memory_own_stats ON ((CASE WHEN jsonb_typeof(payload->'memory_request') = 'number' THEN (payload->>'memory_request')::numeric ELSE 0 END)) FROM jobs;

CREATE STATISTICS jobs_queued_pids_own_stats ON ((CASE WHEN jsonb_typeof(payload->'pids_request') = 'number' THEN (payload->>'pids_request')::numeric ELSE 0 END)) FROM jobs;

CREATE STATISTICS jobs_queued_disk_own_stats ON ((CASE WHEN jsonb_typeof(payload->'disk_request') = 'number' THEN (payload->>'disk_request')::numeric ELSE 0 END)) FROM jobs;

ALTER TABLE jobs ALTER COLUMN required_labels SET STATISTICS 1000;

ALTER TABLE jobs ALTER COLUMN placement_regions SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_runtime_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_cpu_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_memory_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_pids_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_disk_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_cpu_own_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_memory_own_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_pids_own_stats SET STATISTICS 1000;

ALTER STATISTICS jobs_queued_disk_own_stats SET STATISTICS 1000;

ANALYZE jobs;
