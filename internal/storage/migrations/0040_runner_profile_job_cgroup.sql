-- 0040_runner_profile_job_cgroup.sql — the runner profile's job-scoped
-- cgroup capability flag.
--
-- A runner whose profile sets job_cgroup can establish a job-scoped parent
-- cgroup that bounds the main container and every service together by the
-- job's declared envelope. ResolveRunnerProfile copies the flag onto the
-- effective runner (Runner.JobCgroup) and a lease on such a runner may
-- reserve the job's own request instead of the job+services union
-- (LeaseClaim.IgnoreServiceEnvelope). Additive with a false default: every
-- existing profile keeps the union reservation and the per-container caps +
-- fair split path.

ALTER TABLE runner_profiles ADD COLUMN IF NOT EXISTS job_cgroup BOOLEAN NOT NULL DEFAULT FALSE;
