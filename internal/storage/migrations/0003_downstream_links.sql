-- 0003_downstream_links.sql — durable cross-repo downstream dispatch claims.
--
-- 0001_init.sql created a provisional downstream_links table (id/run pair
-- shape) that nothing has written to yet; 0003 supersedes it with the real
-- claim contract, mirroring how 0002 superseded the provisional schedules
-- table. The (parent_job_id, target_repo, target_ref) row IS the exactly-
-- once launch claim: MarkDownstreamLaunched sets child_run_id only when it
-- is still empty, so a crash between dispatch and child submission can
-- never launch the same child twice.

DROP TABLE IF EXISTS downstream_links

CREATE TABLE downstream_links (
    parent_job_id TEXT NOT NULL,
    target_repo TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    launch_token TEXT NOT NULL,
    child_run_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (parent_job_id, target_repo, target_ref)
)

CREATE INDEX downstream_links_child_run_idx ON downstream_links (child_run_id)
