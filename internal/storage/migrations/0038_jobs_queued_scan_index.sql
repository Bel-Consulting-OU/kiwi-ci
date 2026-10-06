-- Bounded queued-candidate scans: a partial index over only queued rows
-- keeps the top-N scan compact independently of the full jobs table.
CREATE INDEX jobs_queued_priority_idx ON jobs (priority DESC, created_at ASC, id ASC) WHERE status='queued';
