-- 0009_lease_claim.sql — claim-path columns and indexes.
--
-- runners gains real disabled/draining columns: the atomic lease claim
-- (AcquireLeaseAtomic) filters on them inside the SQL transaction, so a
-- concurrent disable/drain can never lose a race against a lease that
-- already passed the caller's pre-check. Existing rows migrate their
-- payload flags into the columns exactly once, then UpsertRunner keeps
-- both views in sync.
--
-- The jobs environment index backs the in-transaction environment
-- concurrency count (payload->>'repo_url' + payload->>'environment' for
-- running jobs), the cert_profile_links index backs the live profile
-- resolution used by the claim predicates.

ALTER TABLE runners ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE runners ADD COLUMN IF NOT EXISTS draining BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE runners SET disabled = COALESCE((payload->>'disabled')::boolean, FALSE), draining = COALESCE((payload->>'draining')::boolean, FALSE);

CREATE INDEX IF NOT EXISTS runners_claim_idx ON runners (disabled, draining);

CREATE INDEX IF NOT EXISTS jobs_environment_running_idx ON jobs ((payload->>'repo_url'), (payload->>'environment')) WHERE status = 'running';

CREATE INDEX IF NOT EXISTS cert_profile_links_profile_id_idx ON cert_profile_links (profile_id);
