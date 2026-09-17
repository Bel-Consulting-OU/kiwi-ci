-- 0006_runner_profiles.sql — server-owned runner identity profiles and
-- per-runner credentials.
--
-- runner_profiles is the server-owned source of runner scheduling
-- attributes: a runner may not self-report labels, region, repository
-- scope, capabilities, capacity or cost rates at registration — its
-- linked profile supplies them (cert_profile_links binds a runner
-- certificate serial to a profile). A runner without a linked profile
-- registers empty (capacity 0, no labels/region, no rates).
--
-- runner_bearer_tokens holds per-runner bearer credentials (token digests
-- only, never the raw token) for production deployments that run without
-- runner mTLS.
--
-- cert_revocations is the durable certificate revocation list: verify
-- checks it on every runner identity validation so any replica rejects a
-- revoked certificate.
--
-- enrollment_grants is the durable single-use enrollment grant store:
-- consumption is the conditional UPDATE in ConsumeEnrollGrant, so two
-- concurrent enrollments of the same grant yield exactly one winner.

CREATE TABLE runner_profiles (
    id TEXT NOT NULL PRIMARY KEY,
    labels JSONB NOT NULL DEFAULT '[]',
    region TEXT NOT NULL DEFAULT '',
    repositories JSONB NOT NULL DEFAULT '[]',
    capabilities JSONB NOT NULL DEFAULT '[]',
    max_capacity INTEGER NOT NULL DEFAULT 0,
    cost_per_hour DOUBLE PRECISION NOT NULL DEFAULT 0,
    power_watts DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cert_profile_links (
    serial TEXT NOT NULL PRIMARY KEY,
    profile_id TEXT NOT NULL
);

CREATE TABLE runner_bearer_tokens (
    runner_id TEXT NOT NULL PRIMARY KEY,
    token_digest TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cert_revocations (
    serial TEXT NOT NULL PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason TEXT NOT NULL DEFAULT '',
    runner_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE enrollment_grants (
    digest TEXT NOT NULL PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    bound_labels JSONB NOT NULL DEFAULT '[]',
    consumed_at TIMESTAMPTZ,
    consumed_by TEXT
);
