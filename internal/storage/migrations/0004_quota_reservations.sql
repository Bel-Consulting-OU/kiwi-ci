-- 0004_quota_reservations.sql — quota reservation counters, the real shared
-- cache manifest table, and downstream reservation/forge-identity columns.
--
-- quota_reservations holds the per-repository and per-team running/queued
-- counters reserved inside the InsertCompiledRun transaction (SELECT ... FOR
-- UPDATE via INSERT ... ON CONFLICT DO UPDATE ... RETURNING). Daily cost and
-- energy are kept on the same row for the budget read path.
--
-- 0001_init.sql created a provisional cache_manifests table (cache_key /
-- entries shape) that nothing has written to yet; 0004 supersedes it with
-- the real contract: the (repo, trust_domain, logical_key) namespace maps to
-- a content-addressed blob digest with producer provenance and the signed
-- manifest envelope, mirroring how 0002/0003 superseded their provisional
-- tables.
--
-- downstream_links gains the reservation columns (the launch claim is now
-- reserve-first: ReserveDownstreamLaunch sets reserved before the child run
-- is enqueued) and the persisted forge identity coordinates so dispatch
-- never re-derives hosts from hard-coded public endpoints.

CREATE TABLE quota_reservations (
    key TEXT PRIMARY KEY,
    running INT NOT NULL DEFAULT 0,
    queued INT NOT NULL DEFAULT 0,
    daily_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    daily_energy DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)

CREATE INDEX quota_reservations_updated_at_idx ON quota_reservations (updated_at)

DROP TABLE IF EXISTS cache_manifests

CREATE TABLE cache_manifests (
    repo TEXT NOT NULL,
    trust_domain TEXT NOT NULL,
    logical_key TEXT NOT NULL,
    blob_sha256 TEXT NOT NULL,
    blob_size BIGINT NOT NULL DEFAULT 0,
    producer_run TEXT,
    producer_job TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (repo, trust_domain, logical_key)
)

CREATE INDEX cache_manifests_blob_sha256_idx ON cache_manifests (blob_sha256)

ALTER TABLE downstream_links
    ADD COLUMN reserved BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN reserved_at TIMESTAMPTZ,
    ADD COLUMN target_forge TEXT NOT NULL DEFAULT '',
    ADD COLUMN target_base_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN target_repo_id TEXT NOT NULL DEFAULT ''

CREATE INDEX downstream_links_reserved_idx ON downstream_links (reserved, reserved_at)
