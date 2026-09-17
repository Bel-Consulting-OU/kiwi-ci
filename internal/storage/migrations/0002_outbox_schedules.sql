-- 0002_outbox_schedules.sql — durable outbox, cron schedules, and occurrence
-- claims for the SQL control plane.
--
-- The provisional `schedules` table in 0001_init.sql (cron column, no
-- repository/spec/last_run, no occurrence tracking) is superseded by the
-- richer shape below. Nothing has written to it yet, so dropping and
-- recreating it here is safe, on databases where 0001 already ran this
-- replaces the placeholder table with the real contract.

DROP TABLE IF EXISTS schedules;

CREATE TABLE schedules (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    spec TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX schedules_repository_idx ON schedules (repository);

CREATE TABLE schedule_occurrences (
    schedule_id TEXT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    nominal TIMESTAMPTZ NOT NULL,
    run_id TEXT NOT NULL,
    PRIMARY KEY (schedule_id, nominal)
);

CREATE INDEX schedule_occurrences_nominal_idx ON schedule_occurrences (nominal);

CREATE TABLE outbox (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX outbox_created_at_idx ON outbox (created_at ASC);
