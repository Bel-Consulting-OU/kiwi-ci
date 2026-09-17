-- 0008_logs_history.sql — identity-sequenced log entries and the SQL-backed
-- test-intelligence history cache.
--
-- log_entries replaces log_chunks as the append target: seq is a
-- GENERATED ALWAYS AS IDENTITY column assigned by Postgres in the append
-- transaction, so appends never depend on wall-clock nanoseconds and
-- sequences stay strictly increasing across replicas and restarts.
--
-- test_history caches the serialized per-test history aggregates with a
-- monotonically increasing version bumped on every upload, replicas reload
-- the cache when the version advances so sharding decisions converge.

CREATE TABLE log_entries (
    seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT,
    job_key TEXT,
    step TEXT,
    line TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX log_entries_run_id_seq_idx ON log_entries (run_id, seq);

INSERT INTO log_entries (run_id, job_id, job_key, step, line, created_at)
    SELECT run_id, job_id, job_key, step, line, created_at FROM log_chunks ORDER BY seq;

CREATE TABLE test_history (
    id INT PRIMARY KEY,
    version BIGINT NOT NULL DEFAULT 0,
    stats JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO test_history (id, version, stats) VALUES (1, 0, '{}');
