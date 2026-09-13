-- 0001_init.sql — full control-plane schema.
-- Hot paths (statuses, leases, counters, ordering) get real columns; payload
-- fields (pipeline text, metadata, outputs, manifests) live in jsonb payload
-- columns for flexibility. Reads merge the real columns over the payload.

CREATE TABLE schema_migrations (
    version INT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)

CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE INDEX runs_status_idx ON runs (status)

CREATE INDEX runs_created_at_idx ON runs (created_at DESC)

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    status TEXT NOT NULL,
    dependency_status TEXT NOT NULL DEFAULT 'success',
    priority INT NOT NULL DEFAULT 0,
    attempts INT NOT NULL DEFAULT 0,
    error TEXT,
    outputs JSONB,
    lease_runner_id TEXT,
    lease_token_hash BYTEA,
    lease_generation BIGINT NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE INDEX jobs_run_id_idx ON jobs (run_id)

CREATE INDEX jobs_status_priority_idx ON jobs (status, priority DESC, created_at ASC)

CREATE TABLE job_dependencies (
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    depends_on TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    PRIMARY KEY (job_id, depends_on)
)

CREATE INDEX job_dependencies_depends_on_idx ON job_dependencies (depends_on)

CREATE TABLE job_leases (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    runner_id TEXT NOT NULL,
    token_hash BYTEA NOT NULL,
    generation BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)

CREATE INDEX job_leases_expires_at_idx ON job_leases (expires_at)

CREATE TABLE completion_receipts (
    job_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    runner_id TEXT NOT NULL,
    result_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, generation, runner_id)
)

CREATE TABLE runners (
    id TEXT PRIMARY KEY,
    busy BOOLEAN NOT NULL DEFAULT FALSE,
    capacity INT NOT NULL DEFAULT 1,
    completed BIGINT NOT NULL DEFAULT 0,
    failed BIGINT NOT NULL DEFAULT 0,
    current_job TEXT,
    active_jobs JSONB NOT NULL DEFAULT '[]'::jsonb,
    registered TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    payload JSONB NOT NULL
)

CREATE TABLE runner_certificates (
    serial TEXT PRIMARY KEY,
    runner_id TEXT NOT NULL REFERENCES runners(id) ON DELETE CASCADE,
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    payload JSONB NOT NULL
)

CREATE INDEX runner_certificates_runner_id_idx ON runner_certificates (runner_id)

CREATE TABLE runner_capabilities (
    runner_id TEXT NOT NULL REFERENCES runners(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    PRIMARY KEY (runner_id, capability)
)

CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT,
    job_key TEXT,
    name TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    payload JSONB NOT NULL
)

CREATE INDEX artifacts_run_id_idx ON artifacts (run_id)

CREATE TABLE cache_manifests (
    cache_key TEXT PRIMARY KEY,
    entries JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE TABLE deployments (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT,
    environment TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE INDEX deployments_run_id_idx ON deployments (run_id)

CREATE TABLE environments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE INDEX approvals_job_id_idx ON approvals (job_id)

CREATE TABLE schedules (
    id TEXT PRIMARY KEY,
    cron TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE TABLE test_cases (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    name TEXT NOT NULL,
    class TEXT,
    duration DOUBLE PRECISION,
    passed BOOLEAN NOT NULL,
    message TEXT,
    payload JSONB NOT NULL
)

CREATE INDEX test_cases_report_id_idx ON test_cases (report_id)

CREATE TABLE test_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT,
    job_key TEXT,
    path TEXT,
    tests INT NOT NULL DEFAULT 0,
    failures INT NOT NULL DEFAULT 0,
    duration DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE INDEX test_results_run_id_idx ON test_results (run_id)

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    actor TEXT,
    run_id TEXT,
    job_id TEXT,
    message TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL
)

CREATE INDEX audit_events_created_at_idx ON audit_events (created_at DESC)

CREATE TABLE log_chunks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT,
    job_key TEXT,
    step TEXT,
    seq BIGINT NOT NULL,
    line TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (run_id, seq)
)

CREATE INDEX log_chunks_run_id_seq_idx ON log_chunks (run_id, seq)

CREATE TABLE usage_records (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    quantity BIGINT NOT NULL DEFAULT 0,
    unit TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE TABLE webhook_deliveries (
    forge TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    payload_digest TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (forge, delivery_id)
)

CREATE TABLE downstream_links (
    id TEXT PRIMARY KEY,
    upstream_run_id TEXT NOT NULL,
    downstream_run_id TEXT NOT NULL,
    kind TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)

CREATE TABLE workspace_snapshots (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    job_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
)
