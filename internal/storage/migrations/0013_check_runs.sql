CREATE TABLE IF NOT EXISTS check_runs (
    key TEXT PRIMARY KEY,
    check_run_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
