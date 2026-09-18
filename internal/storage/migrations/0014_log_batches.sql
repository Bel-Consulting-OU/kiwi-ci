CREATE TABLE IF NOT EXISTS log_batches (
    job_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    batch_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, generation, batch_id)
);
