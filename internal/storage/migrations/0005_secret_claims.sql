-- 0005_secret_claims.sql — durable one-time secret delivery claims.
--
-- secret_claims is the SQL-mode once-only record for secret deliveries: a
-- secret is delivered at most once per (job, lease generation, secret name).
-- ClaimSecretDelivery inserts with ON CONFLICT DO NOTHING, the row count
-- tells the caller whether it made the claim, so two concurrent deliveries
-- of the same (job, generation, name) can never both receive the sealed
-- value. The memory-mode file receipts (secrets-receipts.json) remain the
-- dev-mode equivalent.

CREATE TABLE secret_claims (
    job_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    secret_name TEXT NOT NULL,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, generation, secret_name)
);
