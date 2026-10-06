-- Durable idempotency receipts for run submission (API submit and rerun).
--
-- A client-supplied Idempotency-Key names one intended submission. The
-- receipt is written in the SAME transaction as the run it acknowledges, so
-- a commit plus lost response can never leave the durable receipt and the
-- run disagreeing. Replaying the key returns the original run, and replaying
-- it with a different request digest fails closed (409) instead of
-- enqueueing a duplicate.
--
-- repo_id is the canonical CHECKOUT repository identity (the same
-- storage.RepoIDForRun scope the run itself carries), so two repositories
-- sharing a key never collide. The receipt outlives the run row only until
-- retention prunes it, at which point it simply stops deduplicating.
CREATE TABLE run_idempotency (
    repo_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, idempotency_key)
);

-- Retention scans delete receipts by creation time, and the run_id index
-- lets an operator (or a future cascade) resolve the originating run cheaply.
CREATE INDEX run_idempotency_created_at_idx ON run_idempotency (created_at);
CREATE INDEX run_idempotency_run_idx ON run_idempotency (run_id);
