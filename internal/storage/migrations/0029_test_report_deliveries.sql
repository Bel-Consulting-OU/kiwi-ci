-- 0029_test_report_deliveries.sql — durable test-report delivery identity.
--
-- The runner posts /api/v1/jobs/{id}/tests once and only warns on failure, and
-- the server used to mint a fresh report ID per request. A response lost after
-- the transaction committed therefore double-inserted the report and
-- double-folded test-history aggregates on the runner's retry, while no retry
-- lost valid intelligence forever.
--
-- This migration adds the durable delivery receipt that makes the upload
-- idempotent: (job_id, lease_generation, delivery_id) is the unique delivery
-- identity the runner derives from the report payload, and content_digest is
-- the server-computed digest of the payload bytes it received. The report
-- insert, the aggregate fold and this row commit in ONE transaction
-- (storage.InsertTestReportWithHistoryDelivery), so a replay of the same
-- delivery + digest is an idempotent success without re-inserting or
-- re-folding, and the same delivery with a different digest is a 409 conflict
-- with history untouched.
--
-- DEPLOY-SAFETY (same discipline as 0021-0028): the new table is empty and
-- referenced by no other relation, so CREATE TABLE + CREATE INDEX touch only
-- this relation and are safe to run while uploads continue. The PK index is
-- the delivery lookup, the created_at index supports future retention pruning
-- exactly like the pending-sidecar table's prune index, and IF NOT EXISTS
-- keeps a replay harmless.

CREATE TABLE IF NOT EXISTS test_report_deliveries (
    job_id TEXT NOT NULL,
    lease_generation BIGINT NOT NULL,
    delivery_id TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    report_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, lease_generation, delivery_id)
);

CREATE INDEX IF NOT EXISTS test_report_deliveries_created_at_idx
    ON test_report_deliveries (created_at);
