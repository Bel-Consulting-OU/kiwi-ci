-- 0050_execution_attestations.sql — durable final execution attestations.
--
-- One completed ATTEMPT (job_id, generation) gets exactly one signed final
-- execution attestation: the DSSE envelope lives in the CAS (or, in fs dev
-- mode, in a durable sidecar file), and this table is the durable index and
-- idempotency marker. The primary key makes the emission effect insert-once
-- (ON CONFLICT DO NOTHING plus read back), so repeated dispatches, HA
-- replicas and restarts converge on exactly one row, one CAS object and one
-- execution.attested event.
--
-- Columns:
--   job_id, generation   the canonical attempt identity (model.AttemptID)
--   run_id, status       denormalized evidence for listing/GC without a join
--   statement_sha256     SHA-256 of the signed statement JSON (the DSSE
--                        payload bytes)
--   envelope_ref         "cas:<sha256>" in CAS mode, sidecar path in fs mode
--   created_at           database clock at commit
--
-- Additive: no existing table or column changes, so older binaries keep
-- operating unchanged after this migration applies.
CREATE TABLE IF NOT EXISTS execution_attestations (
    job_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    run_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    statement_sha256 TEXT NOT NULL DEFAULT '',
    envelope_ref TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (job_id, generation)
);

CREATE INDEX IF NOT EXISTS execution_attestations_envelope_ref_idx
    ON execution_attestations (envelope_ref)
    WHERE envelope_ref <> '';
