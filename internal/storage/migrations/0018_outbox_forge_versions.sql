-- 0018_outbox_forge_versions.sql — versioned forge-delivery identity.
--
-- A forge check is a LOGICAL remote object (run + check name) whose state
-- advances monotonically queued -> in_progress -> completed. The outbox row
-- identity itself must advance with the state: the pre-0018 design re-used
-- one deterministic ID for every state of a logical check, so a newer state
-- arriving while an older one was pending was deduped away in process and a
-- dead-lettered row blocked every later state forever.
--
-- logical_key is the stable logical identity of the remote check (the
-- existing 128-bit sha256 check key: forge host + run + check name).
-- state_version is the logical state rank (queued=1, in_progress=2,
-- completed=3), so the row ID becomes logical_key || '#' || state_version and
-- a newer state can never collide with, or be blocked by, an older one.
--
-- forge_check_state is the durable delivery watermark per logical key: the
-- highest state_version whose publication was ACKed. It is updated in the
-- SAME statement as the outbox row deletion (OutboxAck) so the watermark can
-- never lag an acknowledged delivery, and it outlives the deleted outbox row
-- (a max() over the outbox itself would lose the watermark on every ACK).

ALTER TABLE outbox ADD COLUMN IF NOT EXISTS logical_key TEXT;

ALTER TABLE outbox ADD COLUMN IF NOT EXISTS state_version BIGINT NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS outbox_logical_version_idx
    ON outbox (logical_key, state_version)
    WHERE logical_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS outbox_logical_pending_idx
    ON outbox (logical_key, state_version)
    WHERE logical_key IS NOT NULL AND dead_lettered_at IS NULL;

CREATE TABLE IF NOT EXISTS forge_check_state (
    logical_key       TEXT PRIMARY KEY,
    delivered_version BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
