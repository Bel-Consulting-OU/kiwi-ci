-- 0025_leader_fence.sql — monotonic leadership epoch (the fence) for
-- leader-only housekeeping mutations.
--
-- The scheduler's leadership claim is a session-level advisory lock, and the
-- cached expiry/probe window on top of it means a replica can briefly keep
-- reporting "leader" after its lock session died. Health checks cannot close
-- that window: the lock lives on a different connection than the mutations,
-- so proving liveness and then mutating is still a TOCTOU. This table is the
-- fence that closes it.
--
-- On every successful advisory-lock acquisition the leader ADVANCES the
-- singleton epoch on that same dedicated session (so a connection that dies
-- before commit cannot publish an epoch) and retains it. Every leader-only
-- transactional mutation re-reads this row with FOR SHARE inside its own
-- transaction and refuses to mutate unless its retained epoch is still the
-- current one. The epoch is strictly monotonic and never decremented: a
-- released or crashed leader's epoch can never become valid again, and a new
-- leader always publishes a strictly greater one.
--
-- The row seeds at epoch 1 so that "no leader has ever published" is still a
-- valid, non-matching value: a store without a retained epoch matches nothing
-- and every fenced mutation is rejected (there is no unset/0 state on the
-- durable side to mistake for a match).
--
-- DEPLOY-SAFETY (same discipline as 0021-0024): this file contains only
-- metadata-only DDL — CREATE TABLE for a brand-new relation plus its single
-- seed row. No existing table is locked or rewritten, so there is nothing to
-- split further: the only ACCESS EXCLUSIVE lock taken is on a table no other
-- session can reference yet. IF NOT EXISTS keeps a replay harmless, and the
-- ON CONFLICT seed never resets an already-advanced epoch.

CREATE TABLE IF NOT EXISTS leader_fence (
    id text PRIMARY KEY,
    epoch bigint NOT NULL,
    holder text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT leader_fence_singleton CHECK (id = 'singleton')
);

INSERT INTO leader_fence (id, epoch, holder, updated_at)
VALUES ('singleton', 1, NULL, now())
ON CONFLICT (id) DO NOTHING;
