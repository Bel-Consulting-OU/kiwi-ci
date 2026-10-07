-- 0042_queued_traversal_index.sql — dedicated partial index for the immutable
-- creation-order queued traversal, plus schema comments pinning which queued
-- index serves which walk.
--
-- The immutable traversal (QueuedJobTraversalStore) pages by
-- created_at ASC, id ASC but reused jobs_queued_boost_sweep_idx
-- (created_at, queue_boost, id) WHERE status='queued'. Those orderings differ
-- whenever several rows share created_at with different queue_boost:
-- PostgreSQL can stream created_at from the sweep index, but the id order
-- inside each timestamp group can only be produced by an Incremental Sort
-- over queue_boost, so the page walk could materialize a whole tie group
-- before its early stop. This migration adds an index whose key IS the
-- traversal order, so the page walk stops after limit+1 index entries with no
-- sort of any kind.
--
-- jobs_queued_boost_sweep_idx stays for the PROMOTION sweep
-- (PromoteQueuedJobBoosts), whose bounded batch selection orders by
-- created_at, queue_boost, id — it is not the traversal index. The COMMENTs
-- record that split in the schema catalog itself, so an operator inspecting
-- the database sees which index belongs to which walk. This migration is
-- ADD-only (one partial index plus catalog comments) and keeps older
-- binaries operating unchanged.

CREATE INDEX IF NOT EXISTS jobs_queued_traversal_idx
    ON jobs (created_at ASC, id ASC)
    WHERE status='queued';

COMMENT ON INDEX jobs_queued_boost_sweep_idx IS 'PROMOTION sweep index on (created_at, queue_boost, id) WHERE status=queued, used by PromoteQueuedJobBoosts only, never by the immutable creation-order traversal (created_at, id), which is served by jobs_queued_traversal_idx';

COMMENT ON INDEX jobs_queued_traversal_idx IS 'Immutable creation-order traversal index on (created_at, id) WHERE status=queued, serving ORDER BY created_at ASC, id ASC with no Sort or Incremental Sort';
