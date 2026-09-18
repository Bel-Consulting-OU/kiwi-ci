-- 0016_completion_receipt_retention.sql — retention index for completion
-- receipts.
--
-- DB mode shares the fs store's completion receipt retention contract
-- (CompletionReceiptTTL / MaxCompletionReceipts): a receipt is honored for
-- replay detection only while it is younger than the TTL, and the durable set
-- is bounded to the newest receipts. The store reclaims expired receipts on
-- the write path (completion and receipt insert), so this index makes that
-- reclaim a cheap ordered range scan on created_at instead of a table scan.
--
-- created_at already exists and defaults to now() (0001_init.sql), so existing
-- rows are backfilled by the column default and no data migration is needed.

CREATE INDEX IF NOT EXISTS completion_receipts_created_at_idx ON completion_receipts (created_at);
