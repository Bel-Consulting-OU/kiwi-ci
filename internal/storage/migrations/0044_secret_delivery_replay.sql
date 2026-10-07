-- 0044_secret_delivery_replay.sql — retry-stable sealed secret delivery.
--
-- The once-only secret_claims row now carries the sealed envelope it was
-- committed with, so an identical retry of the same delivery (same job,
-- generation, secret AND same runner ephemeral public key) replays the exact
-- same ciphertext, ephemeral public key and nonce instead of being refused
-- forever after a lost response. recipient_public is the runner's X25519
-- request key the envelope was sealed for and is the replay identity. A
-- presented key that differs from the stored one stays a duplicate refusal.
-- Nullable and additive: legacy rows have no envelope and remain permanent
-- duplicate refusals, and older binaries ignore the new columns.

ALTER TABLE secret_claims ADD COLUMN IF NOT EXISTS recipient_public BYTEA;
ALTER TABLE secret_claims ADD COLUMN IF NOT EXISTS ephemeral_public BYTEA;
ALTER TABLE secret_claims ADD COLUMN IF NOT EXISTS ciphertext BYTEA;
ALTER TABLE secret_claims ADD COLUMN IF NOT EXISTS nonce BYTEA;
ALTER TABLE secret_claims ADD COLUMN IF NOT EXISTS sealed_at TIMESTAMPTZ;
