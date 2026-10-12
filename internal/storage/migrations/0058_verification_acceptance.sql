-- 0058_verification_acceptance.sql — durable acceptance integrity records
-- for verified verification outcomes.
--
-- A verification_outcomes row is NOT authority: the process seal cannot be
-- serialized, and without an integrity binding a tampered row (or a flipped
-- is_verified flag) could recreate a proven pass. The acceptance column
-- holds the verifyapi.AcceptanceRecord computed at persist time —
-- acceptance-version, obligation-digest, outcome-digest,
-- verified-evidence-digest, algorithm, verified-at, key-id and the
-- HMAC/signature — so the read path can re-check the exact (obligation,
-- outcome, evidence) triple before restoring a seal.
--
-- Additive: one nullable column, no existing column changes. Rows written
-- before this migration carry no acceptance record and are refused on the
-- verified read path (fail closed) rather than restored as authority.
-- kiwi:compatible-from 57
ALTER TABLE verification_outcomes
    ADD COLUMN acceptance JSONB;
