-- 0057_verification_store.sql — durable verification substrate
-- (verifyapi.VerificationStore).
--
-- Three tables mirror the contract's three aggregates:
--
--   - verification_obligations: one row per claim-bound demand for
--     verification. obligation_id is the SubmitObligation idempotency key,
--     content_digest pins the canonical encoding so an identical resubmit
--     is a no-op success while a different payload under the same key is
--     refused (SQLSTATE 23505, mapped to verifyapi.ErrExists).
--   - verification_outcomes: one row per verification id. The claim side is
--     always present (claim JSONB), the verified side (evidence JSONB +
--     is_verified) is written only by RecordVerifiedOutcome, so a claim can
--     never discharge an obligation as proven. content_digest is the
--     claim-equivalent digest (substrate-derived Measured facts stripped),
--     so retries of one submission dedupe while two runs under one
--     verification id collide. group_id / candidate_id are denormalized
--     from ResourceFacts at record time for CompareGroup.
--   - verification_groups: speculative comparison groups, idempotent on
--     verification_group_id via content_digest exactly like the other two.
--
-- created_at/verified_at carry the store clock, the JSONB payloads hold the
-- full wire-shaped structs (timestamps included) so reads round-trip
-- byte-faithful claim identities.
CREATE TABLE verification_obligations (
    obligation_id TEXT PRIMARY KEY,
    content_digest TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE verification_outcomes (
    verification_id TEXT PRIMARY KEY,
    obligation_id TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    content_digest TEXT NOT NULL,
    claim JSONB NOT NULL,
    evidence JSONB,
    group_id TEXT NOT NULL DEFAULT '',
    candidate_id TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ
);

CREATE INDEX verification_outcomes_obligation_idx
    ON verification_outcomes (obligation_id, verification_id);

CREATE INDEX verification_outcomes_group_idx
    ON verification_outcomes (group_id, candidate_id, completed_at DESC, verification_id);

CREATE TABLE verification_groups (
    verification_group_id TEXT PRIMARY KEY,
    content_digest TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
