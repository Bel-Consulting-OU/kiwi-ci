-- 0059_verification_subject_scope.sql — normalized subject/scope columns
-- for the durable verification substrate (P7).
--
-- Canonical source of truth: these normalized columns are AUTHORITATIVE for
-- subject, scope, and the outcome index dimensions. The JSONB payload stays
-- the wire-faithful encoding of the whole struct. The write path
-- (verifystore.subject_scope.go) derives columns and payload from the same
-- Go value in one write-all statement, and the read path restores
-- subject/scope onto the returned struct from the columns, so a tampered
-- payload can never present a different authority subject than the row
-- indexes.
--
-- verification_obligations gains the obligation's subject name plus the
-- SubjectRef hierarchy (authority_namespace / tenant_id / project_id /
-- repository_id). verification_outcomes gains the same hierarchy columns,
-- denormalized from its obligation so scope queries need no join.
--
-- The backfill copies the existing payload values into the columns, so rows
-- written before this migration are consistent on arrival. Additive:
-- columns and indexes only, no existing column changes.
-- kiwi:compatible-from 58
ALTER TABLE verification_obligations
    ADD COLUMN subject TEXT NOT NULL DEFAULT '',
    ADD COLUMN authority_namespace TEXT NOT NULL DEFAULT '',
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN project_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN repository_id TEXT NOT NULL DEFAULT '';

ALTER TABLE verification_outcomes
    ADD COLUMN authority_namespace TEXT NOT NULL DEFAULT '',
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN project_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN repository_id TEXT NOT NULL DEFAULT '';

UPDATE verification_obligations SET
    subject = COALESCE(payload->>'subject', ''),
    authority_namespace = COALESCE(payload->'subject_ref'->>'authority_namespace', ''),
    tenant_id = COALESCE(payload->'subject_ref'->>'tenant_id', ''),
    project_id = COALESCE(payload->'subject_ref'->>'project_id', ''),
    repository_id = COALESCE(payload->'subject_ref'->>'repository_id', '');

UPDATE verification_outcomes vo SET
    authority_namespace = COALESCE(o.payload->'subject_ref'->>'authority_namespace', ''),
    tenant_id = COALESCE(o.payload->'subject_ref'->>'tenant_id', ''),
    project_id = COALESCE(o.payload->'subject_ref'->>'project_id', ''),
    repository_id = COALESCE(o.payload->'subject_ref'->>'repository_id', '')
FROM verification_obligations o
WHERE o.obligation_id = vo.obligation_id;

CREATE INDEX verification_obligations_scope_idx
    ON verification_obligations (authority_namespace, tenant_id, project_id, repository_id);

CREATE INDEX verification_outcomes_scope_idx
    ON verification_outcomes (authority_namespace, tenant_id, project_id, repository_id);
