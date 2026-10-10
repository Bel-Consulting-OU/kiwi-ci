-- 0056_execution_event_repo_scope.sql — repository dimension and per-scope
-- retention frontier for the execution event stream.
--
-- 0045/0046/0049 made execution_events a commit-ordered, cursor-addressed,
-- prefix-pruned stream, but the stream carried no repository dimension: every
-- read was global (or filtered by one run_id) and the single global
-- retained_from watermark expired EVERY cursor below the pruned prefix, even
-- when the consumer had lost nothing visible because only other repositories'
-- events were pruned. A least-privilege repository consumer therefore could
-- not be served correctly nor proven scope-correct.
--
-- This migration adds the repository dimension to the stream and the durable
-- per-run deletion frontier the scope-aware resume decision needs:
--
--   - execution_events.repo_id is the owning run's immutable RepoID, copied
--     at append time from runs.payload->>'repo_id'. The existing rows are
--     backfilled from their run. An index (repo_id, seq) makes a
--     repository-scoped keyset scan an index range scan.
--   - execution_event_pruned records, per run, the highest seq retention has
--     deleted for that run. A repository frontier is MAX(max_seq) over its
--     runs, a run frontier is its own row (0 when none). The global
--     execution_event_cursor.retained_from stays authoritative for the
--     unscoped stream.
--   - the trigger function is replaced so newly appended jobs events capture
--     the run's repository (looked up after the commit-ordered cursor lock)
--     and newly appended runs events capture NEW.payload->>'repo_id'.
--
-- Prune semantics: execution_event_pruned rows are written INSIDE the prune
-- transaction, BEFORE the victim rows are deleted, so the frontier can only
-- ever be conservative (a crash may expire a scoped cursor whose events are
-- still present, never the reverse). Rows pruned before this migration have
-- no per-run record and cannot be reconstructed — scoped consumers that
-- resume below such a prefix see resume_ok, which is the pre-0056 status quo
-- for every cursor.
--
-- Additive column with a default: older binaries read the table unchanged.
-- The new binary is required before mutating because the replaced trigger
-- function is the authority for the repository dimension.
ALTER TABLE execution_events ADD COLUMN IF NOT EXISTS repo_id TEXT NOT NULL DEFAULT '';

UPDATE execution_events e
SET repo_id = COALESCE(r.payload->>'repo_id', '')
FROM runs r
WHERE r.id = e.run_id AND e.repo_id = '';

CREATE INDEX IF NOT EXISTS execution_events_repo_seq_idx ON execution_events (repo_id, seq);

CREATE TABLE IF NOT EXISTS execution_event_pruned (
    run_id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL DEFAULT '',
    max_seq BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS execution_event_pruned_repo_idx ON execution_event_pruned (repo_id);

CREATE OR REPLACE FUNCTION kiwi_append_execution_event() RETURNS trigger
LANGUAGE plpgsql
AS $kiwi$
DECLARE
    v_from TEXT;
    v_type TEXT;
    v_attempt BIGINT := 0;
    v_payload JSONB;
    v_repo TEXT := '';
    v_seq BIGINT;
BEGIN
    IF TG_TABLE_NAME = 'jobs' THEN
        IF TG_OP = 'INSERT' THEN
            v_from := NULL;
        ELSE
            v_from := OLD.status;
        END IF;
        IF NEW.status IS NOT DISTINCT FROM v_from THEN
            RETURN NEW;
        END IF;
        v_attempt := COALESCE(NEW.lease_generation, 0);
        v_type := CASE NEW.status
            WHEN 'success' THEN 'job.succeeded'
            WHEN 'failure' THEN 'job.failed'
            ELSE 'job.' || NEW.status
        END;
        IF TG_OP = 'UPDATE' AND OLD.status = 'running' AND NEW.status = 'queued' THEN
            v_type := 'job.requeued';
        END IF;
        v_payload := jsonb_strip_nulls(jsonb_build_object(
            'job', NEW.key,
            'runner', CASE WHEN NEW.status = 'running' THEN NEW.lease_runner_id END,
            'started_at', CASE WHEN NEW.status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked') THEN to_jsonb(NEW.started_at) END,
            'finished_at', CASE WHEN NEW.status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked') THEN to_jsonb(NEW.finished_at) END,
            'duration_ms', CASE WHEN NEW.status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked') AND NEW.started_at IS NOT NULL AND NEW.finished_at IS NOT NULL THEN to_jsonb((floor(EXTRACT(EPOCH FROM (NEW.finished_at - NEW.started_at)) * 1000)::bigint)::text) END
        ));
        UPDATE execution_event_cursor SET value = value + 1 RETURNING value INTO v_seq;
        SELECT COALESCE((SELECT payload->>'repo_id' FROM runs WHERE id = NEW.run_id), '') INTO v_repo;
        INSERT INTO execution_events (seq, schema_version, run_id, job_id, repo_id, attempt, event_type, from_status, to_status, payload, created_at)
        VALUES (v_seq, 1, NEW.run_id, NEW.id, v_repo, v_attempt, v_type, v_from, NEW.status, v_payload, clock_timestamp());
    ELSE
        IF TG_OP = 'INSERT' THEN
            v_from := NULL;
        ELSE
            v_from := OLD.status;
        END IF;
        IF NEW.status IS NOT DISTINCT FROM v_from THEN
            RETURN NEW;
        END IF;
        v_type := CASE NEW.status
            WHEN 'success' THEN 'run.succeeded'
            WHEN 'failure' THEN 'run.failed'
            ELSE 'run.' || NEW.status
        END;
        v_repo := COALESCE(NEW.payload->>'repo_id', '');
        UPDATE execution_event_cursor SET value = value + 1 RETURNING value INTO v_seq;
        INSERT INTO execution_events (seq, schema_version, run_id, repo_id, event_type, from_status, to_status, created_at)
        VALUES (v_seq, 1, NEW.id, v_repo, v_type, v_from, NEW.status, clock_timestamp());
    END IF;
    RETURN NEW;
END;
$kiwi$;
