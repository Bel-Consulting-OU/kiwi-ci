-- 0045_execution_events.sql — canonical ordered execution event stream.
--
-- Kiwi previously had only an audit trail (random-id rows ordered by
-- created_at, id) and no ordered lifecycle feed with a transition cursor, so
-- external controllers had to infer events by diffing mutable resources. This
-- migration adds execution_events: an append-only stream whose BIGSERIAL seq
-- is the canonical cursor and whose rows are produced by row triggers in the
-- SAME transaction as the state change they describe.
--
-- Transactional append via trigger is what makes the stream exactly-once
-- with its state change without every store method learning about events:
--   - AFTER INSERT OR UPDATE OF status ON jobs appends job.<status>, with
--     from/to statuses, attempt = the row's lease_generation, and a small
--     payload (job key plus runner id on running and started/finished
--     timestamps on terminal statuses). A running -> queued move is the
--     recovery requeue and appends job.requeued.
--   - AFTER INSERT OR UPDATE OF status ON runs appends run.<status> so the
--     run aggregate transitions (queued/running/waiting_approval/terminal)
--     are in the same stream.
-- The triggers fire only on a REAL status change (IS DISTINCT FROM), because
-- PostgreSQL fires an UPDATE OF trigger whenever the column is assigned even
-- if the value is unchanged. A statement that only rewrites payload with the
-- same status therefore appends nothing.
--
-- created_at uses clock_timestamp() so the recorded instant is the row's
-- actual write time (statement/transaction start would cluster a batch of
-- events at the transaction start and misorder commits). The sequence, not
-- the timestamp, remains the canonical cursor.
--
-- Additive: no existing table or index changes, so older binaries keep
-- operating unchanged after this migration applies.

CREATE TABLE IF NOT EXISTS execution_events (
    seq BIGSERIAL PRIMARY KEY,
    schema_version INT NOT NULL DEFAULT 1,
    run_id TEXT,
    job_id TEXT,
    attempt BIGINT NOT NULL DEFAULT 0,
    event_type TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    actor TEXT,
    payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS execution_events_run_seq_idx ON execution_events (run_id, seq);

CREATE INDEX IF NOT EXISTS execution_events_job_seq_idx ON execution_events (job_id, seq);

CREATE OR REPLACE FUNCTION kiwi_append_execution_event() RETURNS trigger
LANGUAGE plpgsql
AS $kiwi$
DECLARE
    v_from TEXT;
    v_type TEXT;
    v_attempt BIGINT := 0;
    v_payload JSONB;
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
            'started_at', CASE WHEN NEW.status IN ('success', 'failure', 'cancelled', 'skipped') THEN to_jsonb(NEW.started_at) END,
            'finished_at', CASE WHEN NEW.status IN ('success', 'failure', 'cancelled', 'skipped') THEN to_jsonb(NEW.finished_at) END,
            'duration_ms', CASE WHEN NEW.status IN ('success', 'failure', 'cancelled', 'skipped') AND NEW.started_at IS NOT NULL AND NEW.finished_at IS NOT NULL THEN to_jsonb((floor(EXTRACT(EPOCH FROM (NEW.finished_at - NEW.started_at)) * 1000)::bigint)::text) END
        ));
        INSERT INTO execution_events (schema_version, run_id, job_id, attempt, event_type, from_status, to_status, payload, created_at)
        VALUES (1, NEW.run_id, NEW.id, v_attempt, v_type, v_from, NEW.status, v_payload, clock_timestamp());
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
        INSERT INTO execution_events (schema_version, run_id, event_type, from_status, to_status, created_at)
        VALUES (1, NEW.id, v_type, v_from, NEW.status, clock_timestamp());
    END IF;
    RETURN NEW;
END;
$kiwi$;

DROP TRIGGER IF EXISTS jobs_execution_events ON jobs;

CREATE TRIGGER jobs_execution_events
    AFTER INSERT OR UPDATE OF status ON jobs
    FOR EACH ROW EXECUTE FUNCTION kiwi_append_execution_event();

DROP TRIGGER IF EXISTS runs_execution_events ON runs;

CREATE TRIGGER runs_execution_events
    AFTER INSERT OR UPDATE OF status ON runs
    FOR EACH ROW EXECUTE FUNCTION kiwi_append_execution_event();
