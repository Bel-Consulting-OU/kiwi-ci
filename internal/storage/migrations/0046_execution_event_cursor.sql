-- 0046_execution_event_cursor.sql — commit-ordered execution event cursor.
--
-- 0045 made execution_events.seq a BIGSERIAL: the sequence allocates as each
-- statement executes, BEFORE its transaction commits. A consumer could
-- therefore observe seq 6 (committed) while seq 5 was still uncommitted,
-- advance its cursor past 5, and lose 5 forever — a rollback hole and a late
-- commit are indistinguishable on the stream.
--
-- This migration replaces that allocation with a single-row cursor table
-- locked by the appending transaction:
--   UPDATE execution_event_cursor SET value = value + 1 RETURNING value
-- The row lock is held to commit, so a later event transaction BLOCKS until
-- the earlier one commits or rolls back: allocation order is exactly visible
-- order, and a rollback also rolls back its allocation (no holes). The seq
-- column and its primary key stay. The now-unused sequence object behind the
-- dropped BIGSERIAL default is harmless and deliberately left in place.
--
-- The cursor is seeded from the current stream maximum so an upgraded
-- database never reuses a seq that is already published. The trigger
-- function keeps the 0045 IS DISTINCT FROM guards and the same payload, with
-- terminal timings now also covering blocked (terminal in the model).

CREATE TABLE IF NOT EXISTS execution_event_cursor (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    value BIGINT NOT NULL DEFAULT 0
);

INSERT INTO execution_event_cursor (id, value)
SELECT TRUE, COALESCE((SELECT MAX(seq) FROM execution_events), 0)
ON CONFLICT (id) DO NOTHING;

ALTER TABLE execution_events ALTER COLUMN seq DROP DEFAULT;

CREATE OR REPLACE FUNCTION kiwi_append_execution_event() RETURNS trigger
LANGUAGE plpgsql
AS $kiwi$
DECLARE
    v_from TEXT;
    v_type TEXT;
    v_attempt BIGINT := 0;
    v_payload JSONB;
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
        INSERT INTO execution_events (seq, schema_version, run_id, job_id, attempt, event_type, from_status, to_status, payload, created_at)
        VALUES (v_seq, 1, NEW.run_id, NEW.id, v_attempt, v_type, v_from, NEW.status, v_payload, clock_timestamp());
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
        UPDATE execution_event_cursor SET value = value + 1 RETURNING value INTO v_seq;
        INSERT INTO execution_events (seq, schema_version, run_id, event_type, from_status, to_status, created_at)
        VALUES (v_seq, 1, NEW.id, v_type, v_from, NEW.status, clock_timestamp());
    END IF;
    RETURN NEW;
END;
$kiwi$;
