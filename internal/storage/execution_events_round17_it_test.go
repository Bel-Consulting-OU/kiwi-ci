package storage

// Coverage round: reader and snapshot arms of the execution-event surface:
// list/payload decode failures, append failure returns and the one-statement
// snapshot's cursor/scan arms.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationExecutionSnapshotArms drives ExecutionSnapshot's
// default-limit, begin, cursor-read, runs-query and run-scan error arms.
func TestPostgresIntegrationExecutionSnapshotArms(t *testing.T) {
	ctx := context.Background()

	t.Run("default run limit", func(t *testing.T) {
		st := pgITStore(t)
		snap, err := st.ExecutionSnapshot(ctx, 0)
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		if snap.GeneratedAt.IsZero() {
			t.Fatal("snapshot has no generation timestamp")
		}
	})

	t.Run("begin error", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		if _, err := st.ExecutionSnapshot(ctx, 0); err == nil {
			t.Fatal("snapshot over a closed pool succeeded")
		}
	})

	t.Run("cursor read error", func(t *testing.T) {
		st := pgITStore(t)
		pgITDropColumn(t, st, "execution_event_cursor", "value")
		if _, err := st.ExecutionSnapshot(ctx, 0); err == nil {
			t.Fatal("snapshot without the cursor column succeeded")
		}
	})

	t.Run("runs query error", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `ALTER TABLE runs RENAME TO runs_r17`); err != nil {
			t.Fatalf("rename runs: %v", err)
		}
		if _, err := st.ExecutionSnapshot(ctx, 0); err == nil {
			t.Fatal("snapshot without the runs table succeeded")
		}
	})

	t.Run("run scan error", func(t *testing.T) {
		st := pgITStore(t)
		pgITInsertRunIdentity(t, st, pgITNewID(t), "group/sub/project", "group/sub/project", "", "")
		pgITBreakColumnToArray(t, st, "runs", "status")
		if _, err := st.ExecutionSnapshot(ctx, 0); err == nil {
			t.Fatal("snapshot over an undecodable status succeeded")
		}
	})
}

// TestPostgresIntegrationListExecutionEventsArms drives the reader's query,
// scan and payload-decode failure returns.
func TestPostgresIntegrationListExecutionEventsArms(t *testing.T) {
	ctx := context.Background()

	t.Run("query error", func(t *testing.T) {
		st := pgITStore(t)
		pgITDropColumn(t, st, "execution_events", "event_type")
		if _, _, err := st.ListExecutionEvents(ctx, 0, 10, ""); err == nil {
			t.Fatal("list without the event_type column succeeded")
		}
	})

	t.Run("scan error", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("append: %v", err)
		}
		pgITBreakColumnToArray(t, st, "execution_events", "event_type")
		if _, _, err := st.ListExecutionEvents(ctx, 0, 10, ""); err == nil {
			t.Fatal("list over an undecodable event type succeeded")
		}
	})

	t.Run("payload decode error", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx,
			`INSERT INTO execution_events (seq, schema_version, event_type, payload, created_at) VALUES (1, 1, 'job.queued', '"scalar"'::jsonb, now())`); err != nil {
			t.Fatalf("seed corrupt payload: %v", err)
		}
		if _, _, err := st.ListExecutionEvents(ctx, 0, 10, ""); err == nil {
			t.Fatal("list over a scalar payload succeeded")
		}
	})
}

// TestPostgresIntegrationExecutionRetentionArms drives the retention reader's
// cursor-scan and payload-decode failure returns.
func TestPostgresIntegrationExecutionRetentionArms(t *testing.T) {
	ctx := context.Background()

	t.Run("cursor scan error", func(t *testing.T) {
		st := pgITStore(t)
		pgITBreakColumnToArray(t, st, "execution_event_cursor", "retained_from")
		if _, _, _, _, err := st.ReadExecutionEventsRetention(ctx, 0, 10, ""); err == nil {
			t.Fatal("retention read over an undecodable watermark succeeded")
		}
	})

	t.Run("page decode error", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("append: %v", err)
		}
		pgITBreakColumnToArray(t, st, "execution_events", "attempt")
		if _, _, _, _, err := st.ReadExecutionEventsRetention(ctx, 0, 10, ""); err == nil {
			t.Fatal("retention read over an undecodable attempt succeeded")
		}
	})
}

// TestPostgresIntegrationAppendExecutionEventArms drives the manual append's
// validation, begin, cursor-update, insert and encode failure returns.
func TestPostgresIntegrationAppendExecutionEventArms(t *testing.T) {
	ctx := context.Background()

	t.Run("type required", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{}); err == nil {
			t.Fatal("event without a type was appended")
		}
	})

	t.Run("begin error", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued"}); err == nil {
			t.Fatal("append over a closed pool succeeded")
		}
	})

	t.Run("cursor update error", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "execution_event_cursor", "UPDATE")
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued", CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("append with a failing cursor update succeeded")
		}
	})

	t.Run("event insert error", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued", CreatedAt: time.Now().UTC()}); err == nil {
			t.Fatal("append with a failing event insert succeeded")
		}
	})

	t.Run("payload encode error", func(t *testing.T) {
		st := pgITStore(t)
		defer seamPGFailAll(t)()
		if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{Type: "job.queued", Payload: map[string]string{"a": "b"}}); err == nil {
			t.Fatal("append with a failing payload encode succeeded")
		}
	})

	t.Run("helper type required", func(t *testing.T) {
		st := pgITStore(t)
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := appendExecutionEventTx(ctx, tx, model.ExecutionEvent{}); err == nil {
			t.Fatal("in-transaction append without a type succeeded")
		}
	})
}
