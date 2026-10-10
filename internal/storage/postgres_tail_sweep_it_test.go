package storage

// Tail coverage for the PostgreSQL store: pure/validation branches that need
// no database, a closed-pool sweep over the methods the original sweep did
// not list, and an aborted-transaction sweep over the remaining internal
// transaction helpers. The integration cases are gated by the shared
// PostgreSQL helpers and named *Integration*.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresPureHelperAndValidationBranches(t *testing.T) {
	ctx := context.Background()

	// jsonPayloadEqual: byte-equal short-circuits; either side failing to
	// decode fails closed; semantic JSON equality ignores key order.
	if !jsonPayloadEqual([]byte(`{"a":1}`), []byte(`{"a":1}`)) {
		t.Fatal("byte-equal payloads must compare equal")
	}
	if jsonPayloadEqual([]byte(`{`), []byte(`{}`)) {
		t.Fatal("undecodable left payload must not compare equal")
	}
	if jsonPayloadEqual([]byte(`{}`), []byte(`{`)) {
		t.Fatal("undecodable right payload must not compare equal")
	}
	if !jsonPayloadEqual([]byte(`{"a":1,"b":2}`), []byte("{\n \"b\": 2, \n \"a\": 1}")) {
		t.Fatal("semantically equal JSON must compare equal")
	}
	if jsonPayloadEqual([]byte(`{"a":1}`), []byte(`{"a":2}`)) {
		t.Fatal("different JSON must not compare equal")
	}

	// storedCompletionObservedRuntime: every early nil and the success path.
	obs := &model.ObservedRuntime{}
	jobPayload, err := jsonMarshal(model.Job{ObservedRuntime: obs})
	if err != nil {
		t.Fatal(err)
	}
	if got := storedCompletionObservedRuntime(jobPayload, CompletionResultHashVersionV2, 1, 1, string(model.StatusSuccess), obs); got != nil {
		t.Fatal("v2 stored receipt must not return observed runtime")
	}
	if got := storedCompletionObservedRuntime(jobPayload, 0, 1, 1, string(model.StatusSuccess), nil); got != nil {
		t.Fatal("nil request observed runtime must not return stored runtime")
	}
	if got := storedCompletionObservedRuntime(jobPayload, 0, 1, 2, string(model.StatusSuccess), obs); got != nil {
		t.Fatal("generation mismatch must not return stored runtime")
	}
	if got := storedCompletionObservedRuntime(jobPayload, 0, 1, 1, string(model.StatusRunning), obs); got != nil {
		t.Fatal("non-terminal stored status must not return stored runtime")
	}
	if got := storedCompletionObservedRuntime([]byte("{"), 0, 1, 1, string(model.StatusSuccess), obs); got != nil {
		t.Fatal("undecodable payload must not return stored runtime")
	}
	if got := storedCompletionObservedRuntime(jobPayload, 0, 1, 1, string(model.StatusSuccess), obs); got == nil {
		t.Fatal("terminal legacy receipt must return the stored runtime evidence")
	}

	// schemaFloorExceeded short-circuits when the fence is off or the binary
	// version was never resolved: neither may consult the pool.
	off := &PostgresStore{}
	if off.schemaFloorExceeded(ctx) {
		t.Fatal("store without the schema fence reported an exceeded floor")
	}
	unresolved := &PostgresStore{schemaFence: true}
	if unresolved.schemaFloorExceeded(ctx) {
		t.Fatal("store without a resolved binary schema version reported an exceeded floor")
	}

	// Nil-tx validation branches.
	if err := off.checkCompiledRunJobKeysTx(ctx, nil, "run", nil); err != nil {
		t.Fatalf("empty job set = %v, want nil before any query", err)
	}
	if err := off.claimRunIdempotencyTx(ctx, nil, &RunIdempotencyClaim{}); err == nil {
		t.Fatal("empty idempotency claim accepted")
	}
	if err := off.claimRunIdempotencyTx(ctx, nil, &RunIdempotencyClaim{RepoID: "r", Key: "k", RunID: "bad"}); err == nil {
		t.Fatal("malformed idempotency run id accepted")
	}
	if ok, err := off.OutboxVersionGuard(ctx, "id", "", 0); err != nil || !ok {
		t.Fatalf("guard without identity = (%v, %v), want (true, nil)", ok, err)
	}
	validationCalls := map[string]func() error{
		"OutboxHas":            func() error { _, err := off.OutboxHas(ctx, ""); return err },
		"OutboxRequeue":        func() error { return off.OutboxRequeue(ctx, "") },
		"OutboxDelete":         func() error { return off.OutboxDelete(ctx, "") },
		"OutboxAck":            func() error { return off.OutboxAck(ctx, "") },
		"AppendLog/bad-run":    func() error { return off.AppendLog(ctx, model.LogEntry{RunID: "bad"}) },
		"LatestLogSeq/bad-run": func() error { _, err := off.LatestLogSeq(ctx, "bad"); return err },
		"ApproveJob/bad-id":    func() error { _, err := off.ApproveJob(ctx, "bad", "actor"); return err },
		"TouchRunnerLastSeen":  func() error { return off.TouchRunnerLastSeen(ctx, "bad") },
	}
	for name, fn := range validationCalls {
		err := fn()
		if err == nil {
			t.Fatalf("%s accepted a malformed argument", name)
		}
	}
	if _, err := off.TryAcquireLeadership(ctx, "", time.Minute); err == nil {
		t.Fatal("empty leadership key accepted")
	}
	if _, err := off.TryAcquireLeadership(ctx, "k", 0); err == nil {
		t.Fatal("non-positive leadership ttl accepted")
	}
	if _, _, err := off.StartDeployment(ctx, model.Deployment{}, model.AuditEvent{}); err == nil {
		t.Fatal("malformed deployment id accepted")
	}
	if _, _, err := off.StartDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: "bad"}, model.AuditEvent{}); err == nil {
		t.Fatal("malformed deployment run id accepted")
	}
	if _, err := off.FinishDeploymentOnce(ctx, "bad", model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); err == nil {
		t.Fatal("malformed finish deployment id accepted")
	}
	if _, err := off.ClaimScheduleOccurrence(ctx, "", time.Now().UTC(), pgITNewID(t)); err == nil {
		t.Fatal("empty schedule id accepted")
	}
	if _, err := off.ClaimScheduleOccurrence(ctx, pgITNewID(t), time.Now().UTC(), ""); err == nil {
		t.Fatal("empty run id accepted")
	}
}

func TestPostgresIntegrationClosedPoolTailSweep(t *testing.T) {
	dsn := pgITDSN(t)
	st, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	_ = st.Close()
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	now := time.Now().UTC()

	calls := map[string]func() error{
		"ApproveJob": func() error { _, err := st.ApproveJob(ctx, jobID, "actor"); return err },
		"HeartbeatLeaseWithTTL": func() error {
			_, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, time.Minute)
			return err
		},
		"CancelRunJobs":       func() error { _, err := st.CancelRunJobs(ctx, runID, "reason"); return err },
		"TouchRunnerLastSeen": func() error { return st.TouchRunnerLastSeen(ctx, runnerID) },
		"AppendLog":           func() error { return st.AppendLog(ctx, model.LogEntry{RunID: runID, Line: "l", CreatedAt: now}) },
		"LatestLogSeq":        func() error { _, err := st.LatestLogSeq(ctx, runID); return err },
		"OutboxHas":           func() error { _, err := st.OutboxHas(ctx, "row"); return err },
		"OutboxVersionGuard":  func() error { _, err := st.OutboxVersionGuard(ctx, "row", "lk", 1); return err },
		"OutboxDeadLetters":   func() error { _, err := st.OutboxDeadLetters(ctx); return err },
		"OutboxRequeue":       func() error { return st.OutboxRequeue(ctx, "row") },
		"OutboxRetryClaimed":  func() error { return st.OutboxRetryClaimed(ctx, "row", "claimer", errors.New("x"), 3) },
		"ReleaseOutboxClaims": func() error { _, err := st.ReleaseOutboxClaims(ctx, []string{"row"}, "claimer"); return err },
		"ClaimScheduleOccur":  func() error { _, err := st.ClaimScheduleOccurrence(ctx, pgITNewID(t), now, runID); return err },
		"StartDeployment": func() error {
			_, _, err := st.StartDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: runID, CreatedAt: now}, model.AuditEvent{ID: pgITNewID(t)})
			return err
		},
		"FinishDeploymentOnce": func() error {
			_, err := st.FinishDeploymentOnce(ctx, pgITNewID(t), model.StatusSuccess, now, model.AuditEvent{ID: pgITNewID(t)})
			return err
		},
		"FindRunIdempotency": func() error {
			_, _, _, err := st.FindRunIdempotency(ctx, "repo", "key")
			return err
		},
		"PruneRunIdempotency": func() error { _, err := st.PruneRunIdempotency(ctx, now, 10); return err },
		"SchemaFloor":         func() error { _, err := st.SchemaCompatibilityFloor(ctx); return err },
		"GetSnapshot":         func() error { _, _, err := st.GetSnapshot(ctx, runID, pgITNewID(t)); return err },
		"ListSnapshotsPage": func() error {
			_, err := st.ListSnapshotsPage(ctx, runID, time.Time{}, "", 10)
			return err
		},
		"ReleaseRunnerJob": func() error { return st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusSuccess) },
	}
	for name, fn := range calls {
		t.Run(name, func(t *testing.T) {
			err := fn()
			if err == nil {
				t.Fatalf("%s on a closed pool must report an error", name)
			}
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: closed pool must not masquerade as ErrNotFound", name)
			}
		})
	}
}

func TestPostgresIntegrationAbortedTxTailSweep(t *testing.T) {
	st := pgITStore(t)
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	now := time.Now().UTC()

	cases := map[string]func(ctx context.Context, tx pgx.Tx) error{
		"claimRunIdempotencyTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.claimRunIdempotencyTx(ctx, tx, &RunIdempotencyClaim{RepoID: "repo", Key: "key", RunID: pgITNewID(t), Digest: "d", CreatedAt: now})
		},
		"checkCompiledRunJobKeysTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.checkCompiledRunJobKeysTx(ctx, tx, runID, map[string]model.Job{"build": {ID: jobID, Key: "build"}})
		},
		"cancelJobTx": func(ctx context.Context, tx pgx.Tx) error {
			_, err := st.cancelJobTx(ctx, tx, jobID, "reason", JobCancelOperator)
			return err
		},
		"cancelRunRowTx": func(ctx context.Context, tx pgx.Tx) error {
			_, err := st.cancelRunRowTx(ctx, tx, runID, "reason", JobCancelOperator)
			return err
		},
		"writeRunnerProfileTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.writeRunnerProfileTx(ctx, tx, model.Runner{ID: runnerID, Capacity: 1}, false)
		},
		"pruneCompletionReceiptsTx": func(ctx context.Context, tx pgx.Tx) error {
			return pruneCompletionReceiptsTx(ctx, tx)
		},
		"insertDeploymentOnceTx": func(ctx context.Context, tx pgx.Tx) error {
			_, _, err := insertDeploymentOnceTx(ctx, tx, model.Deployment{ID: pgITNewID(t), RunID: runID, CreatedAt: now})
			return err
		},
		"startDeploymentAuditTx": func(ctx context.Context, tx pgx.Tx) error {
			return startDeploymentAuditTx(ctx, tx, model.AuditEvent{ID: pgITNewID(t), Action: "deployment.started", CreatedAt: now})
		},
		"reserveDownstreamLaunchTx": func(ctx context.Context, tx pgx.Tx) error {
			_, err := st.reserveDownstreamLaunchTx(ctx, tx, jobID, "acme/child", "refs/heads/main", "token")
			return err
		},
		"lockedLeaseJobTx": func(ctx context.Context, tx pgx.Tx) error {
			_, _, err := st.lockedLeaseJobTx(ctx, tx, jobID, runnerID, 1)
			return err
		},
		"recoverCorruptLeaseTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.recoverCorruptLeaseTx(ctx, tx, jobID, runID, "build", runnerID, now)
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, tx := pgITAbortedTx(t, st)
			if err := fn(ctx, tx); err == nil {
				t.Fatalf("aborted transaction must surface an error")
			}
		})
	}
}
