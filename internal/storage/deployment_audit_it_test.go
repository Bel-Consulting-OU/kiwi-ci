package storage

// Real-PostgreSQL integration tests for transactional deployment lifecycle:
// StartDeployment and FinishDeploymentOnce commit the state row and its audit
// event in ONE transaction, so a deployment can never exist without its
// deployment.started audit, an audit failure never advances the state, and
// completion is exactly-once across concurrent replicas.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func deploymentAuditCount(t *testing.T, st *PostgresStore, action, jobID string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action=$1 AND job_id=$2`, action, jobID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func deploymentAuditEvent(t *testing.T, action, jobID string) model.AuditEvent {
	t.Helper()
	return model.AuditEvent{ID: pgITNewID(t), Action: action, Actor: "test", JobID: jobID, Message: action}
}

// TestIntegrationDeploymentStartAuditAtomic pins the create path: the row and
// its deployment.started audit commit together, and a replay appends nothing.
func TestIntegrationDeploymentStartAuditAtomic(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()
	stored, created, err := st.StartDeployment(ctx, candidate, deploymentAuditEvent(t, "deployment.started", candidate.JobID))
	if err != nil || !created || stored.ID != candidate.ID {
		t.Fatalf("start = (%+v, created=%t, err=%v)", stored, created, err)
	}
	if n := deploymentAuditCount(t, st, "deployment.started", candidate.JobID); n != 1 {
		t.Fatalf("start audits = %d, want 1", n)
	}
	replay, created, err := st.StartDeployment(ctx, candidate, deploymentAuditEvent(t, "deployment.started", candidate.JobID))
	if err != nil || created || replay.ID != candidate.ID {
		t.Fatalf("replay = (%+v, created=%t, err=%v)", replay, created, err)
	}
	if n := deploymentAuditCount(t, st, "deployment.started", candidate.JobID); n != 1 {
		t.Fatalf("replay duplicated the start audit: %d", n)
	}
}

// TestIntegrationDeploymentStartAuditFailureRollsBackDeployment pins the
// atomicity: when the audit insert fails, the deployment row is rolled back
// too (no state without audit).
func TestIntegrationDeploymentStartAuditFailureRollsBackDeployment(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()

	// Plant an audit row whose id will collide with the start event's id.
	colliding := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO audit_events (id, action, actor, created_at) VALUES ($1, 'planted', 'test', now())`, colliding); err != nil {
		t.Fatal(err)
	}
	audit := deploymentAuditEvent(t, "deployment.started", candidate.JobID)
	audit.ID = colliding
	if _, _, err := st.StartDeployment(ctx, candidate, audit); err == nil {
		t.Fatal("start with a colliding audit id = nil error")
	}
	if rows := deploymentRowCount(t, st, candidate.ID); rows != 0 {
		t.Fatalf("failed-audit start committed %d deployment rows", rows)
	}
	if n := deploymentAuditCount(t, st, "deployment.started", candidate.JobID); n != 0 {
		t.Fatalf("failed-audit start committed %d start audits", n)
	}
}

// TestIntegrationDeploymentConcurrentStartExactlyOneAudit races many replicas
// on the same deterministic ID: one row, one start audit.
func TestIntegrationDeploymentConcurrentStartExactlyOneAudit(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()
	const workers = 20
	var wg sync.WaitGroup
	createdCount := 0
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := st.StartDeployment(ctx, candidate, deploymentAuditEvent(t, "deployment.started", candidate.JobID))
			if err != nil {
				t.Errorf("start: %v", err)
				return
			}
			if created {
				mu.Lock()
				createdCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if createdCount != 1 {
		t.Fatalf("created count = %d, want exactly 1", createdCount)
	}
	if rows := deploymentRowCount(t, st, candidate.ID); rows != 1 {
		t.Fatalf("deployment rows = %d, want 1", rows)
	}
	if n := deploymentAuditCount(t, st, "deployment.started", candidate.JobID); n != 1 {
		t.Fatalf("start audits = %d, want exactly 1", n)
	}
}

// TestIntegrationDeploymentFinishAuditAtomic pins the finish path: the finish
// marker and the completion audit commit together, and a replay appends
// nothing.
func TestIntegrationDeploymentFinishAuditAtomic(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()
	if _, _, err := st.StartDeployment(ctx, candidate, deploymentAuditEvent(t, "deployment.started", candidate.JobID)); err != nil {
		t.Fatal(err)
	}
	finishedAt := time.Now().UTC().Truncate(time.Microsecond)
	changed, err := st.FinishDeploymentOnce(ctx, candidate.ID, model.StatusSuccess, finishedAt, deploymentAuditEvent(t, "deployment.completed", candidate.JobID))
	if err != nil || !changed {
		t.Fatalf("finish = (changed=%t, err=%v)", changed, err)
	}
	recs, err := st.ListDeploymentsByRun(ctx, candidate.RunID)
	if err != nil || len(recs) != 1 {
		t.Fatalf("deployments = %+v err=%v", recs, err)
	}
	if recs[0].Status != model.StatusSuccess || recs[0].FinishedAt == nil || !recs[0].FinishedAt.Equal(finishedAt) {
		t.Fatalf("stored finish state = %+v", recs[0])
	}
	if n := deploymentAuditCount(t, st, "deployment.completed", candidate.JobID); n != 1 {
		t.Fatalf("completion audits = %d, want 1", n)
	}
	changed, err = st.FinishDeploymentOnce(ctx, candidate.ID, model.StatusFailure, time.Now().UTC(), deploymentAuditEvent(t, "deployment.completed", candidate.JobID))
	if err != nil || changed {
		t.Fatalf("finish replay = (changed=%t, err=%v), want a no-op", changed, err)
	}
	if n := deploymentAuditCount(t, st, "deployment.completed", candidate.JobID); n != 1 {
		t.Fatalf("finish replay duplicated the audit: %d", n)
	}
}

// TestIntegrationDeploymentFinishAuditFailureLeavesFinishRetryable pins the
// retryability: an audit failure rolls the finish marker back, and a retry
// with a healthy audit completes exactly once.
func TestIntegrationDeploymentFinishAuditFailureLeavesFinishRetryable(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()
	if _, _, err := st.StartDeployment(ctx, candidate, deploymentAuditEvent(t, "deployment.started", candidate.JobID)); err != nil {
		t.Fatal(err)
	}
	colliding := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO audit_events (id, action, actor, created_at) VALUES ($1, 'planted', 'test', now())`, colliding); err != nil {
		t.Fatal(err)
	}
	bad := deploymentAuditEvent(t, "deployment.completed", candidate.JobID)
	bad.ID = colliding
	if changed, err := st.FinishDeploymentOnce(ctx, candidate.ID, model.StatusSuccess, time.Now().UTC(), bad); err == nil || changed {
		t.Fatalf("finish with a colliding audit id = (changed=%t, err=%v), want a rollback", changed, err)
	}
	recs, err := st.ListDeploymentsByRun(ctx, candidate.RunID)
	if err != nil || len(recs) != 1 || recs[0].FinishedAt != nil {
		t.Fatalf("failed-audit finish advanced state: %+v err=%v", recs, err)
	}
	if n := deploymentAuditCount(t, st, "deployment.completed", candidate.JobID); n != 0 {
		t.Fatalf("failed-audit finish committed %d completion audits", n)
	}
	// Retry converges: marker + audit exactly once.
	changed, err := st.FinishDeploymentOnce(ctx, candidate.ID, model.StatusSuccess, time.Now().UTC(), deploymentAuditEvent(t, "deployment.completed", candidate.JobID))
	if err != nil || !changed {
		t.Fatalf("retry finish = (changed=%t, err=%v)", changed, err)
	}
	if n := deploymentAuditCount(t, st, "deployment.completed", candidate.JobID); n != 1 {
		t.Fatalf("retry completion audits = %d, want 1", n)
	}
}

// TestIntegrationDeploymentConcurrentFinishExactlyOneAudit races two replicas
// finishing the same deployment: exactly one transition and one audit.
func TestIntegrationDeploymentConcurrentFinishExactlyOneAudit(t *testing.T) {
	st, candidate := deploymentOnceFixture(t)
	ctx := context.Background()
	if _, _, err := st.StartDeployment(ctx, candidate, deploymentAuditEvent(t, "deployment.started", candidate.JobID)); err != nil {
		t.Fatal(err)
	}
	finishedAt := time.Now().UTC()
	var wg sync.WaitGroup
	changedCount := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			changed, err := st.FinishDeploymentOnce(ctx, candidate.ID, model.StatusSuccess, finishedAt, deploymentAuditEvent(t, "deployment.completed", candidate.JobID))
			if err != nil {
				t.Errorf("finish: %v", err)
				return
			}
			if changed {
				mu.Lock()
				changedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if changedCount != 1 {
		t.Fatalf("changed count = %d, want exactly 1", changedCount)
	}
	if n := deploymentAuditCount(t, st, "deployment.completed", candidate.JobID); n != 1 {
		t.Fatalf("completion audits = %d, want exactly 1", n)
	}
}
