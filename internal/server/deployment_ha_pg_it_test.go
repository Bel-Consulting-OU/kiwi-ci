package server

// Real-PostgreSQL HA/idempotency tests for deployment recording: replicas,
// restarts and concurrent callers must converge on ONE durable deployment
// record with one deployment.started audit event, and replay must return the
// canonical stored record (never a locally reconstructed one).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// deploymentHAJob builds the running environment-job shape recordDeploymentDB
// consumes; the deterministic deployment ID is the job ID.
func deploymentHAJob(t *testing.T) model.Job {
	t.Helper()
	return model.Job{
		ID: pgITServerRandomHex(t, 32), RunID: pgITServerRandomHex(t, 32),
		Environment: "prod", Status: model.StatusRunning,
		RepoURL: "https://github.com/kiwi-it/repo.git",
	}
}

func deploymentHARows(t *testing.T, env *pgITServerEnv, id string) int {
	t.Helper()
	return pgITServerCount(t, env, `SELECT COUNT(*) FROM deployments WHERE id=$1`, id)
}

func deploymentHAStartedAudits(t *testing.T, env *pgITServerEnv, jobID string) int {
	t.Helper()
	return pgITServerCount(t, env, `SELECT COUNT(*) FROM audit_events WHERE action='deployment.started' AND job_id=$1`, jobID)
}

// TestIntegrationRecordDeploymentReplayAfterRestart pins the restart path:
// the same process loses its local mirror, the durable row survives, and the
// replay returns the stored record without a second audit.
func TestIntegrationRecordDeploymentReplayAfterRestart(t *testing.T) {
	env := pgITServerSetup(t)
	s, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	ctx := context.Background()
	job := deploymentHAJob(t)

	startedA := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	first, err := s.recordDeploymentDB(ctx, job, startedA)
	if err != nil {
		t.Fatalf("first record: %v", err)
	}
	// Restart: the local mirror is gone, the DB row is not.
	s.mu.Lock()
	delete(s.deployments, job.ID)
	s.mu.Unlock()
	replayed, err := s.recordDeploymentDB(ctx, job, time.Now().UTC())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.ID != first.ID || !sameInstantPtr(replayed.StartedAt, first.StartedAt) || !replayed.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("replay after restart = %+v, want the canonical %+v", replayed, first)
	}
	if n := deploymentHARows(t, env, job.ID); n != 1 {
		t.Fatalf("deployment rows = %d, want 1", n)
	}
	if n := deploymentHAStartedAudits(t, env, job.ID); n != 1 {
		t.Fatalf("deployment.started audits = %d, want 1", n)
	}
}

// TestIntegrationRecordDeploymentExistingDBEmptyLocalMirror pins the failover
// path: a second replica with an empty mirror replays against the existing
// durable row and adopts the canonical record.
func TestIntegrationRecordDeploymentExistingDBEmptyLocalMirror(t *testing.T) {
	env := pgITServerSetup(t)
	sA, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, sA)
	ctx := context.Background()
	job := deploymentHAJob(t)

	startedA := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	first, err := sA.recordDeploymentDB(ctx, job, startedA)
	if err != nil {
		t.Fatalf("replica A record: %v", err)
	}
	sB, _ := pgITServerWithEnv(t, env, t.TempDir())
	replayed, err := sB.recordDeploymentDB(ctx, job, time.Now().UTC())
	if err != nil {
		t.Fatalf("replica B replay: %v", err)
	}
	if replayed.ID != first.ID || !sameInstantPtr(replayed.StartedAt, first.StartedAt) {
		t.Fatalf("replica B returned %+v, want the canonical %+v", replayed, first)
	}
	sB.mu.Lock()
	cached, ok := sB.deployments[job.ID]
	sB.mu.Unlock()
	if !ok || !sameInstantPtr(cached.StartedAt, first.StartedAt) {
		t.Fatalf("replica B cached %+v (present=%t), want the canonical record", cached, ok)
	}
	if n := deploymentHARows(t, env, job.ID); n != 1 {
		t.Fatalf("deployment rows = %d, want 1", n)
	}
	if n := deploymentHAStartedAudits(t, env, job.ID); n != 1 {
		t.Fatalf("deployment.started audits = %d, want 1", n)
	}
}

// TestIntegrationRecordDeploymentCreatedAuditExactlyOnce races two replicas
// on the same deterministic ID: one durable row, one audit event, and every
// caller observes the same record.
func TestIntegrationRecordDeploymentConcurrentReplicas(t *testing.T) {
	env := pgITServerSetup(t)
	sA, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, sA)
	sB, _ := pgITServerWithEnv(t, env, t.TempDir())
	ctx := context.Background()
	job := deploymentHAJob(t)
	started := time.Now().UTC().Truncate(time.Microsecond)

	const workers = 20
	results := make([]model.Deployment, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := sA
			if i%2 == 1 {
				s = sB
			}
			results[i], errs[i] = s.recordDeploymentDB(ctx, job, started)
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if results[i].ID != job.ID || !sameInstantPtr(results[i].StartedAt, &started) {
			t.Fatalf("worker %d returned a divergent record: %+v", i, results[i])
		}
	}
	if n := deploymentHARows(t, env, job.ID); n != 1 {
		t.Fatalf("deployment rows = %d, want 1", n)
	}
	if n := deploymentHAStartedAudits(t, env, job.ID); n != 1 {
		t.Fatalf("deployment.started audits = %d, want exactly one", n)
	}
}

// TestIntegrationRecordDeploymentIdentityConflictFailsClosed pins the
// fail-closed guard through the server path: an existing durable row with the
// same deterministic ID but a different environment is never adopted.
func TestIntegrationRecordDeploymentIdentityConflictFailsClosed(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	ctx := context.Background()
	job := deploymentHAJob(t)
	if _, err := s.recordDeploymentDB(ctx, job, time.Now().UTC()); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// The same job ID now reports a different environment: the replay must
	// fail rather than serve another environment's deployment record.
	s.mu.Lock()
	delete(s.deployments, job.ID)
	s.mu.Unlock()
	conflicting := job
	conflicting.Environment = "staging"
	if _, err := s.recordDeploymentDB(ctx, conflicting, time.Now().UTC()); err == nil {
		t.Fatal("identity conflict was adopted instead of refused")
	}
	recs, err := st.ListDeploymentsByRun(ctx, job.RunID)
	if err != nil || len(recs) != 1 || recs[0].Environment != "prod" {
		t.Fatalf("deployments after conflict = %+v err=%v, want only the prod record", recs, err)
	}
}

// sameInstantPtr compares two optional instants.
func sameInstantPtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}
