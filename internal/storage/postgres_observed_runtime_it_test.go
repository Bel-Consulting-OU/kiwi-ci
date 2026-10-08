package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationObservedRuntimeCompletion proves the completion
// transaction persists the executor-observed runtime identity on the job
// payload, that the completion effect outbox payload names the attempt, and
// that usage accounting stamps the same attempt generation.
func TestPostgresIntegrationObservedRuntimeCompletion(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	job := pgITJob(runID, jobID, pgITRepo)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: job},
	}); err != nil {
		t.Fatal(err)
	}
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	obs := memObservedRuntime()
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "hash-observed"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt, obs); err != nil {
		t.Fatalf("completion: %v", err)
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if j.ObservedRuntime == nil {
		t.Fatal("observed runtime not persisted")
	}
	if j.ObservedRuntime.RuntimeName != "docker" || j.ObservedRuntime.MainImageDigest != obs.MainImageDigest ||
		j.ObservedRuntime.ServiceImages["db"] != "postgres:16" || j.ObservedRuntime.ServiceImageDigests["db"] != obs.ServiceImageDigests["db"] {
		t.Fatalf("observed runtime round trip = %+v, want %+v", j.ObservedRuntime, obs)
	}
	if j.ObservedRuntime.CapturedAt.UTC() != obs.CapturedAt.UTC() {
		t.Fatalf("CapturedAt = %s, want %s", j.ObservedRuntime.CapturedAt, obs.CapturedAt)
	}

	// The durable completion effect names the attempt.
	var payload []byte
	if err := st.pool.QueryRow(ctx, `SELECT payload FROM outbox WHERE id=$1`, CompletionEffectID(jobID, 1, OutboxKindCompletionReconcile)).Scan(&payload); err != nil {
		t.Fatalf("effect payload: %v", err)
	}
	var effects CompletionEffectsPayload
	if err := json.Unmarshal(payload, &effects); err != nil {
		t.Fatal(err)
	}
	if effects.JobID != jobID || effects.RunID != runID || effects.Generation != 1 {
		t.Fatalf("effect payload = %+v", effects)
	}

	// Usage accounting stamps the attempt generation in the same payload.
	won, err := st.RecordUsageOnce(ctx, jobID, 1, 0.25, 0.5)
	if err != nil || !won {
		t.Fatalf("RecordUsageOnce = %v/%v, want win", won, err)
	}
	j, err = st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if !j.UsageRecorded || j.UsageLeaseGeneration != 1 || j.Cost != 0.25 || j.EnergyWh != 0.5 {
		t.Fatalf("usage record = %+v", j)
	}
}

// TestPostgresIntegrationAttemptIdentityOnReportAndDeployment proves the
// attempt (lease generation) is stamped on the lease-fenced test report and
// on the deployment record, and that the deployment finish preserves it.
func TestPostgresIntegrationAttemptIdentityOnReportAndDeployment(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	job, repo := testReportLeaseClaim(t, st, jobID, runnerID, time.Minute)

	rep := testReportForLease(t, job, "attempt-identity", true, time.Now().UTC())
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: job.LeaseGeneration, DeliveryID: "attempt-identity", ContentDigest: "digest-attempt"}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, job.LeaseGeneration, rep, repo, delivery); err != nil {
		t.Fatalf("report delivery: %v", err)
	}
	reports, err := st.ListTestReports(ctx, job.RunID)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports = %+v err=%v", reports, err)
	}
	if reports[0].LeaseGeneration != job.LeaseGeneration {
		t.Fatalf("report generation = %d, want %d", reports[0].LeaseGeneration, job.LeaseGeneration)
	}

	d := model.Deployment{
		ID: pgITNewID(t), RunID: job.RunID, JobID: jobID, Environment: "prod",
		Status: model.StatusRunning, CreatedAt: time.Now().UTC(), LeaseGeneration: job.LeaseGeneration,
	}
	audit := model.AuditEvent{ID: pgITNewID(t), Action: "deployment.started"}
	stored, created, err := st.StartDeployment(ctx, d, audit)
	if err != nil || !created {
		t.Fatalf("StartDeployment = created=%v err=%v", created, err)
	}
	if stored.LeaseGeneration != job.LeaseGeneration {
		t.Fatalf("stored deployment generation = %d, want %d", stored.LeaseGeneration, job.LeaseGeneration)
	}
	changed, err := st.FinishDeploymentOnce(ctx, d.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{ID: pgITNewID(t), Action: "deployment.completed"})
	if err != nil || !changed {
		t.Fatalf("FinishDeploymentOnce = changed=%v err=%v", changed, err)
	}
	recs, err := st.ListDeploymentsByRun(ctx, job.RunID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range recs {
		if rec.ID == d.ID {
			found = true
			if rec.LeaseGeneration != job.LeaseGeneration {
				t.Fatalf("finished deployment generation = %d, want %d preserved", rec.LeaseGeneration, job.LeaseGeneration)
			}
		}
	}
	if !found {
		t.Fatal("deployment record not found after finish")
	}
}
