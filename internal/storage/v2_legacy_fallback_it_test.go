package storage

import (
	"context"
	"testing"
	"time"
)

// TestPostgresIntegrationArtifactGenerationPayloadFallback pins the rolling
// upgrade read fallback: a pre-0010 writer stores job_generation=0 while the
// generation lives in the payload, and the artifact must still be found.
func TestPostgresIntegrationArtifactGenerationPayloadFallback(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID := pgITNewID(t)
	runID := pgITNewID(t)

	payload := []byte(`{"id":"` + jobID + `","run_id":"` + runID + `","lease_generation":7,"name":"bin","size":1,"sha256":"aa","created_at":"2024-01-01T00:00:00Z"}`)
	if _, err := st.pool.Exec(ctx, `INSERT INTO artifacts (id, run_id, job_id, job_key, name, size, sha256, created_at, expires_at, job_generation, payload)
		VALUES ($1,$2,$3,'build','bin',1,'aa',now(),now()+interval '1 day',0,$4)`, pgITNewID(t), runID, jobID, payload); err != nil {
		t.Fatalf("seed artifact: %v", err)
	}
	rec, err := st.artifactByGenerationKey(ctx, jobID, 7, "bin")
	if err != nil {
		t.Fatalf("generation from payload must resolve: %v", err)
	}
	if rec.Name != "bin" {
		t.Fatalf("resolved artifact = %+v", rec)
	}
}

// TestPostgresIntegrationRunnerPayloadDisableFallbackDeniesClaim pins the
// pre-0009 fallback: a runner whose payload says disabled=true must not be
// claimable even when the materialized column is still false.
func TestPostgresIntegrationRunnerPayloadDisableFallbackDeniesClaim(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	payload := []byte(`{"id":"` + runnerID + `","disabled":true,"capacity":1,"labels":{},"registered":true}`)
	if _, err := st.pool.Exec(ctx, `INSERT INTO runners (id, busy, capacity, active_jobs, registered, last_seen, payload, disabled, draining)
		VALUES ($1,false,1,'[]'::jsonb,now(),now(),$2,false,false)`, runnerID, payload); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{RunnerID: runnerID, JobID: pgITNewID(t), TokenHash: []byte("tok"), Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
		t.Fatal("a payload-disabled runner must not be claimable")
	}
}
