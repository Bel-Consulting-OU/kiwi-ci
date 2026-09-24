package server

// G1-A/G1-B fresh-PostgreSQL handler ITs: the drain/enable handlers must not
// clobber a job the scheduler just leased, and the report-delivery identity is
// scoped by job so two jobs reusing one delivery_id both store.
//
// Gated on KIWI_TEST_POSTGRES_URL via the shared pgITServer* helpers.

import (
	"context"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationServerDrainEnablePreservesLeasedJob(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)
	ctx := context.Background()

	// The drain handler's read must not clobber the scheduler's lease.
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/drain", "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("drain = %d: %s", w.Code, w.Body.String())
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if len(ri.ActiveJobs) != 1 || ri.ActiveJobs[0] != task.Job.ID || !ri.Draining {
		t.Fatalf("drain clobbered the leased slot: %+v (want active %s, draining)", ri, task.Job.ID)
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/enable", "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	ri, err = st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner after enable: %v", err)
	}
	if len(ri.ActiveJobs) != 1 || ri.ActiveJobs[0] != task.Job.ID || ri.Draining || ri.Disabled {
		t.Fatalf("enable clobbered the leased slot: %+v", ri)
	}
}

func TestPostgresIntegrationServerReportDeliveryScopedByJob(t *testing.T) {
	env := pgITServerSetup(t)
	s, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	pgITSubmit(t, s, pgITServerPipeline)
	pgITSubmit(t, s, pgITServerPipeline)
	taskA := pgITNext(t, s, runnerID)
	taskB := pgITNext(t, s, runnerID)
	if taskA.Job.ID == taskB.Job.ID {
		t.Fatalf("both leases returned the same job %s", taskA.Job.ID)
	}

	const shared = "shared-delivery-id"
	bodyA, _ := explicitDeliveryBody(taskA.Job.ID, runnerID, taskA.LeaseToken, taskA.LeaseGeneration, shared,
		model.TestResult{Name: "A", Class: "C", Duration: 1, Passed: true})
	bodyB, _ := explicitDeliveryBody(taskB.Job.ID, runnerID, taskB.LeaseToken, taskB.LeaseGeneration, shared,
		model.TestResult{Name: "B", Class: "C", Duration: 1, Passed: true})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+taskA.Job.ID+"/tests", "token", bodyA, nil); w.Code != http.StatusCreated {
		t.Fatalf("job A upload = %d: %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+taskB.Job.ID+"/tests", "token", bodyB, nil); w.Code != http.StatusCreated {
		t.Fatalf("job B upload = %d: %s", w.Code, w.Body.String())
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(*) FROM test_results WHERE job_id = ANY($1::text[])`, []string{taskA.Job.ID, taskB.Job.ID}); got != 2 {
		t.Fatalf("stored reports for both jobs = %d, want 2 (pre-fix the scoped-out delivery dropped job B)", got)
	}
	if got := pgITServerCount(t, env, `SELECT COUNT(DISTINCT job_id) FROM test_results WHERE job_id = ANY($1::text[])`, []string{taskA.Job.ID, taskB.Job.ID}); got != 2 {
		t.Fatalf("distinct jobs with a stored report = %d, want 2", got)
	}
}
