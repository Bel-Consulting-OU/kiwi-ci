package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Part 2: two-replica races on the changed surfaces against a live
// PostgreSQL. The harness is the existing pgITServerSetup /
// pgITServerWithEnv pattern: two Server instances share one schema and one
// data dir (the production HA topology). Every test asserts the invariant,
// not which replica wins.
//
// The storage-level half of these surfaces is already pinned by the
// storage-package ITs (referenced in the report):
//   - completion conflict:    storage/postgres_completion_conflict_it_test.go
//   - versioned enqueue/ack:  storage/postgres_outbox_version_it_test.go
//
// The tests below add the SERVER-level concurrency mapping.

type crashPGRaceResult struct {
	code int
	body string
}

// crashPGCount counts responses with one status code.
func crashPGCount(results []crashPGRaceResult, code int) int {
	n := 0
	for _, r := range results {
		if r.code == code {
			n++
		}
	}
	return n
}

// crashPGCompleteBody renders a completion body for a leased task.
func crashPGCompleteBody(t *testing.T, task Task, runnerID, status string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"runner_id":        runnerID,
		"lease_token":      task.LeaseToken,
		"lease_generation": task.LeaseGeneration,
		"status":           status,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestPostgresIntegrationServerCompletionRaceDifferingResults is Part 2a: two
// replicas complete the SAME lease with DIFFERENT results concurrently. The
// durable receipt arbitrates: exactly one 204 (the winner), the loser maps
// ErrCompletionConflict to 409, the job is terminal exactly once and usage is
// accounted exactly once.
func TestPostgresIntegrationServerCompletionRaceDifferingResults(t *testing.T) {
	dir := t.TempDir()
	env := pgITServerSetup(t)
	sA, st := pgITServerWithEnv(t, env, dir)
	pgITServerAwaitLeadership(t, sA)
	sB, _ := pgITServerWithEnv(t, env, dir)

	w := pgITDo(t, sA, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"race-runner","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2,"cost_per_hour":7200,"power_watts":500}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var runner model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &runner); err != nil {
		t.Fatal(err)
	}
	run := pgITSubmit(t, sA, pgITServerPipeline)
	task := pgITNext(t, sA, runner.ID)
	time.Sleep(20 * time.Millisecond) // non-zero billable duration

	successBody := crashPGCompleteBody(t, task, runner.ID, "success")
	failureBody := crashPGCompleteBody(t, task, runner.ID, "failure")
	start := make(chan struct{})
	results := make(chan crashPGRaceResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		w := pgITDo(t, sA, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", successBody, nil)
		results <- crashPGRaceResult{code: w.Code, body: w.Body.String()}
	}()
	go func() {
		defer wg.Done()
		<-start
		w := pgITDo(t, sB, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", failureBody, nil)
		results <- crashPGRaceResult{code: w.Code, body: w.Body.String()}
	}()
	close(start)
	wg.Wait()
	close(results)
	all := make([]crashPGRaceResult, 0, 2)
	for r := range results {
		all = append(all, r)
	}
	if got := crashPGCount(all, http.StatusNoContent); got != 1 {
		t.Fatalf("completion race = %+v, want exactly one 204 (single commit)", all)
	}
	if got := crashPGCount(all, http.StatusConflict); got != 1 {
		t.Fatalf("completion race = %+v, want exactly one 409 for the losing result", all)
	}

	ctx := context.Background()
	job, err := st.GetJob(ctx, task.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != model.StatusSuccess && job.Status != model.StatusFailure {
		t.Fatalf("job status = %s, want one terminal winner", job.Status)
	}
	if job.LeaseRunnerID != "" || job.LeaseExpiresAt != nil || job.LeaseTokenHash != nil {
		t.Fatalf("terminal winner kept lease state: %+v", job)
	}
	if !job.UsageRecorded || job.Cost <= 0 {
		t.Fatalf("winner did not account usage exactly once: %+v", job)
	}
	rec, ok, err := st.HasCompletionReceipt(ctx, job.ID, task.LeaseGeneration, runner.ID)
	if err != nil || !ok {
		t.Fatalf("durable receipt = %+v ok=%v err=%v", rec, ok, err)
	}
	wantHash := completionResultHash(job.Status, "", nil)
	if rec.ResultHash != wantHash {
		t.Fatalf("durable receipt hash = %q, want the winner's %q", rec.ResultHash, wantHash)
	}
	// The exactly-once usage transition is durable: a replayed effect loses.
	won, err := st.RecordUsageOnce(ctx, job.ID, 0, 0)
	if err != nil || won {
		t.Fatalf("second RecordUsageOnce = won=%v err=%v, want false/nil", won, err)
	}
	gotRun, err := st.GetRun(ctx, run.ID)
	if err != nil || gotRun.Status != job.Status {
		t.Fatalf("run = %+v err=%v, want status %s", gotRun, err, job.Status)
	}
}

// TestPostgresIntegrationServerWebhookEnqueueRace is Part 2b: two replicas
// enqueue the SAME webhook delivery concurrently. The in-transaction webhook
// claim admits exactly one run and both callers observe it idempotently.
func TestPostgresIntegrationServerWebhookEnqueueRace(t *testing.T) {
	dir := t.TempDir()
	env := pgITServerSetup(t)
	sA, st := pgITServerWithEnv(t, env, dir)
	pgITServerAwaitLeadership(t, sA)
	sB, _ := pgITServerWithEnv(t, env, dir)

	delivery := "race-delivery-" + pgITServerRandomHex(t, 10)
	in := SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc123", Event: "push",
		Pipeline: pgITServerPipeline,
		Metadata: map[string]string{"github_delivery": delivery},
	}
	type enqueueResult struct {
		run model.Run
		err error
	}
	start := make(chan struct{})
	results := make(chan enqueueResult, 2)
	var wg sync.WaitGroup
	for _, s := range []*Server{sA, sB} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			<-start
			r, err := s.enqueue(in)
			results <- enqueueResult{run: r, err: err}
		}(s)
	}
	close(start)
	wg.Wait()
	close(results)
	var ids []string
	for r := range results {
		if r.err != nil {
			t.Fatalf("concurrent webhook enqueue: %v", r.err)
		}
		ids = append(ids, r.run.ID)
	}
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("idempotent webhook enqueue returned different runs: %v", ids)
	}
	runs, err := st.ListRuns(context.Background(), 100)
	if err != nil || len(runs) != 1 {
		t.Fatalf("durable runs = %d err=%v, want exactly 1 (no ghost duplicate)", len(runs), err)
	}
	got, found, err := st.FindDelivery(context.Background(), "github", delivery)
	if err != nil || !found || got != ids[0] {
		t.Fatalf("delivery claim = %q found=%v err=%v, want %q", got, found, err, ids[0])
	}
}

// TestPostgresIntegrationServerReplicaForgeCheckConvergence is Part 2c's
// server-level convergence assertion: two replicas enqueue and flush the
// SAME versioned forge-check state concurrently; the versioned store and the
// per-check fence leave exactly one remote publication, and a stale
// re-enqueue after delivery publishes nothing.
func TestPostgresIntegrationServerReplicaForgeCheckConvergence(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	dir := t.TempDir()
	env := pgITServerSetup(t)
	sA, _ := pgITServerWithEnv(t, env, dir)
	pgITServerAwaitLeadership(t, sA)
	sB, _ := pgITServerWithEnv(t, env, dir)
	for _, s := range []*Server{sA, sB} {
		s.GitHubToken = "tok"
		s.gitHubAPIBase = srv.URL
	}

	run := model.Run{ID: "run-replica-check", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-replica", Status: model.StatusSuccess}
	itemA := sA.checkIntent(run, "Pipeline", "completed", "success", "done", nil)
	itemB := sB.checkIntent(run, "Pipeline", "completed", "success", "done", nil)
	if itemA.ID != itemB.ID || itemA.LogicalKey == "" || itemA.StateVersion != itemB.StateVersion {
		t.Fatalf("deterministic check identity diverged: %+v vs %+v", itemA, itemB)
	}

	// Concurrent versioned enqueue of the same row.
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, pair := range []struct {
		s  *Server
		it forge.OutboxItem
	}{{sA, itemA}, {sB, itemB}} {
		wg.Add(1)
		go func(s *Server, it forge.OutboxItem) {
			defer wg.Done()
			<-start
			errs <- s.outbox.Enqueue(it)
		}(pair.s, pair.it)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent versioned enqueue: %v", err)
		}
	}
	ctx := context.Background()
	outboxStore, ok := sA.DB.(storage.OutboxStore)
	if !ok {
		t.Fatal("store lacks the outbox contract")
	}
	pending, err := outboxStore.OutboxPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != itemA.ID {
		t.Fatalf("pending rows after concurrent enqueue = %+v, want the one newest row", pending)
	}

	// Concurrent flush from both replicas: the claim lease admits one, so the
	// remote sees exactly one publication.
	start = make(chan struct{})
	errs = make(chan error, 2)
	for _, s := range []*Server{sA, sB} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			<-start
			_, ferr := s.outbox.Flush(ctx, s.dispatchOutbox)
			errs <- ferr
		}(s)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent flush: %v", err)
		}
	}
	posts, patches, published := api.snapshot()
	if posts != 1 || patches != 0 {
		t.Fatalf("remote publications = posts=%d patches=%d, want exactly one POST", posts, patches)
	}
	if len(published) != 1 || published[0] != "completed" {
		t.Fatalf("published states = %v, want [completed]", published)
	}

	// A stale equal-version re-enqueue after delivery is refused by the
	// durable watermark: no second publication.
	if err := sA.outbox.Enqueue(itemA); err != nil {
		t.Fatalf("stale re-enqueue: %v", err)
	}
	sA.flushOutbox()
	if posts, patches, _ := api.snapshot(); posts != 1 || patches != 0 {
		t.Fatalf("stale re-enqueue republished: posts=%d patches=%d", posts, patches)
	}
}

// TestPostgresIntegrationServerCancelHeartbeatRace is Part 2d: one replica
// cancels a run while the other heartbeats its running job. Whichever order
// commits, the cancelled job must never keep an extended lease: the heartbeat
// either loses the status='running' guard (409) or is superseded by the
// cancellation's lease clear, and both replicas converge on one cancelled
// terminal state with the runner slot released.
func TestPostgresIntegrationServerCancelHeartbeatRace(t *testing.T) {
	dir := t.TempDir()
	env := pgITServerSetup(t)
	sA, st := pgITServerWithEnv(t, env, dir)
	pgITServerAwaitLeadership(t, sA)
	sB, _ := pgITServerWithEnv(t, env, dir)
	runnerID := pgITRegisterRunner(t, sA)

	ctx := context.Background()
	for iter := 0; iter < 3; iter++ {
		run := pgITSubmit(t, sA, pgITServerPipeline)
		task := pgITNext(t, sA, runnerID)

		start := make(chan struct{})
		cancelCh := make(chan crashPGRaceResult, 1)
		heartbeatCh := make(chan crashPGRaceResult, 1)
		go func() {
			<-start
			w := pgITDo(t, sB, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", "", nil)
			cancelCh <- crashPGRaceResult{code: w.Code, body: w.Body.String()}
		}()
		go func() {
			<-start
			w := pgITDo(t, sA, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token", pgITLeaseBody(task, runnerID), nil)
			heartbeatCh <- crashPGRaceResult{code: w.Code, body: w.Body.String()}
		}()
		close(start)
		cancel := <-cancelCh
		heartbeat := <-heartbeatCh

		if cancel.code != http.StatusOK {
			t.Fatalf("iteration %d: cancel = %d %s", iter, cancel.code, cancel.body)
		}
		if heartbeat.code != http.StatusOK && heartbeat.code != http.StatusConflict {
			t.Fatalf("iteration %d: heartbeat = %d %s, want 200 (cancelled report) or 409 (lost lease)", iter, heartbeat.code, heartbeat.body)
		}
		if heartbeat.code == http.StatusOK {
			var resp HeartbeatResponse
			if err := json.Unmarshal([]byte(heartbeat.body), &resp); err != nil {
				t.Fatalf("iteration %d: decode heartbeat: %v", iter, err)
			}
		}

		job, err := st.GetJob(ctx, task.Job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status != model.StatusCancelled {
			t.Fatalf("iteration %d: job status = %s, want cancelled", iter, job.Status)
		}
		if job.LeaseRunnerID != "" || job.LeaseExpiresAt != nil || job.LeaseTokenHash != nil {
			t.Fatalf("iteration %d: cancelled job kept an extended lease: %+v", iter, job)
		}
		gotRun, err := st.GetRun(ctx, run.ID)
		if err != nil || gotRun.Status != model.StatusCancelled {
			t.Fatalf("iteration %d: run = %+v err=%v, want cancelled", iter, gotRun, err)
		}
		ri, err := st.GetRunner(ctx, runnerID)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ri.ActiveJobs {
			if id == task.Job.ID {
				t.Fatalf("iteration %d: cancelled job still holds the runner slot: %+v", iter, ri.ActiveJobs)
			}
		}
	}
}
