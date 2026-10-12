package dist_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// chaosPipeline is the two-job workload the DF3 chaos drill drives. Both
// jobs are independent so the drill can always lease one, complete it, and
// hold the other's lease across the kill.
const chaosPipeline = `version: 1
jobs:
  alpha:
    runtime: container
    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
    network: none
    steps:
      - run: echo alpha
  beta:
    runtime: container
    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
    network: none
    steps:
      - run: echo beta
`

// TestSysDFChaos001Integration is the DF3 chaos proof: a real `kiwi server` OS process
// is hard-killed (SIGKILL) while work is mid-flight — one job already
// completed, one job leased and NOT completed — and then restarted on the
// SAME PostgreSQL database and data directory. It asserts the three chaos
// contracts:
//
//   - no double completion: the pre-kill terminal job keeps exactly one
//     terminal state — an identical completion replay is idempotent, a
//     conflicting second completion is refused, and neither mutates the job;
//   - liveness: work continues — the surviving (unexpired) lease completes
//     after the restart, and fresh work submitted afterwards also completes;
//   - stale state safety: a completion under a stale lease generation is
//     refused and mutates nothing.
//
// The workload is driven over the real product HTTP API (register / next /
// complete) via system.Attach against the spawned process, so every
// assertion lands on the same handler → authorization → store path a
// production runner uses. This is the kill-around-transitions arm of
// DF-CHAOS-001 at the process level (control-plane SIGKILL, not a graceful
// stop).
func TestSysDFChaos001Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("dist dogfood builds real binaries and starts real PostgreSQL")
	}
	root := t.TempDir()
	bin := buildKiwi(t, root)
	pgDSN, _ := startPostgres(t)

	serverPort := freeTCPPort(t)
	listen := fmt.Sprintf("127.0.0.1:%d", serverPort)
	serverURL := fmt.Sprintf("http://%s", listen)
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const runnerToken = "chaos-runner-token"
	const adminToken = "chaos-admin-token"
	srv := spawnServer(t, bin, listen, dataDir, pgDSN, runnerToken, adminToken)
	waitFor(t, "server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// Client-only handle against the real server process. Everything below
	// is real HTTP on the product surface.
	sys, err := system.Attach(serverURL, adminToken, runnerToken, filepath.Join(root, "work"))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	runnerID, err := sys.RegisterRunner(ctx, "chaos-holder", []string{"native", "container"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	runID, err := sys.SubmitPipeline(ctx, chaosPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// --- Before the kill: one completed job, one leased mid-flight job. ---
	task1 := leaseOne(t, ctx, sys, runnerID)
	code, err := sys.Complete(ctx, task1, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("pre-kill complete transport: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("pre-kill complete = HTTP %d, want 204", code)
	}
	j1Before, err := sys.JobByKey(ctx, runID, task1.JobKey)
	if err != nil {
		t.Fatalf("job %q before kill: %v", task1.JobKey, err)
	}
	if j1Before.Status != model.StatusSuccess {
		t.Fatalf("pre-kill job status = %s, want success", j1Before.Status)
	}
	if j1Before.AttemptRunnerID != runnerID {
		t.Fatalf("pre-kill attempt runner = %q, want %q", j1Before.AttemptRunnerID, runnerID)
	}
	// Lease the second job and hold it: this is the mid-flight state the
	// kill lands in (leased, running, not completed).
	task2 := leaseOne(t, ctx, sys, runnerID)
	if task2.JobID == task1.JobID {
		t.Fatal("leased the already-completed job twice")
	}
	j2Before, err := sys.JobByKey(ctx, runID, task2.JobKey)
	if err != nil {
		t.Fatalf("job %q before kill: %v", task2.JobKey, err)
	}
	if j2Before.Status.Terminal() {
		t.Fatalf("mid-flight job is already terminal: %s", j2Before.Status)
	}

	// --- CHAOS: SIGKILL the control plane mid-flight. ---
	srv.killNow()

	// --- Restart on the SAME database and data directory (same listen
	// address, so the same client keeps talking to "the server"). ---
	srv2 := spawnServer(t, bin, listen, dataDir, pgDSN, runnerToken, adminToken)
	_ = srv2
	waitFor(t, "restarted server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// --- Safety: stale state must be refused and must not mutate. ---
	stale := task2
	stale.LeaseGeneration = task2.LeaseGeneration + 99
	code, err = sys.Complete(ctx, stale, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("stale complete transport: %v", err)
	}
	if code != http.StatusConflict {
		t.Fatalf("stale complete after restart = HTTP %d, want 409", code)
	}
	j2AfterStale, err := sys.JobByKey(ctx, runID, task2.JobKey)
	if err != nil {
		t.Fatalf("job %q after stale complete: %v", task2.JobKey, err)
	}
	if j2AfterStale.Status.Terminal() {
		t.Fatalf("stale completion mutated job %q to %s", task2.JobKey, j2AfterStale.Status)
	}
	if j2AfterStale.Status != j2Before.Status {
		t.Fatalf("stale completion changed job status %s -> %s", j2Before.Status, j2AfterStale.Status)
	}

	// --- No double completion: the pre-kill terminal job keeps exactly one
	// terminal state. ---
	// (a) An identical replay of the pre-kill completion is idempotent.
	code, err = sys.Complete(ctx, task1, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("replay complete transport: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("identical completion replay = HTTP %d, want 204 (idempotent)", code)
	}
	// (b) A conflicting second completion (same identity, different result)
	// must be refused — the terminal state is monotonic.
	code, err = sys.Complete(ctx, task1, model.StatusFailure, "chaos conflicting second completion")
	if err != nil {
		t.Fatalf("conflict complete transport: %v", err)
	}
	if code == http.StatusNoContent {
		t.Fatalf("conflicting completion of a terminal job was acknowledged (HTTP 204)")
	}
	if code != http.StatusConflict {
		t.Fatalf("conflicting completion = HTTP %d, want 409", code)
	}
	// (c) Neither replay nor conflict moved the job.
	j1After, err := sys.JobByKey(ctx, runID, task1.JobKey)
	if err != nil {
		t.Fatalf("job %q after replay attempts: %v", task1.JobKey, err)
	}
	if j1After.Status != j1Before.Status || j1After.Status != model.StatusSuccess {
		t.Fatalf("double completion moved job %q: %s -> %s", task1.JobKey, j1Before.Status, j1After.Status)
	}
	if j1After.AttemptRunnerID != j1Before.AttemptRunnerID {
		t.Fatalf("double completion restamped attempt runner: %q -> %q", j1Before.AttemptRunnerID, j1After.AttemptRunnerID)
	}
	if j1After.Error != j1Before.Error {
		t.Fatalf("double completion changed job error: %q -> %q", j1Before.Error, j1After.Error)
	}

	// --- Liveness: work continues. ---
	// (a) The mid-flight lease (unexpired leases survive the restart) still
	// completes.
	code, err = sys.Complete(ctx, task2, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("post-restart complete transport: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("surviving-lease complete = HTTP %d, want 204", code)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, task2.JobKey)
	if err != nil {
		t.Fatalf("wait mid-flight job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, task2.JobKey)
		t.Fatalf("mid-flight job finished %s error=%q, want success", status, j.Error)
	}
	// (b) Fresh work submitted after the restart also runs to completion.
	run2ID, err := sys.SubmitPipeline(ctx, chaosPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit after restart: %v", err)
	}
	task3 := leaseOne(t, ctx, sys, runnerID)
	code, err = sys.Complete(ctx, task3, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("post-restart fresh complete transport: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("post-restart fresh complete = HTTP %d, want 204", code)
	}
	status, err = sys.WaitJobTerminal(ctx, run2ID, task3.JobKey)
	if err != nil {
		t.Fatalf("wait fresh job: %v", err)
	}
	if status != model.StatusSuccess {
		t.Fatalf("fresh post-restart job finished %s, want success", status)
	}

	// Both original jobs are terminal success: the run as a whole survived
	// the kill without a double completion or lost work.
	run, err := sys.QueryRun(ctx, runID)
	if err != nil {
		t.Fatalf("query run: %v", err)
	}
	if run.Status != model.StatusSuccess {
		t.Fatalf("run status after chaos = %s, want success", run.Status)
	}
}

// leaseOne polls the product next endpoint until one task is leased.
func leaseOne(t *testing.T, ctx context.Context, sys *system.System, runnerID string) system.LeaseTask {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		task, ok, err := sys.Next(ctx, runnerID)
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if ok {
			return task
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done waiting for a lease: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("no task was leased within the deadline")
	return system.LeaseTask{}
}
