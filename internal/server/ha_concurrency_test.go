package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// HAC-1: the two-replica concurrency suite. Two Server instances share one
// DB-fake store, one CAS backend and (as in production, where the lease key
// lives in dataDir) one lease HMAC key. Every test exercises one concurrent
// protocol and asserts the shared invariant: at most one running lease per
// job, no duplicate artifacts, no duplicate fragment children, no duplicate
// outbox dispatch, no double accounting.

type haCluster struct {
	f   *dbFakeStore
	s   [2]*Server
	cas *cas.CAS
}

func newHACluster(t *testing.T) *haCluster {
	t.Helper()
	f := newDBFakeStore()
	bs := blob.NewFS(t.TempDir())
	c := &haCluster{f: f, cas: cas.New(bs)}
	for i := 0; i < 2; i++ {
		s, err := NewPersistent("token", "token", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s.SetBlobStore(bs)
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		c.s[i] = s
	}
	c.s[1].leaseKey = c.s[0].leaseKey
	return c
}

// registerRunner registers a container runner with the given capacity
// through replica 0's HTTP surface.
func haRegisterRunner(t *testing.T, s *Server, capacity int) model.Runner {
	t.Helper()
	body := fmt.Sprintf(`{"name":"ha-runner","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":%d}`, capacity)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", body)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	return ri
}

// submitHAPipeline enqueues one trusted run through the same admission path
// the webhook handlers use (the HTTP surface deliberately never accepts the
// trusted flag from clients).
func submitHAPipeline(t *testing.T, s *Server, pipelineText string) model.Run {
	t.Helper()
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: pipelineText, Trusted: true,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return run
}

// race runs fn on both replicas behind a start barrier and returns the
// response codes.
func (c *haCluster) race(t *testing.T, fn func(s *Server) int) []int {
	t.Helper()
	start := make(chan struct{})
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		s := c.s[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- fn(s)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	out := make([]int, 0, 2)
	for code := range results {
		out = append(out, code)
	}
	return out
}

func countCodes(codes []int, want int) int {
	n := 0
	for _, c := range codes {
		if c == want {
			n++
		}
	}
	return n
}

// TestHAConcurrentLeaseClaimOneWinner: two replicas poll for the same queued
// job at once; the atomic claim admits exactly one running lease.
func TestHAConcurrentLeaseClaimOneWinner(t *testing.T) {
	c := newHACluster(t)
	ri := haRegisterRunner(t, c.s[0], 1)
	run := submitHAPipeline(t, c.s[0], testPipeline)
	codes := c.race(t, func(s *Server) int {
		return doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "").Code
	})
	if countCodes(codes, http.StatusOK) != 1 || countCodes(codes, http.StatusNoContent) != 1 {
		t.Fatalf("lease race codes = %v, want exactly one 200 and one 204", codes)
	}
	running := runningJobsInRun(t, c.f, run.ID)
	if len(running) != 1 {
		t.Fatalf("running jobs = %d, want exactly 1", len(running))
	}
	if running[0].LeaseGeneration != 1 || running[0].LeaseRunnerID != ri.ID {
		t.Fatalf("lease = runner %s gen %d", running[0].LeaseRunnerID, running[0].LeaseGeneration)
	}
	c.f.mu.Lock()
	active := len(c.f.runners[ri.ID].ActiveJobs)
	c.f.mu.Unlock()
	if active != 1 {
		t.Fatalf("runner active jobs = %d, want 1", active)
	}
}

// TestHAConcurrentArtifactRace: two replicas upload the same artifact name
// for one lease generation at once; the unique key admits exactly one record.
func TestHAConcurrentArtifactRace(t *testing.T) {
	s1, s2, f, runnerID, task := artifactRaceReplicas(t)
	path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
	hdrs := leaseHeaders(task, runnerID)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	start := make(chan struct{})
	for _, s := range []*Server{s1, s2} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			<-start
			codes <- doJSONHeaders(t, s, http.MethodPut, path, "token", "same-bytes", hdrs).Code
		}(s)
	}
	close(start)
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for code := range codes {
		got[code]++
	}
	if got[http.StatusCreated] != 1 || got[http.StatusOK] != 1 {
		t.Fatalf("artifact race codes = %v, want one 201 and one 200", got)
	}
	f.mu.Lock()
	rows := len(f.artifacts)
	f.mu.Unlock()
	if rows != 1 {
		t.Fatalf("artifact rows = %d, want 1", rows)
	}
}

// TestHAConcurrentFragmentUploadIdempotent: two replicas upload the SAME
// fragment (same deterministic fragment_id) at once; exactly one fragment
// commits and both callers observe the same child.
func TestHAConcurrentFragmentUploadIdempotent(t *testing.T) {
	c := newHACluster(t)
	for i := 0; i < 2; i++ {
		c.s[i].Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {GenerateChildGraph: boolPtr(true)}}}
	}
	ri := haRegisterRunner(t, c.s[0], 2)
	run := submitHAPipeline(t, c.s[0], generatePipeline)
	w := doJSON(t, c.s[0], http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	body := fragmentBody(t, replayFragmentA)
	hdrs := leaseHeaders(task, ri.ID)
	start := make(chan struct{})
	results := make(chan haFragmentResult, 2)
	var wg sync.WaitGroup
	for _, s := range []*Server{c.s[0], c.s[1]} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			<-start
			w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", body, hdrs)
			results <- haFragmentResult{code: w.Code, body: w.Body.String()}
		}(s)
	}
	close(start)
	wg.Wait()
	close(results)
	all := []haFragmentResult{}
	for r := range results {
		all = append(all, r)
	}
	if len(all) != 2 {
		t.Fatalf("results = %d", len(all))
	}
	if countFragCode(all, http.StatusCreated) != 1 || countFragCode(all, http.StatusOK) != 1 {
		t.Fatalf("fragment race codes = %v, want one 201 and one 200", all)
	}
	var ids []string
	for _, r := range all {
		var res generatedResponse
		if err := json.Unmarshal([]byte(r.body), &res); err != nil {
			t.Fatalf("decode %q: %v", r.body, err)
		}
		if len(res.JobIDs) != 1 {
			t.Fatalf("response children = %v", res.JobIDs)
		}
		ids = append(ids, res.JobIDs[0])
	}
	if ids[0] != ids[1] {
		t.Fatalf("replicas observed different children: %v", ids)
	}
	children := dynamicChildren(t, c.f, run.ID)
	if len(children) != 1 {
		t.Fatalf("child jobs = %d, want exactly 1 (no duplicate fragment)", len(children))
	}
	if children[0].ID != ids[0] {
		t.Fatalf("stored child %s = %s, responses = %v", children[0].Key, children[0].ID, ids)
	}
}

// haFragmentResult is one fragment upload response captured by a racing
// replica.
type haFragmentResult struct {
	code int
	body string
}

func countFragCode(results []haFragmentResult, want int) int {
	n := 0
	for _, r := range results {
		if r.code == want {
			n++
		}
	}
	return n
}

// TestHAConcurrentOutboxFlushDisjoint: two replicas flush one durable outbox
// concurrently; the claims partition the rows and every intent is dispatched
// exactly once.
func TestHAConcurrentOutboxFlushDisjoint(t *testing.T) {
	c := newHACluster(t)
	d := newOutboxDispatcher()
	const items = 10
	ids := make([]string, 0, items)
	for i := 0; i < items; i++ {
		it := forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{}`)}
		if err := c.s[0].outbox.Enqueue(context.Background(), it); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.s[0].outbox.Pending()[i].ID)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			<-start
			if _, err := s.outbox.Flush(context.Background(), d.dispatch); err != nil {
				t.Errorf("flush: %v", err)
			}
		}(c.s[i])
	}
	close(start)
	wg.Wait()
	for _, id := range ids {
		if got := d.count(id); got != 1 {
			t.Fatalf("intent %s dispatched %d times, want exactly 1", id, got)
		}
	}
	if d.total() != items {
		t.Fatalf("dispatched %d intents, want %d", d.total(), items)
	}
	c.f.mu.Lock()
	remaining := len(c.f.outboxItems)
	c.f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("durable outbox rows after race = %d, want 0", remaining)
	}
}

// TestHACancelVersusCompleteNoDoubleEffects: cancel and complete race on one
// leased job. Whichever wins, the job ends terminal exactly once, the runner
// slot is released once, at most one completion receipt exists and the
// completion effect intents are all-or-nothing (never duplicated).
func TestHACancelVersusCompleteNoDoubleEffects(t *testing.T) {
	for iter := 0; iter < 8; iter++ {
		t.Run(fmt.Sprintf("iter-%d", iter), func(t *testing.T) {
			c := newHACluster(t)
			ri := haRegisterRunner(t, c.s[0], 1)
			run := submitHAPipeline(t, c.s[0], testPipeline)
			w := doJSON(t, c.s[0], http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
			if w.Code != http.StatusOK {
				t.Fatalf("next: %d %s", w.Code, w.Body.String())
			}
			var task Task
			if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
				t.Fatal(err)
			}
			hdrs := leaseHeaders(task, ri.ID)
			completeBody := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":%d,"status":"success"}`, ri.ID, task.LeaseToken, task.LeaseGeneration)
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				doJSON(t, c.s[0], http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", "")
			}()
			go func() {
				defer wg.Done()
				<-start
				doJSONHeaders(t, c.s[1], http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", completeBody, hdrs)
			}()
			close(start)
			wg.Wait()

			c.f.mu.Lock()
			j := c.f.jobs[task.Job.ID]
			r := c.f.runners[ri.ID]
			receipts := 0
			for key := range c.f.receipts {
				if len(key) > len(task.Job.ID) && key[:len(task.Job.ID)] == task.Job.ID {
					receipts++
				}
			}
			effects := 0
			for _, it := range c.f.outboxItems {
				if isCompletionEffectKind(it.Kind) {
					effects++
				}
			}
			storedRun := c.f.runs[run.ID]
			c.f.mu.Unlock()

			if !j.Status.Terminal() {
				t.Fatalf("job status = %s, want terminal", j.Status)
			}
			if len(r.ActiveJobs) != 0 || r.Busy {
				t.Fatalf("runner slot not released exactly once: active=%v busy=%v", r.ActiveJobs, r.Busy)
			}
			if receipts > 1 {
				t.Fatalf("completion receipts = %d, want at most 1", receipts)
			}
			if j.Status == model.StatusSuccess {
				// Usage accounting is applied by the completion effect pass,
				// not inside CompleteJob; only the runner counter is a
				// completion-transaction side effect.
				if r.Completed != 1 {
					t.Fatalf("runner completed = %d, want exactly 1", r.Completed)
				}
				if effects != 0 && effects != storage.CompletionEffectIntentCount {
					t.Fatalf("completion effect intents = %d, want 0 or %d (all-or-nothing)", effects, storage.CompletionEffectIntentCount)
				}
			} else {
				if r.Completed != 0 {
					t.Fatalf("runner completed = %d, want 0 for a cancelled job", r.Completed)
				}
				if effects != 0 {
					t.Fatalf("cancelled job left %d completion effect intents", effects)
				}
			}
			if !storedRun.Status.Terminal() {
				t.Fatalf("run status = %s, want terminal after cancel", storedRun.Status)
			}
		})
	}
}

func isCompletionEffectKind(kind string) bool {
	return storage.IsCompletionEffectKind(kind)
}

// TestHAEnvironmentConcurrencyOneWinner: two queued jobs share a
// (repo, environment) concurrency slot of 1; concurrent polls across
// replicas admit exactly one.
func TestHAEnvironmentConcurrencyOneWinner(t *testing.T) {
	const envPipeline = `version: 1
jobs:
  a:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    environment:
      name: production
      concurrency: 1
    steps:
      - run: echo a
  b:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    environment:
      name: production
      concurrency: 1
    steps:
      - run: echo b
`
	for iter := 0; iter < 4; iter++ {
		t.Run(fmt.Sprintf("iter-%d", iter), func(t *testing.T) {
			c := newHACluster(t)
			envCaps := policy.DefaultTrustedCapabilities()
			envCaps.Deployments = true
			for i := 0; i < 2; i++ {
				c.s[i].AdmissionCapabilities = &envCaps
			}
			ri := haRegisterRunner(t, c.s[0], 2)
			run := submitHAPipeline(t, c.s[0], envPipeline)
			codes := c.race(t, func(s *Server) int {
				return doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "").Code
			})
			if countCodes(codes, http.StatusOK) != 1 {
				t.Fatalf("environment race codes = %v, want exactly one lease", codes)
			}
			running := runningJobsInRun(t, c.f, run.ID)
			if len(running) != 1 {
				t.Fatalf("running jobs in environment = %d, want 1", len(running))
			}
			if running[0].Environment != "production" || running[0].EnvironmentConcurrency != 1 {
				t.Fatalf("leased job environment = %q/%d", running[0].Environment, running[0].EnvironmentConcurrency)
			}
		})
	}
}

// TestHACompletionEffectsConvergeAcrossReplicas: the completion commits on
// replica 0 (durable receipt + in-transaction effect intents) but the process
// dies before any effect runs. Replica 1 then replays the outbox and applies
// every effect; replica 0's later receipt replay must not double-account. The
// downstream link, deployment finish and usage marker converge to exactly one
// application each.
func TestHACompletionEffectsConvergeAcrossReplicas(t *testing.T) {
	c := newHACluster(t)
	for i := 0; i < 2; i++ {
		grantEffectsCapabilities(c.s[i])
		c.s[i].DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
		c.s[i].DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
			return childPipeline, nil
		}
	}
	ri := haRegisterRunner(t, c.s[0], 1)
	// Give the runner a usage rate so the usage effect is observable.
	c.f.mu.Lock()
	r := c.f.runners[ri.ID]
	r.CostPerHour = 10
	r.PowerWatts = 25
	c.f.runners[ri.ID] = r
	c.f.mu.Unlock()
	submitHAPipeline(t, c.s[0], effectsPipeline)
	w := doJSON(t, c.s[0], http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	// Replica 0's completion transaction commits; the effect pass is "lost"
	// (the replica crashes before running it). The store-level completion is
	// exactly what CompleteJob did before the HTTP handler would reconcile.
	hash := completionResultHash(model.StatusSuccess, "", nil)
	if err := c.s[0].Sched.Complete(context.Background(), task.Job.ID, task.LeaseGeneration, ri.ID, model.StatusSuccess, "", nil, hash); err != nil {
		t.Fatalf("store completion: %v", err)
	}
	c.f.mu.Lock()
	j := c.f.jobs[task.Job.ID]
	effectsQueued := 0
	for _, it := range c.f.outboxItems {
		if isCompletionEffectKind(it.Kind) {
			effectsQueued++
		}
	}
	c.f.mu.Unlock()
	if j.UsageRecorded {
		t.Fatal("usage recorded before any effect pass ran")
	}
	if effectsQueued != storage.CompletionEffectIntentCount {
		t.Fatalf("effect intents = %d, want %d committed with the completion", effectsQueued, storage.CompletionEffectIntentCount)
	}
	// Replica 1 restart-replays the durable outbox and runs the effects.
	if err := c.s[1].outbox.ReplayDB(context.Background()); err != nil {
		t.Fatalf("replay db: %v", err)
	}
	c.s[1].flushOutbox(context.Background())
	c.f.mu.Lock()
	j = c.f.jobs[task.Job.ID]
	_, hasLink := c.f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	remaining := len(c.f.outboxItems)
	c.f.mu.Unlock()
	// EITHER replica may win the usage accounting (both are allowed to
	// flush the same durable outbox); exactly-once accounting is the
	// invariant, not which replica performs it. Cost itself depends on the
	// completion's wall-clock duration (which can be ~0 in a fast test), so
	// assert the durable markers and the frozen rates instead.
	if !j.UsageRecorded {
		t.Fatalf("usage not accounted after replica-1 flush: %+v", j)
	}
	if j.CostRate <= 0 || j.PowerWatts <= 0 {
		t.Fatalf("lease-time usage rates not frozen on the job: cost_rate=%v power_watts=%v", j.CostRate, j.PowerWatts)
	}
	if !hasLink {
		t.Fatal("replica-1 flush did not record the downstream link")
	}
	if d := deploymentOfJob(t, c.f, task.Job.ID); d.FinishedAt == nil {
		t.Fatal("replica-1 flush did not finish the deployment")
	}
	if remaining != 0 {
		t.Fatalf("outbox rows after flush = %d, want 0", remaining)
	}
	// EITHER replica may win the usage accounting (whichever flushes the
	// durable outbox first); the invariant is exactly one accounting across
	// the pair, not which counter moved.
	usageTotal := func() float64 {
		return c.s[0].Metrics.counters["kiwi_usage_cost_total"][""] +
			c.s[1].Metrics.counters["kiwi_usage_cost_total"][""]
	}
	cost := usageTotal()
	if cost <= 0 {
		t.Fatalf("no replica accounted usage (total = %v)", cost)
	}
	// Replica 0's receipt replay reconciles again: convergence, not double
	// accounting. The pair's usage counter must not move and no new
	// downstream intent may appear.
	body := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":%d,"status":"success"}`, ri.ID, task.LeaseToken, task.LeaseGeneration)
	if w := doJSONHeaders(t, c.s[0], http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", body, leaseHeaders(task, ri.ID)); w.Code != http.StatusNoContent {
		t.Fatalf("receipt replay = %d: %s", w.Code, w.Body.String())
	}
	if got := usageTotal(); got != cost {
		t.Fatalf("receipt replay double-accounted usage: total %v -> %v", cost, got)
	}
	// The replay REPAIRS the downstream intent if its durable row is absent
	// (the crash window this effect exists for) and is a no-op when the row
	// is present. The invariant is exactly one durable row, not zero.
	if n := downstreamIntentsQueued(c.f); n > 1 {
		t.Fatalf("replica-0 replay created %d downstream intents, want ≤1", n)
	}
	if n := downstreamIntentsQueued(c.f); n == 1 {
		// A repair must have used the stored link's token and stable ID.
		f := c.f
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, it := range f.outboxItems {
			if it.Kind == forge.OutboxKindDownstream && !strings.Contains(string(it.Payload), `"launch_token"`) {
				t.Fatal("repaired downstream intent lacks its launch token")
			}
		}
	}
}

// runningJobsInRun returns the run's running jobs (the "at most one running
// lease per job" invariant checker).
func runningJobsInRun(t *testing.T, f *dbFakeStore, runID string) []model.Job {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Job{}
	leases := map[string]int{}
	for _, j := range f.jobs {
		if j.RunID != runID || j.Status != model.StatusRunning {
			continue
		}
		if j.LeaseGeneration > 0 {
			leases[j.ID]++
		}
		out = append(out, j)
	}
	for id, n := range leases {
		if n > 1 {
			t.Fatalf("job %s holds %d running leases", id, n)
		}
	}
	return out
}

// dynamicChildren returns the run's generated (dynamic) child jobs.
func dynamicChildren(t *testing.T, f *dbFakeStore, runID string) []model.Job {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []model.Job{}
	for _, j := range f.jobs {
		if j.RunID == runID && j.DynamicDepth > 0 {
			out = append(out, j)
		}
	}
	return out
}
