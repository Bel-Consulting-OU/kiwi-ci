package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// dropResponseWithoutWriting hijacks the connection and closes it without
// writing a single response byte. The handler's side effects are already
// durable; the client sees a transport error. This is the dropped-
// acknowledgement boundary every retry contract in this file must survive.
func dropResponseWithoutWriting(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

// jobIDFromPath extracts {id} from a /api/v1/jobs/{id}/... control-plane
// path (plain handlers have no ServeMux wildcards).
func jobIDFromPath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, part := range parts {
		if part == "jobs" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// batchDeliveryAttempt is one /log/batch request as the stub control plane
// observed it.
type batchDeliveryAttempt struct {
	JobID      string
	RunnerID   string
	Token      string
	Generation int64
	BatchID    string
	Sequence   int64
	Lines      []string
}

// droppedBatchControlPlane commits the first delivery of every batch
// identity to a receipt store keyed by (job, generation, batch_id) and then
// kills the response, so the runner only learns of the commit through its
// retry. Duplicate deliveries of a committed identity answer 204 without
// appending again.
type droppedBatchControlPlane struct {
	mu       sync.Mutex
	attempts []batchDeliveryAttempt
	store    map[string]map[string][]string
}

func newDroppedBatchControlPlane() *droppedBatchControlPlane {
	return &droppedBatchControlPlane{store: map[string]map[string][]string{}}
}

func (s *droppedBatchControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jobID := jobIDFromPath(r.URL.Path)
	var body struct {
		RunnerID        string           `json:"runner_id"`
		LeaseToken      string           `json:"lease_token"`
		LeaseGeneration int64            `json:"lease_generation"`
		BatchID         string           `json:"batch_id"`
		BatchSequence   int64            `json:"batch_sequence"`
		Lines           []server.LogLine `json:"lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	lines := make([]string, 0, len(body.Lines))
	for _, l := range body.Lines {
		lines = append(lines, l.Step+": "+l.Line)
	}
	key := jobID + "\x00" + strconv.FormatInt(body.LeaseGeneration, 10)
	s.mu.Lock()
	s.attempts = append(s.attempts, batchDeliveryAttempt{
		JobID: jobID, RunnerID: body.RunnerID, Token: body.LeaseToken,
		Generation: body.LeaseGeneration, BatchID: body.BatchID,
		Sequence: body.BatchSequence, Lines: lines,
	})
	batches := s.store[key]
	if batches == nil {
		batches = map[string][]string{}
		s.store[key] = batches
	}
	if _, committed := batches[body.BatchID]; committed {
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	batches[body.BatchID] = lines
	s.mu.Unlock()
	// First delivery of this identity: the commit above is durable, the
	// acknowledgement is not.
	dropResponseWithoutWriting(w)
}

func (s *droppedBatchControlPlane) snapshot() ([]batchDeliveryAttempt, map[string]map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempts := append([]batchDeliveryAttempt(nil), s.attempts...)
	store := map[string]map[string][]string{}
	for key, batches := range s.store {
		copied := map[string][]string{}
		for id, lines := range batches {
			copied[id] = append([]string(nil), lines...)
		}
		store[key] = copied
	}
	return attempts, store
}

func countCommittedBatches(store map[string]map[string][]string) int {
	n := 0
	for _, batches := range store {
		n += len(batches)
	}
	return n
}

func flattenCommittedLines(store map[string]map[string][]string) []string {
	var out []string
	for _, batches := range store {
		for _, lines := range batches {
			out = append(out, lines...)
		}
	}
	sort.Strings(out)
	return out
}

// TestLogBatchDroppedConnectionCommitsExactlyOnce is the dropped-response
// regression for log delivery: the stub control plane commits the first
// delivery of each batch and then kills the connection without a response,
// so the runner's asyncLogSink retry loop (not just the delivery callback)
// must retry with the identical batch_id and sequence. The (job, generation,
// batch_id) receipt store must end up with exactly one copy of every line,
// and two batches carrying identical payloads must still get distinct
// identities because their sequences differ.
func TestLogBatchDroppedConnectionCommitsExactlyOnce(t *testing.T) {
	cp := newDroppedBatchControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)
	sink := newAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}))

	sink.WriteLine("build", "step", "line-1")
	waitUntil(t, 15*time.Second, "the dropped first delivery and its retry", func() bool {
		attempts, _ := cp.snapshot()
		return len(attempts) >= 2
	})

	// The identical payload in a NEW batch must still get a distinct
	// identity: only the sequence differs.
	sink.WriteLine("build", "step", "line-1")
	waitUntil(t, 15*time.Second, "the second batch commit", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) >= 2
	})

	out := sink.Finish(15 * time.Second)
	if out.Err != nil || out.Dropped != 0 || out.Remaining != 0 || !out.Stopped {
		t.Fatalf("delivery outcome = %+v, want a clean stop", out)
	}

	attempts, store := cp.snapshot()
	if len(store) != 1 {
		t.Fatalf("receipt store has %d (job, generation) keys, want 1", len(store))
	}
	byBatch := map[string][]batchDeliveryAttempt{}
	for _, a := range attempts {
		if a.JobID != "job-1" || a.RunnerID != "runner-1" || a.Token != "lease-token" || a.Generation != 3 {
			t.Fatalf("attempt carried the wrong delivery identity: %+v", a)
		}
		if a.BatchID == "" {
			t.Fatal("a batch attempt carried an empty batch_id")
		}
		byBatch[a.BatchID] = append(byBatch[a.BatchID], a)
	}
	if len(byBatch) != 2 {
		t.Fatalf("server saw %d distinct batch ids, want 2: %v", len(byBatch), byBatch)
	}
	for id, as := range byBatch {
		if len(as) < 2 {
			t.Fatalf("dropped batch %s was sent %d time(s); the sink retry path was not exercised", id, len(as))
		}
		seq := as[0].Sequence
		for _, a := range as {
			if a.Sequence != seq {
				t.Fatalf("batch %s was retried with sequence %d after %d", id, a.Sequence, seq)
			}
			if len(a.Lines) != 1 || a.Lines[0] != "step: line-1" {
				t.Fatalf("batch %s attempt carried lines %v", id, a.Lines)
			}
		}
	}
	for _, batches := range store {
		if len(batches) != 2 {
			t.Fatalf("receipt store holds %d committed batches, want 2", len(batches))
		}
		for id, lines := range batches {
			if len(lines) != 1 || lines[0] != "step: line-1" {
				t.Fatalf("store[%s] = %v, want exactly one copy of the line", id, lines)
			}
		}
	}
}

// TestHeartbeatDeadlineOnlyMovesForwardFromConfirmedResponses pins the
// heartbeatTick contract: an error keeps the deadline, and a CONFIRMED
// response may only extend it. A stale, zero or regressed LeaseExpiresAt
// must never shorten the local deadline, or a healthy job would self-cancel
// and be re-queued (duplicate execution) while the control plane still
// considers its lease valid.
func TestHeartbeatDeadlineOnlyMovesForwardFromConfirmedResponses(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(45 * time.Second)

	nd, cancel := heartbeatTick(now, deadline, &server.HeartbeatResponse{LeaseExpiresAt: now.Add(10 * time.Second)}, nil)
	if cancel {
		t.Fatal("a shortened confirmed deadline must not cancel the job immediately")
	}
	if !nd.Equal(deadline) {
		t.Fatalf("heartbeatTick adopted a regressed deadline from a confirmed response: %v -> %v", deadline, nd)
	}

	nd, cancel = heartbeatTick(now, deadline, &server.HeartbeatResponse{}, nil)
	if cancel {
		t.Fatal("a zero confirmed deadline must not cancel the job immediately")
	}
	if !nd.Equal(deadline) {
		t.Fatalf("heartbeatTick adopted a zero deadline from a confirmed response: %v -> %v", deadline, nd)
	}

	forward := now.Add(90 * time.Second)
	nd, cancel = heartbeatTick(now, deadline, &server.HeartbeatResponse{LeaseExpiresAt: forward}, nil)
	if cancel || !nd.Equal(forward) {
		t.Fatalf("forward extension lost: deadline=%v cancel=%v, want %v", nd, cancel, forward)
	}

	nd, cancel = heartbeatTick(now, deadline, nil, errBoom())
	if cancel {
		t.Fatal("an unreachable control plane with time remaining must not cancel")
	}
	if !nd.Equal(deadline) {
		t.Fatalf("an error moved the deadline: %v -> %v", deadline, nd)
	}
}

// droppedHeartbeatControlPlane accepts (applies) the first heartbeat and
// then drops the response; later heartbeats are confirmed with a forward
// lease extension. It keeps one state entry per lease so the test can prove
// the dropped response did not duplicate state.
type droppedHeartbeatControlPlane struct {
	mu           sync.Mutex
	attempts     []server.Heartbeat
	applied      map[string]int
	droppedFirst bool
}

func (s *droppedHeartbeatControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var hb server.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := hb.RunnerID + "|" + strconv.FormatInt(hb.LeaseGeneration, 10)
	s.mu.Lock()
	if s.applied == nil {
		s.applied = map[string]int{}
	}
	s.attempts = append(s.attempts, hb)
	s.applied[key]++
	drop := !s.droppedFirst
	s.droppedFirst = true
	s.mu.Unlock()
	if drop {
		dropResponseWithoutWriting(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(server.HeartbeatResponse{LeaseExpiresAt: time.Now().Add(30 * time.Second)})
}

func (s *droppedHeartbeatControlPlane) snapshot() ([]server.Heartbeat, map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied := map[string]int{}
	for k, v := range s.applied {
		applied[k] = v
	}
	return append([]server.Heartbeat(nil), s.attempts...), applied
}

func (s *droppedHeartbeatControlPlane) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.attempts)
}

// TestHeartbeatDroppedResponseRetriesWithoutDuplicatingState proves the
// heartbeat loop retries on the next tick after a committed-but-dropped
// response, keeps the same lease identity, does not self-cancel the job, and
// updates exactly one lease state entry (the heartbeat is an in-place lease
// extension, never a new lease).
func TestHeartbeatDroppedResponseRetriesWithoutDuplicatingState(t *testing.T) {
	cp := new(droppedHeartbeatControlPlane)
	ts := httptest.NewServer(cp)
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{Heartbeat: 20 * time.Millisecond})
	var cancelled atomic.Bool
	ctx, realCancel := context.WithCancel(context.Background())
	defer realCancel()
	cancel := func() {
		cancelled.Store(true)
		realCancel()
	}
	done := make(chan struct{})
	go r.heartbeatLoop(ctx, cancel, basicTask(payloadPipeline), done)

	waitUntil(t, 10*time.Second, "the dropped heartbeat and its confirmed retry", func() bool {
		return cp.attemptCount() >= 2
	})
	if cancelled.Load() {
		t.Fatal("a dropped heartbeat response aborted a healthy job: the confirmed deadline was not preserved")
	}
	close(done)
	realCancel()

	attempts, applied := cp.snapshot()
	for _, a := range attempts {
		if a.RunnerID != "runner-1" || a.LeaseToken != "lease-token" || a.LeaseGeneration != 3 {
			t.Fatalf("heartbeat attempt lost the lease identity: %+v", a)
		}
	}
	if len(applied) != 1 {
		t.Fatalf("heartbeat state entries = %v, want exactly one lease entry", applied)
	}
	for key, n := range applied {
		if n < 2 {
			t.Fatalf("lease %s was applied %d time(s); the dropped response was not retried", key, n)
		}
	}
}

// stubLeaseState mirrors the control plane's in-memory lease for one job.
type stubLeaseState struct {
	RunnerID   string
	Token      string
	Generation int64
	ExpiresAt  time.Time
	Spent      bool
}

// stubCompletion is one /complete request as the stub observed it.
type stubCompletion struct {
	RunnerID   string
	Token      string
	Generation int64
	Status     model.Status
	Hash       string
	Outcome    string
}

// leaseCompletionControlPlane models the completion contract that makes a
// dropped response recoverable: the receipt keyed by (job, generation,
// runner) with the result hash is written BEFORE the response can be lost,
// a replay of the same result is acknowledged 204 without re-accounting
// usage, and artifact uploads are idempotent by (job, generation, name).
type leaseCompletionControlPlane struct {
	mu              sync.Mutex
	leases          map[string]*stubLeaseState
	receipts        map[string]string
	usage           map[string]int
	completions     []stubCompletion
	dropCompletions int
	dropArtifact    bool
	artifacts       map[string][]byte
	artifactLog     []string
	logLines        []string
	task            server.Task
	nextServed      bool
}

func newLeaseCompletionControlPlane() *leaseCompletionControlPlane {
	return &leaseCompletionControlPlane{
		leases:    map[string]*stubLeaseState{},
		receipts:  map[string]string{},
		usage:     map[string]int{},
		artifacts: map[string][]byte{},
	}
}

// acquire binds a fresh lease to runnerID and returns the wire task a runner
// would receive, mirroring next()'s lease issuance.
func (s *leaseCompletionControlPlane) acquire(jobID, runnerID, pipelineText string) server.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	lease := &stubLeaseState{
		RunnerID: runnerID, Token: "lease-token-" + jobID,
		Generation: 5, ExpiresAt: time.Now().Add(time.Hour),
	}
	s.leases[jobID] = lease
	s.task = server.Task{
		Job: model.Job{
			ID: jobID, RunID: "run-" + jobID, Key: "build", BaseKey: "build",
			RepoURL: "https://github.com/acme/app.git", Ref: "refs/heads/main",
			Trusted: true, Pipeline: pipelineText, Attempts: 1,
		},
		LeaseToken: lease.Token, LeaseGeneration: lease.Generation, LeaseExpiresAt: lease.ExpiresAt,
	}
	s.nextServed = false
	return s.task
}

func stubCompletionHash(in server.Complete) string {
	b, _ := json.Marshal(struct {
		Status  model.Status      `json:"status"`
		Error   string            `json:"error"`
		Outputs map[string]string `json:"outputs"`
	}{in.Status, in.Error, in.Outputs})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func completionReceiptKey(jobID string, generation int64, runnerID string) string {
	return jobID + "|" + strconv.FormatInt(generation, 10) + "|" + runnerID
}

func (s *leaseCompletionControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jobID := jobIDFromPath(r.URL.Path)
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/register"):
		writeStubJSON(w, map[string]string{"id": "runner-1"})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/next"):
		s.mu.Lock()
		if s.nextServed {
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.nextServed = true
		task := s.task
		s.mu.Unlock()
		writeStubJSON(w, task)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/complete"):
		s.complete(w, r, jobID)
	case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/artifacts/"):
		s.uploadArtifact(w, r, jobID)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/log/batch"):
		var body struct {
			Lines []server.LogLine `json:"lines"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		for _, l := range body.Lines {
			s.logLines = append(s.logLines, l.Step+": "+l.Line)
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/cache/"):
		http.NotFound(w, r)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func writeStubJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *leaseCompletionControlPlane) complete(w http.ResponseWriter, r *http.Request, jobID string) {
	var in server.Complete
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash := stubCompletionHash(in)
	key := completionReceiptKey(jobID, in.LeaseGeneration, in.RunnerID)
	s.mu.Lock()
	if existing, ok := s.receipts[key]; ok {
		outcome := "replayed"
		if existing != hash {
			outcome = "rejected-result-conflict"
		}
		s.completions = append(s.completions, stubCompletion{
			RunnerID: in.RunnerID, Token: in.LeaseToken, Generation: in.LeaseGeneration,
			Status: in.Status, Hash: hash, Outcome: outcome,
		})
		s.mu.Unlock()
		if outcome == "replayed" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "completion result conflict", http.StatusConflict)
		return
	}
	lease := s.leases[jobID]
	if lease == nil || lease.Spent || lease.RunnerID != in.RunnerID ||
		lease.Token != in.LeaseToken || lease.Generation != in.LeaseGeneration ||
		!lease.ExpiresAt.After(time.Now()) {
		s.completions = append(s.completions, stubCompletion{
			RunnerID: in.RunnerID, Token: in.LeaseToken, Generation: in.LeaseGeneration,
			Status: in.Status, Hash: hash, Outcome: "rejected-stale-lease",
		})
		s.mu.Unlock()
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	s.receipts[key] = hash
	s.usage[jobID]++
	lease.Spent = true
	drop := s.dropCompletions > 0
	if drop {
		s.dropCompletions--
	}
	outcome := "committed"
	if drop {
		outcome = "committed-response-dropped"
	}
	s.completions = append(s.completions, stubCompletion{
		RunnerID: in.RunnerID, Token: in.LeaseToken, Generation: in.LeaseGeneration,
		Status: in.Status, Hash: hash, Outcome: outcome,
	})
	s.mu.Unlock()
	if drop {
		// The receipt and usage accounting above are durable; the
		// acknowledgement never reaches the runner.
		dropResponseWithoutWriting(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *leaseCompletionControlPlane) uploadArtifact(w http.ResponseWriter, r *http.Request, jobID string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := filepath.Base(r.URL.Path)
	key := jobID + "|" + r.Header.Get("X-Kiwi-Lease-Generation") + "|" + name
	s.mu.Lock()
	if _, ok := s.artifacts[key]; ok {
		s.artifactLog = append(s.artifactLog, "replayed:"+name)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.artifacts[key] = body
	drop := s.dropArtifact
	if drop {
		s.dropArtifact = false
	}
	s.artifactLog = append(s.artifactLog, "committed:"+name)
	s.mu.Unlock()
	if drop {
		dropResponseWithoutWriting(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *leaseCompletionControlPlane) completionAttempts() []stubCompletion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubCompletion(nil), s.completions...)
}

func (s *leaseCompletionControlPlane) usageCount(jobID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage[jobID]
}

func (s *leaseCompletionControlPlane) artifactState() (map[string][]byte, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	artifacts := map[string][]byte{}
	for k, v := range s.artifacts {
		artifacts[k] = append([]byte(nil), v...)
	}
	return artifacts, append([]string(nil), s.artifactLog...)
}

// TestDroppedArtifactUploadResponseIsRetriedAndDeduped is the dropped-
// response regression for artifact upload: the control plane commits the
// artifact under (job, generation, name) and then kills the response. The
// upload is idempotent, so the runner must retry it rather than surface a
// lost-upload warning (which would leave required artifacts missing at
// completion).
func TestDroppedArtifactUploadResponseIsRetriedAndDeduped(t *testing.T) {
	cp := newLeaseCompletionControlPlane()
	cp.dropArtifact = true
	ts := httptest.NewServer(cp)
	defer ts.Close()

	task := cp.acquire("job-1", "runner-1", payloadPipeline)
	art := filepath.Join(t.TempDir(), "app.tar.gz")
	if err := os.WriteFile(art, []byte("artifact-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := testRunnerFor(t, ts, Config{})
	if err := r.uploadArtifact(context.Background(), task, "app", art); err != nil {
		t.Fatalf("dropped artifact response was not recovered: %v", err)
	}

	artifacts, log := cp.artifactState()
	if len(artifacts) != 1 {
		t.Fatalf("artifact store has %d entries, want exactly 1: %v", len(artifacts), artifacts)
	}
	want := []string{"committed:app", "replayed:app"}
	if strings.Join(log, ",") != strings.Join(want, ",") {
		t.Fatalf("artifact delivery log = %v, want %v", log, want)
	}
}

// TestDroppedCompletionResponseIsRetriedAndDeduped drives the REAL runner
// loop (Run: register -> next -> execute -> complete) against a control
// plane that commits the first artifact upload and the first completion and
// then drops both responses. The retries must replay the identical
// (job, generation, runner) completion and the identical artifact name: the
// receipt dedupes the replay, usage accounts once, and the local side effects
// (checkout) happen exactly once because the completion retry never
// re-executes the job.
func TestDroppedCompletionResponseIsRetriedAndDeduped(t *testing.T) {
	buildStep := nativeScript(
		"mkdir -p out && echo hello > out/app.txt",
		"New-Item -ItemType Directory -Force -Path out | Out-Null; 'hello' | Out-File -Encoding utf8 out/app.txt",
	)
	artifactPipeline := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + buildStep + "\n    artifacts:\n      - name: app\n        paths: [out]\n"

	cp := newLeaseCompletionControlPlane()
	cp.dropCompletions = 1
	cp.dropArtifact = true
	cp.acquire("job-1", "runner-1", artifactPipeline)
	ts := httptest.NewServer(cp)
	defer ts.Close()

	var checkouts atomic.Int64
	r := testRunnerFor(t, ts, Config{Poll: 10 * time.Millisecond, Concurrency: 1})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, _ string) error {
		checkouts.Add(1)
		return nil
	}
	// Keep the loop hermetic: no prewarm state in $HOME, no GC walk of the
	// user's temp tree.
	r.Cfg.PrewarmStateFile = filepath.Join(t.TempDir(), "prewarm.json")
	r.Cfg.WorkDir = t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- r.Run(ctx) }()

	waitUntil(t, 20*time.Second, "the dropped completion and its replay", func() bool {
		return len(cp.completionAttempts()) >= 2
	})
	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("runner loop did not stop after cancellation")
	}

	attempts := cp.completionAttempts()
	if attempts[0].Outcome != "committed-response-dropped" {
		t.Fatalf("first completion outcome = %q, want committed-response-dropped", attempts[0].Outcome)
	}
	if attempts[1].Outcome != "replayed" {
		t.Fatalf("second completion outcome = %q, want replayed (the receipt must dedupe it)", attempts[1].Outcome)
	}
	if attempts[0].Hash != attempts[1].Hash {
		t.Fatalf("completion replay changed the result hash: %s -> %s", attempts[0].Hash, attempts[1].Hash)
	}
	if attempts[0].RunnerID != attempts[1].RunnerID || attempts[0].Generation != attempts[1].Generation {
		t.Fatalf("completion replay changed the receipt identity: %+v -> %+v", attempts[0], attempts[1])
	}
	if got := checkouts.Load(); got != 1 {
		t.Fatalf("job was executed %d time(s) across the completion retry, want exactly 1", got)
	}
	if got := cp.usageCount("job-1"); got != 1 {
		t.Fatalf("usage accounted %d time(s), want exactly 1", got)
	}
	artifacts, log := cp.artifactState()
	if len(artifacts) != 1 {
		t.Fatalf("artifact store has %d entries, want exactly 1: %v", len(artifacts), artifacts)
	}
	want := []string{"committed:app", "replayed:app"}
	if strings.Join(log, ",") != strings.Join(want, ",") {
		t.Fatalf("artifact delivery log = %v, want %v", log, want)
	}
}

// restartLogControlPlane is the /log/batch receipt store for the restart
// tests: first deliveries of new identities are committed, an optional
// first-response drop models a lost acknowledgement, and duplicate
// deliveries can be parked (held open) so the test can kill a sink while a
// batch is in flight.
type restartLogControlPlane struct {
	mu        sync.Mutex
	attempts  []batchDeliveryAttempt
	store     map[string]map[string][]string
	dropFirst bool
	park      chan struct{}
	parking   bool
}

func newRestartLogControlPlane() *restartLogControlPlane {
	return &restartLogControlPlane{store: map[string]map[string][]string{}}
}

func (s *restartLogControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jobID := jobIDFromPath(r.URL.Path)
	var body struct {
		RunnerID        string           `json:"runner_id"`
		LeaseToken      string           `json:"lease_token"`
		LeaseGeneration int64            `json:"lease_generation"`
		BatchID         string           `json:"batch_id"`
		BatchSequence   int64            `json:"batch_sequence"`
		Lines           []server.LogLine `json:"lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	lines := make([]string, 0, len(body.Lines))
	for _, l := range body.Lines {
		lines = append(lines, l.Step+": "+l.Line)
	}
	key := jobID + "\x00" + strconv.FormatInt(body.LeaseGeneration, 10)
	s.mu.Lock()
	s.attempts = append(s.attempts, batchDeliveryAttempt{
		JobID: jobID, RunnerID: body.RunnerID, Token: body.LeaseToken,
		Generation: body.LeaseGeneration, BatchID: body.BatchID,
		Sequence: body.BatchSequence, Lines: lines,
	})
	batches := s.store[key]
	if batches == nil {
		batches = map[string][]string{}
		s.store[key] = batches
	}
	if _, committed := batches[body.BatchID]; committed {
		park, ch := s.parking, s.park
		s.mu.Unlock()
		if park && ch != nil {
			select {
			case <-ch:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	batches[body.BatchID] = lines
	drop := s.dropFirst
	if drop {
		s.dropFirst = false
	}
	s.mu.Unlock()
	if drop {
		dropResponseWithoutWriting(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// startRestartPhase configures the stub for the restart phase: no more
// dropped responses, no more parking.
func (s *restartLogControlPlane) startRestartPhase() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropFirst = false
	s.parking = false
	if s.park != nil {
		close(s.park)
		s.park = nil
	}
}

func (s *restartLogControlPlane) snapshot() ([]batchDeliveryAttempt, map[string]map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempts := append([]batchDeliveryAttempt(nil), s.attempts...)
	store := map[string]map[string][]string{}
	for key, batches := range s.store {
		copied := map[string][]string{}
		for id, lines := range batches {
			copied[id] = append([]string(nil), lines...)
		}
		store[key] = copied
	}
	return attempts, store
}

// TestRestartMidBatchIdenticalReplayDedupes simulates a runner restart in
// the middle of a log batch: the first sink commits batch 1 (the response is
// dropped, its retry is parked) and dies with lines 2 spooled but never
// delivered. A fresh sink with the same runner identity and the same lease
// starts its sequence counter at 1 again and replays the identical batches;
// the (job, generation, batch_id) receipt dedupes the replay instead of
// duplicating the committed line. The unsent spool is process-local and is
// only recovered because the restarted run re-emits it from the start.
func TestRestartMidBatchIdenticalReplayDedupes(t *testing.T) {
	cp := newRestartLogControlPlane()
	cp.dropFirst = true
	cp.parking = true
	cp.park = make(chan struct{})
	ts := httptest.NewServer(cp)
	defer ts.Close()

	task := basicTask(payloadPipeline)
	r := testRunnerFor(t, ts, Config{})
	sinkA := newAsyncLogSink(nil, r.logBatchPost(task, &secrets.Masker{}))
	sinkA.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "batch 1 to be committed with its response dropped", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) == 1
	})
	waitUntil(t, 10*time.Second, "the parked retry of batch 1", func() bool {
		attempts, _ := cp.snapshot()
		return len(attempts) >= 2
	})
	// The sender is parked; this line stays in the process-local spool.
	sinkA.WriteLine("build", "step", "line-2")
	outA := sinkA.Finish(50 * time.Millisecond)
	if outA.Err == nil && outA.Remaining == 0 && outA.Stopped {
		t.Fatalf("parked sink reported a clean stop: %+v", outA)
	}
	t.Logf("GAP: sink A died with Err=%v Remaining=%d Stopped=%v; the spool and the batch sequence are process-local, so lines spooled after the last acked batch are lost unless the restarted run re-emits them", outA.Err, outA.Remaining, outA.Stopped)
	cp.startRestartPhase()

	// Restart: a fresh process (new sink, sequence restarting at 1) replays
	// the identical line sequence with identical batch boundaries.
	r2 := testRunnerFor(t, ts, Config{})
	sinkB := newAsyncLogSink(nil, r2.logBatchPost(task, &secrets.Masker{}))
	sinkB.WriteLine("build", "step", "line-1")
	waitUntil(t, 10*time.Second, "the replayed batch 1 to be deduped", func() bool {
		attempts, store := cp.snapshot()
		return len(attempts) >= 3 && countCommittedBatches(store) == 1
	})
	sinkB.WriteLine("build", "step", "line-2")
	waitUntil(t, 10*time.Second, "batch 2 from the restarted sink", func() bool {
		_, store := cp.snapshot()
		return countCommittedBatches(store) == 2
	})
	outB := sinkB.Finish(10 * time.Second)
	if outB.Err != nil || outB.Dropped != 0 || outB.Remaining != 0 || !outB.Stopped {
		t.Fatalf("restarted sink outcome = %+v, want a clean stop", outB)
	}

	_, store := cp.snapshot()
	got := flattenCommittedLines(store)
	want := []string{"step: line-1", "step: line-2"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("receipt store lines = %v, want exactly %v (the replayed batch must be deduped)", got, want)
	}
}

// TestRestartMidBatchDifferentBoundariesDuplicateGap documents the restart
// gap that remains: batch identity is a function of (sequence, payload), so
// the SAME lines replayed under the SAME lease generation but with different
// batch boundaries (the drain boundary is timing-dependent) are a different
// batch_id and are committed a second time. Server-side dedupe is per batch,
// never per line. If sequence/spool persistence is added to the runner, this
// test must be replaced by one asserting zero duplicates.
func TestRestartMidBatchDifferentBoundariesDuplicateGap(t *testing.T) {
	cp := newRestartLogControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	task := basicTask(payloadPipeline)
	post := testRunnerFor(t, ts, Config{}).logBatchPost(task, &secrets.Masker{})

	// Original process: one drain formed batch 1 carrying both lines.
	original := logBatch{
		Sequence: 1,
		Lines: []logLine{
			{Job: "build", Step: "step", Line: "line-1"},
			{Job: "build", Step: "step", Line: "line-2"},
		},
	}
	original.ID = logBatchID(original.Sequence, original.Lines)
	if err := post(context.Background(), original); err != nil {
		t.Fatalf("original batch delivery: %v", err)
	}

	// Restarted process, same lease generation, fresh sequence counter, and
	// a different drain boundary: the same lines are now two batches.
	for i, line := range []string{"line-1", "line-2"} {
		batch := logBatch{Sequence: int64(i + 1), Lines: []logLine{{Job: "build", Step: "step", Line: line}}}
		batch.ID = logBatchID(batch.Sequence, batch.Lines)
		if err := post(context.Background(), batch); err != nil {
			t.Fatalf("restarted batch %d delivery: %v", i+1, err)
		}
	}

	_, store := cp.snapshot()
	if got := countCommittedBatches(store); got != 3 {
		t.Fatalf("committed batches = %d, want 3 (the original plus the two re-batched deliveries)", got)
	}
	lines := flattenCommittedLines(store)
	counts := map[string]int{}
	for _, l := range lines {
		counts[l]++
	}
	if counts["step: line-1"] != 2 || counts["step: line-2"] != 2 {
		t.Fatalf("line counts = %v, want each line twice under the current per-batch contract", counts)
	}
	t.Logf("GAP: a restarted runner with the same lease but different drain boundaries duplicates lines (%v); batch identity includes the boundary, so only identical replays dedupe", counts)
}

// TestRestartLeaseAcquireToCompletionAccountsUsageOnce simulates a runner
// that acquired a lease and died before completing. A brand-new runner
// process with the same identity and the persisted lease/task can still
// complete the job (the lease token stays valid server-side), and usage is
// accounted exactly once across the completion and its replay. A forged
// generation/token is rejected.
func TestRestartLeaseAcquireToCompletionAccountsUsageOnce(t *testing.T) {
	cp := newLeaseCompletionControlPlane()
	ts := httptest.NewServer(cp)
	defer ts.Close()

	task := cp.acquire("job-1", "runner-1", payloadPipeline)

	executeWithFreshRunner := func(lease server.Task) {
		t.Helper()
		r := testRunnerFor(t, ts, Config{})
		r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
			return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
		}
		r.execute(context.Background(), lease)
	}

	// Restart #1: the new process holds the persisted lease and completes.
	executeWithFreshRunner(task)
	attempts := cp.completionAttempts()
	if len(attempts) != 1 || attempts[0].Outcome != "committed" {
		t.Fatalf("completions after restart = %+v, want one committed under the persisted lease", attempts)
	}
	if got := cp.usageCount("job-1"); got != 1 {
		t.Fatalf("usage after the restarted completion = %d, want 1", got)
	}

	// Restart #2: the same completion is replayed; the receipt dedupes it
	// and usage does not move.
	executeWithFreshRunner(task)
	attempts = cp.completionAttempts()
	if len(attempts) != 2 || attempts[1].Outcome != "replayed" {
		t.Fatalf("completions after replay = %+v, want a deduped replay", attempts)
	}
	if got := cp.usageCount("job-1"); got != 1 {
		t.Fatalf("usage after the replay = %d, want still 1", got)
	}

	// Boundary: a forged generation/token cannot complete the job.
	tampered := task
	tampered.LeaseGeneration++
	tampered.LeaseToken = "forged-lease"
	r := testRunnerFor(t, ts, Config{})
	r.complete(context.Background(), tampered, model.StatusSuccess, nil, nil)
	attempts = cp.completionAttempts()
	if len(attempts) != 3 || attempts[2].Outcome != "rejected-stale-lease" {
		t.Fatalf("forged completion = %+v, want rejected-stale-lease", attempts)
	}
	if got := cp.usageCount("job-1"); got != 1 {
		t.Fatalf("forged completion moved usage to %d, want 1", got)
	}
}
