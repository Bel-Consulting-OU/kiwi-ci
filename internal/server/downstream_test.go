package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const downstreamPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    downstream:
      repository: acme/child
      ref: refs/heads/main
    steps:
      - run: echo build
`

const downstreamWaitPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    downstream:
      repository: acme/child
      ref: refs/heads/main
      wait: true
    steps:
      - run: echo build
`

// downstreamPendingItem returns the queued downstream dispatch intent. A
// completion also queues its marker-guarded effect intents, so the
// downstream intent is located by kind rather than position.
func downstreamPendingItem(t *testing.T, s *Server) forge.OutboxItem {
	t.Helper()
	for _, it := range s.outbox.Pending() {
		if it.Kind == forge.OutboxKindDownstream {
			return it
		}
	}
	t.Fatal("no downstream dispatch intent queued")
	return forge.OutboxItem{}
}

const childPipeline = `version: 1
jobs:
  child-build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo child
`

// downstreamServer builds a persistent server whose policy grants
// cross_repo_trigger for repo o/r and enqueues a trusted run declaring a
// downstream dispatch. The target policy consent (DownstreamAllowlist) is
// configured so the dispatch is authorized.
func downstreamServer(t *testing.T, pipelineText string) (*Server, model.Run) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {CrossRepoTrigger: boolPtr(true)},
		},
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: pipelineText, Trusted: true,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return s, run
}

func completeTask(t *testing.T, s *Server, task Task, runnerID, status string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":%d,"status":%q}`,
		runnerID, task.LeaseToken, task.LeaseGeneration, status)
	return doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", body)
}

func childRunsOf(s *Server) []model.Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Run
	for _, r := range s.runs {
		if r.RepoFullName == "acme/child" {
			out = append(out, r)
		}
	}
	return out
}

func TestDownstreamCapabilityRejectionAtEnqueue(t *testing.T) {
	// No cross_repo_trigger grant: the downstream declaration must be
	// rejected at enqueue with a 403 policy denial.
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://github.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","pipeline":`+jsonString(downstreamPipeline)+`}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("submit without grant = %d, want 403: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["reason"] != "policy_denied" || body["error"] == "" {
		t.Fatalf("response body = %v", body)
	}
	// The same pipeline is admitted when the grant exists.
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue with grant: %v", err)
	}
}

func TestDownstreamInvalidRepositoryRejected(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	bad := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    downstream:
      repository: "not-an-owner-name"
    steps:
      - run: echo hi
`
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: bad, Trusted: true,
	}); err == nil {
		t.Fatal("malformed downstream.repository must be rejected at enqueue")
	}
}

func TestDownstreamLaunchExactlyOnceAcrossRestart(t *testing.T) {
	s, run := downstreamServer(t, downstreamPipeline)
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	// The completion recorded the claim and enqueued the dispatch intent
	// (alongside the marker-guarded completion effect intents).
	item := downstreamPendingItem(t, s)
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		if repo != "acme/child" || ref != "refs/heads/main" {
			return "", fmt.Errorf("unexpected fetch %s@%s", repo, ref)
		}
		return childPipeline, nil
	}
	// Reserve-first flow: the link reservation is claimed BEFORE the child
	// run is enqueued, so a crash between the launch and the outbox ack
	// leaves a launched link that a replayed dispatch must skip. Dispatch
	// the intent directly (no ack), then restart the control plane.
	if err := s.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if got := childRunsOf(s); len(got) != 1 {
		t.Fatalf("child runs after dispatch = %d, want 1", len(got))
	}
	link, ok, err := s.getDownstreamLink(context.Background(), task.Job.ID, "acme/child", "refs/heads/main")
	if err != nil || !ok {
		t.Fatalf("link: ok=%v err=%v", ok, err)
	}
	if link.ChildRunID == "" {
		t.Fatal("link was not launched")
	}
	if link.Reserved {
		t.Fatal("mark-launched must consume the reservation")
	}

	// Restart from the same dataDir: the outbox replays the unacked intents
	// (the downstream intent plus the completion effects), the link row
	// (snapshot) is the claim, and dispatch must skip.
	s2, err := NewPersistent("token", "token", s.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	s2.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s2.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	replayed := s2.outbox.Pending()
	if downstreamPendingItem(t, s2).Kind != forge.OutboxKindDownstream {
		t.Fatalf("replayed intents missing the downstream intent: %d items", len(replayed))
	}
	s2.flushOutbox(context.Background())
	if got := childRunsOf(s2); len(got) != 1 {
		t.Fatalf("child runs after replay = %d, want exactly 1 (no duplicate launch)", len(got))
	}
	if got := s2.outbox.Pending(); len(got) != 0 {
		t.Fatalf("outbox not drained after replay: %d intents", len(got))
	}
	_ = run
}

func TestDownstreamWaitAggregation(t *testing.T) {
	s, parent := downstreamServer(t, downstreamWaitPipeline)
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	s.flushOutbox(context.Background())
	children := childRunsOf(s)
	if len(children) != 1 {
		t.Fatalf("child runs = %d, want 1", len(children))
	}
	child := children[0]
	s.mu.Lock()
	parent = s.runs[parent.ID]
	s.mu.Unlock()
	if len(parent.DownstreamRuns) != 1 || parent.DownstreamRuns[0] != child.ID {
		t.Fatalf("parent.DownstreamRuns = %v", parent.DownstreamRuns)
	}
	if parent.Status != model.StatusRunning {
		t.Fatalf("parent status = %s, want running while the child is in flight", parent.Status)
	}
	// Completing the child must finalize the parent back to success.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("lease child job = %d: %s", w.Code, w.Body.String())
	}
	var childTask Task
	if err := json.Unmarshal(w.Body.Bytes(), &childTask); err != nil {
		t.Fatal(err)
	}
	if w := completeTask(t, s, childTask, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("child complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	parent = s.runs[parent.ID]
	s.mu.Unlock()
	if parent.Status != model.StatusSuccess {
		t.Fatalf("parent status after child success = %s, want success", parent.Status)
	}
}

func TestDownstreamWaitChildFailure(t *testing.T) {
	s, parent := downstreamServer(t, downstreamWaitPipeline)
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	s.flushOutbox(context.Background())
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("lease child job = %d: %s", w.Code, w.Body.String())
	}
	var childTask Task
	if err := json.Unmarshal(w.Body.Bytes(), &childTask); err != nil {
		t.Fatal(err)
	}
	if w := completeTask(t, s, childTask, runnerID, "failure"); w.Code != http.StatusNoContent {
		t.Fatalf("child complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	parent = s.runs[parent.ID]
	s.mu.Unlock()
	if parent.Status != model.StatusFailure {
		t.Fatalf("parent status after child failure = %s, want failure", parent.Status)
	}
}

func TestDownstreamDBModeExactlyOnce(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	_, hasLink := f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	f.mu.Unlock()
	if !hasLink {
		t.Fatal("downstream link was not persisted through DownstreamStore")
	}

	// A second server on the same store replays the pending outbox intents
	// (the completion effects created inside the completion transaction
	// plus the downstream dispatch intent).
	s2 := New("token")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s2.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	item := downstreamPendingItem(t, s2)
	// Crash between launch and ack: dispatch the intent directly first.
	if err := s2.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	s2.flushOutbox(context.Background())
	f.mu.Lock()
	childCount := 0
	for _, r := range f.runs {
		if r.RepoFullName == "acme/child" {
			childCount++
		}
	}
	f.mu.Unlock()
	if childCount != 1 {
		t.Fatalf("child runs in store = %d, want exactly 1", childCount)
	}
}

// ---------------------------------------------------------------------------
// Bilateral authorization (target policy consent)
// ---------------------------------------------------------------------------

// TestDownstreamRefusedWithoutTargetConsent: without a DownstreamAllowlist
// entry for the target repository the dispatch is refused, audited, and the
// outbox intent is dropped.
func TestDownstreamRefusedWithoutTargetConsent(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	// No DownstreamAllowlist at all: default deny.
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	fetched := false
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		fetched = true
		return childPipeline, nil
	}
	s.flushOutbox(context.Background())
	if fetched {
		t.Fatal("pipeline fetched despite missing target consent")
	}
	if got := childRunsOf(s); len(got) != 0 {
		t.Fatalf("child runs = %d, want 0 (refused)", len(got))
	}
	// The outbox intent was dropped.
	if got := s.outbox.Pending(); len(got) != 0 {
		t.Fatalf("outbox not drained after refusal: %d intents", len(got))
	}
	// The refusal is audited.
	events, err := s.store.ReadAudit(100)
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	for _, e := range events {
		if e.Action == "downstream.refused" {
			refused = true
		}
	}
	if !refused {
		t.Fatal("refused dispatch was not audited")
	}
}

// TestDownstreamAllowlistedSourceUntrustedChild: an allowlisted source is
// enqueued, but the child inherits trust only when the target explicitly
// grants trusted ingress.
func TestDownstreamAllowlistedSourceUntrustedChild(t *testing.T) {
	s, _ := downstreamServer(t, downstreamPipeline)
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	s.flushOutbox(context.Background())
	children := childRunsOf(s)
	if len(children) != 1 {
		t.Fatalf("child runs = %d, want 1", len(children))
	}
	if children[0].Trusted {
		t.Fatal("child must be untrusted without trusted ingress consent")
	}
}

// TestDownstreamTrustedIngressPreservesTrust: a target with trusted
// ingress consent receives a trusted child.
func TestDownstreamTrustedIngressPreservesTrust(t *testing.T) {
	s, _ := downstreamServer(t, downstreamPipeline)
	s.DownstreamTrustedIngress = map[string]bool{"acme/child": true}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	s.flushOutbox(context.Background())
	children := childRunsOf(s)
	if len(children) != 1 {
		t.Fatalf("child runs = %d, want 1", len(children))
	}
	if !children[0].Trusted {
		t.Fatal("child must be trusted with trusted-ingress consent")
	}
}

// TestDownstreamRefusedDBMode: the same default-deny refusal on the DB-mode
// dispatch path.
func TestDownstreamRefusedDBMode(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// No allowlist: default deny.
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.flushOutbox(context.Background())
	f.mu.Lock()
	childCount := 0
	refused := false
	for _, r := range f.runs {
		if r.RepoFullName == "acme/child" {
			childCount++
		}
	}
	for _, e := range f.audit {
		if e.Action == "downstream.refused" {
			refused = true
		}
	}
	f.mu.Unlock()
	if childCount != 0 {
		t.Fatalf("child runs in store = %d, want 0 (refused)", childCount)
	}
	if !refused {
		t.Fatal("DB-mode refusal was not audited")
	}
}
