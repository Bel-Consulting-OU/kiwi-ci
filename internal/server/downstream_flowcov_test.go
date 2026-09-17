package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func fcRecordJob(id string) model.Job {
	return model.Job{ID: id, RunID: "run-1", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusSuccess, Pipeline: fcDownstreamNoRefPipeline}
}

func TestFlowDownstreamRecordIntents(t *testing.T) {
	s := fcEffectsServerWithRun(t)
	ctx := context.Background()
	// Unparseable pipeline is a no-op.
	if err := s.recordDownstreamIntents(ctx, model.Job{ID: "j"}, model.Run{}); err != nil {
		t.Fatalf("unparseable record = %v", err)
	}
	// Ref fallback and outbox enqueue.
	run := model.Run{ID: "run-1", Ref: "refs/heads/dev"}
	if err := s.recordDownstreamIntents(ctx, fcRecordJob("j"), run); err != nil {
		t.Fatalf("record intents = %v", err)
	}
	s.mu.Lock()
	link, ok := s.downstreamLinks[downstreamLinkKey("j", "o/target", "refs/heads/dev")]
	s.mu.Unlock()
	if !ok || link.TargetRef != "refs/heads/dev" || link.TargetRepoID == "" || link.StableChildID == "" {
		t.Fatalf("recorded link = %+v ok=%v", link, ok)
	}
	if len(s.outbox.Pending()) != 1 {
		t.Fatalf("outbox pending = %d, want 1", len(s.outbox.Pending()))
	}
	// Duplicate recording is a no-op through the link claim.
	if err := s.recordDownstreamIntents(ctx, fcRecordJob("j"), run); err != nil {
		t.Fatalf("duplicate record = %v", err)
	}
	if got := len(s.outbox.Pending()); got != 2 {
		t.Fatalf("outbox after duplicate record = %d, want 2 (intent re-enqueued)", got)
	}
}

func TestFlowDownstreamRecordIntentsStoreErrors(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Pipeline: fcDownstreamNoRefPipeline, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	f.mu.Unlock()
	job := model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Pipeline: fcDownstreamNoRefPipeline, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	run := model.Run{ID: "run-c", Ref: "refs/heads/main"}
	// Link insert failure.
	s.DB = &fcStore{dbFakeStore: f, insertDownstreamLinkErr: errors.New("link insert down")}
	if err := s.recordDownstreamIntents(context.Background(), job, run); err == nil {
		t.Fatal("link insert failure must propagate")
	}
	// Outbox append failure after a successful link insert.
	s.DB = f
	if err := s.recordDownstreamIntents(context.Background(), job, run); err != nil {
		t.Fatalf("link insert = %v", err)
	}
	f.mu.Lock()
	f.outboxAppendErr = errors.New("outbox append down")
	f.mu.Unlock()
	job2 := job
	job2.ID = "job-b"
	s.DB = &fcStore{dbFakeStore: f}
	if err := s.recordDownstreamIntents(context.Background(), job2, run); err == nil {
		t.Fatal("outbox enqueue failure must propagate")
	}
	f.mu.Lock()
	f.outboxAppendErr = nil
	f.mu.Unlock()
}

func TestFlowDownstreamRecordForCompletedBranches(t *testing.T) {
	ctx := context.Background()
	// Memory mode: missing job, missing run, non-success, success.
	s := fcEffectsServerWithRun(t)
	if err := s.recordDownstreamIntentsForCompleted(ctx, "ghost"); err != nil {
		t.Fatalf("missing job = %v", err)
	}
	s.mu.Lock()
	s.jobs["j"] = model.Job{ID: "j", RunID: "ghost-run", Key: "build", Status: model.StatusSuccess, Pipeline: fcDownstreamNoRefPipeline, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	s.mu.Unlock()
	if err := s.recordDownstreamIntentsForCompleted(ctx, "j"); err != nil {
		t.Fatalf("missing run = %v", err)
	}
	s.mu.Lock()
	j := s.jobs["j"]
	j.RunID = "run-1"
	j.Status = model.StatusFailure
	s.jobs["j"] = j
	s.mu.Unlock()
	if err := s.recordDownstreamIntentsForCompleted(ctx, "j"); err != nil {
		t.Fatalf("non-success = %v", err)
	}
	s.mu.Lock()
	j.Status = model.StatusSuccess
	s.jobs["j"] = j
	s.mu.Unlock()
	if err := s.recordDownstreamIntentsForCompleted(ctx, "j"); err != nil {
		t.Fatalf("success = %v", err)
	}

	// DB mode: read failures, non-success, success.
	s2, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Pipeline: fcDownstreamNoRefPipeline, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	f.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Ref: "refs/heads/main", Status: model.StatusRunning}
	f.mu.Unlock()
	s2.DB = &fcStore{dbFakeStore: f, getJobErr: errors.New("job read down")}
	if err := s2.recordDownstreamIntentsForCompleted(ctx, "job-a"); err == nil {
		t.Fatal("job read failure must propagate")
	}
	s2.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run read down")}
	if err := s2.recordDownstreamIntentsForCompleted(ctx, "job-a"); err == nil {
		t.Fatal("run read failure must propagate")
	}
	s2.DB = f
	f.mu.Lock()
	dj := f.jobs["job-a"]
	dj.Status = model.StatusFailure
	f.jobs["job-a"] = dj
	f.mu.Unlock()
	if err := s2.recordDownstreamIntentsForCompleted(ctx, "job-a"); err != nil {
		t.Fatalf("db non-success = %v", err)
	}
	f.mu.Lock()
	dj.Status = model.StatusSuccess
	f.jobs["job-a"] = dj
	f.mu.Unlock()
	if err := s2.recordDownstreamIntentsForCompleted(ctx, "job-a"); err != nil {
		t.Fatalf("db success = %v", err)
	}
}

func TestFlowDownstreamForgeBaseURL(t *testing.T) {
	s := New("tok")
	s.SetForgeBaseURL("github", "https://gh.example.com")
	s.SetForgeBaseURL("gitlab", "https://gl.example.com")
	s.SetForgeBaseURL("forgejo", "https://fj.example.com")
	s.SetForgeBaseURL("unknown", "https://ignored.example.com")
	if got := s.forgeBaseURL("github"); got != "https://gh.example.com" {
		t.Fatalf("github base = %q", got)
	}
	if got := s.forgeBaseURL("gitlab"); got != "https://gl.example.com" {
		t.Fatalf("gitlab base = %q", got)
	}
	if got := s.forgeBaseURL("forgejo"); got != "https://fj.example.com" {
		t.Fatalf("forgejo base = %q", got)
	}
	if got := s.forgeBaseURL("unknown"); got != "" {
		t.Fatalf("unknown base = %q", got)
	}
}

func TestFlowDownstreamStableHelpers(t *testing.T) {
	if got := downstreamStableChildRunID("short"); got != "short" {
		t.Fatalf("short stable child = %q", got)
	}
	key := downstreamStableKey("p", "o/r", "refs/heads/main")
	if len(key) != 64 {
		t.Fatalf("stable key = %q", key)
	}
	if got := downstreamStableChildRunID(key); got != key[:32] {
		t.Fatalf("stable child = %q", got)
	}
	s := New("tok")
	s.DownstreamTrustedIngress = map[string]bool{"o/r": true}
	if !s.downstreamTrustedIngress("github.com/o/r", "o/r") {
		t.Fatal("bare alias must resolve")
	}
	if s.downstreamTrustedIngress("github.com/o/r", "o/other") {
		t.Fatal("unknown target must not resolve")
	}
	canonical := New("tok")
	canonical.DownstreamTrustedIngress = map[string]bool{"github.com/o/r": true}
	if !canonical.downstreamTrustedIngress("github.com/o/r", "o/r") {
		t.Fatal("canonical key must resolve")
	}
}

func TestFlowDownstreamAllowedBranches(t *testing.T) {
	ctx := context.Background()
	p := downstreamPayload{ParentRunID: "run-1", TargetRepo: "o/target", TargetRef: "refs/heads/main"}
	// No allowlist entry: default deny.
	s := fcEffectsServerWithRun(t)
	if s.downstreamAllowed(ctx, p, "github.com/o/target") {
		t.Fatal("missing allowlist must deny")
	}
	// Empty source list allows any source.
	s.DownstreamAllowlist = map[string][]string{"github.com/o/target": {}}
	if !s.downstreamAllowed(ctx, p, "github.com/o/target") {
		t.Fatal("empty allowlist must allow")
	}
	// Missing parent run refuses.
	missing := New("tok")
	missing.DownstreamAllowlist = map[string][]string{"github.com/o/target": {"github.com/o/repo-a"}}
	if missing.downstreamAllowed(ctx, p, "github.com/o/target") {
		t.Fatal("missing parent run must deny")
	}
	// Identity-less run falls back to the full name for the comparison.
	empty := New("tok")
	empty.DownstreamAllowlist = map[string][]string{"github.com/o/target": {"o/repo-a"}}
	empty.mu.Lock()
	empty.runs["run-1"] = model.Run{ID: "run-1"}
	empty.mu.Unlock()
	if empty.downstreamAllowed(ctx, p, "github.com/o/target") {
		t.Fatal("empty identity must not match a source entry")
	}
	// Bare full-name alias matches.
	alias := fcEffectsServerWithRun(t)
	alias.DownstreamAllowlist = map[string][]string{"github.com/o/target": {"o/repo-a"}}
	if !alias.downstreamAllowed(ctx, p, "github.com/o/target") {
		t.Fatal("bare source alias must match")
	}
	// Non-matching source denies.
	other := fcEffectsServerWithRun(t)
	other.DownstreamAllowlist = map[string][]string{"github.com/o/target": {"github.com/o/other"}}
	if other.downstreamAllowed(ctx, p, "github.com/o/target") {
		t.Fatal("non-listed source must deny")
	}
	// DB parent-run read failure denies.
	s2, f, _, _ := cacheFixture(t)
	s2.DownstreamAllowlist = map[string][]string{"github.com/o/target": {"github.com/o/repo-a"}}
	s2.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run read down")}
	if s2.downstreamAllowed(ctx, p, "github.com/o/target") {
		t.Fatal("run read failure must deny")
	}
}

const fcInputPipeline = `version: 1
inputs:
  k:
    default: v
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
`

func TestFlowDownstreamDispatchValidation(t *testing.T) {
	s := fcEffectsServerWithRun(t)
	ctx := context.Background()
	if err := s.dispatchDownstream(ctx, forge.OutboxItem{Payload: []byte("{")}); err == nil {
		t.Fatal("invalid payload must fail")
	}
	payload, _ := json.Marshal(downstreamPayload{ParentJobID: "p"})
	if err := s.dispatchDownstream(ctx, forge.OutboxItem{Payload: payload}); err == nil {
		t.Fatal("incomplete payload must fail")
	}
	// Link read failure.
	s2, f, _, _ := cacheFixture(t)
	s2.DB = &fcStore{dbFakeStore: f, getDownstreamLinkErr: errors.New("link read down")}
	payload, _ = json.Marshal(downstreamPayload{ParentJobID: "p", ParentRunID: "run-c", TargetRepo: "o/target", TargetRef: "refs/heads/main"})
	if err := s2.dispatchDownstream(ctx, forge.OutboxItem{Payload: payload}); err == nil {
		t.Fatal("link read failure must propagate")
	}
}

func TestFlowDownstreamDispatchReserveAndFetchFailures(t *testing.T) {
	ctx := context.Background()
	// Reserve error.
	s, f, _, _ := cacheFixture(t)
	s.DownstreamAllowlist = map[string][]string{"o/target": {}}
	s.DB = &fcStore{dbFakeStore: f, reserveDownstreamErr: errors.New("reserve down")}
	payload, _ := json.Marshal(downstreamPayload{ParentJobID: "p", ParentRunID: "run-c", TargetRepo: "o/target", TargetRef: "refs/heads/main"})
	if err := s.dispatchDownstream(ctx, forge.OutboxItem{Payload: payload}); err == nil {
		t.Fatal("reserve failure must propagate")
	}

	// Fetch failure releases the reservation (memory mode).
	s2 := fcEffectsServerWithRun(t)
	s2.DownstreamAllowlist = map[string][]string{"o/target": {}}
	s2.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) {
		return "", errors.New("fetch down")
	}
	if err := s2.dispatchDownstream(ctx, forge.OutboxItem{Payload: payload}); err == nil {
		t.Fatal("fetch failure must propagate")
	}
	s2.mu.Lock()
	link := s2.downstreamLinks[downstreamLinkKey("p", "o/target", "refs/heads/main")]
	s2.mu.Unlock()
	if link.Reserved {
		t.Fatal("failed fetch must release the reservation")
	}
}

func TestFlowDownstreamDispatchTargetIdentityFallback(t *testing.T) {
	ctx := context.Background()
	s := fcEffectsServerWithRun(t)
	// A persisted link without TargetRepoID forces the host derivation, and
	// inputs ride into the child metadata.
	s.mu.Lock()
	s.downstreamLinks[downstreamLinkKey("p", "o/target", "refs/heads/main")] = storage.DownstreamLink{
		ParentJobID: "p", TargetRepo: "o/target", TargetRef: "refs/heads/main", TargetForge: "github",
	}
	s.mu.Unlock()
	s.DownstreamAllowlist = map[string][]string{"github.com/o/target": {}}
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		if repo != "o/target" || ref != "refs/heads/main" {
			t.Fatalf("fetcher args = %q %q", repo, ref)
		}
		return fcInputPipeline, nil
	}
	payload, _ := json.Marshal(downstreamPayload{
		ParentJobID: "p", ParentRunID: "run-1", TargetRepo: "o/target", TargetRef: "refs/heads/main",
		LaunchToken: "tok", Event: "upstream", Inputs: map[string]string{"k": "v"},
	})
	if err := s.dispatchDownstream(ctx, forge.OutboxItem{Payload: payload}); err != nil {
		t.Fatalf("dispatch = %v", err)
	}
	s.mu.Lock()
	childID := ""
	for _, r := range s.runs {
		if r.ID != "run-1" {
			childID = r.ID
		}
	}
	s.mu.Unlock()
	if childID == "" {
		t.Fatal("child run not enqueued")
	}
	// A launched link is skipped by subsequent dispatches.
	if err := s.dispatchDownstream(ctx, forge.OutboxItem{Payload: payload}); err != nil {
		t.Fatalf("launched replay = %v", err)
	}
}

func TestFlowDownstreamReserveMemoryBranches(t *testing.T) {
	ctx := context.Background()
	s := New("tok")
	won, err := s.reserveDownstreamLaunch(ctx, "p", "o/r", "refs/heads/main", "tok-1")
	if err != nil || !won {
		t.Fatalf("fresh reserve = %v %v", won, err)
	}
	// Already reserved: not won.
	if won, err := s.reserveDownstreamLaunch(ctx, "p", "o/r", "refs/heads/main", "tok-2"); err != nil || won {
		t.Fatalf("double reserve = %v %v", won, err)
	}
	s.mu.Lock()
	link := s.downstreamLinks[downstreamLinkKey("p", "o/r", "refs/heads/main")]
	link.Reserved = false
	link.ReservedAt = nil
	link.LaunchToken = ""
	s.downstreamLinks[downstreamLinkKey("p", "o/r", "refs/heads/main")] = link
	s.mu.Unlock()
	if won, err := s.reserveDownstreamLaunch(ctx, "p", "o/r", "refs/heads/main", "tok-3"); err != nil || !won {
		t.Fatalf("re-reserve = %v %v", won, err)
	}
	s.mu.Lock()
	link = s.downstreamLinks[downstreamLinkKey("p", "o/r", "refs/heads/main")]
	launched := link.LaunchToken == "tok-3"
	s.mu.Unlock()
	if !launched {
		t.Fatal("empty launch token must be filled on re-reserve")
	}
	// Persist failure rolls the reservation back: fresh-link path and
	// existing-link path.
	s.store = storage.New(t.TempDir())
	block := t.TempDir()
	if err := storage.AtomicWriteFile(block+"/x", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.store.Root = block + "/x"
	if _, err := s.reserveDownstreamLaunch(ctx, "p2", "o/r", "refs/heads/main", "tok-4"); err == nil {
		t.Fatal("persist failure must be reported by the reserve")
	}
	s.mu.Lock()
	s.downstreamLinks[downstreamLinkKey("p3", "o/r", "refs/heads/main")] = storage.DownstreamLink{ParentJobID: "p3", TargetRepo: "o/r", TargetRef: "refs/heads/main"}
	s.mu.Unlock()
	if won, err := s.reserveDownstreamLaunch(ctx, "p3", "o/r", "refs/heads/main", "tok-5"); err == nil || won {
		t.Fatalf("existing-link persist failure = %v %v", won, err)
	}
	s.mu.Lock()
	rolled := s.downstreamLinks[downstreamLinkKey("p3", "o/r", "refs/heads/main")]
	s.mu.Unlock()
	if rolled.Reserved || rolled.ReservedAt != nil {
		t.Fatalf("failed reserve did not roll back: %+v", rolled)
	}
}

func TestFlowDownstreamReleaseBranches(t *testing.T) {
	ctx := context.Background()
	// DB error path logs and returns.
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, releaseDownstreamErr: errors.New("release down")}
	s.releaseDownstreamReservation(ctx, "p", "o/r", "refs/heads/main")

	// Memory: missing link and launched link are no-ops.
	s2 := New("tok")
	s2.releaseDownstreamReservation(ctx, "missing", "o/r", "refs/heads/main")
	s2.mu.Lock()
	s2.downstreamLinks[downstreamLinkKey("p", "o/r", "refs/heads/main")] = storage.DownstreamLink{ParentJobID: "p", TargetRepo: "o/r", TargetRef: "refs/heads/main", ChildRunID: "child", Reserved: true}
	s2.mu.Unlock()
	s2.releaseDownstreamReservation(ctx, "p", "o/r", "refs/heads/main")
	s2.mu.Lock()
	link := s2.downstreamLinks[downstreamLinkKey("p", "o/r", "refs/heads/main")]
	s2.mu.Unlock()
	if !link.Reserved {
		t.Fatal("launched links must keep their reservation state")
	}
}

func TestFlowDownstreamRecoverReservations(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	// DB error path.
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, expireReservationsErr: errors.New("expire down")}
	s.recoverDownstreamReservations(ctx, now)

	// Memory: stale reservations expire, fresh and launched ones survive.
	s2 := New("tok")
	old := now.Add(-2 * time.Hour)
	fresh := now.Add(-time.Minute)
	s2.mu.Lock()
	s2.downstreamLinks[downstreamLinkKey("stale", "o/r", "refs/heads/main")] = storage.DownstreamLink{ParentJobID: "stale", TargetRepo: "o/r", TargetRef: "refs/heads/main", Reserved: true, ReservedAt: &old}
	s2.downstreamLinks[downstreamLinkKey("fresh", "o/r", "refs/heads/main")] = storage.DownstreamLink{ParentJobID: "fresh", TargetRepo: "o/r", TargetRef: "refs/heads/main", Reserved: true, ReservedAt: &fresh}
	s2.downstreamLinks[downstreamLinkKey("launched", "o/r", "refs/heads/main")] = storage.DownstreamLink{ParentJobID: "launched", TargetRepo: "o/r", TargetRef: "refs/heads/main", Reserved: true, ChildRunID: "child"}
	s2.mu.Unlock()
	s2.recoverDownstreamReservations(ctx, now)
	s2.mu.Lock()
	stale := s2.downstreamLinks[downstreamLinkKey("stale", "o/r", "refs/heads/main")]
	freshLink := s2.downstreamLinks[downstreamLinkKey("fresh", "o/r", "refs/heads/main")]
	s2.mu.Unlock()
	if stale.Reserved {
		t.Fatal("stale reservation must expire")
	}
	if !freshLink.Reserved {
		t.Fatal("fresh reservation must survive")
	}
}

func TestFlowDownstreamAppendRunBranches(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	// Memory: missing run is a no-op.
	s := New("tok")
	s.appendDownstreamRun(ctx, "missing", "child")

	// Memory: append dedupes and refreshes the parent.
	s2 := fcEffectsServerWithRun(t)
	s2.mu.Lock()
	s2.runs["child-1"] = model.Run{ID: "child-1", Status: model.StatusRunning, CreatedAt: now}
	s2.jobs["j1"] = model.Job{ID: "j1", RunID: "run-1", Status: model.StatusSuccess}
	s2.mu.Unlock()
	s2.appendDownstreamRun(ctx, "run-1", "child-1")
	s2.appendDownstreamRun(ctx, "run-1", "child-1")
	s2.mu.Lock()
	run := s2.runs["run-1"]
	s2.mu.Unlock()
	if len(run.DownstreamRuns) != 1 {
		t.Fatalf("downstream runs = %v", run.DownstreamRuns)
	}
	if run.Status != model.StatusRunning {
		t.Fatalf("parent status = %s, want running while the child is in flight", run.Status)
	}
}

func TestFlowDownstreamAppendRunDB(t *testing.T) {
	ctx := context.Background()
	// Store without the run-downstream extension: adjust only.
	s, f, _, _ := cacheFixture(t)
	s.DB = fcPlainStore{f}
	s.appendDownstreamRun(ctx, "run-c", "child")
	// Append failure is logged, then the adjustment still runs.
	s2, f2, _, _ := cacheFixture(t)
	s2.DB = &fcStore{dbFakeStore: f2, appendDownstreamErr: errors.New("append down")}
	s2.appendDownstreamRun(ctx, "run-c", "child")
	// Successful append.
	s3, f3, _, _ := cacheFixture(t)
	s3.appendDownstreamRun(ctx, "run-c", "child")
	f3.mu.Lock()
	run := f3.runs["run-c"]
	f3.mu.Unlock()
	if len(run.DownstreamRuns) != 1 {
		t.Fatalf("db downstream runs = %v", run.DownstreamRuns)
	}
}

func TestFlowDownstreamFetchPipelineDefaultForgeSuccess(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"content": base64.StdEncoding.EncodeToString([]byte("pipeline body")), "encoding": "base64"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	s := New("tok")
	s.SetForgeBaseURL("github", srv.URL)
	got, err := s.fetchDownstreamPipeline(context.Background(), "mystery", "", "o/r", "refs/heads/main")
	if err != nil || got != "pipeline body" {
		t.Fatalf("default forge fetch = %q %v", got, err)
	}
}

func TestFlowDownstreamFetchPipelineBranches(t *testing.T) {
	ctx := context.Background()
	s := New("tok")
	s.SetForgeBaseURL("github", "http://127.0.0.1:1")
	s.SetForgeBaseURL("gitlab", "http://127.0.0.1:1")
	s.SetForgeBaseURL("forgejo", "http://127.0.0.1:1")
	for _, kind := range []string{"github", "gitlab", "forgejo", "mystery"} {
		if _, err := s.fetchDownstreamPipeline(ctx, kind, "", "o/r", "refs/heads/main"); err == nil {
			t.Fatalf("fetch for %q must fail against a closed endpoint", kind)
		}
		if _, err := s.fetchDownstreamPipeline(ctx, kind, "http://127.0.0.1:1", "o/r", "refs/heads/main"); err == nil {
			t.Fatalf("fetch for %q with base override must fail", kind)
		}
	}
	s.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) {
		return "pipeline", nil
	}
	if got, err := s.fetchDownstreamPipeline(ctx, "github", "", "o/r", "main"); err != nil || got != "pipeline" {
		t.Fatalf("fetcher seam = %q %v", got, err)
	}
}

func TestFlowDownstreamRefreshParentsDB(t *testing.T) {
	ctx := context.Background()
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listRunsErr: errors.New("run list down")}
	s.refreshDownstreamParentsDB(ctx, "child")

	s2, f2, _, _ := cacheFixture(t)
	f2.mu.Lock()
	f2.runs["parent"] = model.Run{ID: "parent", Status: model.StatusSuccess, DownstreamRuns: []string{"child"}, CreatedAt: time.Now().UTC()}
	f2.jobs["p1"] = model.Job{ID: "p1", RunID: "parent", Status: model.StatusSuccess}
	f2.runs["child"] = model.Run{ID: "child", Status: model.StatusSuccess}
	f2.mu.Unlock()
	s2.refreshDownstreamParentsDB(ctx, "child")
	f2.mu.Lock()
	parent := f2.runs["parent"]
	f2.mu.Unlock()
	if parent.Status != model.StatusSuccess {
		t.Fatalf("parent after refresh = %s", parent.Status)
	}
}

func TestFlowDownstreamAdjustRunForChildren(t *testing.T) {
	ctx := context.Background()
	newStore := func(t *testing.T) (*Server, *dbFakeStore) {
		s, f, _, _ := cacheFixture(t)
		f.mu.Lock()
		f.runs["parent"] = model.Run{ID: "parent", Status: model.StatusRunning, DownstreamRuns: []string{"child"}}
		f.jobs["p1"] = model.Job{ID: "p1", RunID: "parent", Status: model.StatusSuccess}
		f.runs["child"] = model.Run{ID: "child", Status: model.StatusRunning}
		f.mu.Unlock()
		return s, f
	}

	// Missing run.
	s := New("tok")
	s.DB = newDBFakeStore()
	s.adjustRunForChildrenDB(ctx, "missing")

	// No downstream runs.
	s, f := newStore(t)
	f.mu.Lock()
	run := f.runs["parent"]
	run.DownstreamRuns = nil
	f.runs["parent"] = run
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")

	// Terminal non-success run.
	s, f = newStore(t)
	f.mu.Lock()
	run = f.runs["parent"]
	run.Status = model.StatusFailure
	f.runs["parent"] = run
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")

	// Own jobs list failure.
	s, f = newStore(t)
	s.DB = &fcStore{dbFakeStore: f, listJobsErr: errors.New("job list down")}
	s.adjustRunForChildrenDB(ctx, "parent")

	// Own job still running: no adjustment.
	s, f = newStore(t)
	f.mu.Lock()
	f.jobs["p1"] = model.Job{ID: "p1", RunID: "parent", Status: model.StatusRunning}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")

	// Own failure and cancellation short-circuit.
	s, f = newStore(t)
	f.mu.Lock()
	f.jobs["p1"] = model.Job{ID: "p1", RunID: "parent", Status: model.StatusFailure}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")
	s, f = newStore(t)
	f.mu.Lock()
	f.jobs["p1"] = model.Job{ID: "p1", RunID: "parent", Status: model.StatusCancelled}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")

	// Child still in flight: the parent is reopened.
	s, f = newStore(t)
	f.mu.Lock()
	run = f.runs["parent"]
	run.Status = model.StatusSuccess
	f.runs["parent"] = run
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")
	f.mu.Lock()
	run = f.runs["parent"]
	f.mu.Unlock()
	if run.Status != model.StatusRunning {
		t.Fatalf("reopened parent = %s, want running", run.Status)
	}

	// Missing child rows are skipped; an all-terminal success set finalizes
	// nothing.
	s, f = newStore(t)
	f.mu.Lock()
	f.runs["parent"] = model.Run{ID: "parent", Status: model.StatusRunning, DownstreamRuns: []string{"missing-child"}}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")

	// Child failure finalizes the parent as failed.
	s, f = newStore(t)
	f.mu.Lock()
	f.runs["child"] = model.Run{ID: "child", Status: model.StatusFailure}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")
	f.mu.Lock()
	parent := f.runs["parent"]
	f.mu.Unlock()
	if parent.Status != model.StatusFailure || parent.FinishedAt == nil {
		t.Fatalf("failed parent = %+v", parent)
	}

	// Child cancellation finalizes the parent as cancelled.
	s, f = newStore(t)
	f.mu.Lock()
	f.runs["child"] = model.Run{ID: "child", Status: model.StatusCancelled}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")
	f.mu.Lock()
	parent = f.runs["parent"]
	f.mu.Unlock()
	if parent.Status != model.StatusCancelled {
		t.Fatalf("cancelled parent = %+v", parent)
	}

	// Store update failure is logged, never fatal.
	s, f = newStore(t)
	s.DB = &fcStore{dbFakeStore: f, updateRunStatusErr: errors.New("update down")}
	f.mu.Lock()
	f.runs["child"] = model.Run{ID: "child", Status: model.StatusFailure}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")

	// Reopen failure is ignored.
	s, f = newStore(t)
	s.DB = &fcStore{dbFakeStore: f, reopenRunErr: errors.New("reopen down")}
	f.mu.Lock()
	run = f.runs["parent"]
	run.Status = model.StatusSuccess
	f.runs["parent"] = run
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")

	// Child read failure is skipped like a missing child.
	s, f = newStore(t)
	s.DB = &fcStore{dbFakeStore: f, getRunErrFor: map[string]error{"child": errors.New("child read down")}}
	s.adjustRunForChildrenDB(ctx, "parent")
	f.mu.Lock()
	parent = f.runs["parent"]
	f.mu.Unlock()
	if parent.Status != model.StatusRunning {
		t.Fatalf("unreadable child changed the parent: %+v", parent)
	}

	// Cancelled finalize failure is logged, never fatal.
	s, f = newStore(t)
	s.DB = &fcStore{dbFakeStore: f, updateRunStatusErr: errors.New("update down")}
	f.mu.Lock()
	f.runs["child"] = model.Run{ID: "child", Status: model.StatusCancelled}
	f.mu.Unlock()
	s.adjustRunForChildrenDB(ctx, "parent")
}

func TestFlowDownstreamApplyChildrenLocked(t *testing.T) {
	now := time.Now().UTC()
	// No children: untouched.
	s := New("tok")
	run := model.Run{ID: "run-1", Status: model.StatusSuccess}
	s.mu.Lock()
	s.applyDownstreamChildrenLocked("run-1", &run)
	s.mu.Unlock()
	if run.Status != model.StatusSuccess {
		t.Fatalf("childless run = %s", run.Status)
	}
	// Non-success run: untouched.
	run = model.Run{ID: "run-1", Status: model.StatusFailure, DownstreamRuns: []string{"child"}}
	s.mu.Lock()
	s.applyDownstreamChildrenLocked("run-1", &run)
	s.mu.Unlock()
	if run.Status != model.StatusFailure {
		t.Fatalf("non-success run = %s", run.Status)
	}
	// Missing child rows are skipped; an in-flight child keeps the run open.
	run = model.Run{ID: "run-1", Status: model.StatusSuccess, DownstreamRuns: []string{"ghost", "child"}}
	s.mu.Lock()
	s.runs["child"] = model.Run{ID: "child", Status: model.StatusRunning}
	s.applyDownstreamChildrenLocked("run-1", &run)
	s.mu.Unlock()
	if run.Status != model.StatusRunning || run.FinishedAt != nil {
		t.Fatalf("in-flight child run = %+v", run)
	}
	// Cancelled child inherits once every child is terminal.
	run = model.Run{ID: "run-1", Status: model.StatusSuccess, DownstreamRuns: []string{"child"}, FinishedAt: &now}
	s.mu.Lock()
	s.runs["child"] = model.Run{ID: "child", Status: model.StatusCancelled}
	s.applyDownstreamChildrenLocked("run-1", &run)
	s.mu.Unlock()
	if run.Status != model.StatusCancelled {
		t.Fatalf("cancelled child run = %+v", run)
	}
	// Failed child wins over cancellation.
	run = model.Run{ID: "run-1", Status: model.StatusSuccess, DownstreamRuns: []string{"child", "child2"}}
	s.mu.Lock()
	s.runs["child2"] = model.Run{ID: "child2", Status: model.StatusBlocked}
	s.applyDownstreamChildrenLocked("run-1", &run)
	s.mu.Unlock()
	if run.Status != model.StatusFailure {
		t.Fatalf("failed child run = %+v", run)
	}
}
