package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const fcOneChildFragment = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`

func fcDynamicServer(t *testing.T) (*Server, Task) {
	t.Helper()
	s, _ := trustedGenerateServer(t)
	_, task := leaseRunJob(t, s)
	return s, task
}

func fcStoredParent(t *testing.T, s *Server, jobID string) model.Job {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		t.Fatalf("parent %s not found", jobID)
	}
	return j
}

func fcFragment(t *testing.T, raw string) generatedFragment {
	t.Helper()
	var frag generatedFragment
	if err := json.Unmarshal([]byte(fragmentBody(t, raw)), &frag); err != nil {
		t.Fatal(err)
	}
	return frag
}

func TestFlowDynamicDecodeLimit(t *testing.T) {
	s, task := fcDynamicFixtureHTTP(t)
	body := strings.Repeat("x", maxGeneratedFragmentBytes+16)
	w := doJSONHeaders(t, s, "POST", "/api/v1/jobs/"+task.Job.ID+"/generated", "token", body, leaseHeaders(task, task.Job.LeaseRunnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized fragment = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func fcDynamicFixtureHTTP(t *testing.T) (*Server, Task) {
	t.Helper()
	s, _ := trustedGenerateServer(t)
	_, task := leaseRunJob(t, s)
	return s, task
}

func TestFlowDynamicVerifyParentState(t *testing.T) {
	base := model.Job{ID: "p", Status: model.StatusRunning}
	if err := verifyGeneratedFragmentGraph(base, base, 1, 0, 1); err != nil {
		t.Fatalf("valid parent graph state = %v", err)
	}
	if err := verifyGeneratedFragmentGraph(base, model.Job{ID: "other", Status: model.StatusRunning}, 1, 0, 1); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("identity change = %v, want a changed-parent refusal", err)
	}
	if err := verifyGeneratedFragmentGraph(base, base, 1, maxJobsPerRun, 1); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("run cap = %v, want the limit refusal", err)
	}
}

func TestFlowDynamicFragmentShapeErrors(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	ctx := context.Background()

	// Missing fragment id.
	frag := fcFragment(t, fcOneChildFragment)
	frag.FragmentID = ""
	if _, err := s.processGeneratedFragment(ctx, parent, frag); err == nil || !strings.Contains(err.Error(), "missing fragment_id") {
		t.Fatalf("missing id error = %v", err)
	}
	// Mismatched fragment id.
	frag = fcFragment(t, fcOneChildFragment)
	frag.FragmentID = strings.Repeat("0", 64)
	if _, err := s.processGeneratedFragment(ctx, parent, frag); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched id error = %v", err)
	}
	// No jobs.
	empty := fcFragment(t, `{"jobs":{},"deps":{}}`)
	if _, err := s.processGeneratedFragment(ctx, parent, empty); err == nil || !strings.Contains(err.Error(), "no jobs") {
		t.Fatalf("empty fragment error = %v", err)
	}
	// Matrix declared inside a fragment.
	matrix := fcFragment(t, `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","matrix":{"os":["linux"]},"steps":[{"run":"echo"}]}},"deps":{}}`)
	if _, err := s.processGeneratedFragment(ctx, parent, matrix); err == nil || !strings.Contains(err.Error(), "matrix") {
		t.Fatalf("matrix fragment error = %v", err)
	}
	// Deps referencing an unknown job key.
	unknownDepKey := fcFragment(t, `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo"}]}},"deps":{"ghost":[]}}`)
	if _, err := s.processGeneratedFragment(ctx, parent, unknownDepKey); err == nil || !strings.Contains(err.Error(), "unknown generated job") {
		t.Fatalf("unknown dep key error = %v", err)
	}
	// Self dependency.
	selfDep := fcFragment(t, `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo"}]}},"deps":{"child-a":["child-a"]}}`)
	if _, err := s.processGeneratedFragment(ctx, parent, selfDep); err == nil || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("self dep error = %v", err)
	}
	// Duplicate dependency.
	dupDep := fcFragment(t, `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo"}]},"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo"}]}},"deps":{"child-a":["child-b","child-b"]}}`)
	if _, err := s.processGeneratedFragment(ctx, parent, dupDep); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate dep error = %v", err)
	}
	// Strict pipeline validation failure: native runtime with an image.
	invalidSpec := fcFragment(t, `{"jobs":{"child-a":{"runtime":"native","image":"alpine:3","steps":[{"run":"echo"}]}},"deps":{}}`)
	if _, err := s.processGeneratedFragment(ctx, parent, invalidSpec); err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatalf("invalid spec error = %v", err)
	}
	// Depth limit exceeded.
	deep := parent
	deep.DynamicDepth = maxDynamicDepth
	if _, err := s.processGeneratedFragment(ctx, deep, fcFragment(t, fcOneChildFragment)); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("depth error = %v", err)
	}
	// Too many jobs per fragment.
	var b strings.Builder
	b.WriteString(`{"jobs":{`)
	for i := 0; i <= maxGeneratedJobsPerFragment; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"j` + jsonInt(i) + `":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo"}]}`)
	}
	b.WriteString(`},"deps":{}}`)
	if _, err := s.processGeneratedFragment(ctx, parent, fcFragment(t, b.String())); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("job-count limit error = %v", err)
	}
}

// TestFlowDynamicFragmentHonorsParentGenerateEnvelope pins the parent policy:
// the compiled parent's generate.max_jobs/max_depth tighten the fragment
// ceilings below the global caps, and a legacy parent without a compiled
// payload keeps the global caps.
func TestFlowDynamicFragmentHonorsParentGenerateEnvelope(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	ctx := context.Background()

	raw, err := json.Marshal(map[string]any{"generate": map[string]any{"max_jobs": 1, "max_depth": 1}})
	if err != nil {
		t.Fatal(err)
	}
	enveloped := parent
	enveloped.CompiledJobPayload = &model.CompiledJobPayload{EffectiveJob: json.RawMessage(raw)}

	twoJobs := fcFragment(t, `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo"}]},"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo"}]}},"deps":{}}`)
	if _, err := s.processGeneratedFragment(ctx, enveloped, twoJobs); err == nil || !strings.Contains(err.Error(), "limit is 1") {
		t.Fatalf("parent max_jobs envelope = %v, want the limit-is-1 refusal", err)
	}

	deep := enveloped
	deep.DynamicDepth = 1 // child depth 2 > parent max_depth 1
	if _, err := s.processGeneratedFragment(ctx, deep, fcFragment(t, fcOneChildFragment)); err == nil || !strings.Contains(err.Error(), "maximum 1") {
		t.Fatalf("parent max_depth envelope = %v, want the maximum-1 refusal", err)
	}

	// A legacy parent (no compiled payload) keeps the global caps.
	if got, err := effectiveGeneratedJobsLimit(parent); err != nil || got != maxGeneratedJobsPerFragment {
		t.Fatalf("legacy jobs limit = %d err=%v, want the global %d", got, err, maxGeneratedJobsPerFragment)
	}
	if got, err := effectiveGeneratedDepthLimit(parent); err != nil || got != maxDynamicDepth {
		t.Fatalf("legacy depth limit = %d err=%v, want the global %d", got, err, maxDynamicDepth)
	}
	// A more permissive parent cannot loosen the global caps.
	looseRaw, _ := json.Marshal(map[string]any{"generate": map[string]any{"max_jobs": 100000, "max_depth": 100}})
	loose := parent
	loose.CompiledJobPayload = &model.CompiledJobPayload{EffectiveJob: json.RawMessage(looseRaw)}
	if got, err := effectiveGeneratedJobsLimit(loose); err != nil || got != maxGeneratedJobsPerFragment {
		t.Fatalf("loose jobs limit = %d err=%v, want the global %d", got, err, maxGeneratedJobsPerFragment)
	}
	if got, err := effectiveGeneratedDepthLimit(loose); err != nil || got != maxDynamicDepth {
		t.Fatalf("loose depth limit = %d err=%v, want the global %d", got, err, maxDynamicDepth)
	}

	// A CURRENT-format payload that cannot be decoded fails closed instead of
	// widening the envelope back to the global caps.
	corrupt := parent
	corrupt.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: json.RawMessage(`{"generate":{"max_jobs":"not-a-number"}}`)}
	if _, err := effectiveGeneratedJobsLimit(corrupt); err == nil {
		t.Fatal("corrupt current-schema jobs envelope must fail closed")
	}
	if _, err := effectiveGeneratedDepthLimit(corrupt); err == nil {
		t.Fatal("corrupt current-schema depth envelope must fail closed")
	}
	missing := parent
	missing.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1}
	if _, err := effectiveGeneratedJobsLimit(missing); err == nil {
		t.Fatal("current-schema payload without an effective job must fail closed")
	}
	if _, err := s.processGeneratedFragment(ctx, corrupt, fcFragment(t, fcOneChildFragment)); err == nil {
		t.Fatal("fragment against a corrupt parent payload must be refused")
	}
}

func TestFlowDynamicChildGraphDenied(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	parent.Trusted = false
	parent.CompiledJobPayload = nil
	if _, err := s.processGeneratedFragment(context.Background(), parent, fcFragment(t, fcOneChildFragment)); err == nil || !strings.Contains(err.Error(), "capabilities") {
		t.Fatalf("capability denial = %v", err)
	}
}

func TestFlowDynamicMemoryParentDisappeared(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	parent.ID = "ghost-parent"
	if _, err := s.processGeneratedFragment(context.Background(), parent, fcFragment(t, fcOneChildFragment)); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("ghost parent error = %v", err)
	}
}

func TestFlowDynamicMemoryPersistFailure(t *testing.T) {
	s, task := fcDynamicServer(t)
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.store.Root = block
	if _, err := s.processGeneratedFragment(context.Background(), fcStoredParent(t, s, task.Job.ID), fcFragment(t, fcOneChildFragment)); err == nil {
		t.Fatal("persist failure must propagate")
	}
}

func TestFlowDynamicMemoryConcurrentReplay(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	frag := fcFragment(t, fcOneChildFragment)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*generatedResponse, 16)
	errs := make([]error, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = s.processGeneratedFragment(context.Background(), parent, frag)
		}(i)
	}
	close(start)
	wg.Wait()
	created := 0
	for i, res := range results {
		if errs[i] != nil {
			t.Fatalf("concurrent generation %d: %v", i, errs[i])
		}
		if res == nil || len(res.JobIDs) != 1 {
			t.Fatalf("concurrent response %d: %+v", i, res)
		}
		if !res.Replayed {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created responses = %d, want exactly 1", created)
	}
	s.mu.Lock()
	children := 0
	for _, j := range s.jobs {
		if j.DynamicDepth == 1 {
			children++
		}
	}
	s.mu.Unlock()
	if children != 1 {
		t.Fatalf("child jobs = %d, want 1", children)
	}
}

func fcDynamicDBFixture(t *testing.T) (*Server, *dbFakeStore, Task) {
	t.Helper()
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true), CrossRepoTrigger: boolPtr(true)},
		},
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, task := leaseRunJob(t, s)
	return s, f, task
}

func TestFlowDynamicDBListJobsFailure(t *testing.T) {
	s, f, task := fcDynamicDBFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listJobsErr: errors.New("job list down")}
	if _, err := s.processGeneratedFragment(context.Background(), fcStoredParentDB(t, f, task.Job.ID), fcFragment(t, fcOneChildFragment)); err == nil {
		t.Fatal("db list jobs failure must propagate")
	}
}

func TestFlowDynamicDBReceiptReadFailure(t *testing.T) {
	s, f, task := fcDynamicDBFixture(t)
	s.DB = &fcStore{dbFakeStore: f, fragmentGetErr: errors.New("fragment table down")}
	if _, err := s.processGeneratedFragment(context.Background(), fcStoredParentDB(t, f, task.Job.ID), fcFragment(t, fcOneChildFragment)); err == nil {
		t.Fatal("receipt read failure must propagate")
	}
}

func TestFlowDynamicDBWithoutTxStore(t *testing.T) {
	s, f, task := fcDynamicDBFixture(t)
	s.DB = fcPlainStore{f}
	if _, err := s.processGeneratedFragment(context.Background(), fcStoredParentDB(t, f, task.Job.ID), fcFragment(t, fcOneChildFragment)); err == nil || !strings.Contains(err.Error(), "transactional") {
		t.Fatalf("no-tx store error = %v", err)
	}
}

func TestFlowDynamicDBTxReplay(t *testing.T) {
	s, f, task := fcDynamicDBFixture(t)
	frag := fcFragment(t, fcOneChildFragment)
	parent := fcStoredParentDB(t, f, task.Job.ID)
	first, err := s.processGeneratedFragment(context.Background(), parent, frag)
	if err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	// Force the fast-path receipt read to miss so the transaction's own
	// dedupe answers the replay.
	s.DB = &fcStore{dbFakeStore: f, fragmentGetMiss: true}
	replay, err := s.processGeneratedFragment(context.Background(), parent, frag)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.Replayed || strings.Join(replay.JobIDs, ",") != strings.Join(first.JobIDs, ",") {
		t.Fatalf("replay = %+v, first = %+v", replay, first)
	}
}

func TestFlowDynamicReceiptWithoutStore(t *testing.T) {
	s, f, _ := fcDynamicDBFixture(t)
	s.DB = fcPlainStore{f}
	if _, found, err := s.generatedFragmentReceipt(context.Background(), "p", storage.GeneratedFragmentMutationSlotDefault, "f"); err != nil || found {
		t.Fatalf("receipt without store = %v %v", found, err)
	}
}

func fcStoredParentDB(t *testing.T, f *dbFakeStore, jobID string) model.Job {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[jobID]
	if !ok {
		t.Fatalf("parent %s not found", jobID)
	}
	return j
}

func TestFlowDynamicRepoIdentityHelpers(t *testing.T) {
	if got := repoFullNameOf(model.Job{RepoURL: "https://github.com/o/r.git"}); got != "github.com/o/r" {
		t.Fatalf("repoFullNameOf = %q", got)
	}
	if got := repoFullNameOf(model.Job{RepoURL: "not-a-url"}); got != "not-a-url" {
		t.Fatalf("repoFullNameOf bare = %q", got)
	}
	if got := repoFullNameOf(model.Job{RepoURL: "http://[::1"}); got != "http://[::1" {
		t.Fatalf("repoFullNameOf parse error = %q", got)
	}
	id := repoIdentityOfJob(model.Job{RepoURL: "https://github.com/o/r.git"})
	if id.RepoID != "github.com/o/r" || id.RepoFullName != "github.com/o/r" {
		t.Fatalf("repoIdentityOfJob = %+v", id)
	}
	id = repoIdentityOfJob(model.Job{RepoID: "gitlab.com/o/r", RepoURL: "https://gitlab.com/o/r.git", RepoFullName: "o/r"})
	if id.RepoID != "gitlab.com/o/r" || id.RepoFullName != "o/r" {
		t.Fatalf("repoIdentityOfJob stored = %+v", id)
	}
}

// TestFlowDynamicCorruptEffectivePolicyFailsClosed pins the policy-metadata
// rule: a current-format parent whose effective policy cannot be decoded must
// refuse generated children instead of falling back to (possibly broader)
// trust defaults.
func TestFlowDynamicCorruptEffectivePolicyFailsClosed(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	ctx := context.Background()

	corrupt := parent
	effJob, err := json.Marshal(map[string]any{"generate": map[string]any{"max_jobs": 10}})
	if err != nil {
		t.Fatal(err)
	}
	corrupt.CompiledJobPayload = &model.CompiledJobPayload{
		SchemaVersion:   1,
		EffectiveJob:    json.RawMessage(effJob),
		EffectivePolicy: json.RawMessage(`{"container":"not-a-bool"}`),
	}
	if _, err := s.processGeneratedFragment(ctx, corrupt, fcFragment(t, fcOneChildFragment)); err == nil || !strings.Contains(err.Error(), "effective policy") {
		t.Fatalf("corrupt policy fragment = %v, want a fail-closed policy error", err)
	}
	if _, err := s.generatedChildCapabilities(corrupt); err == nil {
		t.Fatal("corrupt parent policy produced a capability set")
	}

	missing := parent
	missing.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1}
	if _, err := s.processGeneratedFragment(ctx, missing, fcFragment(t, fcOneChildFragment)); err == nil {
		t.Fatal("current-format parent without an effective policy admitted a fragment")
	}
}
