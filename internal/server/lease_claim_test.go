package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// ---------------------------------------------------------------------------
// cancel/supersede runner-slot release (HIGH-6)
// ---------------------------------------------------------------------------

// registerLeaseRunner registers a capacity-1 container runner through the
// HTTP surface and returns it.
func registerLeaseRunner(t *testing.T, s *Server, token string) model.Runner {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", token, `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	return ri
}

// submitLeaseRun submits one run through the HTTP surface and returns it.
func submitLeaseRun(t *testing.T, s *Server, token, repo string) model.Run {
	t.Helper()
	body := `{"repo_url":"` + repo + `","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","pipeline":` + jsonString(testPipeline) + `}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", token, body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	return run
}

// TestCancelRunReleasesRunnerSlotMemory: cancelling a running job frees the
// capacity-1 runner's slot immediately; the next poll leases another job.
func TestCancelRunReleasesRunnerSlotMemory(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ri := registerLeaseRunner(t, s, "token")
	run := submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("first next = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	after := s.runners[ri.ID]
	s.mu.Unlock()
	if len(after.ActiveJobs) != 0 || after.Busy || after.CurrentJob != "" {
		t.Fatalf("runner after cancel = active=%v busy=%v current=%q, want released", after.ActiveJobs, after.Busy, after.CurrentJob)
	}
	// A queued job in a second run leases immediately.
	_ = submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("next after cancel = %d, want 200 (runner immediately schedulable)", w.Code)
	}
}

// TestCancelRunReleasesRunnerSlotDBFake: the DB fake mirrors the SQL cancel
// transaction (slot release + busy recompute).
func TestCancelRunReleasesRunnerSlotDBFake(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ri := registerLeaseRunner(t, s, "token")
	run := submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("first next = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", w.Code, w.Body.String())
	}
	after, err := f.GetRunner(context.Background(), ri.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.ActiveJobs) != 0 || after.Busy || after.CurrentJob != "" {
		t.Fatalf("runner after cancel = active=%v busy=%v current=%q, want released", after.ActiveJobs, after.Busy, after.CurrentJob)
	}
	_ = submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("next after cancel = %d, want 200 (runner immediately schedulable)", w.Code)
	}
}

// TestSupersedeReleasesRunnerSlotDBFake: the atomic-enqueue supersession
// path releases the superseded running job's runner slot.
func TestSupersedeReleasesRunnerSlotDBFake(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ri := registerLeaseRunner(t, s, "token")
	body := `{"repo_url":"https://github.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","pipeline":` + jsonString(concurrencyPipeline) + `}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body); w.Code != http.StatusAccepted {
		t.Fatalf("first submit: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("first next = %d: %s", w.Code, w.Body.String())
	}
	// The second submission supersedes the first run's running job.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body); w.Code != http.StatusAccepted {
		t.Fatalf("second submit: %d %s", w.Code, w.Body.String())
	}
	after, err := f.GetRunner(context.Background(), ri.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.ActiveJobs) != 0 || after.Busy {
		t.Fatalf("runner after supersession = active=%v busy=%v, want released", after.ActiveJobs, after.Busy)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("next after supersession = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// disable/drain serialization against the lease claim (HIGH-8)
// ---------------------------------------------------------------------------

// TestDisableCommitsThenNoNewLeaseDBFake: once a disable commits, the SQL
// claim predicate (disabled = FALSE) refuses every further lease even though
// queued jobs remain.
func TestDisableCommitsThenNoNewLeaseDBFake(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ri := registerLeaseRunner(t, s, "token")
	for i := 0; i < 3; i++ {
		_ = submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	}
	// Concurrent lease pollers race the disable: each lease either happens
	// before the disable commits (and is then revoked by the kill switch)
	// or is refused.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
		}()
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/disable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	wg.Wait()
	// After the disable committed, every subsequent lease is refused.
	for i := 0; i < 2; i++ {
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
		if w.Code != http.StatusNoContent {
			t.Fatalf("next after disable = %d, want 204 (no lease after disable commits)", w.Code)
		}
		if w.Header().Get("X-Kiwi-Disabled") != "true" {
			t.Fatalf("disabled header = %q", w.Header().Get("X-Kiwi-Disabled"))
		}
	}
	// No running job may reference the disabled runner.
	jobs, err := f.ListJobsByRunner(context.Background(), ri.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("disabled runner still holds %d running job(s)", len(jobs))
	}
}

// TestDrainingRunnerGetsNoLeaseDBFake: a draining runner finishes its work
// but receives no new lease from the claim.
func TestDrainingRunnerGetsNoLeaseDBFake(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ri := registerLeaseRunner(t, s, "token")
	ri.Draining = true
	if err := s.DB.UpsertRunner(context.Background(), ri); err != nil {
		t.Fatal(err)
	}
	_ = submitLeaseRun(t, s, "token", "https://github.com/o/r.git")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("draining next = %d, want 204: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("draining header = %q", w.Header().Get("X-Kiwi-Draining"))
	}
}

// ---------------------------------------------------------------------------
// live profile resolution at lease time (HIGH-11)
// ---------------------------------------------------------------------------

// TestMemoryLiveProfileRepoACLShrink: the memory-mode next() resolves the
// live profile at lease time. A profile edited to exclude the job's
// repository immediately stops the lease, even though the registration
// snapshot still allows it.
func TestMemoryLiveProfileRepoACLShrink(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := model.Runner{ID: parityRunnerID, Name: "pr", Capacity: 1, Labels: []string{"container"}, CertSerial: "cert-1", AllowedRepositories: []string{"github.com/o/r"}}
	s.mu.Lock()
	s.profiles["p1"] = model.RunnerProfile{ID: "p1", MaxCapacity: 1, Labels: []string{"container"}, Repositories: []string{"github.com/o/other"}}
	s.certProfiles["cert-1"] = "p1"
	s.mu.Unlock()
	paritySeedMemory(s, runner, parityJob("pjob-1"))
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+parityRunnerID+"/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("memory live-profile mismatch next = %d, want 204", w.Code)
	}
	// The live profile now allows the repository: the same job leases.
	s.mu.Lock()
	s.profiles["p1"] = model.RunnerProfile{ID: "p1", MaxCapacity: 1, Labels: []string{"container"}, Repositories: []string{"github.com/o/r"}}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+parityRunnerID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("memory live-profile match next = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestDBFakeLiveProfileRepoACLShrink: the DB-fake claim resolves the live
// profile rows (cert_profile_links -> runner_profiles), so a profile edit
// takes effect on the next lease.
func TestDBFakeLiveProfileRepoACLShrink(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	runner := model.Runner{ID: parityRunnerID, Name: "pr", Capacity: 1, Labels: []string{"container"}, CertSerial: "cert-1", AllowedRepositories: []string{"github.com/o/r"}}
	paritySeedDB(f, runner, parityJob("pjob-1"))
	if err := f.UpsertProfile(context.Background(), model.RunnerProfile{ID: "p1", MaxCapacity: 1, Labels: []string{"container"}, Repositories: []string{"github.com/o/other"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.BindCertProfile(context.Background(), "cert-1", "p1"); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+parityRunnerID+"/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("db live-profile mismatch next = %d, want 204", w.Code)
	}
	if err := f.UpsertProfile(context.Background(), model.RunnerProfile{ID: "p1", MaxCapacity: 1, Labels: []string{"container"}, Repositories: []string{"github.com/o/r"}}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+parityRunnerID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("db live-profile match next = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// identity semantics unification (HIGH-18)
// ---------------------------------------------------------------------------

// TestRunnerBearerAcceptableWithCAWhenCertsNotRequired: with a runner CA but
// RequireRunnerClientCerts=false, a per-runner bearer authenticates every
// runner route (register AND lease-bound calls) with no peer certificate.
func TestRunnerBearerAcceptableWithCAWhenCertsNotRequired(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-token")
	s.RunnerCA = ca
	s.RequireRunnerClientCerts = false
	s.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("per-runner-token")})
	h := s.Handler()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "labels": []string{"container"}, "protocol_min": 3, "protocol_max": 3}, "per-runner-token", nil); w.Code != http.StatusOK {
		t.Fatalf("bearer-only register with CA (Require=false): %d %s", w.Code, w.Body.String())
	}
	// Lease-bound call: submit (open RBAC mode) then poll with the bearer.
	run := SubmitRun{RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", Ref: "refs/heads/main", SHA: "abc", Pipeline: testPipeline}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runs", run, "runner-token", nil); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "per-runner-token", nil); w.Code != http.StatusOK {
		t.Fatalf("bearer-only next with CA (Require=false): %d %s", w.Code, w.Body.String())
	}
}

// TestRunnerCertRequiredEverywhereWhenEnforced: with RequireRunnerClientCerts
// the peer certificate is mandatory on every runner route; a bearer-only
// request is rejected.
func TestRunnerCertRequiredEverywhereWhenEnforced(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-token")
	s.RunnerCA = ca
	s.RequireRunnerClientCerts = true
	s.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("per-runner-token")})
	h := s.Handler()
	_, cert := pkiSignRunner(t, ca, "runner-a")
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "labels": []string{"container"}, "protocol_min": 3, "protocol_max": 3}, "per-runner-token", nil); w.Code == http.StatusOK {
		t.Fatalf("register without cert accepted under RequireRunnerClientCerts: %d", w.Code)
	}
	// A valid certificate plus the bearer is accepted.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "labels": []string{"container"}, "protocol_min": 3, "protocol_max": 3}, "per-runner-token", cert); w.Code != http.StatusOK {
		t.Fatalf("register with cert: %d %s", w.Code, w.Body.String())
	}
	run := SubmitRun{RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", Ref: "refs/heads/main", SHA: "abc", Pipeline: testPipeline}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runs", run, "runner-token", nil); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "per-runner-token", nil); w.Code == http.StatusOK {
		t.Fatalf("bearer-only next accepted under RequireRunnerClientCerts: %d", w.Code)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "per-runner-token", cert); w.Code != http.StatusOK {
		t.Fatalf("cert next: %d %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// memory vs DB-fake parity table (HIGH-14)
// ---------------------------------------------------------------------------

const parityRunnerID = "parity-runner"

// parityJob builds the base job used by the parity matrix.
func parityJob(id string) model.Job {
	return model.Job{
		ID: id, RunID: "parity-run", Key: "build", Status: model.StatusQueued,
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		CreatedAt: time.Now().UTC().Add(-time.Minute),
	}
}

func paritySeedMemory(s *Server, runner model.Runner, jobs ...model.Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range jobs {
		if _, ok := s.runs[j.RunID]; !ok {
			s.runs[j.RunID] = model.Run{ID: j.RunID, Repo: j.RepoURL, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
		}
		s.jobs[j.ID] = j
	}
	s.runners[runner.ID] = runner
}

func paritySeedDB(f *dbFakeStore, runner model.Runner, jobs ...model.Job) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, j := range jobs {
		if _, ok := f.runs[j.RunID]; !ok {
			f.runs[j.RunID] = model.Run{ID: j.RunID, Repo: j.RepoURL, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
		}
		f.jobs[j.ID] = j
		// Mirror the durable quota counters for seeded running jobs, exactly
		// as claims/completions would keep them.
		if j.Status == model.StatusRunning && j.RepoURL != "" {
			c := f.quotas[j.RepoURL]
			c[0]++
			f.quotas[j.RepoURL] = c
			if team := repoURLTeam(j.RepoURL); team != j.RepoURL {
				tc := f.quotas[team]
				tc[0]++
				f.quotas[team] = tc
			}
		}
	}
	f.runners[runner.ID] = runner
}

// TestLeaseDecisionParityMemoryVsDBFake runs a matrix of scheduling cases
// through BOTH the memory-mode next() and the DB-fake nextDB() paths and
// asserts the lease decision (200 vs 204) is identical. The two modes share
// storage.LeasePredicate, so any divergence fails here.
func TestLeaseDecisionParityMemoryVsDBFake(t *testing.T) {
	containerRuntime := map[string]any{"job": map[string]any{"runtime": "container"}}
	baseRunner := func() model.Runner {
		return model.Runner{ID: parityRunnerID, Name: "pr", Capacity: 1, Labels: []string{"container"}}
	}
	cases := []struct {
		name   string
		runner func() model.Runner
		jobs   func() []model.Job
		lease  bool
		quota  float64
	}{
		{
			name:   "matching labels and capabilities",
			runner: baseRunner,
			jobs: func() []model.Job {
				j := parityJob("pjob-1")
				j.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: containerRuntime}
				return []model.Job{j}
			},
			lease: true,
		},
		{
			name: "label mismatch",
			runner: func() model.Runner {
				r := baseRunner()
				r.Labels = []string{"native"}
				return r
			},
			jobs: func() []model.Job {
				j := parityJob("pjob-1")
				j.RequiredLabels = []string{"container"}
				return []model.Job{j}
			},
			lease: false,
		},
		{
			name: "repo ACL mismatch",
			runner: func() model.Runner {
				r := baseRunner()
				r.AllowedRepositories = []string{"github.com/o/other"}
				return r
			},
			jobs:  func() []model.Job { return []model.Job{parityJob("pjob-1")} },
			lease: false,
		},
		{
			name: "repo ACL match",
			runner: func() model.Runner {
				r := baseRunner()
				r.AllowedRepositories = []string{"github.com/o/r"}
				return r
			},
			jobs:  func() []model.Job { return []model.Job{parityJob("pjob-1")} },
			lease: true,
		},
		{
			name: "capability mismatch",
			runner: func() model.Runner {
				r := baseRunner()
				r.Capabilities = []string{"native"}
				return r
			},
			jobs: func() []model.Job {
				j := parityJob("pjob-1")
				j.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: containerRuntime}
				return []model.Job{j}
			},
			lease: false,
		},
		{
			name:   "enforced empty policy denies all runtimes",
			runner: baseRunner,
			jobs: func() []model.Job {
				j := parityJob("pjob-1")
				j.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: containerRuntime, EffectivePolicy: policy.Capabilities{Enforced: true}}
				return []model.Job{j}
			},
			lease: false,
		},
		{
			name: "capacity zero takes no work",
			runner: func() model.Runner {
				r := baseRunner()
				r.Capacity = 0
				return r
			},
			jobs:  func() []model.Job { return []model.Job{parityJob("pjob-1")} },
			lease: false,
		},
		{
			name: "disabled",
			runner: func() model.Runner {
				r := baseRunner()
				r.Disabled = true
				return r
			},
			jobs:  func() []model.Job { return []model.Job{parityJob("pjob-1")} },
			lease: false,
		},
		{
			name: "draining",
			runner: func() model.Runner {
				r := baseRunner()
				r.Draining = true
				return r
			},
			jobs:  func() []model.Job { return []model.Job{parityJob("pjob-1")} },
			lease: false,
		},
		{
			name: "region mismatch",
			runner: func() model.Runner {
				r := baseRunner()
				r.Region = "us-east"
				return r
			},
			jobs: func() []model.Job {
				j := parityJob("pjob-1")
				j.PlacementRegions = []string{"eu-west"}
				return []model.Job{j}
			},
			lease: false,
		},
		{
			name: "region match",
			runner: func() model.Runner {
				r := baseRunner()
				r.Region = "eu-west"
				return r
			},
			jobs: func() []model.Job {
				j := parityJob("pjob-1")
				j.PlacementRegions = []string{"eu-west"}
				return []model.Job{j}
			},
			lease: true,
		},
		{
			name:   "environment at capacity",
			runner: baseRunner,
			jobs: func() []model.Job {
				exp := time.Now().UTC().Add(time.Hour)
				running := parityJob("pjob-running")
				running.Status = model.StatusRunning
				running.Environment = "prod"
				running.EnvironmentConcurrency = 1
				running.LeaseRunnerID = "other-runner"
				running.LeaseGeneration = 1
				running.LeaseExpiresAt = &exp
				queued := parityJob("pjob-1")
				queued.Environment = "prod"
				queued.EnvironmentConcurrency = 1
				return []model.Job{running, queued}
			},
			lease: false,
		},
		{
			name:   "environment slot free",
			runner: baseRunner,
			jobs: func() []model.Job {
				exp := time.Now().UTC().Add(time.Hour)
				running := parityJob("pjob-running")
				running.Status = model.StatusRunning
				running.Environment = "staging"
				running.EnvironmentConcurrency = 1
				running.LeaseRunnerID = "other-runner"
				running.LeaseGeneration = 1
				running.LeaseExpiresAt = &exp
				queued := parityJob("pjob-1")
				queued.Environment = "prod"
				queued.EnvironmentConcurrency = 1
				return []model.Job{running, queued}
			},
			lease: true,
		},
		{
			name: "profile snapshot restricts repo (no live profile link)",
			runner: func() model.Runner {
				r := baseRunner()
				r.AllowedRepositories = []string{"github.com/o/other"}
				return r
			},
			jobs: func() []model.Job {
				j := parityJob("pjob-1")
				j.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: containerRuntime}
				return []model.Job{j}
			},
			lease: false,
		},
		{
			name:   "repo concurrency saturated at lease time",
			runner: baseRunner,
			jobs: func() []model.Job {
				exp := time.Now().UTC().Add(time.Hour)
				running := parityJob("pjob-running")
				running.Status = model.StatusRunning
				running.LeaseRunnerID = "other-runner"
				running.LeaseGeneration = 1
				running.LeaseExpiresAt = &exp
				return []model.Job{running, parityJob("pjob-1")}
			},
			lease: false,
			quota: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Memory mode.
			memSrv, err := NewPersistent("token", "token", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			memSrv.RequireProfiles = true
			memSrv.QuotaLimits.RepoConcurrency = tc.quota
			paritySeedMemory(memSrv, tc.runner(), tc.jobs()...)
			memW := doJSON(t, memSrv, http.MethodPost, "/api/v1/runners/"+parityRunnerID+"/next", "token", "")

			// DB-fake mode.
			f := newDBFakeStore()
			dbSrv, err := NewPersistent("token", "token", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dbSrv.RequireProfiles = true
			if err := dbSrv.SwitchToDB(f); err != nil {
				t.Fatal(err)
			}
			dbSrv.QuotaLimits.RepoConcurrency = tc.quota
			paritySeedDB(f, tc.runner(), tc.jobs()...)
			dbW := doJSON(t, dbSrv, http.MethodPost, "/api/v1/runners/"+parityRunnerID+"/next", "token", "")

			if memW.Code != dbW.Code {
				t.Fatalf("lease decision diverged: memory=%d db=%d (memory body %q, db body %q)", memW.Code, dbW.Code, memW.Body.String(), dbW.Body.String())
			}
			want := http.StatusNoContent
			if tc.lease {
				want = http.StatusOK
			}
			if memW.Code != want {
				t.Fatalf("lease decision = %d, want %d (memory body %q, db body %q)", memW.Code, want, memW.Body.String(), dbW.Body.String())
			}
		})
	}
}
