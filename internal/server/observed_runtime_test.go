package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func observedRuntimeFixture() *model.ObservedRuntime {
	return &model.ObservedRuntime{
		OS:                  "linux",
		Arch:                "amd64",
		RuntimeName:         "native",
		RuntimeVersion:      "27.1.2",
		MainImage:           "alpine:3.19",
		MainImageDigest:     "sha256:" + strings.Repeat("a", 64),
		ServiceImages:       map[string]string{"db": "postgres:16"},
		ServiceImageDigests: map[string]string{"db": "sha256:" + strings.Repeat("b", 64)},
	}
}

// TestCompletePersistsObservedRuntimeMemory: the memory completion path
// persists the validated wire evidence on the job, and a client-supplied
// Components map is never trusted.
func TestCompletePersistsObservedRuntimeMemory(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	obs := observedRuntimeFixture()
	obs.Components = map[string]string{"spoofed": "sha256:deadbeef"}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", Complete{
		RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen,
		Status: model.StatusSuccess, ObservedRuntime: obs,
	}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs[jobID]
	s.mu.Unlock()
	if j.ObservedRuntime == nil {
		t.Fatal("observed runtime not persisted on the job")
	}
	if j.ObservedRuntime.RuntimeName != "native" || j.ObservedRuntime.MainImageDigest != obs.MainImageDigest ||
		j.ObservedRuntime.ServiceImages["db"] != "postgres:16" || j.ObservedRuntime.ServiceImageDigests["db"] != obs.ServiceImageDigests["db"] {
		t.Fatalf("observed runtime = %+v", j.ObservedRuntime)
	}
	if len(j.ObservedRuntime.Components) != 0 {
		t.Fatalf("client-supplied components were trusted: %v", j.ObservedRuntime.Components)
	}
}

// TestCompleteRejectsMalformedObservedRuntime: shape/size violations are
// refused with 400 before any lease or completion state changes.
func TestCompleteRejectsMalformedObservedRuntime(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)

	tooLong := &model.ObservedRuntime{RuntimeVersion: strings.Repeat("v", 500)}
	tooMany := &model.ObservedRuntime{ServiceImages: map[string]string{}}
	for i := 0; i < maxObservedRuntimeNames+1; i++ {
		tooMany.ServiceImages[strings.Repeat("s", i+1)] = "img"
	}
	control := &model.ObservedRuntime{MainImage: "alpine\x00:3"}

	for name, obs := range map[string]*model.ObservedRuntime{"too_long": tooLong, "too_many": tooMany, "control_chars": control} {
		w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", Complete{
			RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen,
			Status: model.StatusSuccess, ObservedRuntime: obs,
		}, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s complete = %d, want 400: %s", name, w.Code, w.Body.String())
		}
	}
	s.mu.Lock()
	j := s.jobs[jobID]
	s.mu.Unlock()
	if j.Status != model.StatusRunning {
		t.Fatalf("malformed completion changed the job: %s", j.Status)
	}
}

// TestDeploymentLeaseGenerationStampedAndPreserved: the deployment record
// names the attempt at start, and the finish preserves it.
func TestDeploymentLeaseGenerationStampedAndPreserved(t *testing.T) {
	s := New("secret")
	grantDeployments(s)
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseDeploymentJob(t, s, c)

	s.mu.Lock()
	d := s.deployments[jobID]
	s.mu.Unlock()
	if d.LeaseGeneration != gen {
		t.Fatalf("deployment generation = %d, want %d", d.LeaseGeneration, gen)
	}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", Complete{
		RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Status: model.StatusSuccess,
	}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	d = s.deployments[jobID]
	s.mu.Unlock()
	if d.LeaseGeneration != gen || d.FinishedAt == nil {
		t.Fatalf("finished deployment = %+v, want the attempt generation preserved", d)
	}
}

// TestObservedRuntimeComponentsFromPersistedJob: Components is server-owned:
// the wire value is discarded and replaced with the job's resolved component
// digest, keyed by the declared (base) job key.
func TestObservedRuntimeComponentsFromPersistedJob(t *testing.T) {
	obs := &model.ObservedRuntime{Components: map[string]string{"spoofed": "sha256:deadbeef"}}
	j := model.Job{Key: "build[1]", BaseKey: "build", ComponentDigest: "sha256:" + strings.Repeat("c", 64)}
	out := observedRuntimeWithComponents(obs, j)
	if out == nil || out.Components["build"] != j.ComponentDigest {
		t.Fatalf("components = %+v, want the persisted component digest under the base key", out.Components)
	}
	if len(out.Components) != 1 || out.Components["spoofed"] != "" {
		t.Fatalf("client components were trusted: %+v", out.Components)
	}
	// Without a resolved component the map stays empty (and nil input stays
	// nil: omission is preserved).
	if plain := observedRuntimeWithComponents(obs, model.Job{BaseKey: "build"}); len(plain.Components) != 0 {
		t.Fatalf("components without a digest = %+v, want empty", plain.Components)
	}
	if observedRuntimeWithComponents(nil, j) != nil {
		t.Fatal("nil observed runtime must stay nil")
	}
}

// TestLogEntryCarriesLeaseGeneration: the runner already sends the lease
// generation on the log wire; the fs/memory log store records it on the entry
// so a read can attribute the line to an attempt.
func TestLogEntryCarriesLeaseGeneration(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/log", LogLine{
		RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen,
		JobKey: "build", Step: "run", Line: "hi",
	}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("log = %d: %s", w.Code, w.Body.String())
	}
	logs, err := s.store.ReadLogs(runID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].LeaseGeneration != gen {
		t.Fatalf("stored log entries = %+v, want one with generation %d", logs, gen)
	}
}

// TestCompleteDBPersistsObservedRuntime: the DB completion path forwards the
// evidence through the scheduler into the store, where it persists on the
// job payload.
func TestCompleteDBPersistsObservedRuntime(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/r","ref":"refs/heads/main","sha":"abc","pipeline":`+jsonStr(smokePipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"runner1","labels":["container"],"protocol_min":3,"protocol_max":3}`); w.Code != http.StatusOK {
		t.Fatalf("register = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	runnerID := ""
	for id := range f.runners {
		runnerID = id
	}
	f.mu.Unlock()
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatalf("decode task: %v", err)
	}
	obs := observedRuntimeFixture()
	body, err := json.Marshal(Complete{
		RunnerID: runnerID, LeaseToken: task.LeaseToken, LeaseGeneration: task.LeaseGeneration,
		Status: model.StatusSuccess, ObservedRuntime: obs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(body)); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	f.mu.Unlock()
	if j.ObservedRuntime == nil || j.ObservedRuntime.MainImageDigest != obs.MainImageDigest {
		t.Fatalf("db-mode observed runtime = %+v", j.ObservedRuntime)
	}
}
