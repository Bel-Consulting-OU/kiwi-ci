package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestDrainBlocksLeasesAndReadiness(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("maintenance")
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("next while draining = %d, want 503", w.Code)
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("next draining header = %q", w.Header().Get("X-Kiwi-Draining"))
	}
	if w = doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness while draining = %d, want 503", w.Code)
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("readiness draining header = %q", w.Header().Get("X-Kiwi-Draining"))
	}
	if w = doJSON(t, s, http.MethodGet, "/liveness", "", ""); w.Code != http.StatusOK {
		t.Fatalf("liveness while draining = %d, want 200", w.Code)
	}
}

func TestDrainKeepsHeartbeatAndComplete(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, smokePipeline)
	s.BeginDrain("maintenance")
	hb := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":%d}`, runnerID, task.LeaseToken, task.LeaseGeneration)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token", hb); w.Code != http.StatusOK {
		t.Fatalf("heartbeat while draining = %d: %s", w.Code, w.Body.String())
	}
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete while draining = %d: %s", w.Code, w.Body.String())
	}
	if got := s.ActiveJobs(); got != 0 {
		t.Fatalf("ActiveJobs after drain completion = %d, want 0", got)
	}
}

func TestDrainActiveJobsCount(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ActiveJobs(); got != 0 {
		t.Fatalf("ActiveJobs on empty server = %d", got)
	}
	runnerID, task := leaseArtifactJob(t, s, smokePipeline)
	if got := s.ActiveJobs(); got != 1 {
		t.Fatalf("ActiveJobs with one leased job = %d, want 1", got)
	}
	s.BeginDrain("maintenance")
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	if got := s.ActiveJobs(); got != 0 {
		t.Fatalf("ActiveJobs after completion = %d, want 0", got)
	}
}

func TestDrainFlagPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("operator maintenance")
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.isDraining() {
		t.Fatal("restarted server must stay draining")
	}
	if s2.drainReasonOf() != "operator maintenance" {
		t.Fatalf("restarted drain reason = %q", s2.drainReasonOf())
	}
	if w := doJSON(t, s2, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("restarted readiness = %d, want 503", w.Code)
	}
}

func TestDrainEndpoints(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/drain", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET drain = %d", w.Code)
	}
	var st drainStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Draining {
		t.Fatal("fresh server must not be draining")
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/drain", "token", `{"reason":"rolling update"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST drain = %d: %s", w.Code, w.Body.String())
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/drain", "token", "")
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Draining || st.Reason != "rolling update" {
		t.Fatalf("drain status = %+v", st)
	}
	// The drain endpoint is admin tier: a bare request is rejected when a
	// token is configured.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/drain", "", `{"reason":"x"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated drain = %d, want 401", w.Code)
	}
}

func TestDrainBlocksLeasesDBMode(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("db drain")
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("db next while draining = %d, want 503", w.Code)
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("db next draining header = %q", w.Header().Get("X-Kiwi-Draining"))
	}
}
