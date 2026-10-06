package server

// Job-scoped cgroup capability plumbing through the /next task: the additive
// JSON field, the DB path's effective-runner advertisement, and the
// memory-mode path's overlay advertisement.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestTaskJobCgroupJSONRoundTrip pins the additive wire field: job_cgroup is
// omitted when false, carried when true, and a legacy payload without the key
// decodes to false.
func TestTaskJobCgroupJSONRoundTrip(t *testing.T) {
	raw, err := json.Marshal(Task{LeaseToken: "lease", JobCgroup: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"job_cgroup":true`) {
		t.Fatalf("marshaled task = %s, want job_cgroup true", raw)
	}
	var decoded Task
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.JobCgroup || decoded.LeaseToken != "lease" {
		t.Fatalf("round trip = %+v, want job_cgroup carried", decoded)
	}

	off, err := json.Marshal(Task{LeaseToken: "lease"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(off), "job_cgroup") {
		t.Fatalf("false job_cgroup must be omitted: %s", off)
	}
	var legacy Task
	if err := json.Unmarshal([]byte(`{"job":{"id":"job-1"},"lease_token":"lease"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.JobCgroup {
		t.Fatal("a legacy task without job_cgroup must decode to false")
	}
}

// TestMemoryNextAdvertisesJobCgroupCapability drives the memory-mode lease
// path: a profile with JobCgroup=true is overlaid live, the task carries the
// flag, and the profile's absence keeps it false.
func TestMemoryNextAdvertisesJobCgroupCapability(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
	createProfile(t, s, model.RunnerProfile{
		ID: "cg-mem", Labels: []string{"container"}, Capabilities: []string{"native", "container"}, MaxCapacity: 2, JobCgroup: true,
	})
	bindRunnerProfile(t, s, "cg-mem", "runner-a", "admin-tok")
	registerWithToken(t, s, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
		"capabilities": []string{"native", "container"},
	}, "token-a")

	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: twoJobPipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/next", "token-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if !task.JobCgroup {
		t.Fatalf("memory-mode task = %+v, want job_cgroup advertised from the live profile", task)
	}
}

// TestDBNextAdvertisesJobCgroupCapability is the durable-mode mirror: nextDB
// resolves the effective runner through the same live-profile precedence the
// scheduler's claim used and puts the capability on the wire task.
func TestDBNextAdvertisesJobCgroupCapability(t *testing.T) {
	f := newDBFakeStore()
	s := New("shared-dev-tok")
	s.AdminToken = "admin-tok"
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := s.ProvisionRunnerTokensDB(t.Context(), map[string]string{"runner-a": auth.TokenDigest("token-a")}); err != nil {
		t.Fatal(err)
	}
	createProfile(t, s, model.RunnerProfile{
		ID: "cg-db", Labels: []string{"container"}, Capabilities: []string{"native", "container"}, MaxCapacity: 2, JobCgroup: true,
	})
	bindRunnerProfile(t, s, "cg-db", "runner-a", "admin-tok")
	registerWithToken(t, s, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
		"capabilities": []string{"native", "container"},
	}, "token-a")

	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: twoJobPipeline,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/next", "token-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if !task.JobCgroup {
		t.Fatalf("db task = %+v, want job_cgroup advertised from the effective runner", task)
	}
}
