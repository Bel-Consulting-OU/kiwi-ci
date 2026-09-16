package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const bareContainerPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    steps:
      - run: echo hi
`

// TestUntrustedResourceCeilingsAppliedAtEnqueue (P1-15): an UNTRUSTED job
// without declared CPU/memory/PID requests gets the server-side ceiling
// values stamped on its compiled resources at enqueue, so the executor
// always applies limits to untrusted work. The ceilings appear in BOTH the
// persisted request fields and the effective compiled job payload.
func TestUntrustedResourceCeilingsAppliedAtEnqueue(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.UntrustedCPUCeiling != 2.0 || s.UntrustedMemoryCeiling != 4<<30 || s.UntrustedPIDCeiling != 256 {
		t.Fatalf("default ceilings = %v/%d/%d, want 2.0/4GiB/256", s.UntrustedCPUCeiling, s.UntrustedMemoryCeiling, s.UntrustedPIDCeiling)
	}
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: bareContainerPipeline,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	var job model.Job
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			job = j
		}
	}
	s.mu.Unlock()
	if job.ID == "" {
		t.Fatal("no job enqueued")
	}
	if job.CPURequest != 2.0 {
		t.Fatalf("CPURequest = %v, want 2.0", job.CPURequest)
	}
	if job.MemoryRequest != 4<<30 {
		t.Fatalf("MemoryRequest = %d, want 4 GiB", job.MemoryRequest)
	}
	if job.PIDsRequest != 256 {
		t.Fatalf("PIDsRequest = %d, want 256", job.PIDsRequest)
	}
	// The effective compiled job payload carries the ceilings too (the
	// executor reads it, so the limits are actually applied).
	raw, err := json.Marshal(job.CompiledJobPayload.EffectiveJob)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"cpu":2`, `"memory":4294967296`, `"pids":256`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("effective job payload missing %s: %s", want, raw)
		}
	}
}

// TestTrustedJobWithoutResourcesGetsNoCeilings (P1-15): trusted jobs keep
// their declared resources exactly — no implicit ceilings.
func TestTrustedJobWithoutResourcesGetsNoCeilings(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: bareContainerPipeline, Trusted: true,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	var job model.Job
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			job = j
		}
	}
	s.mu.Unlock()
	if job.CPURequest != 0 || job.MemoryRequest != 0 || job.PIDsRequest != 0 {
		t.Fatalf("trusted job requests = %v/%d/%d, want all zero", job.CPURequest, job.MemoryRequest, job.PIDsRequest)
	}
}

// TestUntrustedDeclaredResourcesUntouched (P1-15): an untrusted job that
// DECLARES requests keeps them — the ceiling only fills absent fields.
func TestUntrustedDeclaredResourcesUntouched(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	declared := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
      cpu: 0.5
      memory: 1GiB
      pids: 100
    steps:
      - run: echo hi
`
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: declared,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	var job model.Job
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			job = j
		}
	}
	s.mu.Unlock()
	if job.CPURequest != 0.5 || job.MemoryRequest != 1<<30 || job.PIDsRequest != 100 {
		t.Fatalf("declared requests = %v/%d/%d, want 0.5/1GiB/100", job.CPURequest, job.MemoryRequest, job.PIDsRequest)
	}
}

// TestCustomUntrustedCeilings (P1-15): operators can override the ceiling
// defaults per server.
func TestCustomUntrustedCeilings(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.UntrustedCPUCeiling = 1.5
	s.UntrustedMemoryCeiling = 1 << 30
	s.UntrustedPIDCeiling = 64
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: bareContainerPipeline,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	var job model.Job
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			job = j
		}
	}
	s.mu.Unlock()
	if job.CPURequest != 1.5 || job.MemoryRequest != 1<<30 || job.PIDsRequest != 64 {
		t.Fatalf("custom ceilings = %v/%d/%d, want 1.5/1GiB/64", job.CPURequest, job.MemoryRequest, job.PIDsRequest)
	}
}
