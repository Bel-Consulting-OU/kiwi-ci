package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
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
// without declared CPU/memory/PID/disk requests gets the server-side ceiling
// values stamped on its compiled resources at enqueue, so the executor
// always applies limits to untrusted work. The ceilings appear in BOTH the
// persisted request fields and the effective compiled job payload.
func TestUntrustedResourceCeilingsAppliedAtEnqueue(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.UntrustedCPUCeiling != 2.0 || s.UntrustedMemoryCeiling != 4<<30 || s.UntrustedDiskCeiling != 10<<30 || s.UntrustedPIDCeiling != 256 {
		t.Fatalf("default ceilings = %v/%d/%d/%d, want 2.0/4GiB/10GiB/256", s.UntrustedCPUCeiling, s.UntrustedMemoryCeiling, s.UntrustedDiskCeiling, s.UntrustedPIDCeiling)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
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
	if job.DiskRequest != 10<<30 {
		t.Fatalf("DiskRequest = %d, want 10 GiB", job.DiskRequest)
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
	for _, want := range []string{`"cpu":2`, `"memory":4294967296`, `"disk":10737418240`, `"pids":256`} {
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
	run, err := s.enqueue(context.Background(), SubmitRun{
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
	if job.CPURequest != 0 || job.MemoryRequest != 0 || job.DiskRequest != 0 || job.PIDsRequest != 0 {
		t.Fatalf("trusted job requests = %v/%d/%d/%d, want all zero", job.CPURequest, job.MemoryRequest, job.DiskRequest, job.PIDsRequest)
	}
}

// TestUntrustedDeclaredResourcesUntouched (P1-15): an untrusted job that
// DECLARES requests within the ceilings keeps them exactly — the ceiling
// only fills absent fields.
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
      disk: 2GiB
      pids: 100
    steps:
      - run: echo hi
`
	run, err := s.enqueue(context.Background(), SubmitRun{
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
	if job.CPURequest != 0.5 || job.MemoryRequest != 1<<30 || job.DiskRequest != 2<<30 || job.PIDsRequest != 100 {
		t.Fatalf("declared requests = %v/%d/%d/%d, want 0.5/1GiB/2GiB/100", job.CPURequest, job.MemoryRequest, job.DiskRequest, job.PIDsRequest)
	}
}

// TestUntrustedExplicitRequestAboveCeilingRejected (D2-A): an untrusted job
// that explicitly asks for MORE than a configured ceiling is rejected at
// enqueue with an opaque 4xx admission error naming the offending field, the
// requested value and the ceiling — for every dimension, including disk
// (which had no ceiling at all). NOTHING is persisted and nothing is signed.
func TestUntrustedExplicitRequestAboveCeilingRejected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		resources string
		contains  []string
	}{
		{"cpu", "      cpu: 8\n", []string{"resources.cpu", "8", "2"}},
		{"memory", "      memory: 8GiB\n", []string{"resources.memory", "8589934592", "4294967296"}},
		{"disk", "      disk: 20GiB\n", []string{"resources.disk", "21474836480", "10737418240"}},
		{"pids", "      pids: 4096\n", []string{"resources.pids", "4096", "256"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewPersistent("token", "token", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			pipelineYAML := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
` + tc.resources + `    steps:
      - run: echo hi
`
			run, err := s.enqueue(context.Background(), SubmitRun{
				RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
				Ref: "main", Pipeline: pipelineYAML,
			})
			if err == nil {
				t.Fatalf("oversized untrusted %s request accepted, run %s", tc.name, run.ID)
			}
			var adm *admissionError
			if !errors.As(err, &adm) {
				t.Fatalf("error = %v (%T), want *admissionError", err, err)
			}
			if adm.Status != 400 || adm.Reason != "untrusted_resource_ceiling_exceeded" {
				t.Fatalf("admission status/reason = %d/%q, want 400/untrusted_resource_ceiling_exceeded", adm.Status, adm.Reason)
			}
			for _, want := range tc.contains {
				if !strings.Contains(adm.Msg, want) {
					t.Fatalf("message %q does not name %q", adm.Msg, want)
				}
			}
			// Nothing may be persisted: no run, no job.
			s.mu.Lock()
			runs, jobs := len(s.runs), len(s.jobs)
			s.mu.Unlock()
			if runs != 0 || jobs != 0 {
				t.Fatalf("rejected enqueue persisted %d runs / %d jobs", runs, jobs)
			}
		})
	}
}

// TestUntrustedCeilingRejectionMapsToOpaqueHTTP4xx (D2-A): the rejection
// travels through the public submit API as a 4xx JSON body carrying the
// machine-readable reason and the field/value/ceiling message, with no
// internal detail.
func TestUntrustedCeilingRejectionMapsToOpaqueHTTP4xx(t *testing.T) {
	s := New("token")
	body := `{"repo_url":"https://github.com/o/r.git","repo_full_name":"o/r","ref":"main","pipeline":"version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:` + pinnedImageDigest + `\n    resources:\n      memory: 8GiB\n    steps:\n      - run: echo hi\n"}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out["reason"] != "untrusted_resource_ceiling_exceeded" {
		t.Fatalf("reason = %q", out["reason"])
	}
	if !strings.Contains(out["error"], "resources.memory") {
		t.Fatalf("error = %q, want the offending field named", out["error"])
	}
}

// TestUntrustedDiskCeilingNotStampedOnNonContainerRuntimes (D2-A): the disk
// ceiling is filled only where the backend enforces resources.disk as a
// workspace bound (container); tart jobs keep an absent disk request instead
// of an advisory fabricated one.
func TestUntrustedDiskCeilingNotStampedOnNonContainerRuntimes(t *testing.T) {
	s := New("token")
	for _, runtimeName := range []string{"tart", "native"} {
		cj := pipeline.CompiledJob{Job: pipeline.Job{Runtime: runtimeName}}
		out, err := s.applyUntrustedResourceCeilings(cj, false)
		if err != nil {
			t.Fatalf("%s: %v", runtimeName, err)
		}
		if out.Job.Resources.Disk != 0 {
			t.Fatalf("%s disk = %d, want 0", runtimeName, out.Job.Resources.Disk)
		}
	}
	cj := pipeline.CompiledJob{Job: pipeline.Job{Runtime: "container"}}
	out, err := s.applyUntrustedResourceCeilings(cj, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Job.Resources.Disk != 10<<30 {
		t.Fatalf("container disk = %d, want 10 GiB", out.Job.Resources.Disk)
	}
}

// TestTrustedJobAboveUntrustedCeilingsAllowed (D2-A): the ceilings are an
// UNTRUSTED-only admission rule. A trusted job may declare requests far above
// every untrusted ceiling and keeps them exactly.
func TestTrustedJobAboveUntrustedCeilingsAllowed(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	big := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
      cpu: 64
      memory: 256GiB
      disk: 512GiB
      pids: 65536
    steps:
      - run: echo hi
`
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: big, Trusted: true,
	})
	if err != nil {
		t.Fatalf("trusted enqueue above untrusted ceilings rejected: %v", err)
	}
	s.mu.Lock()
	var job model.Job
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			job = j
		}
	}
	s.mu.Unlock()
	if job.CPURequest != 64 || job.MemoryRequest != 256<<30 || job.DiskRequest != 512<<30 || job.PIDsRequest != 65536 {
		t.Fatalf("trusted requests = %v/%d/%d/%d, want 64/256GiB/512GiB/65536", job.CPURequest, job.MemoryRequest, job.DiskRequest, job.PIDsRequest)
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
	s.UntrustedDiskCeiling = 3 << 30
	s.UntrustedPIDCeiling = 64
	run, err := s.enqueue(context.Background(), SubmitRun{
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
	if job.CPURequest != 1.5 || job.MemoryRequest != 1<<30 || job.DiskRequest != 3<<30 || job.PIDsRequest != 64 {
		t.Fatalf("custom ceilings = %v/%d/%d/%d, want 1.5/1GiB/3GiB/64", job.CPURequest, job.MemoryRequest, job.DiskRequest, job.PIDsRequest)
	}
}

// TestZeroUntrustedCeilingDisablesDimension (D2-A): a zero ceiling disables
// that dimension entirely — no rejection and no fill — while the remaining
// dimensions keep their ceilings.
func TestZeroUntrustedCeilingDisablesDimension(t *testing.T) {
	s := New("token")
	s.UntrustedCPUCeiling = 0
	s.UntrustedMemoryCeiling = 0
	s.UntrustedDiskCeiling = 0
	s.UntrustedPIDCeiling = 0
	var cj pipeline.CompiledJob
	cj.Job.Runtime = "container"
	cj.Job.Resources.CPU = 100
	cj.Job.Resources.Memory = 64 << 30
	cj.Job.Resources.Disk = 64 << 30
	cj.Job.Resources.PIDs = 65536
	out, err := s.applyUntrustedResourceCeilings(cj, false)
	if err != nil {
		t.Fatalf("disabled ceilings rejected an explicit untrusted request: %v", err)
	}
	if out.Job.Resources != cj.Job.Resources {
		t.Fatalf("disabled ceilings changed resources: %+v, want %+v", out.Job.Resources, cj.Job.Resources)
	}
}
