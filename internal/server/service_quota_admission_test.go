package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// decodeEffectiveJob re-encodes the stored effective-job payload and decodes
// it into a compiled job; the stored field is an `any`, so it may hold
// either a json.RawMessage or a decoded map.
func decodeEffectiveJob(p *model.CompiledJobPayload, dst *pipeline.CompiledJob) error {
	raw, err := json.Marshal(p.EffectiveJob)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

// serviceQuotaPipeline builds a minimal untrusted-admissible container
// pipeline declaring n sidecar services with unique aliases.
func serviceQuotaPipeline(n int) string {
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:" + pinnedImageDigest + "\n    services:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "      - name: svc-%d\n        image: redis:7\n", i)
	}
	b.WriteString("    steps:\n      - run: echo hi\n")
	return b.String()
}

// TestUntrustedServiceCeilingRejectedAtAdmission (K5-B): an untrusted run
// declaring more services than pipeline.MaxUntrustedServicesPerJob is
// rejected at admission — before the run digest is signed and before
// anything is persisted or queued — with the admission error the executor
// would otherwise only raise mid-run.
func TestUntrustedServiceCeilingRejectedAtAdmission(t *testing.T) {
	s := New("token")
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: serviceQuotaPipeline(pipeline.MaxUntrustedServicesPerJob + 1),
	})
	if err == nil {
		t.Fatalf("untrusted run with %d services admitted as %s", pipeline.MaxUntrustedServicesPerJob+1, run.ID)
	}
	var adm *admissionError
	if !errors.As(err, &adm) {
		t.Fatalf("error = %v (%T), want *admissionError", err, err)
	}
	if adm.Status != http.StatusBadRequest || adm.Reason != "untrusted_service_ceiling_exceeded" {
		t.Fatalf("admission status/reason = %d/%q, want 400/untrusted_service_ceiling_exceeded", adm.Status, adm.Reason)
	}
	if !strings.Contains(adm.Msg, fmt.Sprintf("%d services", pipeline.MaxUntrustedServicesPerJob+1)) ||
		!strings.Contains(adm.Msg, fmt.Sprintf("limit is %d", pipeline.MaxUntrustedServicesPerJob)) {
		t.Fatalf("message %q does not name the count and the ceiling", adm.Msg)
	}
	// Nothing may be persisted: no run, no job, no signed payload.
	s.mu.Lock()
	runs, jobs := len(s.runs), len(s.jobs)
	s.mu.Unlock()
	if runs != 0 || jobs != 0 {
		t.Fatalf("rejected enqueue persisted %d runs / %d jobs", runs, jobs)
	}
}

// TestUntrustedServiceCeilingAtLimitAccepted (K5-B): exactly the ceiling is
// admissible and the declared services survive into the persisted job, so
// the admission cut is at > ceiling, never >=.
func TestUntrustedServiceCeilingAtLimitAccepted(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: serviceQuotaPipeline(pipeline.MaxUntrustedServicesPerJob),
	})
	if err != nil {
		t.Fatalf("at-limit enqueue: %v", err)
	}
	s.mu.Lock()
	jobs := 0
	for _, j := range s.jobs {
		if j.RunID != run.ID {
			continue
		}
		jobs++
		var cj pipeline.CompiledJob
		if err := decodeEffectiveJob(j.CompiledJobPayload, &cj); err != nil {
			t.Fatalf("decode effective job: %v", err)
		}
		if len(cj.Job.Services) != pipeline.MaxUntrustedServicesPerJob {
			t.Fatalf("persisted %d services, want %d", len(cj.Job.Services), pipeline.MaxUntrustedServicesPerJob)
		}
	}
	s.mu.Unlock()
	if jobs != 1 {
		t.Fatalf("persisted %d jobs, want 1", jobs)
	}
}

// TestTrustedServiceCeilingUnchanged (K5-B): trusted runs keep the
// historical 32-service allowance; the untrusted ceiling never leaks into
// trusted admission.
func TestTrustedServiceCeilingUnchanged(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: serviceQuotaPipeline(32), Trusted: true,
	})
	if err != nil {
		t.Fatalf("trusted 32-service enqueue: %v", err)
	}
	s.mu.Lock()
	jobs := 0
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			jobs++
			var cj pipeline.CompiledJob
			if err := decodeEffectiveJob(j.CompiledJobPayload, &cj); err != nil {
				t.Fatalf("decode effective job: %v", err)
			}
			if len(cj.Job.Services) != 32 {
				t.Fatalf("trusted job persisted %d services, want 32", len(cj.Job.Services))
			}
		}
	}
	s.mu.Unlock()
	if jobs != 1 {
		t.Fatalf("persisted %d jobs, want 1", jobs)
	}
}

// TestUntrustedServiceCeilingMapsToOpaqueHTTP4xx (K5-B): the public submit
// API answers the same opaque 4xx envelope as the resource-ceiling
// rejections, with the machine-readable reason.
func TestUntrustedServiceCeilingMapsToOpaqueHTTP4xx(t *testing.T) {
	s := New("token")
	pipelineYAML := strings.ReplaceAll(serviceQuotaPipeline(pipeline.MaxUntrustedServicesPerJob+1), "\n", `\n`)
	body := `{"repo_url":"https://github.com/o/r.git","repo_full_name":"o/r","ref":"main","pipeline":"` + pipelineYAML + `"}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out["reason"] != "untrusted_service_ceiling_exceeded" {
		t.Fatalf("reason = %q", out["reason"])
	}
	if !strings.Contains(out["error"], "services") {
		t.Fatalf("error = %q, want the service count named", out["error"])
	}
	s.mu.Lock()
	runs := len(s.runs)
	s.mu.Unlock()
	if runs != 0 {
		t.Fatalf("rejected HTTP submission persisted %d runs", runs)
	}
}

// TestCompiledServiceCeilingBackstop (K5-B): the compiled-job choke point
// used by generated fragments (which do not pass through enqueueID) refuses
// an oversized untrusted service list, while the trusted path stays
// unconstrained there.
func TestCompiledServiceCeilingBackstop(t *testing.T) {
	s := New("token")
	services := make([]pipeline.Service, pipeline.MaxUntrustedServicesPerJob+1)
	for i := range services {
		services[i] = pipeline.Service{Name: fmt.Sprintf("svc-%d", i), Image: "redis:7"}
	}
	cj := pipeline.CompiledJob{BaseID: "build", Job: pipeline.Job{Runtime: "container", Services: services}}
	_, err := s.applyUntrustedResourceCeilings(cj, false)
	var adm *admissionError
	if !errors.As(err, &adm) || adm.Reason != "untrusted_service_ceiling_exceeded" || adm.Status != 400 {
		t.Fatalf("compiled backstop = %v, want the 400 service-ceiling admission error", err)
	}
	if _, err := s.applyUntrustedResourceCeilings(cj, true); err != nil {
		t.Fatalf("trusted compiled job rejected by the untrusted backstop: %v", err)
	}
}
