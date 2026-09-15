package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestEnqueueInterpolatesInputsIntoStoredPipeline covers the CompileWithInputs
// adoption at enqueue: submitting validated inputs interpolates ${{ inputs.x }}
// in the stored job pipeline text, and the persisted pipeline digest and job
// digest derive from the effective (input-interpolated) compiled result.
func TestEnqueueInterpolatesInputsIntoStoredPipeline(t *testing.T) {
	s := New("token")
	c := newTestClient(t, s.Handler(), "token")
	pipelineText := `version: 1
inputs:
  environment:
    type: enum
    required: true
    options: [staging, production]
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    env:
      TARGET: "${{ inputs.environment }}"
    steps:
      - run: echo "${{ inputs.environment }}"
`
	ok := SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText,
		Metadata: map[string]string{"input.environment": "production"}}
	w := c.do(http.MethodPost, "/api/v1/runs", ok, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	var stored string
	var job model.Job
	for _, j := range s.jobs {
		stored = j.Pipeline
		job = j
	}
	s.mu.Unlock()
	if !strings.Contains(stored, `"TARGET":"production"`) || !strings.Contains(stored, `echo \"production\"`) {
		t.Fatalf("stored pipeline does not carry the interpolated input:\n%s", stored)
	}
	if strings.Contains(stored, `${{ inputs.environment }}`) {
		t.Fatalf("stored pipeline still carries the raw input hole:\n%s", stored)
	}
	// The persisted pipeline digest derives from the EFFECTIVE spec (the
	// stored text itself), not from the raw submission.
	effective, err := pipeline.Parse([]byte(stored))
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := pipeline.PipelineDigest(effective)
	if err != nil {
		t.Fatal(err)
	}
	if job.CompiledJobPayload == nil || job.CompiledJobPayload.PipelineDigest != wantDigest {
		t.Fatalf("pipeline digest = %q, want effective-spec digest %q", job.CompiledJobPayload.PipelineDigest, wantDigest)
	}
	// The persisted job digest derives from the effective compiled job.
	raw, err := json.Marshal(job.CompiledJobPayload.EffectiveJob)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if want := hex.EncodeToString(sum[:]); job.CompiledJobPayload.JobDigest != want {
		t.Fatalf("job digest = %q, want %q (effective compiled job)", job.CompiledJobPayload.JobDigest, want)
	}
	var cj pipeline.CompiledJob
	if err := json.Unmarshal(raw, &cj); err != nil {
		t.Fatal(err)
	}
	if cj.Job.Steps[0].Run != `echo "production"` {
		t.Fatalf("effective compiled step = %q, want interpolated", cj.Job.Steps[0].Run)
	}
}

// TestEnqueueStrictResolutionOnOriginalBytes covers the strict resolution
// parser: unknown fields, duplicate keys and aliases are rejected on the
// ORIGINAL submission bytes, with line numbers, before any component
// resolution or normalization.
func TestEnqueueStrictResolutionOnOriginalBytes(t *testing.T) {
	cspec := components.Spec{
		Name: "build",
		Inputs: []components.Input{
			{Name: "environment", Type: "enum", Options: []string{"staging", "production"}},
		},
		Steps: []pipeline.Step{{Run: "make build"}},
	}
	digest, err := components.Digest(cspec)
	if err != nil {
		t.Fatal(err)
	}
	reg := components.NewLocalRegistry()
	reg.Register(cspec)
	s := New("token")
	s.ComponentRegistry = reg
	c := newTestClient(t, s.Handler(), "token")
	submit := func(doc string) *httptest.ResponseRecorder {
		return c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: doc}, nil)
	}
	// Unknown field inside a component-using pipeline: rejected with a line
	// number on the original bytes.
	w := submit(`version: 1
jobs:
  build:
    component: build@sha256:` + digest + `
    with:
      environment: staging
    bogus_field: true
`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unknown field") || !strings.Contains(w.Body.String(), "line 7") {
		t.Fatalf("unknown field = %d %s, want line-numbered unknown-field rejection", w.Code, w.Body.String())
	}
	// Duplicate keys are rejected on the original bytes.
	w = submit("version: 1\njobs:\n  build:\n    component: build\n    component: build\n")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "duplicate key") {
		t.Fatalf("duplicate key = %d %s, want duplicate-key rejection", w.Code, w.Body.String())
	}
	// Anchors/aliases are rejected (the anchor is caught on the original
	// bytes; aliases cannot exist without one).
	w = submit("version: 1\njobs:\n  build: &anchor\n    component: build\n  other: *anchor\n")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "anchor") {
		t.Fatalf("alias = %d %s, want anchor/alias rejection", w.Code, w.Body.String())
	}
	// A well-formed component pipeline still resolves.
	w = submit(`version: 1
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    component: build@sha256:` + digest + `
    with:
      environment: staging
`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("valid component submit = %d %s", w.Code, w.Body.String())
	}
}

func TestEnqueueJobResourcePersistence(t *testing.T) {
	now := time.Now().UTC()
	cj := pipeline.CompiledJob{ID: "build", BaseID: "build"}
	cj.Job.Resources = pipeline.Resources{CPU: 2.5, Memory: 512 << 20, Disk: 2 << 30, PIDs: 100}
	cj.Job.QueueTimeout.Duration = 5 * time.Minute
	cj.Job.QueueTimeout.Set = true
	var j model.Job
	applyCompiledJobFields(&j, cj, now)
	if j.CPURequest != 2.5 || j.MemoryRequest != 512<<20 || j.DiskRequest != 2<<30 || j.PIDsRequest != 100 {
		t.Fatalf("resource requests = %v/%d/%d/%d, want populated", j.CPURequest, j.MemoryRequest, j.DiskRequest, j.PIDsRequest)
	}
	if j.QueueDeadline == nil || !j.QueueDeadline.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("queue deadline = %v, want %v", j.QueueDeadline, now.Add(5*time.Minute))
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"cpu_request":2.5`, `"memory_request":536870912`, `"disk_request":2147483648`, `"pids_request":100`, `"queue_deadline"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("job payload missing %s: %s", want, b)
		}
	}
	var rt model.Job
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatal(err)
	}
	if rt.CPURequest != 2.5 || rt.QueueDeadline == nil {
		t.Fatalf("payload round-trip lost resource/deadline fields: %+v", rt)
	}
	// Jobs without a queue timeout get no deadline.
	cj.Job.QueueTimeout.Duration = 0
	cj.Job.QueueTimeout.Set = false
	j2 := model.Job{}
	applyCompiledJobFields(&j2, cj, now)
	if j2.QueueDeadline != nil {
		t.Fatalf("job without queue_timeout got a deadline: %v", j2.QueueDeadline)
	}
}
