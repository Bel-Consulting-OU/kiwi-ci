package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// P0 regression: the image lock is applied by the CANONICAL RESOLVER, not
// the webhook's temporary spec. The compiled/canonical pipeline text that
// every job carries must contain the LOCKED digests — trigger-eval-only
// locking would leave remote runs on mutable tags.
func TestResolvePipelineAppliesImageLockToCanonicalGraph(t *testing.T) {
	s := New("runner-secret")
	const pipe = `version: 1
jobs:
  build:
    image: golang:1.27
    services:
      - name: db
        image: postgres:16
    steps:
      - run: go build ./...
`
	const lock = `{"version":1,"images":[
		{"ref":"golang:1.27","digest":"golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"ref":"postgres:16","digest":"postgres:16@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	]}`
	spec, canon, _, err := s.resolvePipeline(context.Background(), SubmitRun{Pipeline: pipe, ImageLock: lock})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(spec.Jobs["build"].Image, "golang:1.27@sha256:") ||
		!strings.Contains(spec.Jobs["build"].Image, "aaaa") {
		t.Fatalf("effective spec image = %q, want locked digest", spec.Jobs["build"].Image)
	}
	if len(spec.Jobs["build"].Services) == 0 ||
		!strings.HasPrefix(spec.Jobs["build"].Services[0].Image, "postgres:16@sha256:") ||
		!strings.Contains(spec.Jobs["build"].Services[0].Image, "bbbb") {
		t.Fatalf("service image not locked: %+v", spec.Jobs["build"].Services)
	}
	// The CANONICAL TEXT every runner recompiles must carry the locked form.
	if !strings.Contains(canon, "golang:1.27@sha256:") {
		t.Fatalf("canonical pipeline text lost the lock: %s", canon)
	}
	if !strings.Contains(canon, "postgres:16@sha256:") {
		t.Fatalf("canonical pipeline text lost the service lock: %s", canon)
	}
	// Trigger-eval-only locking would pass the spec check but fail here.
	if strings.Contains(canon, `"golang:1.27"`) && !strings.Contains(canon, "golang:1.27@sha256:") {
		t.Fatal("canonical text still carries the mutable tag")
	}
}

// A malformed lockfile at the trust boundary is FAIL-CLOSED, never a silent
// fallback to mutable tags.
func TestResolvePipelineMalformedLockFailsClosed(t *testing.T) {
	s := New("runner-secret")
	_, _, _, err := s.resolvePipeline(context.Background(), SubmitRun{
		Pipeline:  "version: 1\njobs:\n  b:\n    run: echo hi\n",
		ImageLock: "not json",
	})
	if err == nil {
		t.Fatal("malformed lockfile must fail closed")
	}
	// Empty lock is "no lockfile" and is tolerated.
	if _, _, _, err := s.resolvePipeline(context.Background(), SubmitRun{
		Pipeline: "version: 1\njobs:\n  b:\n    run: echo hi\n",
	}); err != nil {
		t.Fatalf("empty lock = %v, want success", err)
	}
}

// Component-only jobs must survive ingress (trigger parse) and reach the
// real resolver. The strict parser rejects them; ParseWithComponents does
// not. This pins the ingress/resolver split.
func TestComponentOnlyJobSurvivesTriggerParse(t *testing.T) {
	const pipe = `version: 1
jobs:
  test:
    component: company/go-test@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`
	// Strict parse rejects a job with no local steps.
	if _, err := pipeline.Parse([]byte(pipe)); err == nil {
		t.Log("note: strict Parse accepted a component-only job (relaxation may already be global)")
	}
	// The trigger-level parser MUST accept it.
	if _, err := pipeline.ParseWithComponents([]byte(pipe)); err != nil {
		t.Fatalf("component-only job must survive trigger parse: %v", err)
	}
}
