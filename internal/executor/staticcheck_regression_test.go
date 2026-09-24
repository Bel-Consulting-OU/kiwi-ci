package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestServiceStartupFailureFailsClosed pins the contract around the
// cleanupServices handling in runJob: when container services cannot be
// started, the job fails with the infra error instead of proceeding under a
// silently no-op cleanup function. The nil cleanup declaration must never be
// deferred: it is only assigned by a successful startContainerServices call,
// and every startContainerServices failure path returns before the defer.
func TestServiceStartupFailureFailsClosed(t *testing.T) {
	// Force the docker-absent path on every host (including docker-capable CI
	// runners) instead of skipping: an empty PATH makes every
	// exec.LookPath("docker") fail, so the fails-closed contract runs
	// everywhere.
	t.Setenv("PATH", t.TempDir())
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  svc:
    runtime: container
    image: alpine:3.20
    services:
      - name: redis
        image: redis:7
    steps:
      - run: echo ok
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir(), MaxParallel: 1}}
	res, _ := ex.Run(context.Background(), g)
	r := res["svc"]
	if r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	if !strings.Contains(r.Error, "docker not found") {
		t.Fatalf("job error = %q, want docker-not-found infra error", r.Error)
	}
}
