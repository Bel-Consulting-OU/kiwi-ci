package runner

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCompleteForwardsObservedRuntime pins the completion wire: the
// executor-captured runtime identity rides server.Complete.observed_runtime
// and is delivered verbatim.
func TestCompleteForwardsObservedRuntime(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	obs := &model.ObservedRuntime{
		OS:              "linux",
		Arch:            "amd64",
		RuntimeName:     "docker",
		RuntimeVersion:  "27.1.2",
		MainImage:       "alpine:3.19",
		MainImageDigest: "sha256:" + strings.Repeat("a", 64),
	}
	r.complete(context.Background(), basicTask(payloadPipeline), model.StatusSuccess, nil, nil, obs)
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion delivered")
	}
	if c.ObservedRuntime == nil {
		t.Fatal("completion lost the observed runtime")
	}
	if c.ObservedRuntime.RuntimeName != "docker" || c.ObservedRuntime.RuntimeVersion != "27.1.2" ||
		c.ObservedRuntime.MainImageDigest != obs.MainImageDigest || c.ObservedRuntime.MainImage != "alpine:3.19" {
		t.Fatalf("wire observed runtime = %+v, want %+v", c.ObservedRuntime, obs)
	}
}
