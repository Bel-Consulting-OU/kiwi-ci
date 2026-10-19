package executor

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestAllowRootfulUntrustedSkipsRootlessGate: K5 — the [runner]
// allow_rootful_untrusted escape must actually skip the rootless daemon
// gate so darwin/colima can run untrusted jobs.
func TestAllowRootfulUntrustedSkipsRootlessGate(t *testing.T) {
	installFakeBins(t)
	// Fake docker reports no rootless; with the escape the job must not
	// die on requireRootlessDaemon.
	t.Setenv("FAKE_DOCKER_INFO", "[name=seccomp,profile=builtin]")
	script := "          echo ok\n"
	g := envProbeSpec(nativeScript(script, script))
	{
		cj := g.Jobs["probe"]
		cj.Job.Runtime = "container"
		cj.Job.Image = "alpine:3.20"
		cj.Job.Sandbox.Rootless = true
		g.Jobs["probe"] = cj
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir(), AllowRootfulUntrusted: true}}
	res, _ := ex.Run(t.Context(), g)
	if r := res["probe"]; r.Status == model.StatusFailure && strings.Contains(r.Error, "not rootless") {
		t.Fatalf("rootless gate not skipped despite AllowRootfulUntrusted: %v", r.Error)
	}
}

// TestRootlessGateStillEnforcedWithoutEscape: without the escape the gate
// stays fail-closed on a rootful daemon.
func TestRootlessGateStillEnforcedWithoutEscape(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_INFO", "[name=seccomp,profile=builtin]")
	script := "          echo ok\n"
	g := envProbeSpec(nativeScript(script, script))
	{
		cj := g.Jobs["probe"]
		cj.Job.Runtime = "container"
		cj.Job.Image = "alpine:3.20"
		cj.Job.Sandbox.Rootless = true
		g.Jobs["probe"] = cj
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir()}}
	res, _ := ex.Run(t.Context(), g)
	if r := res["probe"]; r.Status != model.StatusFailure || !strings.Contains(r.Error, "not rootless") {
		t.Fatalf("rootless gate must stay fail-closed: %+v", r)
	}
}
