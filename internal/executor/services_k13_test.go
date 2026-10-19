package executor

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestServicesSilentSkipIsImpossible: K13 — a declared-but-unprovisioned
// service must be a LOUD error, never a silent absence.
func TestServicesSilentSkipIsImpossible(t *testing.T) {
	installFakeBins(t)
	g := envProbeSpec(nativeScript("          echo ok\n", "          echo ok\n"))
	{
		cj := g.Jobs["probe"]
		cj.Job.Runtime = "native"
		cj.Job.Services = []pipeline.Service{{Name: "db", Image: "postgres:16"}}
		g.Jobs["probe"] = cj
	}
	ex := Executor{Opt: Options{Workspace: t.TempDir()}}
	res, _ := ex.Run(t.Context(), g)
	r := res["probe"]
	if r.Status != model.StatusFailure {
		t.Fatalf("native+services must fail loud: %+v", r)
	}
	if !strings.Contains(r.Error, "cannot provision") {
		t.Fatalf("error must name the cause: %q", r.Error)
	}
}

// TestServiceLivenessCatchesDeadEntrypoint: docker run -d returns 0 even
// when the entrypoint exits instantly; the liveness check must fail loud.
func TestServiceLivenessCatchesDeadEntrypoint(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_INSPECT_DEAD", "1")
	_, _, err := startContainerServices(t.Context(), "r", "j",
		[]pipeline.Service{{Name: "db", Image: "postgres:16"}}, pipeline.Resources{}, false, false, "", func(string) {})
	if err == nil {
		t.Fatal("dead service accepted")
	}
	if !strings.Contains(err.Error(), "exited immediately") && !strings.Contains(err.Error(), "vanished") {
		t.Fatalf("error = %v, want immediate-exit failure", err)
	}
}

// TestDefaultReadyProbeSkipsWhenHealthcheckSet: the healthcheck IS the
// readiness signal; a default probe must not race it.
func TestDefaultReadyProbeSkipsWhenHealthcheckSet(t *testing.T) {
	installFakeBins(t)
	services := []pipeline.Service{{Name: "db", Image: "postgres:16", Healthcheck: "true"}}
	_, cleanup, err := startContainerServices(t.Context(), "r", "j", services, pipeline.Resources{}, false, false, "", func(string) {})
	if err != nil {
		t.Fatalf("service with healthcheck: %v", err)
	}
	defer cleanup()
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	// No ready-probe container (alpine run) should appear.
	if strings.Count(log, "alpine") > 0 {
		t.Fatalf("default ready probe ran despite healthcheck:\n%s", log)
	}
}

// TestNamelessServiceSkipsReadyProbe: a service with no name has no alias
// to probe; the liveness check already covered entrypoint survival.
func TestNamelessServiceSkipsReadyProbe(t *testing.T) {
	installFakeBins(t)
	_, cleanup, err := startContainerServices(t.Context(), "r", "j",
		[]pipeline.Service{{Image: "postgres:16"}}, pipeline.Resources{}, false, false, "", func(string) {})
	if err != nil {
		t.Fatalf("nameless service: %v", err)
	}
	defer cleanup()
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if strings.Count(log, "alpine") > 0 {
		t.Fatalf("ready probe ran for nameless service:\n%s", log)
	}
}
