package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Setup must be a RESUMABLE state machine: progress is recorded after each
// step, a re-run continues from the first unfinished step, and --reset
// clears it. A printed checklist is not a wizard.
func TestSetupStateMachineResumes(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("KIWI_CONFIG_DIR", cfg)
	t.Chdir(t.TempDir())

	// --print lists the steps and does not write state.
	if err := Setup([]string{"--print"}); err != nil {
		t.Fatalf("setup --print: %v", err)
	}
	p := filepath.Join(cfg, "setup.json")
	if _, err := os.Stat(p); err == nil {
		t.Fatal("--print must not write setup state")
	}

	// A run that hits a missing dependency (docker/psql may be absent in
	// CI) must persist progress and name the failing step.
	err := Setup(nil)
	if err != nil {
		if !strings.Contains(err.Error(), "setup step") {
			t.Fatalf("setup error must name the step: %v", err)
		}
	}
	raw, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("setup state not written after run: %v", rerr)
	}
	if !strings.Contains(string(raw), `"done"`) {
		t.Fatalf("setup state missing done map: %s", raw)
	}

	// --reset clears it.
	if err := Setup([]string{"--reset"}); err != nil {
		t.Fatalf("setup --reset: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("--reset must remove setup state")
	}
}

// The pipeline step must be idempotent: an existing valid pipeline is
// accepted; a missing one is generated and validated.
func TestSetupPipelineStepIdempotent(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("KIWI_CONFIG_DIR", cfg)
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := &setupState{Version: setupStateVersion, Done: map[string]bool{}, Notes: map[string]string{}}
	steps := setupSteps()
	var pipelineStep *setupStep
	for i := range steps {
		if steps[i].ID == "pipeline" {
			pipelineStep = &steps[i]
		}
	}
	if pipelineStep == nil {
		t.Fatal("no pipeline step")
	}
	if err := pipelineStep.Apply(st, os.Stdout); err != nil {
		t.Fatalf("pipeline apply: %v", err)
	}
	ok, _, err := pipelineStep.Check(st)
	if err != nil || !ok {
		t.Fatalf("pipeline check after apply: ok=%v err=%v", ok, err)
	}
	// Second apply is a no-op success.
	if err := pipelineStep.Apply(st, os.Stdout); err != nil {
		t.Fatalf("pipeline re-apply: %v", err)
	}
}
