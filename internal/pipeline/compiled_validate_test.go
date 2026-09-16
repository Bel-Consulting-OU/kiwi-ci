package pipeline

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

func compileSpec(t *testing.T, doc string) (*Graph, error) {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		return nil, err
	}
	return Compile(s)
}

func TestCompileRejectsInterpolatedTraversalWorkingDirectory(t *testing.T) {
	// The literal working_directory is safe; the matrix value smuggles a
	// traversal that only materializes after interpolation.
	_, err := compileSpec(t, `version: 1
jobs:
  x:
    matrix:
      DIR: ["../../evil"]
    steps:
      - working_directory: ${{ matrix.DIR }}
        run: echo hi
`)
	if err == nil || !strings.Contains(err.Error(), ".. component") {
		t.Fatalf("interpolated traversal error = %v, want path-safety rejection", err)
	}
}

func TestCompileRejectsMatrixSmuggledServiceAlias(t *testing.T) {
	_, err := compileSpec(t, `version: 1
jobs:
  x:
    matrix:
      ALIAS: ["bad alias!"]
    services:
      - name: ${{ matrix.ALIAS }}
        image: postgres:16
    steps:
      - run: echo hi
`)
	if err == nil || !strings.Contains(err.Error(), "service alias") {
		t.Fatalf("smuggled service alias error = %v, want alias rejection", err)
	}
}

func TestCompileRejectsDuplicateServiceAliases(t *testing.T) {
	_, err := compileSpec(t, `version: 1
jobs:
  x:
    services:
      - name: db
        image: postgres:16
      - name: db
        image: postgres:15
    steps:
      - run: echo hi
`)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate service alias error = %v, want duplicate rejection", err)
	}
}

func TestDeploymentPhaseStepCounting(t *testing.T) {
	steps := make([]Step, maxStepsPerJob-1)
	for i := range steps {
		steps[i] = Step{Run: "true"}
	}
	j := Job{Steps: steps}
	// One deployment-phase step pushes the total over the cap.
	j.Deployment.Canary = []Step{{Run: "true"}, {Run: "true"}}
	s := &Spec{Version: 1, Jobs: map[string]Job{"x": j}}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "deployment phases") {
		t.Fatalf("deployment phase counting error = %v, want step-cap rejection", err)
	}
	// The compiled validator enforces the same cap post-interpolation.
	cj := CompiledJob{ID: "x", BaseID: "x", Job: Job{Steps: []Step{{Run: "true"}}}}
	for i := 0; i < maxStepsPerJob; i++ {
		cj.Job.Deployment.Canary = append(cj.Job.Deployment.Canary, Step{Run: "true"})
	}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "deployment phases") {
		t.Fatalf("compiled deployment counting error = %v, want step-cap rejection", err)
	}
}

func TestValidateCompiledJobCaps(t *testing.T) {
	mk := func() CompiledJob {
		return CompiledJob{ID: "x", BaseID: "x", Job: Job{Steps: []Step{{ID: "s", Run: "true"}}}}
	}
	cj := mk()
	cj.Job.Steps[0].Run = strings.Repeat("x", maxCommandBytes+1)
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Errorf("oversized command error = %v, want byte-cap rejection", err)
	}
	cj = mk()
	cj.Job.Steps[0].Env = map[string]string{}
	for i := 0; i <= maxEnvVarsPerJob; i++ {
		cj.Job.Steps[0].Env["k"+strconv.Itoa(i)] = "v"
	}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "env vars, limit") {
		t.Errorf("per-step env cap error = %v, want env-cap rejection", err)
	}
	cj = mk()
	cj.Job.Steps[0].ID = "bad id!"
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "invalid id") {
		t.Errorf("invalid step id error = %v, want id rejection", err)
	}
	cj = mk()
	cj.ID = "x[unterminated"
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "compiled job id") {
		t.Errorf("invalid compiled id error = %v, want id rejection", err)
	}
}

func TestValidateCompiledJobArtifactsAndDownloads(t *testing.T) {
	cj := CompiledJob{ID: "x", BaseID: "x", Job: Job{
		Steps: []Step{{Run: "true"}},
		Artifacts: []Artifact{
			{Name: "bin", Paths: []string{"out"}},
			{Name: "bin", Paths: []string{"other"}},
		},
	}}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("duplicate artifact error = %v, want duplicate rejection", err)
	}
	cj = CompiledJob{ID: "x", BaseID: "x", Job: Job{
		Steps:     []Step{{Run: "true"}},
		Artifacts: []Artifact{{Name: "bin", Paths: []string{"../../evil"}}},
	}}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), ".. component") {
		t.Errorf("traversal artifact path error = %v, want path rejection", err)
	}
	cj = CompiledJob{ID: "x", BaseID: "x", Job: Job{
		Steps:     []Step{{Run: "true"}},
		Downloads: []ArtifactInput{{From: "build", Name: "bin", Path: "/etc/passwd"}},
	}}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("absolute download path error = %v, want path rejection", err)
	}
}

func TestValidateResourcesRanges(t *testing.T) {
	mk := func(r Resources, runtime string) *Spec {
		j := Job{Runtime: runtime, Resources: r, Steps: []Step{{Run: "true"}}}
		if runtime == "tart" {
			j.VM = "macos-sequoia"
		}
		return &Spec{Version: 1, Jobs: map[string]Job{"x": j}}
	}
	if err := Validate(mk(Resources{CPU: -1}, "")); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Errorf("negative cpu error = %v", err)
	}
	if err := Validate(mk(Resources{CPU: math.NaN()}, "")); err == nil || !strings.Contains(err.Error(), "finite number") {
		t.Errorf("NaN cpu error = %v, want finite-number rejection", err)
	}
	if err := Validate(mk(Resources{CPU: maxCPURequest + 1}, "")); err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
		t.Errorf("oversized cpu error = %v", err)
	}
	if err := Validate(mk(Resources{Memory: -1}, "")); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Errorf("negative memory error = %v", err)
	}
	if err := Validate(mk(Resources{Disk: maxDiskRequest + 1}, "")); err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
		t.Errorf("oversized disk error = %v", err)
	}
	if err := Validate(mk(Resources{PIDs: -1}, "")); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Errorf("negative pids error = %v", err)
	}
	if err := Validate(mk(Resources{PIDs: 1}, "container")); err != nil {
		t.Errorf("container pids rejected: %v", err)
	}
	if err := Validate(mk(Resources{PIDs: 1}, "tart")); err == nil || !strings.Contains(err.Error(), "tart backend does not honor pid limits") {
		t.Errorf("tart pids error = %v, want tart pid rejection", err)
	}
	if err := Validate(mk(Resources{Disk: 1}, "tart")); err == nil || !strings.Contains(err.Error(), "tart backend does not honor disk limits") {
		t.Errorf("tart disk error = %v, want tart disk rejection", err)
	}
	// Container disk is advisory but accepted (documented, not enforced).
	if err := Validate(mk(Resources{Disk: 1}, "container")); err != nil {
		t.Errorf("container advisory disk rejected: %v", err)
	}
	// The native backend cannot honor any resource request.
	for _, r := range []Resources{
		{CPU: 1},
		{Memory: 1},
		{Disk: 1},
		{PIDs: 1},
		{CPU: 1, Memory: 1, Disk: 1, PIDs: 1},
	} {
		if err := Validate(mk(r, "")); err == nil || !strings.Contains(err.Error(), "native backend does not enforce resource requests") {
			t.Errorf("native resources %+v error = %v, want native resource rejection", r, err)
		}
	}
	// A native job with no resource requests stays valid.
	if err := Validate(mk(Resources{}, "")); err != nil {
		t.Errorf("native job without resources rejected: %v", err)
	}
	// The compiled validator enforces the same admission.
	cj := CompiledJob{ID: "x", BaseID: "x", Job: Job{Runtime: "tart", VM: "vm", Resources: Resources{PIDs: 2}, Steps: []Step{{Run: "true"}}}}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "tart backend does not honor pid limits") {
		t.Errorf("compiled tart pids error = %v", err)
	}
	cj = CompiledJob{ID: "x", BaseID: "x", Job: Job{Runtime: "tart", VM: "vm", Resources: Resources{Disk: 2}, Steps: []Step{{Run: "true"}}}}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "tart backend does not honor disk limits") {
		t.Errorf("compiled tart disk error = %v", err)
	}
	cj = CompiledJob{ID: "x", BaseID: "x", Job: Job{Resources: Resources{CPU: 1}, Steps: []Step{{Run: "true"}}}}
	if err := ValidateCompiledJob(cj); err == nil || !strings.Contains(err.Error(), "native backend does not enforce resource requests") {
		t.Errorf("compiled native resources error = %v", err)
	}
}

func TestResourceCapabilitiesMap(t *testing.T) {
	cpu, mem, disk, pids := ResourceCapabilities("container")
	if !cpu || !mem || disk || !pids {
		t.Error("container must honor cpu/memory/pids and treat disk as advisory")
	}
	cpu, mem, disk, pids = ResourceCapabilities("tart")
	if !cpu || !mem || disk || pids {
		t.Error("tart must honor cpu/memory only")
	}
	cpu, mem, disk, pids = ResourceCapabilities("")
	if cpu || mem || disk || pids {
		t.Error("native runtime must report no enforceable resource limits")
	}
	cpu, mem, disk, pids = ResourceCapabilities("bogus")
	if cpu || mem || disk || pids {
		t.Error("unknown runtime must report no enforceable resource limits")
	}
}

func TestCompileValidatesEveryCompiledJob(t *testing.T) {
	// A matrix value that interpolates into a cache path with a traversal
	// must be rejected at compile for the offending variant.
	_, err := compileSpec(t, `version: 1
jobs:
  x:
    matrix:
      P: ["ok", "../../evil"]
    cache:
      - paths:
          - "${{ matrix.P }}"
    steps:
      - run: echo hi
`)
	if err == nil || !strings.Contains(err.Error(), ".. component") {
		t.Fatalf("compiled cache path error = %v, want traversal rejection", err)
	}
}

func TestCompiledJobJSONRoundTrip(t *testing.T) {
	g, err := compileSpec(t, `version: 1
jobs:
  x:
    steps:
      - id: s
        run: echo hi
`)
	if err != nil {
		t.Fatal(err)
	}
	cj := g.Jobs["x"]
	b, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	var rt CompiledJob
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCompiledJob(rt); err != nil {
		t.Fatalf("round-tripped compiled job must re-validate: %v", err)
	}
}
