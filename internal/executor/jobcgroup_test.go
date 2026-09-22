package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// stubJobCgroup replaces the platform cgroup setup for one test and counts
// invocations. It returns the counter pointer and the stub's cleanup counter.
func stubJobCgroup(t *testing.T, status JobCgroupStatus) (*int, *int) {
	t.Helper()
	orig := jobCgroupSetup
	calls, cleanups := 0, 0
	jobCgroupSetup = func(context.Context, jobCgroupRequest) (JobCgroupStatus, func() error) {
		calls++
		return status, func() error {
			cleanups++
			return nil
		}
	}
	t.Cleanup(func() { jobCgroupSetup = orig })
	return &calls, &cleanups
}

// TestJobCgroupLimitsRenderDeclaredEnvelope pins the cgroup-v2 limit mapping:
// declared axes become kernel limit files, undeclared axes become nothing (a
// zero written to pids.max/memory.max would mean "no limit"), memory gets the
// swap guard, and fractional CPU is expressed in the cpu.max quota/period
// form.
func TestJobCgroupLimitsRenderDeclaredEnvelope(t *testing.T) {
	limits := jobCgroupLimits(jobCgroupRequest{CPU: 2, Memory: 4 << 30, PIDs: 256})
	want := map[string]string{
		"cpu.max":         "200000 100000",
		"memory.max":      "4294967296",
		"memory.swap.max": "0",
		"pids.max":        "256",
	}
	if len(limits) != len(want) {
		t.Fatalf("limits = %+v, want %d entries", limits, len(want))
	}
	for _, l := range limits {
		if got, ok := want[l.File]; !ok || got != l.Value {
			t.Fatalf("limit %q = %q, want %q", l.File, l.Value, want[l.File])
		}
	}
	// Fractional CPU and the degenerate tiny request stay positive.
	frac := jobCgroupLimits(jobCgroupRequest{CPU: 0.25})
	if len(frac) != 1 || frac[0].Value != "25000 100000" {
		t.Fatalf("fractional cpu limit = %+v", frac)
	}
	tiny := jobCgroupLimits(jobCgroupRequest{CPU: 0.000001})
	if len(tiny) != 1 || tiny[0].Value != "1 100000" {
		t.Fatalf("tiny cpu limit = %+v", tiny)
	}
	// Undeclared axes produce no limit files at all.
	if got := jobCgroupLimits(jobCgroupRequest{}); len(got) != 0 {
		t.Fatalf("undeclared request produced limits: %+v", got)
	}
	if got := jobCgroupControllers(jobCgroupRequest{CPU: 1, PIDs: 4}); strings.Join(got, ",") != "cpu,pids" {
		t.Fatalf("controllers = %v", got)
	}
}

// TestCreateJobCgroupUnderWritesLimitsAndCleansUp proves the portable core on
// a plain directory tree (the same operations a real cgroupfs gets): the job
// directory is created under the delegated base, every limit file carries the
// exact value, and cleanup removes the directory including docker's
// per-container child cgroups.
func TestCreateJobCgroupUnderWritesLimitsAndCleansUp(t *testing.T) {
	// A plain temporary directory does not materialize cgroup control files
	// the way cgroupfs does; simulate that with the documented seam.
	orig := materializeCgroupControls
	materializeCgroupControls = func(dir string) error {
		for _, name := range []string{"cpu.max", "memory.max", "memory.swap.max", "pids.max", "cgroup.subtree_control"} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	t.Cleanup(func() { materializeCgroupControls = orig })

	base := t.TempDir()
	dir, cleanup, err := createJobCgroupUnder(base, "kiwi-job-x-1", jobCgroupControllers(jobCgroupRequest{CPU: 1.5, Memory: 1 << 30, PIDs: 64}), jobCgroupLimits(jobCgroupRequest{CPU: 1.5, Memory: 1 << 30, PIDs: 64}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for file, want := range map[string]string{
		"cpu.max":         "150000 100000",
		"memory.max":      "1073741824",
		"memory.swap.max": "0",
		"pids.max":        "64",
	} {
		b, rerr := os.ReadFile(filepath.Join(dir, file))
		if rerr != nil {
			t.Fatalf("read %s: %v", file, rerr)
		}
		if string(b) != want {
			t.Fatalf("%s = %q, want %q", file, string(b), want)
		}
	}
	subtree, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		t.Fatalf("read cgroup.subtree_control: %v", err)
	}
	if string(subtree) != "+cpu +memory +pids" {
		t.Fatalf("cgroup.subtree_control = %q, want the required controllers enabled for the container children", string(subtree))
	}
	// Docker leaves a child cgroup per container behind when teardown races;
	// cleanup removes it so the job directory can go.
	child := filepath.Join(dir, "docker-abc123.scope")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("job cgroup directory survived cleanup: %v", err)
	}
	// Cleanup is idempotent.
	if err := cleanup(); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
}

// TestCreateJobCgroupUnderPartialFailureRemovesDir proves a failed limit write
// never leaves a half-configured job cgroup behind.
func TestCreateJobCgroupUnderPartialFailureRemovesDir(t *testing.T) {
	base := t.TempDir()
	limits := []cgroupLimit{{File: "cpu.max", Value: "100000 100000"}, {File: "missing/memory.max", Value: "1"}}
	dir, cleanup, err := createJobCgroupUnder(base, "kiwi-job-x-2", []string{"cpu"}, limits)
	if err == nil || cleanup != nil || dir != "" {
		t.Fatalf("partial failure = (%q, %v, %v), want an error without cleanup", dir, cleanup != nil, err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("half-created job cgroup left behind: %v", entries)
	}
}

// TestEnsureDelegatedCgroupBase pins the delegation probe: a base is only
// usable when its cgroup.subtree_control already enables every required
// controller (the kernel's no-internal-processes rule means the runner cannot
// enable one on the cgroup its own process occupies).
func TestEnsureDelegatedCgroupBase(t *testing.T) {
	base := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := ensureDelegatedCgroupBase(base, []string{"cpu"}); err == nil {
		t.Fatal("base without cgroup.subtree_control accepted")
	}
	write("cgroup.subtree_control", "+cpu +memory\n")
	if err := ensureDelegatedCgroupBase(base, []string{"cpu", "memory"}); err != nil {
		t.Fatalf("delegated base rejected: %v", err)
	}
	err := ensureDelegatedCgroupBase(base, []string{"cpu", "pids"})
	if err == nil || !strings.Contains(err.Error(), "pids") {
		t.Fatalf("missing controller error = %v, want it to name pids", err)
	}
	// A file is never a usable base.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureDelegatedCgroupBase(file, nil); err == nil {
		t.Fatal("regular file accepted as a cgroup base")
	}
	if err := ensureDelegatedCgroupBase(filepath.Join(t.TempDir(), "absent"), nil); err == nil {
		t.Fatal("missing directory accepted as a cgroup base")
	}
}

// TestJobCgroupDirNameIsUniquePerAttempt proves two attempts for the same job
// ID can never share one parent cgroup directory.
func TestJobCgroupDirNameIsUniquePerAttempt(t *testing.T) {
	a := jobCgroupDirName("job/../weird id", jobCgroupSuffix())
	b := jobCgroupDirName("job/../weird id", jobCgroupSuffix())
	if a == b {
		t.Fatalf("job cgroup names collided: %q", a)
	}
	if !strings.HasPrefix(a, jobCgroupNamePrefix) || strings.Contains(a, "/") {
		t.Fatalf("job cgroup name is not a safe single path component: %q", a)
	}
	if first, second := jobCgroupSuffix(), jobCgroupSuffix(); first == second {
		t.Fatal("job cgroup suffix repeated")
	}
}

// TestRunJobServicesShareJobCgroupParent proves the E3-A wiring on the runJob
// path: when the platform provides a job cgroup, the services AND the main
// container receive --cgroup-parent, and the cgroup is removed only after the
// containers were removed.
func TestRunJobServicesShareJobCgroupParent(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	cleaned, cleanedAfterRemoval, runsAtSetup := 0, false, -1
	orig := jobCgroupSetup
	jobCgroupSetup = func(_ context.Context, req jobCgroupRequest) (JobCgroupStatus, func() error) {
		if req.JobID != "build" || req.CPU != 2 || req.Memory != 4<<30 || req.PIDs != 512 {
			t.Errorf("job cgroup request = %+v, want the compiled job envelope", req)
		}
		// The kernel parent must exist (with its limits) BEFORE any service
		// container starts.
		runsAtSetup = len(runLines(readFakeLog(t, "FAKE_DOCKER_LOG")))
		return JobCgroupStatus{Enabled: true, Parent: "/kiwi-job-test-1", Detail: "stub job cgroup"}, func() error {
			cleaned++
			log := readFakeLog(t, "FAKE_DOCKER_LOG")
			if strings.Contains(log, "rm -f kiwi-job-") && strings.Contains(log, "rm -f "+serviceContainerName("r", "build", 0)) {
				cleanedAfterRemoval = true
			}
			return nil
		}
	}
	t.Cleanup(func() { jobCgroupSetup = orig })

	sink := &covSink{}
	services := []pipeline.Service{
		{Name: "db", Image: "postgres:16"},
		{Name: "cache", Image: "redis:7"},
	}
	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{
		"build": {Runtime: "container", Image: "alpine:3.19", Services: services, Steps: []pipeline.Step{{Run: "echo hi"}}},
	}}
	j := pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{
		Runtime:   "container",
		Image:     "alpine:3.19",
		Resources: pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512},
		Services:  services,
		Steps:     []pipeline.Step{{Run: "echo hi"}},
	}}
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: sink}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "success" {
		t.Fatalf("runJob = status %q error %q", res.Status, res.Error)
	}
	runs := runLines(readFakeLog(t, "FAKE_DOCKER_LOG"))
	if len(runs) != len(services)+1 {
		t.Fatalf("docker run count = %d, want %d (services + main container):\n%v", len(runs), len(services)+1, runs)
	}
	for _, line := range runs {
		if !strings.Contains(line, "--cgroup-parent=/kiwi-job-test-1") {
			t.Fatalf("run without the job cgroup parent: %s", line)
		}
	}
	if cleaned != 1 {
		t.Fatalf("job cgroup cleanups = %d, want 1", cleaned)
	}
	if runsAtSetup != 0 {
		t.Fatalf("containers were already running when the job cgroup was created (%d runs)", runsAtSetup)
	}
	if !cleanedAfterRemoval {
		t.Fatal("job cgroup removed before the containers were gone")
	}
	if !sink.has("job resource cgroup: stub job cgroup") {
		t.Fatalf("job cgroup outcome not logged: %v", sink.lines)
	}
}

// TestRunJobServicesWithoutJobCgroupReportsAggregate proves the documented
// fallback: without a kernel parent the executor keeps per-container caps,
// logs the exact reason and the aggregate service request the scheduler must
// reserve, and passes no --cgroup-parent.
func TestRunJobServicesWithoutJobCgroupReportsAggregate(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	calls, cleanups := stubJobCgroup(t, JobCgroupStatus{Detail: "no delegated cgroup here"})

	sink := &covSink{}
	services := []pipeline.Service{{Name: "db", Image: "postgres:16"}}
	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{
		"build": {Runtime: "container", Image: "alpine:3.19", Services: services, Steps: []pipeline.Step{{Run: "echo hi"}}},
	}}
	j := pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{
		Runtime:   "container",
		Image:     "alpine:3.19",
		Resources: pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512},
		Services:  services,
		Steps:     []pipeline.Step{{Run: "echo hi"}},
	}}
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: sink}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "success" {
		t.Fatalf("runJob = status %q error %q", res.Status, res.Error)
	}
	if *calls != 1 || *cleanups != 0 {
		t.Fatalf("job cgroup setup/cleanup = (%d, %d), want (1, 0)", *calls, *cleanups)
	}
	if !sink.has("job resource cgroup unavailable (no delegated cgroup here)") {
		t.Fatalf("fallback reason not logged: %v", sink.lines)
	}
	if !sink.has("aggregate service request (cpu=2 memory=2147483648 pids=256)") {
		t.Fatalf("aggregate service request not logged: %v", sink.lines)
	}
	if strings.Contains(readFakeLog(t, "FAKE_DOCKER_LOG"), "--cgroup-parent") {
		t.Fatalf("--cgroup-parent passed without a job cgroup:\n%s", readFakeLog(t, "FAKE_DOCKER_LOG"))
	}
}

// TestRunJobWithoutServicesSkipsJobCgroup proves the job cgroup is only
// attempted when service containers exist (a lone container already gets the
// declared limits on its own cgroup).
func TestRunJobWithoutServicesSkipsJobCgroup(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	calls, _ := stubJobCgroup(t, JobCgroupStatus{Enabled: true, Parent: "/never", Detail: "must not be used"})
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: sink}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", BaseID: "j",
		Job: pipeline.Job{Runtime: "container", Image: "alpine:3.19", Resources: pipeline.Resources{CPU: 1}, Steps: []pipeline.Step{{Run: "echo hi"}}},
	}, "success", nil)
	if res.Status != "success" {
		t.Fatalf("runJob = %q %q", res.Status, res.Error)
	}
	if *calls != 0 {
		t.Fatalf("job cgroup attempted %d times without services", *calls)
	}
	if strings.Contains(readFakeLog(t, "FAKE_DOCKER_LOG"), "--cgroup-parent") {
		t.Fatal("--cgroup-parent passed without a job cgroup")
	}
}
