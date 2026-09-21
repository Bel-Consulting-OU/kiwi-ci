package executor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// TestServiceContainerNameIsAlwaysPhysical proves the physical docker
// container name never equals the declared alias, keeps the service index
// even for over-long run/job IDs, and stays distinct between concurrent jobs.
func TestServiceContainerNameIsAlwaysPhysical(t *testing.T) {
	if got := serviceContainerName("run-1", "job-1", 2); got != "kiwi-svc-run-1-job-1-3" {
		t.Fatalf("physical name = %q", got)
	}
	// The alias must never be the physical name.
	if got := serviceContainerName("r", "j", 0); got == "postgres" {
		t.Fatalf("alias leaked into physical name: %q", got)
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		n := serviceContainerName("r", "j", i)
		if seen[n] {
			t.Fatalf("duplicate physical name %q at index %d", n, i)
		}
		seen[n] = true
	}
	// Over-long IDs are truncated to a bounded name but stay distinct and
	// keep the index-bearing suffix deterministic.
	long := strings.Repeat("a", 300)
	first := serviceContainerName(long, long, 0)
	second := serviceContainerName(long, long, 1)
	if len(first) > maxServiceContainerNameLen {
		t.Fatalf("physical name %d chars exceeds %d", len(first), maxServiceContainerNameLen)
	}
	if first == second {
		t.Fatal("services of one job collided after truncation")
	}
	if other := serviceContainerName(long+"b", long, 0); other == first {
		t.Fatal("distinct long job IDs collided after truncation")
	}
	if other := serviceContainerName(long, long+"b", 0); other == first {
		t.Fatal("distinct long run IDs collided after truncation")
	}
}

// TestConcurrentJobsSameServiceAliasBothStartAndCleanup proves the D1-A fix:
// two jobs on one runner may both declare a service aliased "postgres". Each
// gets its own physical container name, the alias is attached with
// --network-alias (so the job can still reach postgres), and cleanup removes
// physical names only.
func TestConcurrentJobsSameServiceAliasBothStartAndCleanup(t *testing.T) {
	installFakeBins(t)
	ctx := context.Background()
	jobs := [][2]string{{"runA", "jobA"}, {"runB", "jobB"}}
	services := []pipeline.Service{{Name: "postgres", Image: "postgres:16"}}
	resources := pipeline.Resources{CPU: 4, Memory: 4 << 30, PIDs: 512}
	var wg sync.WaitGroup
	errs := make(chan error, len(jobs))
	for _, ids := range jobs {
		wg.Add(1)
		go func(runID, jobID string) {
			defer wg.Done()
			_, cleanup, err := startContainerServices(ctx, runID, jobID, services, resources, false, false, func(string) {})
			if err != nil {
				errs <- err
				return
			}
			cleanup()
		}(ids[0], ids[1])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent startContainerServices: %v", err)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if strings.Contains(log, "--name postgres") {
		t.Fatalf("bare alias used as a docker container name:\n%s", log)
	}
	for _, ids := range jobs {
		physical := serviceContainerName(ids[0], ids[1], 0)
		if !strings.Contains(log, "--name "+physical) {
			t.Fatalf("physical name %q missing from docker log:\n%s", physical, log)
		}
		if !strings.Contains(log, "rm -f "+physical) {
			t.Fatalf("cleanup did not kill physical name %q:\n%s", physical, log)
		}
	}
	if got := strings.Count(log, "--network-alias postgres"); got != len(jobs) {
		t.Fatalf("--network-alias postgres count = %d, want %d:\n%s", got, len(jobs), log)
	}
	if strings.Contains(log, "rm -f postgres") {
		t.Fatalf("cleanup referenced the alias instead of the physical name:\n%s", log)
	}
}

// TestServiceWithoutNameKeepsPhysicalNameBehavior proves a service with no
// declared alias keeps working: physical name only, no --network-alias.
func TestServiceWithoutNameKeepsPhysicalNameBehavior(t *testing.T) {
	installFakeBins(t)
	var emitted []string
	_, cleanup, err := startContainerServices(context.Background(), "r", "j",
		[]pipeline.Service{{Image: "postgres:16"}}, pipeline.Resources{}, false, false, func(s string) { emitted = append(emitted, s) })
	if err != nil {
		t.Fatalf("nameless service: %v", err)
	}
	defer cleanup()
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	physical := serviceContainerName("r", "j", 0)
	if !strings.Contains(log, "--name "+physical) {
		t.Fatalf("physical name missing:\n%s", log)
	}
	if strings.Contains(log, "--network-alias") {
		t.Fatalf("nameless service got an alias:\n%s", log)
	}
	if !containsLine(emitted, "service "+physical+" started") {
		t.Fatalf("emitted = %v", emitted)
	}
}

// TestServiceAliasSanitization pins alias sanitization: lowercasing, docker
// name cleaning and the empty-after-cleaning cases.
func TestServiceAliasSanitization(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"", ""},
		{"postgres", "postgres"},
		{"Postgres", "postgres"},
		{"My DB!", "my-db-"},
		{"!!!", "---"},
		{"a_b.c-d", "a_b.c-d"},
	}
	for _, tc := range cases {
		if got := serviceAlias(pipeline.Service{Name: tc.name}); got != tc.want {
			t.Fatalf("serviceAlias(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestServiceBudgetForDerivesJobEnvelope pins the documented aggregate
// formula: services share the job's declared resources, with the documented
// fallbacks when a resource is undeclared.
func TestServiceBudgetForDerivesJobEnvelope(t *testing.T) {
	def := serviceBudgetFor(pipeline.Resources{})
	if def.CPU != serviceAggregateDefaultCPUs || def.Memory != serviceAggregateDefaultMemory || def.PIDs != serviceAggregateDefaultPIDs {
		t.Fatalf("default budget = %+v", def)
	}
	declared := serviceBudgetFor(pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512})
	if declared.CPU != 2 || declared.Memory != 4<<30 || declared.PIDs != 512 {
		t.Fatalf("declared budget = %+v", declared)
	}
	partial := serviceBudgetFor(pipeline.Resources{CPU: 1.5})
	if partial.CPU != 1.5 || partial.Memory != serviceAggregateDefaultMemory || partial.PIDs != serviceAggregateDefaultPIDs {
		t.Fatalf("partial budget = %+v", partial)
	}
}

// TestServiceBudgetAllocationThrottlesToAggregate pins the allocation math:
// min(per-service default, remaining) with a fail-closed exhaustion error and
// exact remaining accounting.
func TestServiceBudgetAllocationThrottlesToAggregate(t *testing.T) {
	b := serviceBudgetFor(pipeline.Resources{CPU: 4.5, Memory: 3 << 30, PIDs: 700})
	a1, err := b.allocate()
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	if a1.CPU != 2 || a1.Memory != 2<<30 || a1.PIDs != 256 {
		t.Fatalf("first allocation = %+v", a1)
	}
	if b.CPU != 2.5 || b.Memory != 1<<30 || b.PIDs != 444 {
		t.Fatalf("remaining after first = %+v", b)
	}
	a2, err := b.allocate()
	if err != nil {
		t.Fatalf("second allocation: %v", err)
	}
	if a2.CPU != 2 || a2.Memory != 1<<30 || a2.PIDs != 256 {
		t.Fatalf("second allocation = %+v", a2)
	}
	if b.CPU != 0.5 || b.Memory != 0 || b.PIDs != 188 {
		t.Fatalf("remaining after second = %+v", b)
	}
	if _, err := b.allocate(); err == nil || !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("exhausted allocation = %v", err)
	}
	// A single service on an undeclared-resource job keeps the historical
	// per-service defaults exactly (2 CPU / 2 GiB / 256 PIDs).
	single := serviceBudgetFor(pipeline.Resources{})
	a, err := single.allocate()
	if err != nil {
		t.Fatalf("single allocation: %v", err)
	}
	if a.CPU != serviceDefaultCPUs || a.Memory != serviceDefaultMemory || a.PIDs != serviceDefaultPIDs {
		t.Fatalf("single-service allocation = %+v", a)
	}
}

// runLines returns the docker log lines that invoked `docker run`.
func runLines(log string) []string {
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "run -d ") {
			out = append(out, line)
		}
	}
	return out
}

// TestStartContainerServicesThrottlesServiceLimits proves two services on a
// 4 CPU / 3 GiB / 700 PID job are throttled by the remaining aggregate: the
// second service gets the remaining 1 GiB instead of a fresh 2 GiB.
func TestStartContainerServicesThrottlesServiceLimits(t *testing.T) {
	installFakeBins(t)
	services := []pipeline.Service{
		{Name: "first", Image: "postgres:16"},
		{Name: "second", Image: "redis:7"},
	}
	_, cleanup, err := startContainerServices(context.Background(), "r", "j", services,
		pipeline.Resources{CPU: 4, Memory: 3 << 30, PIDs: 700}, false, false, func(string) {})
	if err != nil {
		t.Fatalf("throttled services: %v", err)
	}
	cleanup()
	runs := runLines(readFakeLog(t, "FAKE_DOCKER_LOG"))
	if len(runs) != 2 {
		t.Fatalf("docker run count = %d, want 2:\n%v", len(runs), runs)
	}
	for _, want := range []string{"--cpus=2", "--memory=2147483648", "--pids-limit=256"} {
		if !strings.Contains(runs[0], want) {
			t.Fatalf("first service run missing %q: %s", want, runs[0])
		}
	}
	if !strings.Contains(runs[1], "--cpus=2") || !strings.Contains(runs[1], "--memory=1073741824") || !strings.Contains(runs[1], "--pids-limit=256") {
		t.Fatalf("second service was not throttled to the remaining envelope: %s", runs[1])
	}
}

// TestStartContainerServicesRejectsAggregateOverflow proves a second service
// on a 2 CPU / 4 GiB / 512 PID job fails closed with a clear policy error
// after cleaning up the one service the envelope allowed, instead of silently
// starting another container with a zero (unlimited) docker limit.
func TestStartContainerServicesRejectsAggregateOverflow(t *testing.T) {
	installFakeBins(t)
	services := []pipeline.Service{
		{Name: "s1", Image: "postgres:16"},
		{Name: "s2", Image: "redis:7"},
		{Name: "s3", Image: "memcached:1"},
	}
	_, _, err := startContainerServices(context.Background(), "r", "j", services,
		pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512}, false, false, func(string) {})
	if err == nil {
		t.Fatal("over-envelope services accepted")
	}
	if !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("error does not explain the aggregate budget: %v", err)
	}
	if kind := runErrorKind(t, err); kind != ErrorPolicy {
		t.Fatalf("kind = %q, want %q", kind, ErrorPolicy)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if got := len(runLines(log)); got != 1 {
		t.Fatalf("docker run count = %d, want 1 (only the first service fits 2 CPU):\n%s", got, log)
	}
	if !strings.Contains(log, "rm -f "+serviceContainerName("r", "j", 0)) {
		t.Fatalf("cleanup did not remove the started service:\n%s", log)
	}
	if strings.Contains(log, "--name "+serviceContainerName("r", "j", 1)) {
		t.Fatalf("second service started after the budget was exhausted:\n%s", log)
	}
}

// TestUntrustedServiceCountCeilingAtParseTime proves the trust-aware service// ceiling: untrusted specs admit at most pipeline.MaxUntrustedServicesPerJob
// services, trusted specs keep the historical 32, and the executor enforces
// the same ceiling before any docker invocation.
func TestUntrustedServiceCountCeilingAtParseTime(t *testing.T) {
	makeSpec := func(n int) *pipeline.Spec {
		svcs := make([]pipeline.Service, n)
		for i := range svcs {
			svcs[i] = pipeline.Service{Name: fmt.Sprintf("svc%d", i), Image: "alpine:3.19"}
		}
		return &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{
			"build": {Runtime: "container", Image: "alpine:3.19", Services: svcs, Steps: []pipeline.Step{{Run: "echo hi"}}},
		}}
	}
	if err := pipeline.ValidateServiceQuota(makeSpec(pipeline.MaxUntrustedServicesPerJob), true); err != nil {
		t.Fatalf("ceiling-sized untrusted spec rejected: %v", err)
	}
	err := pipeline.ValidateServiceQuota(makeSpec(pipeline.MaxUntrustedServicesPerJob+1), true)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("limit is %d for untrusted jobs", pipeline.MaxUntrustedServicesPerJob)) {
		t.Fatalf("untrusted ceiling = %v", err)
	}
	// The literal D1-C scenario: 32 services on an untrusted job are rejected
	// outright by the untrusted ceiling (8), before any aggregate allocation.
	err = pipeline.ValidateServiceQuota(makeSpec(32), true)
	if err == nil || !strings.Contains(err.Error(), "declares 32 services") {
		t.Fatalf("32 untrusted services = %v", err)
	}
	if err := pipeline.ValidateServiceQuota(makeSpec(pipeline.MaxUntrustedServicesPerJob+1), false); err != nil {
		t.Fatalf("trusted spec below the absolute ceiling rejected: %v", err)
	}
	if err := pipeline.Validate(makeSpec(pipeline.MaxUntrustedServicesPerJob + 1)); err != nil {
		t.Fatalf("absolute pipeline validation rejected a trusted-legal spec: %v", err)
	}
	const absoluteServiceCeiling = 32
	err = pipeline.Validate(makeSpec(absoluteServiceCeiling + 1))
	if err == nil || !strings.Contains(err.Error(), "limit is 32") {
		t.Fatalf("absolute ceiling = %v", err)
	}
	if err := pipeline.ValidateServiceCount("build", make([]pipeline.Service, pipeline.MaxUntrustedServicesPerJob), true); err != nil {
		t.Fatalf("per-job ceiling at limit: %v", err)
	}
	if err := pipeline.ValidateServiceCount("build", make([]pipeline.Service, pipeline.MaxUntrustedServicesPerJob+1), true); err == nil {
		t.Fatal("per-job untrusted ceiling not enforced")
	}
	// Executor enforcement: an untrusted compiled job with too many services
	// fails before any service container starts.
	spec := makeSpec(0)
	j := pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{
		Runtime:  "container",
		Image:    "alpine:3.19",
		Services: make([]pipeline.Service, pipeline.MaxUntrustedServicesPerJob+1),
		Steps:    []pipeline.Step{{Run: "echo hi"}},
	}}
	ex := &Executor{Opt: Options{RunID: "r", Untrusted: true}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "failure" || !strings.Contains(res.Error, "for untrusted jobs") {
		t.Fatalf("executor untrusted service ceiling = status %q error %q", res.Status, res.Error)
	}
}

// TestUntrustedServicesThrottledToAggregateEnvelope proves the D1-C fix on
// the executor path: an untrusted job whose service count is within the
// untrusted ceiling but whose declared 2 CPU / 4 GiB envelope cannot host them
// fails with the aggregate-budget error after starting only the services that
// fit, never 8 sidecars each with their own defaults.
func TestUntrustedServicesThrottledToAggregateEnvelope(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	services := make([]pipeline.Service, pipeline.MaxUntrustedServicesPerJob)
	for i := range services {
		services[i] = pipeline.Service{Name: fmt.Sprintf("svc%d", i), Image: "postgres:16"}
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
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Untrusted: true, RequireImmutableImages: true}, Masker: &secrets.Masker{}}
	// Untrusted service images must be digest-pinned: use a pinned image so
	// the job reaches the aggregate budget check rather than the pin check.
	for i := range services {
		services[i].Image = "postgres@sha256:" + strings.Repeat("a", 64)
	}
	j.Job.Services = services
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "failure" || !strings.Contains(res.Error, "budget exhausted") {
		t.Fatalf("aggregate throttling = status %q error %q", res.Status, res.Error)
	}
	if got := len(runLines(readFakeLog(t, "FAKE_DOCKER_LOG"))); got > pipeline.MaxUntrustedServicesPerJob {
		t.Fatalf("docker run count = %d, over the untrusted ceiling", got)
	}
}
