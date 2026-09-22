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
			_, cleanup, err := startContainerServices(ctx, runID, jobID, services, resources, false, false, "", func(string) {})
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
		[]pipeline.Service{{Image: "postgres:16"}}, pipeline.Resources{}, false, false, "", func(s string) { emitted = append(emitted, s) })
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
	def := serviceBudgetFor(pipeline.Resources{}, 2)
	if def.CPU != serviceAggregateDefaultCPUs || def.Memory != serviceAggregateDefaultMemory || def.PIDs != serviceAggregateDefaultPIDs {
		t.Fatalf("default budget = %+v", def)
	}
	if def.remaining != 2 {
		t.Fatalf("default remaining = %d, want 2", def.remaining)
	}
	declared := serviceBudgetFor(pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512}, 8)
	if declared.CPU != 2 || declared.Memory != 4<<30 || declared.PIDs != 512 {
		t.Fatalf("declared budget = %+v", declared)
	}
	partial := serviceBudgetFor(pipeline.Resources{CPU: 1.5}, 1)
	if partial.CPU != 1.5 || partial.Memory != serviceAggregateDefaultMemory || partial.PIDs != serviceAggregateDefaultPIDs {
		t.Fatalf("partial budget = %+v", partial)
	}
}

// TestServiceBudgetAllocationFairSplit pins the E3-B fair-split math:
// min(per-service default, remaining / remaining-services), so the first
// service of an 8-service job gets 1/8 of the envelope instead of the whole
// per-service default, the last service absorbs the integer-division
// remainder, and the aggregate never exceeds the envelope.
func TestServiceBudgetAllocationFairSplit(t *testing.T) {
	// Two services on a 4.5 CPU / 3 GiB / 700 PID envelope: the first gets
	// its fair half, the second the remainder (both capped by the
	// per-service defaults).
	b := serviceBudgetFor(pipeline.Resources{CPU: 4.5, Memory: 3 << 30, PIDs: 700}, 2)
	a1, err := b.allocate()
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	if a1.CPU != 2 || a1.Memory != 1610612736 || a1.PIDs != 256 {
		t.Fatalf("first allocation = %+v", a1)
	}
	if b.CPU != 2.5 || b.Memory != 1610612736 || b.PIDs != 444 || b.remaining != 1 {
		t.Fatalf("remaining after first = %+v", b)
	}
	a2, err := b.allocate()
	if err != nil {
		t.Fatalf("second allocation: %v", err)
	}
	if a2.CPU != 2 || a2.Memory != 1610612736 || a2.PIDs != 256 {
		t.Fatalf("second allocation = %+v", a2)
	}
	if b.CPU != 0.5 || b.Memory != 0 || b.PIDs != 188 || b.remaining != 0 {
		t.Fatalf("remaining after second = %+v", b)
	}
	// A single service on an undeclared-resource job keeps the historical
	// per-service defaults exactly (2 CPU / 2 GiB / 256 PIDs).
	single := serviceBudgetFor(pipeline.Resources{}, 1)
	a, err := single.allocate()
	if err != nil {
		t.Fatalf("single allocation: %v", err)
	}
	if a.CPU != serviceDefaultCPUs || a.Memory != serviceDefaultMemory || a.PIDs != serviceDefaultPIDs {
		t.Fatalf("single-service allocation = %+v", a)
	}
}

// TestServiceBudgetFairSplitMakesEightServicesPossible is the E3-B proof:
// the untrusted default envelope (2 CPU / 4 GiB / 512 PIDs, the aggregate
// defaults) admits pipeline.MaxUntrustedServicesPerJob = 8 services, each
// with a sensible share, and the aggregate exactly fits the envelope. The
// previous min(default, remaining) rule gave service #1 min(2 CPU, 256 PIDs)
// and left nothing for the rest.
func TestServiceBudgetFairSplitMakesEightServicesPossible(t *testing.T) {
	const n = pipeline.MaxUntrustedServicesPerJob
	b := serviceBudgetFor(pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512}, n)
	var total serviceAllocation
	for i := 0; i < n; i++ {
		a, err := b.allocate()
		if err != nil {
			t.Fatalf("service %d/%d: %v", i+1, n, err)
		}
		if a.CPU != 0.25 || a.Memory != 512<<20 || a.PIDs != 64 {
			t.Fatalf("service %d allocation = %+v, want 0.25 CPU / 512 MiB / 64 PIDs", i+1, a)
		}
		total.CPU += a.CPU
		total.Memory += a.Memory
		total.PIDs += a.PIDs
	}
	if total.CPU != 2 || total.Memory != 4<<30 || total.PIDs != 512 {
		t.Fatalf("aggregate = %+v, want the envelope exactly", total)
	}
	if b.CPU != 0 || b.Memory != 0 || b.PIDs != 0 || b.remaining != 0 {
		t.Fatalf("remaining after the plan = %+v", b)
	}
}

// TestServiceBudgetExhaustsOnlyWhenGenuinelyOversubscribed pins the
// fail-closed boundary: a share that rounds to zero (or an already empty
// plan) fails with the clear budget error, while an envelope that can host
// every declared service never does.
func TestServiceBudgetExhaustsOnlyWhenGenuinelyOversubscribed(t *testing.T) {
	// 2 PIDs across 3 services: every fair share floors to zero.
	oversubscribed := serviceBudgetFor(pipeline.Resources{CPU: 4, Memory: 4 << 30, PIDs: 2}, 3)
	if _, err := oversubscribed.allocate(); err == nil || !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("oversubscribed allocation = %v", err)
	}
	// The same PIDs across 2 services fit (1 PID each).
	fits := serviceBudgetFor(pipeline.Resources{CPU: 4, Memory: 4 << 30, PIDs: 2}, 2)
	for i := 0; i < 2; i++ {
		a, err := fits.allocate()
		if err != nil {
			t.Fatalf("service %d: %v", i+1, err)
		}
		if a.PIDs != 1 {
			t.Fatalf("service %d PIDs = %d, want 1", i+1, a.PIDs)
		}
	}
	// Allocating past the plan is an explicit error, never a zero flag.
	if _, err := fits.allocate(); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("plan-exhausted allocation = %v", err)
	}
	// A zero-service plan allocates nothing and reports exhaustion.
	empty := serviceBudgetFor(pipeline.Resources{}, 0)
	if _, err := empty.allocate(); err == nil {
		t.Fatal("zero-service plan allocated")
	}
}

// TestServiceEnvelopeRequestAggregate pins the exported aggregate the
// scheduler follow-up must reserve when no job-scoped parent cgroup is
// available: it is the fair-split sum, bounded by the envelope, and it
// reports the oversubscription instead of a partial sum.
func TestServiceEnvelopeRequestAggregate(t *testing.T) {
	services := make([]pipeline.Service, pipeline.MaxUntrustedServicesPerJob)
	for i := range services {
		services[i] = pipeline.Service{Name: fmt.Sprintf("svc%d", i), Image: "postgres:16"}
	}
	req, err := ServiceEnvelopeRequest(pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512}, services)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if req.CPU != 2 || int64(req.Memory) != 4<<30 || req.PIDs != 512 {
		t.Fatalf("aggregate = %+v, want the envelope", req)
	}
	if _, err := ServiceEnvelopeRequest(pipeline.Resources{CPU: 4, Memory: 4 << 30, PIDs: 2}, services[:3]); err == nil {
		t.Fatal("oversubscribed plan reported an aggregate")
	}
	// A single-service aggregate on an undeclared job equals one per-service
	// default (2 CPU / 2 GiB / 256 PIDs).
	req, err = ServiceEnvelopeRequest(pipeline.Resources{}, services[:1])
	if err != nil {
		t.Fatalf("single aggregate: %v", err)
	}
	if req.CPU != serviceDefaultCPUs || int64(req.Memory) != serviceDefaultMemory || req.PIDs != serviceDefaultPIDs {
		t.Fatalf("single aggregate = %+v", req)
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

// TestStartContainerServicesFairSplitsEnvelope proves the started containers
// carry the fair-split flags: two services on a 4 CPU / 3 GiB / 700 PID job
// share the envelope evenly (2 CPU and 1.5 GiB each) instead of the second
// service inheriting whatever the first left.
func TestStartContainerServicesFairSplitsEnvelope(t *testing.T) {
	installFakeBins(t)
	services := []pipeline.Service{
		{Name: "first", Image: "postgres:16"},
		{Name: "second", Image: "redis:7"},
	}
	_, cleanup, err := startContainerServices(context.Background(), "r", "j", services,
		pipeline.Resources{CPU: 4, Memory: 3 << 30, PIDs: 700}, false, false, "", func(string) {})
	if err != nil {
		t.Fatalf("throttled services: %v", err)
	}
	cleanup()
	runs := runLines(readFakeLog(t, "FAKE_DOCKER_LOG"))
	if len(runs) != 2 {
		t.Fatalf("docker run count = %d, want 2:\n%v", len(runs), runs)
	}
	for i, want := range []string{"--cpus=2", "--memory=1610612736", "--pids-limit=256"} {
		if !strings.Contains(runs[0], want) {
			t.Fatalf("first service run missing %q: %s", want, runs[0])
		}
		if !strings.Contains(runs[1], want) {
			t.Fatalf("second service run missing %q (fair split, not first-come): %s", want, runs[1])
		}
		_ = i
	}
}

// TestStartContainerServicesEightServicesFitEnvelope proves the E3-B fix on
// the start path: 8 untrusted-limit services on the default 2 CPU / 4 GiB /
// 512 PID envelope all start with a fair share, rather than failing after the
// first service consumed everything.
func TestStartContainerServicesEightServicesFitEnvelope(t *testing.T) {
	installFakeBins(t)
	const n = pipeline.MaxUntrustedServicesPerJob
	services := make([]pipeline.Service, n)
	for i := range services {
		services[i] = pipeline.Service{Name: fmt.Sprintf("svc%d", i), Image: "postgres:16"}
	}
	_, cleanup, err := startContainerServices(context.Background(), "r", "j", services,
		pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512}, false, false, "", func(string) {})
	if err != nil {
		t.Fatalf("eight services on the default envelope: %v", err)
	}
	cleanup()
	runs := runLines(readFakeLog(t, "FAKE_DOCKER_LOG"))
	if len(runs) != n {
		t.Fatalf("docker run count = %d, want %d", len(runs), n)
	}
	for i, run := range runs {
		for _, want := range []string{"--cpus=0.25", "--memory=536870912", "--pids-limit=64"} {
			if !strings.Contains(run, want) {
				t.Fatalf("service %d run missing %q: %s", i+1, want, run)
			}
		}
	}
}

// TestStartContainerServicesRejectsGenuinelyOversubscribedEnvelope proves a
// genuinely oversubscribed envelope still fails closed with a clear policy
// error and starts NO container (not even the first), instead of degrading to
// a zero (unlimited) docker limit.
func TestStartContainerServicesRejectsGenuinelyOversubscribedEnvelope(t *testing.T) {
	installFakeBins(t)
	services := []pipeline.Service{
		{Name: "s1", Image: "postgres:16"},
		{Name: "s2", Image: "redis:7"},
		{Name: "s3", Image: "memcached:1"},
	}
	_, _, err := startContainerServices(context.Background(), "r", "j", services,
		pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 2}, false, false, "", func(string) {})
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
	if got := len(runLines(log)); got != 0 {
		t.Fatalf("docker run count = %d, want 0 (the plan is refused before any container):\n%s", got, log)
	}
	for i := 0; i < len(services); i++ {
		if strings.Contains(log, "--name "+serviceContainerName("r", "j", i)) {
			t.Fatalf("service %d started despite the exhausted envelope:\n%s", i+1, log)
		}
	}
	// The just-created network is removed again on the failure path.
	if !strings.Contains(log, "network rm ") {
		t.Fatalf("failure path did not remove the services network:\n%s", log)
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

// TestUntrustedServicesFairSplitWithinEnvelope is the E3-B fix on the
// executor path: an untrusted job at the service-count ceiling (8) with the
// untrusted default envelope (2 CPU / 4 GiB / 512 PIDs) starts every service
// with a fair 1/8 share, and the services' aggregate never exceeds the
// envelope. The main container keeps its declared per-container flags (the
// kernel-level job cgroup, when the host provides one, is what makes the two
// groups share the envelope; see the jobcgroup tests).
func TestUntrustedServicesFairSplitWithinEnvelope(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	const n = pipeline.MaxUntrustedServicesPerJob
	services := make([]pipeline.Service, n)
	for i := range services {
		services[i] = pipeline.Service{Name: fmt.Sprintf("svc%d", i), Image: "postgres@sha256:" + strings.Repeat("a", 64)}
	}
	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{
		"build": {Runtime: "container", Image: "alpine@sha256:" + strings.Repeat("b", 64), Services: services, Steps: []pipeline.Step{{Run: "echo hi"}}},
	}}
	j := pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{
		Runtime:   "container",
		Image:     "alpine@sha256:" + strings.Repeat("b", 64),
		Resources: pipeline.Resources{CPU: 2, Memory: 4 << 30, PIDs: 512},
		Services:  services,
		Steps:     []pipeline.Step{{Run: "echo hi"}},
	}}
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Untrusted: true, RequireImmutableImages: true}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "success" {
		t.Fatalf("fair-split services = status %q error %q", res.Status, res.Error)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	// Sum the service run flags and prove the aggregate stays within the
	// envelope: 8 x 0.25 CPU, 8 x 512 MiB, 8 x 64 PIDs.
	seen := 0
	for _, line := range runLines(log) {
		if !strings.Contains(line, "kiwi-svc-") {
			continue
		}
		seen++
		for _, want := range []string{"--cpus=0.25", "--memory=536870912", "--pids-limit=64"} {
			if !strings.Contains(line, want) {
				t.Fatalf("service run %d missing fair share %q: %s", seen, want, line)
			}
		}
	}
	if seen != n {
		t.Fatalf("service runs = %d, want %d", seen, n)
	}
}

// TestServiceAliasSharesValidationCanonicalization pins the E3-E extraction:
// the alias execution attaches is exactly pipeline.CanonicalServiceAlias, the
// function admission uses to reject duplicates. Because execution collapses
// "Redis" and "redis" onto one DNS name, admission must reject the pair (see
// internal/pipeline/service_alias_test.go).
func TestServiceAliasSharesValidationCanonicalization(t *testing.T) {
	for _, name := range []string{"postgres", "Postgres", "My.DB", "My DB!", "!!!"} {
		if got, want := serviceAlias(pipeline.Service{Name: name}), pipeline.CanonicalServiceAlias(name); got != want {
			t.Fatalf("serviceAlias(%q) = %q, want the shared canonical form %q", name, got, want)
		}
	}
	if serviceAlias(pipeline.Service{Name: "Redis"}) != serviceAlias(pipeline.Service{Name: "redis"}) {
		t.Fatal("canonical aliases diverged: admission could not detect the runtime collision")
	}
}
