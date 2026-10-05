package executor

// Cleanup-debt propagation: every runtime cleanup primitive that cannot
// prove removal (main backend, service container, service network, job
// cgroup) must report the SAME debt signal so the runner retains durable
// ownership and stops leasing. Logging alone is not enough.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

func debtServicesJob() (*pipeline.Spec, pipeline.CompiledJob) {
	services := []pipeline.Service{{Name: "db", Image: "postgres:16"}}
	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{
		"build": {Runtime: "container", Image: "alpine:3.19", Services: services, Steps: []pipeline.Step{{Run: "echo hi"}}},
	}}
	j := pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{
		Runtime:   "container",
		Image:     "alpine:3.19",
		Resources: pipeline.Resources{CPU: 1, Memory: 1 << 30, PIDs: 128},
		Services:  services,
		Steps:     []pipeline.Step{{Run: "echo hi"}},
	}}
	return spec, j
}

func collectDebt(captured *[]CleanupDebt) func(CleanupDebt) {
	return func(d CleanupDebt) { *captured = append(*captured, d) }
}

func TestCgroupCleanupFailureReportsDebt(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	orig := jobCgroupSetup
	jobCgroupSetup = func(context.Context, jobCgroupRequest) (JobCgroupStatus, func() error) {
		return JobCgroupStatus{Enabled: true, Parent: "/kiwi-job-debt", Detail: "stub"}, func() error {
			return errors.New("cgroup busy")
		}
	}
	t.Cleanup(func() { jobCgroupSetup = orig })

	var debts []CleanupDebt
	spec, j := debtServicesJob()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: &covSink{}, OnCleanupDebt: collectDebt(&debts)}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "success" {
		t.Fatalf("runJob = %q %q (a cleanup warning must not fail the job)", res.Status, res.Error)
	}
	found := false
	for _, d := range debts {
		if d.Kind == CleanupCgroup && strings.Contains(d.Resource, "/kiwi-job-debt") {
			found = true
		}
	}
	if !found {
		t.Fatalf("cgroup cleanup failure produced no debt report: %+v", debts)
	}
}

func TestServiceCleanupFailureReportsDebtWithHealthyMainRuntime(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	// The SERVICE network removal fails; the main job container and every
	// other rm succeed, so only the service debt may be reported.
	t.Setenv("FAKE_DOCKER_NET_RM_EXIT", "1")

	var debts []CleanupDebt
	spec, j := debtServicesJob()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: &covSink{}, OnCleanupDebt: collectDebt(&debts)}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "success" {
		t.Fatalf("runJob = %q %q", res.Status, res.Error)
	}
	if len(debts) != 1 || debts[0].Kind != CleanupService {
		t.Fatalf("debts = %+v, want exactly one service debt", debts)
	}
	if !strings.Contains(debts[0].Err.Error(), "service network") {
		t.Fatalf("service debt does not name the network: %v", debts[0].Err)
	}
	for _, d := range debts {
		if d.Kind == CleanupMainRuntime {
			t.Fatalf("healthy main runtime reported debt: %+v", d)
		}
	}
}

func TestCleanupErrorsJoinedAcrossServiceAndCgroup(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	t.Setenv("FAKE_DOCKER_NET_RM_EXIT", "1")
	orig := jobCgroupSetup
	jobCgroupSetup = func(context.Context, jobCgroupRequest) (JobCgroupStatus, func() error) {
		return JobCgroupStatus{Enabled: true, Parent: "/kiwi-job-debt2", Detail: "stub"}, func() error {
			return errors.New("cgroup still hosts the service")
		}
	}
	t.Cleanup(func() { jobCgroupSetup = orig })

	var debts []CleanupDebt
	spec, j := debtServicesJob()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: &covSink{}, OnCleanupDebt: collectDebt(&debts)}, Masker: &secrets.Masker{}}
	ex.runJob(context.Background(), spec, j, "success", nil)
	kinds := map[CleanupKind]bool{}
	for _, d := range debts {
		kinds[d.Kind] = true
	}
	if !kinds[CleanupService] || !kinds[CleanupCgroup] {
		t.Fatalf("debts = %+v, want both service and cgroup reports", debts)
	}
}
