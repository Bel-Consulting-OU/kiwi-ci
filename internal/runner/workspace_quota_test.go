package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// quotaEventLog records the workspace-lifecycle ordering one test observes.
type quotaEventLog struct {
	events []string
}

func (l *quotaEventLog) add(event string) { l.events = append(l.events, event) }

// stubWorkspaceQuota replaces the runner's quota installer for one test,
// recording the install call and returning a counted cleanup.
func stubWorkspaceQuota(t *testing.T, status executor.DiskQuotaStatus, log *quotaEventLog, installs, cleanups *int, limitSeen *int64, dirSeen *string) {
	t.Helper()
	orig := installWorkspaceDiskQuota
	installWorkspaceDiskQuota = func(workspace string, limit int64) (executor.DiskQuotaStatus, func() error) {
		*installs++
		*limitSeen = limit
		*dirSeen = workspace
		if log != nil {
			log.add("quota-install")
		}
		if !status.Hard {
			return status, nil
		}
		return status, func() error {
			*cleanups++
			if log != nil {
				log.add("quota-cleanup")
			}
			return nil
		}
	}
	t.Cleanup(func() { installWorkspaceDiskQuota = orig })
}

// TestWorkspaceQuotaLimitForTask pins the pre-checkout bound derivation: the
// authoritative persisted t.Job.DiskRequest, the mandatory untrusted default,
// and zero (no hard bound requested) for trusted jobs without a declaration.
func TestWorkspaceQuotaLimitForTask(t *testing.T) {
	task := basicTask(payloadPipeline)
	if got := workspaceQuotaLimitForTask(task); got != 0 {
		t.Fatalf("trusted undeclared = %d, want 0", got)
	}
	task.Job.DiskRequest = 5 << 20
	if got := workspaceQuotaLimitForTask(task); got != 5<<20 {
		t.Fatalf("trusted declared = %d, want 5 MiB", got)
	}
	task.Job.Trusted = false
	task.Job.DiskRequest = 0
	if got := workspaceQuotaLimitForTask(task); got != executor.DefaultUntrustedWorkspaceMaxBytes {
		t.Fatalf("untrusted undeclared = %d, want the mandatory default", got)
	}
	task.Job.DiskRequest = 3 << 20
	if got := workspaceQuotaLimitForTask(task); got != 3<<20 {
		t.Fatalf("untrusted declared = %d, want 3 MiB", got)
	}
}

// TestPayloadRunsOnContainerHint pins the early runtime hint that lets execute
// fail an untrusted job closed before checkout without recompiling: only a
// decodable payload whose effective job is a container job returns true.
func TestPayloadRunsOnContainerHint(t *testing.T) {
	if payloadRunsOnContainer(nil) {
		t.Fatal("nil payload claimed container runtime")
	}
	containerJob := basicTask("version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    steps:\n      - run: echo hi\n")
	payload := buildPayload(t, containerJob.Job.Pipeline, "build")
	if !payloadRunsOnContainer(payload) {
		t.Fatal("container payload not detected")
	}
	native := buildPayload(t, payloadPipeline, "build")
	if payloadRunsOnContainer(native) {
		t.Fatal("native payload claimed container runtime")
	}
	payload.EffectiveJob = "not-a-job"
	if payloadRunsOnContainer(payload) {
		t.Fatal("undecodable effective job claimed container runtime")
	}
}

// TestExecuteInstallsWorkspaceQuotaBeforeCheckout is the E3-C ordering pin:
// execute creates the workspace, installs the hard quota, THEN checks out,
// and removes the quota before the workspace on the way out.
func TestExecuteInstallsWorkspaceQuotaBeforeCheckout(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	log := &quotaEventLog{}
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: 5 << 20, Detail: "fake xfs quota"}, log, &installs, &cleanups, &limitSeen, &dirSeen)

	origRemove := removeJobWorkspace
	removeJobWorkspace = func(string) error {
		log.add("workspace-remove")
		return nil
	}
	t.Cleanup(func() { removeJobWorkspace = origRemove })

	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		log.add("checkout")
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	task.Job.DiskRequest = 5 << 20
	// The compiled job does not declare the persisted request: the persisted
	// (authoritative) value must win.
	r.execute(context.Background(), task)

	if installs != 1 || cleanups != 1 {
		t.Fatalf("quota installs/cleanups = %d/%d, want 1/1 (%v)", installs, cleanups, log.events)
	}
	if limitSeen != 5<<20 {
		t.Fatalf("quota limit = %d, want the persisted DiskRequest 5 MiB", limitSeen)
	}
	if dirSeen == "" {
		t.Fatal("quota installed on an empty workspace path")
	}
	want := []string{"quota-install", "checkout", "quota-cleanup", "workspace-remove"}
	if strings.Join(log.events, ",") != strings.Join(want, ",") {
		t.Fatalf("workspace lifecycle order = %v, want %v", log.events, want)
	}
	if dirSeen != "" {
		defer os.RemoveAll(dirSeen)
	}
	if c, _ := fsrv.lastComplete(); c.Status != model.StatusSuccess {
		t.Fatalf("complete = %+v", c)
	}
}

// TestExecuteQuotaCleanupOnEveryEarlyReturn proves the teardown is deferred:
// a checkout failure still removes the quota and the workspace, in order.
func TestExecuteQuotaCleanupOnEveryEarlyReturn(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	log := &quotaEventLog{}
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: 1 << 20, Detail: "fake xfs quota"}, log, &installs, &cleanups, &limitSeen, &dirSeen)

	origRemove := removeJobWorkspace
	removeJobWorkspace = func(string) error {
		log.add("workspace-remove")
		return nil
	}
	t.Cleanup(func() { removeJobWorkspace = origRemove })

	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error {
		return errCheckoutBoom
	}
	task := basicTask(payloadPipeline)
	task.Job.DiskRequest = 1 << 20
	r.execute(context.Background(), task)

	if installs != 1 || cleanups != 1 {
		t.Fatalf("quota installs/cleanups = %d/%d, want 1/1 (%v)", installs, cleanups, log.events)
	}
	want := []string{"quota-install", "quota-cleanup", "workspace-remove"}
	if strings.Join(log.events, ",") != strings.Join(want, ",") {
		t.Fatalf("failure-path order = %v, want %v", log.events, want)
	}
	if dirSeen != "" {
		defer os.RemoveAll(dirSeen)
	}
	if c, _ := fsrv.lastComplete(); c.Status != model.StatusFailure || !strings.Contains(c.Error, "checkout boom") {
		t.Fatalf("complete = %+v", c)
	}
}

var errCheckoutBoom = errors.New("checkout boom")

// untrustedContainerTask builds a payload-bearing untrusted task whose
// effective job runs on the container backend (what production untrusted
// tasks look like after the enqueue-time compilation).
func untrustedContainerTask(t *testing.T) server.Task {
	t.Helper()
	text := "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:" + strings.Repeat("a", 64) + "\n    steps:\n      - run: echo hi\n"
	task := basicTask(text)
	task.Job.Trusted = false
	payload := buildPayload(t, text, "build")
	payload.EffectivePolicy = mustJSON(t, policy.DefaultUntrustedCapabilities())
	task.Job.CompiledJobPayload = payload
	return task
}

// TestExecuteUntrustedQuotaFailureFailsClosedBeforeCheckout is the E3-C
// security pin: when no hard bound can be established, an untrusted container
// job is failed BEFORE the clone runs, so the unprotected checkout window the
// defect described no longer exists.
func TestExecuteUntrustedQuotaFailureFailsClosedBeforeCheckout(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Detail: "no delegated quota here"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)

	checkedOut := false
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error {
		checkedOut = true
		return nil
	}
	r.execute(context.Background(), untrustedContainerTask(t))

	if checkedOut {
		t.Fatal("untrusted job without a hard bound checked out anyway")
	}
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure {
		t.Fatalf("complete = %+v ok=%v", c, ok)
	}
	for _, want := range []string{"hard workspace disk quota", "no delegated quota here", executor.AllowUnquotaedUntrustedDiskEnv} {
		if !strings.Contains(c.Error, want) {
			t.Fatalf("gate error missing %q: %q", want, c.Error)
		}
	}
	if installs != 1 {
		t.Fatalf("quota installs = %d, want 1", installs)
	}
	if limitSeen != executor.DefaultUntrustedWorkspaceMaxBytes {
		t.Fatalf("untrusted quota limit = %d, want the mandatory default", limitSeen)
	}
	if cleanups != 0 {
		t.Fatalf("cleanups = %d, want 0 (the probe established nothing)", cleanups)
	}
}

// TestExecuteUntrustedQuotaStatusReachesExecutorAndCleansUp proves the
// positive path: a hard bound installed before checkout is reported to the
// executor (which skips its own probe and satisfies the untrusted gate), and
// the quota is removed exactly once even though the job then fails on the
// missing docker binary.
func TestExecuteUntrustedQuotaStatusReachesExecutorAndCleansUp(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: executor.DefaultUntrustedWorkspaceMaxBytes, Detail: "fake xfs quota"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)
	gotOptions := captureExecutorOptions(t)

	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error { return nil }
	t.Setenv("PATH", t.TempDir()) // no docker: the container job fails at the lookup
	r.execute(context.Background(), untrustedContainerTask(t))

	opts, ok := gotOptions()
	if !ok {
		t.Fatal("executor options seam never fired")
	}
	if opts.WorkspaceQuota == nil || !opts.WorkspaceQuota.Hard {
		t.Fatalf("executor did not receive the preinstalled quota: %+v", opts.WorkspaceQuota)
	}
	if !opts.RequireUntrustedDiskQuota {
		t.Fatal("untrusted disk quota requirement lost")
	}
	if opts.WorkspaceMaxBytes != executor.DefaultUntrustedWorkspaceMaxBytes {
		t.Fatalf("WorkspaceMaxBytes = %d, want the untrusted default", opts.WorkspaceMaxBytes)
	}
	if installs != 1 || cleanups != 1 {
		t.Fatalf("quota installs/cleanups = %d/%d, want 1/1", installs, cleanups)
	}
	c, _ := fsrv.lastComplete()
	if c.Status != model.StatusFailure || !strings.Contains(c.Error, "docker not found") {
		t.Fatalf("complete = %+v, want the docker lookup failure (not the quota gate)", c)
	}
}

// TestExecuteTrustedJobWithoutDiskSkipsQuotaInstall proves the bound is only
// attempted when one is known: a trusted job with no disk declaration gets no
// quota call at all (the documented historical unbounded behavior).
func TestExecuteTrustedJobWithoutDiskSkipsQuotaInstall(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Detail: "must not be used"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error { return nil }
	r.execute(context.Background(), basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"))
	if installs != 0 || cleanups != 0 {
		t.Fatalf("quota calls = %d/%d, want none", installs, cleanups)
	}
	if c, _ := fsrv.lastComplete(); c.Status != model.StatusSuccess {
		t.Fatalf("complete = %+v", c)
	}
}

// TestWorkspaceQuotaDetailIsLogged proves the outcome is visible in the job's
// own log: a hard bound (or the absence of one) must never be silent.
func TestWorkspaceQuotaDetailIsLogged(t *testing.T) {
	rsrv := &reportServer{}
	ts := httptest.NewServer(rsrv.handler())
	defer ts.Close()
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: 1 << 20, Detail: "XFS project quota 500001"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error { return nil }
	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	task.Job.DiskRequest = 1 << 20
	r.execute(context.Background(), task)

	rsrv.mu.Lock()
	logs := strings.Join(rsrv.logs, "\n")
	rsrv.mu.Unlock()
	if !strings.Contains(logs, "disk quota: XFS project quota 500001") {
		t.Fatalf("quota outcome not logged: %q", logs)
	}
}

// TestVerifyWorkspaceQuotaPayloadJSONShape pins the payload shape
// untrustedContainerTask relies on: the effective job JSON carries the
// runtime, so payloadRunsOnContainer can decide before checkout.
func TestVerifyWorkspaceQuotaPayloadJSONShape(t *testing.T) {
	task := untrustedContainerTask(t)
	if !payloadRunsOnContainer(task.Job.CompiledJobPayload) {
		t.Fatal("untrusted container payload not detected")
	}
	raw, err := json.Marshal(task.Job.CompiledJobPayload.EffectiveJob)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"runtime":"container"`) {
		t.Fatalf("effective job JSON = %s", raw)
	}
}
