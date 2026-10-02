package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	installWorkspaceDiskQuota = func(workspace string, limit int64, _ func(executor.WorkspaceQuotaAssignment)) (executor.DiskQuotaStatus, func() error) {
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

// TestEffectiveTaskRuntimeForSecurityGate pins the pre-checkout runtime
// resolver used by the hard-quota gate. The persisted pipeline is ALWAYS the
// source of truth (the compiled payload has not been digest-verified before
// checkout); a payload may only CONFIRM it, never override it. A mismatched,
// undecodable, or absent pipeline is an error so the gate fails closed;
// "couldn't establish the runtime" is never treated as "not container".
func TestEffectiveTaskRuntimeForSecurityGate(t *testing.T) {
	containerText := "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    steps:\n      - run: echo hi\n"
	containerJob := basicTask(containerText)
	containerJob.Job.CompiledJobPayload = buildPayload(t, containerText, "build")
	if rt, err := effectiveTaskRuntimeForSecurityGate(containerJob); err != nil || !runtimeRunsOnContainer(rt) {
		t.Fatalf("agreeing container payload runtime = %q, %v", rt, err)
	}
	nativeJob := basicTask(payloadPipeline)
	nativeJob.Job.CompiledJobPayload = buildPayload(t, payloadPipeline, "build")
	if rt, err := effectiveTaskRuntimeForSecurityGate(nativeJob); err != nil || runtimeRunsOnContainer(rt) {
		t.Fatalf("agreeing native payload runtime = %q, %v", rt, err)
	}
	// Legacy record: no compiled payload, the persisted pipeline decides.
	legacy := basicTask(containerText)
	legacy.Job.CompiledJobPayload = nil
	if rt, err := effectiveTaskRuntimeForSecurityGate(legacy); err != nil || !runtimeRunsOnContainer(rt) {
		t.Fatalf("legacy container pipeline runtime = %q, %v", rt, err)
	}
	// A payload that disagrees with the persisted pipeline is corrupt or
	// inconsistent state: the resolver fails closed instead of letting the
	// unverified payload downgrade the runtime past the quota gate.
	mismatch := basicTask(containerText)
	mismatch.Job.CompiledJobPayload = buildPayload(t, payloadPipeline, "build")
	if rt, err := effectiveTaskRuntimeForSecurityGate(mismatch); err == nil {
		t.Fatalf("runtime mismatch resolved to %q, want a fail-closed error", rt)
	} else if !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("mismatch error = %v, want the disagreement named", err)
	}
	// A malformed payload must fail closed too: the missing runtime is never
	// interpreted as "not container".
	bad := basicTask(containerText)
	bad.Job.CompiledJobPayload = buildPayload(t, containerText, "build")
	bad.Job.CompiledJobPayload.EffectiveJob = "not-a-job"
	if _, err := effectiveTaskRuntimeForSecurityGate(bad); err == nil {
		t.Fatal("undecodable effective job resolved a runtime")
	}
	// An unresolvable task (no payload, no persisted pipeline) is an error.
	empty := basicTask("")
	empty.Job.CompiledJobPayload = nil
	if _, err := effectiveTaskRuntimeForSecurityGate(empty); err == nil {
		t.Fatal("task without payload and without pipeline resolved a runtime")
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

// TestExecuteLegacyUntrustedContainerFailsClosedBeforeCheckout is the P4
// regression: a legacy/malformed task WITHOUT a compiled payload must not
// bypass the pre-checkout hard-quota gate just because
// CompiledJobPayload is additive/optional. The effective runtime is resolved
// by recompiling the persisted pipeline before checkout, so an untrusted
// container job with no hard bound still fails before the clone runs.
func TestExecuteLegacyUntrustedContainerFailsClosedBeforeCheckout(t *testing.T) {
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
	// No compiled payload at all: the runtime comes from the persisted
	// pipeline text, exactly like a record written by a pre-payload control
	// plane.
	task := basicTask("version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    steps:\n      - run: echo hi\n")
	task.Job.Trusted = false
	task.Job.CompiledJobPayload = nil
	r.execute(context.Background(), task)

	if checkedOut {
		t.Fatal("legacy untrusted container job without a hard bound checked out anyway")
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
}

// TestExecuteLegacyUntrustedMalformedPayloadFailsClosed proves the other
// fail-closed edge: an undecodable compiled payload cannot be interpreted as
// "not container", so an untrusted job whose runtime cannot be established
// never reaches checkout without the hard bound it demands.
func TestExecuteLegacyUntrustedMalformedPayloadFailsClosed(t *testing.T) {
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
	task := basicTask(payloadPipeline)
	task.Job.Trusted = false
	task.Job.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: json.RawMessage(`"not-a-job"`)}
	r.execute(context.Background(), task)

	if checkedOut {
		t.Fatal("untrusted job with an undecodable payload checked out without the hard bound")
	}
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure {
		t.Fatalf("complete = %+v ok=%v", c, ok)
	}
	if !strings.Contains(c.Error, "hard workspace disk quota") || !strings.Contains(c.Error, "could not be resolved") {
		t.Fatalf("gate error does not name the unresolvable runtime: %q", c.Error)
	}
}

// TestQuotaGateRejectsPayloadRuntimeMismatchBeforeCheckout is the trust-order
// regression: the pre-checkout gate must not trust the NOT-YET-VERIFIED
// compiled payload's claimed runtime. Here the persisted pipeline says
// container while the payload claims native and the hard quota is
// unavailable; the mismatch must refuse the checkout (the payload only
// becomes authoritative after verifyCompiledPayload, which runs after
// checkout).
func TestQuotaGateRejectsPayloadRuntimeMismatchBeforeCheckout(t *testing.T) {
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
	containerText := "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    steps:\n      - run: echo hi\n"
	task := basicTask(containerText)
	task.Job.Trusted = false
	// The payload was compiled from a DIFFERENT (native) pipeline: corrupt or
	// inconsistent persisted state, but plausible enough that trusting it
	// would let the checkout run unprotected.
	task.Job.CompiledJobPayload = buildPayload(t, payloadPipeline, "build")
	r.execute(context.Background(), task)

	if checkedOut {
		t.Fatal("runtime mismatch let the untrusted checkout run without a hard bound")
	}
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure {
		t.Fatalf("complete = %+v ok=%v", c, ok)
	}
	if !strings.Contains(c.Error, "hard workspace disk quota") || !strings.Contains(c.Error, "disagrees") {
		t.Fatalf("gate error does not name the runtime disagreement: %q", c.Error)
	}
}

// TestQuotaGateRejectsCorruptCompiledPayloadBeforeCheckout pins the other
// half of the trust order: an undecodable payload cannot smuggle a
// non-container claim past the gate. The persisted pipeline is container, the
// payload is garbage, and the checkout must not run.
func TestQuotaGateRejectsCorruptCompiledPayloadBeforeCheckout(t *testing.T) {
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
	containerText := "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    steps:\n      - run: echo hi\n"
	task := basicTask(containerText)
	task.Job.Trusted = false
	task.Job.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: json.RawMessage(`{"job":`)}
	r.execute(context.Background(), task)

	if checkedOut {
		t.Fatal("corrupt payload let the untrusted checkout run without a hard bound")
	}
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure {
		t.Fatalf("complete = %+v ok=%v", c, ok)
	}
	if !strings.Contains(c.Error, "hard workspace disk quota") || !strings.Contains(c.Error, "could not be resolved") {
		t.Fatalf("gate error does not name the undecodable payload: %q", c.Error)
	}
}

// TestExecuteLegacyUntrustedNativeSkipsContainerGate proves the resolver
// does not over-fire: a legacy untrusted NATIVE job has no container backend
// to gate (the container builder is the only RequireDiskQuota consumer), so
// checkout proceeds exactly as before when no hard bound is available.
func TestExecuteLegacyUntrustedNativeSkipsContainerGate(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Detail: "no delegated quota here"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)
	// The availability preflight is not what this test exercises; stub it so
	// the assertion does not depend on the host's free space.
	origAvailable := executor.WorkspaceDiskAvailable
	executor.WorkspaceDiskAvailable = func(string, int64) error { return nil }
	t.Cleanup(func() { executor.WorkspaceDiskAvailable = origAvailable })

	checkedOut := false
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		checkedOut = true
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	task.Job.Trusted = false
	task.Job.CompiledJobPayload = nil
	r.execute(context.Background(), task)

	if !checkedOut {
		t.Fatal("legacy untrusted native job did not check out")
	}
	if c, _ := fsrv.lastComplete(); c.Status == model.StatusFailure && strings.Contains(c.Error, "hard workspace disk quota") {
		t.Fatalf("native job was refused by the container quota gate: %+v", c)
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
	// The availability PREFLIGHT is not what this test exercises, and its
	// outcome must not depend on how much space the test host has free: stub
	// it to succeed so the job reaches the docker lookup the assertions pin.
	origAvailable := executor.WorkspaceDiskAvailable
	executor.WorkspaceDiskAvailable = func(string, int64) error { return nil }
	t.Cleanup(func() { executor.WorkspaceDiskAvailable = origAvailable })
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
// runtime, so effectiveTaskRuntimeForSecurityGate can decide before checkout.
func TestVerifyWorkspaceQuotaPayloadJSONShape(t *testing.T) {
	task := untrustedContainerTask(t)
	if rt, err := effectiveTaskRuntimeForSecurityGate(task); err != nil || !runtimeRunsOnContainer(rt) {
		t.Fatalf("untrusted container runtime = %q, %v", rt, err)
	}
	raw, err := json.Marshal(task.Job.CompiledJobPayload.EffectiveJob)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"runtime":"container"`) {
		t.Fatalf("effective job JSON = %s", raw)
	}
}

// TestExecuteUntrustedQuotaAvailabilityFailsClosed deterministically pins the
// availability preflight: even when a hard bound is reported as installed,
// the executor re-checks that the declared budget is actually free on the
// workspace filesystem and fails the job closed (infra) when it is not — an
// unavailable bound is not a bound. The preflight is stubbed so the assertion
// does not depend on the test host's free space. (The preflight runs inside
// the executor, after the runner's pre-checkout install gate, so this test
// asserts the failure and the error shape, not a pre-checkout ordering.)
func TestExecuteUntrustedQuotaAvailabilityFailsClosed(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	// A hard bound IS reported by the quota install (stubbed), so the job
	// reaches the runner's availability PREFLIGHT. The preflight runs on the
	// EMPTY workspace immediately after install, so a failure must stop the
	// job before the checkout ever runs.
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: executor.DefaultUntrustedWorkspaceMaxBytes, Detail: "fake xfs quota"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)
	origAvailable := executor.WorkspaceDiskAvailable
	executor.WorkspaceDiskAvailable = func(workspace string, want int64) error {
		return fmt.Errorf("safefs: %d bytes required, 0 available", want)
	}
	t.Cleanup(func() { executor.WorkspaceDiskAvailable = origAvailable })

	checkedOut := false
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		checkedOut = true
		return nil
	}
	r.execute(context.Background(), untrustedContainerTask(t))

	c, _ := fsrv.lastComplete()
	if c.Status != model.StatusFailure || !strings.Contains(c.Error, "workspace quota") {
		t.Fatalf("complete = %+v, want the fail-closed workspace quota refusal", c)
	}
	if checkedOut {
		t.Fatal("checkout ran despite the workspace bound being unavailable on the empty workspace")
	}
}

// TestExecuteUntrustedQuotaOrdering pins the security-critical event order
// for the distributed runner: create the empty workspace, install the hard
// quota, verify the bound is actually AVAILABLE (before a single checkout
// byte exists — a project quota caps the project but reserves nothing, so a
// hostile checkout could otherwise consume the host's remaining free space
// up to the limit), then check out, and finally tear down quota-before-
// workspace. It also proves the executor does not repeat the full-capacity
// check after checkout: availability must be observed exactly once, or a
// 2 GiB checkout would silently raise the requirement to bound + 2 GiB.
func TestExecuteUntrustedQuotaOrdering(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	log := &quotaEventLog{}
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: executor.DefaultUntrustedWorkspaceMaxBytes, Detail: "fake xfs quota"}, log, &installs, &cleanups, &limitSeen, &dirSeen)
	origAvailable := executor.WorkspaceDiskAvailable
	executor.WorkspaceDiskAvailable = func(string, int64) error {
		log.add("availability")
		return nil
	}
	t.Cleanup(func() { executor.WorkspaceDiskAvailable = origAvailable })
	origRemove := removeJobWorkspace
	removeJobWorkspace = func(string) error {
		log.add("workspace-remove")
		return nil
	}
	t.Cleanup(func() { removeJobWorkspace = origRemove })

	r := testRunnerFor(t, ts, Config{})
	t.Setenv("PATH", t.TempDir()) // no docker: the job fails at the lookup after checkout
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		log.add("checkout")
		return nil
	}
	r.execute(context.Background(), untrustedContainerTask(t))

	want := "quota-install,availability,checkout,quota-cleanup,workspace-remove"
	if got := strings.Join(log.events, ","); got != want {
		t.Fatalf("quota lifecycle order = %q, want %q", got, want)
	}
}

// TestExecuteJoinsHeartbeatGoroutine pins the literal lifecycle contract: a
// task's heartbeat goroutine is not merely signalled, it is JOINED before
// execute returns. The heartbeat's exit is parked on the seam; execute must
// stay blocked in its deferred join until the heartbeat is released, and
// must finish once it is.
func TestExecuteJoinsHeartbeatGoroutine(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	release := make(chan struct{})
	heartbeatExiting = func() { <-release }
	t.Cleanup(func() { heartbeatExiting = nil })

	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return fmt.Errorf("checkout refused for the join test")
	}
	done := make(chan struct{})
	go func() {
		r.execute(context.Background(), untrustedContainerTask(t))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := fsrv.lastComplete(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("task never completed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The task is finished, but the heartbeat is parked in its exit seam:
	// with the join, execute must not have returned yet.
	select {
	case <-done:
		t.Fatal("execute returned without joining its heartbeat goroutine")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("execute did not finish after the heartbeat exited")
	}
}
