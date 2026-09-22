package runner

// Cross-feature composition: disk-exhaustion / quota boundaries in the
// runner's workspace lifecycle.
//
// The runner owns the workspace quota lifecycle: it installs the hard bound
// on the EMPTY workspace before checkout and tears it down on every return
// path. These tests compose that lifecycle with the fail-closed untrusted
// gate (a host where no hard bound can be established must fail the job
// closed before the repository is cloned, not after) and with a client
// cancellation that lands while the checkout runs under the installed quota
// (the quota and the workspace must both be released, the completion must not
// claim success, and the next task must run cleanly). No docker is required:
// the gate fires before the container backend, and the success paths use a
// native step.

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const composeContainerPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine:3.19
    steps:
      - run: echo hi
`

// composeWatchTemp points TMPDIR at a fresh directory and returns it, so the
// test can assert the runner left no workspace behind.
func composeWatchTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

// TestComposeRunnerUntrustedNoHardBoundFailsClosedBeforeCheckout composes the
// disk-exhaustion gate with the quota lifecycle: an untrusted container job
// whose OS-level bound cannot be established must fail BEFORE checkout (no
// clone, no downloads, nothing written to the workspace), so the unbounded
// window the quota exists to close never opens. The next task on the same
// runner succeeds, proving the failed gate left nothing behind.
func TestComposeRunnerUntrustedNoHardBoundFailsClosedBeforeCheckout(t *testing.T) {
	watched := composeWatchTemp(t)
	t.Setenv(executor.AllowUnquotaedUntrustedDiskEnv, "")

	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: false, Detail: "no xfs prjquota on this host"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)

	checkoutRan := false
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		checkoutRan = true
		return os.WriteFile(dir+"/hello.txt", []byte("hi"), 0o644)
	}

	task := basicTask(composeContainerPipeline)
	task.Job.Trusted = false
	task.Job.DiskRequest = 2 << 30
	task.Job.CompiledJobPayload = buildPayload(t, composeContainerPipeline, "build")
	r.execute(context.Background(), task)

	if checkoutRan {
		t.Fatal("checkout ran for an untrusted job with no hard workspace bound (the unbounded clone window opened)")
	}
	if installs != 1 {
		t.Fatalf("quota installs = %d, want the one failed probe", installs)
	}
	if cleanups != 0 {
		t.Fatalf("cleanups = %d, want none: the probe established nothing", cleanups)
	}
	if limitSeen != 2<<30 {
		t.Fatalf("quota limit = %d, want the persisted 2 GiB request", limitSeen)
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded for the failed gate")
	}
	if c.Status != model.StatusFailure {
		t.Fatalf("completion status = %s, want failure", c.Status)
	}
	if !strings.Contains(c.Error, "hard workspace disk quota") || !strings.Contains(c.Error, "no xfs prjquota on this host") {
		t.Fatalf("gate error %q does not name the missing bound and the probe reason", c.Error)
	}
	if dirSeen != "" {
		if _, err := os.Stat(dirSeen); !os.IsNotExist(err) {
			t.Fatalf("failed gate left the workspace directory %s: %v", dirSeen, err)
		}
	}
	if entries, err := os.ReadDir(watched); err == nil && len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("failed gate left temp entries: %v", names)
	}

	// The next task on the same runner succeeds cleanly.
	r2 := testRunnerFor(t, ts, Config{})
	r2.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(dir+"/hello.txt", []byte("hi"), 0o644)
	}
	next := basicTask(payloadPipeline)
	next.Job.ID = "job-2"
	r2.execute(context.Background(), next)
	c, ok = fsrv.lastComplete()
	if !ok || c.Status != model.StatusSuccess {
		t.Fatalf("next task completion = %+v (ok=%v), want success", c, ok)
	}
}

// TestComposeRunnerCancelUnderQuotaReleasesQuotaAndWorkspace cancels the task
// while checkout is running under an installed hard quota: the deferred
// teardown must remove the quota and the workspace, the completion must be
// canceled (never success), and the next task must succeed through the same
// lifecycle.
func TestComposeRunnerCancelUnderQuotaReleasesQuotaAndWorkspace(t *testing.T) {
	watched := composeWatchTemp(t)

	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	log := &quotaEventLog{}
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: 1 << 30, Detail: "fake xfs quota"}, log, &installs, &cleanups, &limitSeen, &dirSeen)

	origRemove := removeJobWorkspace
	removeJobWorkspace = func(path string) error {
		log.add("workspace-remove")
		return origRemove(path)
	}
	t.Cleanup(func() { removeJobWorkspace = origRemove })

	checkoutStarted := make(chan struct{})
	r := testRunnerFor(t, ts, Config{Heartbeat: 5 * time.Millisecond})
	r.Cfg.CheckoutFn = func(ctx context.Context, _ model.Job, dir string) error {
		close(checkoutStarted)
		<-ctx.Done()
		return ctx.Err()
	}

	task := basicTask(payloadPipeline)
	task.Job.Trusted = false
	task.Job.DiskRequest = 1 << 30
	// The lease is about to expire and the control plane cannot extend it, so
	// the runner's own heartbeat loop cancels the job while the checkout runs
	// under the installed quota — the production cancellation path (the
	// parent context stays alive exactly as the runner process's does, so the
	// cancelled completion is deliverable).
	task.LeaseExpiresAt = time.Now().Add(15 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		r.execute(context.Background(), task)
		close(done)
	}()
	select {
	case <-checkoutStarted:
	case <-time.After(30 * time.Second):
		t.Fatal("checkout never started under the installed quota")
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("execute did not return after the lease-driven cancellation")
	}

	if installs != 1 || cleanups != 1 {
		t.Fatalf("quota installs/cleanups = %d/%d, want 1/1 (%v)", installs, cleanups, log.events)
	}
	want := []string{"quota-install", "quota-cleanup", "workspace-remove"}
	if strings.Join(log.events, ",") != strings.Join(want, ",") {
		t.Fatalf("cancelled lifecycle order = %v, want %v", log.events, want)
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded after the cancellation")
	}
	if c.Status != model.StatusCancelled {
		t.Fatalf("completion status after cancellation = %s, want cancelled", c.Status)
	}
	if strings.TrimSpace(c.Error) == "" {
		t.Fatal("cancelled completion carries no error text")
	}
	if entries, err := os.ReadDir(watched); err == nil && len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("cancelled task left temp workspace entries: %v", names)
	}

	// The next task through the same lifecycle succeeds.
	r2 := testRunnerFor(t, ts, Config{})
	r2.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(dir+"/hello.txt", []byte("hi"), 0o644)
	}
	next := basicTask(payloadPipeline)
	next.Job.ID = "job-2"
	next.Job.DiskRequest = 1 << 20
	r2.execute(context.Background(), next)
	c, ok = fsrv.lastComplete()
	if !ok || c.Status != model.StatusSuccess {
		t.Fatalf("next task completion = %+v (ok=%v), want success", c, ok)
	}
	// The second task's own quota lifecycle was complete too.
	if installs != 2 || cleanups != 2 {
		t.Fatalf("accumulated installs/cleanups = %d/%d, want 2/2", installs, cleanups)
	}
}

// TestComposeRunnerCancelLandsDuringQuotaInstall proves the quota lifecycle
// survives a cancellation that arrives WHILE the install itself is in flight:
// the install cannot observe the context, so the cancel is only acted on when
// the install returns — and the deferred teardown must still remove the quota
// and the workspace, with the completion carrying the canceled status and no
// temp directory left behind. The next task runs cleanly through the same
// lifecycle.
func TestComposeRunnerCancelLandsDuringQuotaInstall(t *testing.T) {
	watched := composeWatchTemp(t)

	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	log := &quotaEventLog{}
	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	origInstall := installWorkspaceDiskQuota
	installWorkspaceDiskQuota = func(workspace string, limit int64) (executor.DiskQuotaStatus, func() error) {
		installs++
		limitSeen = limit
		dirSeen = workspace
		log.add("quota-install-start")
		// A slow install (e.g. an XFS project-id allocation under I/O load):
		// the lease expires and the heartbeat cancels the job while this
		// blocking setup is still running.
		time.Sleep(60 * time.Millisecond)
		log.add("quota-install-end")
		return executor.DiskQuotaStatus{Hard: true, Limit: limit, Detail: "slow fake xfs quota"}, func() error {
			cleanups++
			log.add("quota-cleanup")
			return nil
		}
	}
	t.Cleanup(func() { installWorkspaceDiskQuota = origInstall })

	origRemove := removeJobWorkspace
	removeJobWorkspace = func(path string) error {
		log.add("workspace-remove")
		return origRemove(path)
	}
	t.Cleanup(func() { removeJobWorkspace = origRemove })

	var checkoutCtxErr error
	checkoutWrote := false
	r := testRunnerFor(t, ts, Config{Heartbeat: 5 * time.Millisecond})
	r.Cfg.CheckoutFn = func(ctx context.Context, _ model.Job, dir string) error {
		// The real checkout honors the task context; a cancelled task must
		// not clone a repository.
		if err := ctx.Err(); err != nil {
			checkoutCtxErr = err
			return err
		}
		checkoutWrote = true
		return os.WriteFile(dir+"/hello.txt", []byte("hi"), 0o644)
	}

	task := basicTask(payloadPipeline)
	task.Job.Trusted = false
	task.Job.DiskRequest = 1 << 20
	task.LeaseExpiresAt = time.Now().Add(20 * time.Millisecond)
	r.execute(context.Background(), task)

	if installs != 1 || cleanups != 1 {
		t.Fatalf("quota installs/cleanups = %d/%d, want 1/1 (%v)", installs, cleanups, log.events)
	}
	if limitSeen != 1<<20 {
		t.Fatalf("quota limit = %d, want the persisted 1 MiB request", limitSeen)
	}
	if checkoutCtxErr == nil {
		t.Fatalf("checkout did not observe the cancellation that landed during the quota install (%v)", log.events)
	}
	if checkoutWrote {
		t.Fatal("checkout wrote the workspace after the job was cancelled during the quota install")
	}
	// The cancellation landed during the install: the checkout never ran, and
	// the teardown still removed the quota and the workspace.
	want := []string{"quota-install-start", "quota-install-end", "quota-cleanup", "workspace-remove"}
	if strings.Join(log.events, ",") != strings.Join(want, ",") {
		t.Fatalf("install-cancel lifecycle order = %v, want %v", log.events, want)
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded for the install-time cancellation")
	}
	if c.Status != model.StatusCancelled {
		t.Fatalf("completion status = %s, want cancelled", c.Status)
	}
	if dirSeen != "" {
		if _, err := os.Stat(dirSeen); !os.IsNotExist(err) {
			t.Fatalf("install-time cancellation left the workspace %s: %v", dirSeen, err)
		}
	}
	if entries, err := os.ReadDir(watched); err == nil && len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("install-time cancellation left temp entries: %v", names)
	}

	// The next task through the same lifecycle succeeds.
	r2 := testRunnerFor(t, ts, Config{})
	r2.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(dir+"/hello.txt", []byte("hi"), 0o644)
	}
	next := basicTask(payloadPipeline)
	next.Job.ID = "job-2"
	next.Job.DiskRequest = 1 << 20
	r2.execute(context.Background(), next)
	c, ok = fsrv.lastComplete()
	if !ok || c.Status != model.StatusSuccess {
		t.Fatalf("next task completion = %+v (ok=%v), want success", c, ok)
	}
}
