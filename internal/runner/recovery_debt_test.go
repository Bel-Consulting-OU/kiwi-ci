package runner

// Current-incarnation cleanup debt must stop new leases: startup debt fails
// closed, and identical debt discovered while running must not be weaker.
// The runner stops polling /next immediately, lets in-flight jobs finish,
// then performs one bounded reconciliation pass; success clears the debt and
// resumes, failure exits Run non-zero so startup reconciliation owns the
// recovery.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// writeDebtLedgerEntry plants a current-runner ledger entry with recovery
// coordinates for the debt tests.
func writeDebtLedgerEntry(t *testing.T, r *Runner) {
	t.Helper()
	ws := filepath.Join(t.TempDir(), "kiwi-run-debt")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := r.ledgerAdd(runtimeLedgerEntry{Instance: "older-instance", JobID: "job-debt", Workspace: ws})
	if err != nil {
		t.Fatalf("ledgerAdd: %v", err)
	}
	if err := r.ledgerSetCgroup(id, "/sys/fs/cgroup/kiwi/job-debt"); err != nil {
		t.Fatal(err)
	}
}

func nextCountingServer(t *testing.T, nextCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case r.URL.Path == "/api/v1/runners/runner-1/next":
			nextCalls.Add(1)
			w.Header().Set("X-Kiwi-Draining", "true")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

// TestRecoveryDebtStopsNewLeases: with unresolvable debt the runner must
// never poll /next and must exit non-zero.
func TestRecoveryDebtStopsNewLeases(t *testing.T) {
	var nextCalls atomic.Int32
	ts := nextCountingServer(t, &nextCalls)
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	writeDebtLedgerEntry(t, r)
	r.noteRecoveryDebt(executor.CleanupDebt{Kind: executor.CleanupCgroup, Resource: "/cg", Err: errors.New("cgroup busy")})

	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error { return nil }
	reclaimJobCgroup = func(string) error { return errors.New("still busy") }
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })

	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("Run succeeded with unresolved cleanup debt")
	}
	if nextCalls.Load() != 0 {
		t.Fatalf("next calls = %d, want 0 (no new leases while debted)", nextCalls.Load())
	}
}

// TestCurrentIncarnationDebtReconcilesBeforeResume: a bounded in-process
// reconciliation that CLEARS the debt lets the runner resume polling.
func TestCurrentIncarnationDebtReconcilesBeforeResume(t *testing.T) {
	var nextCalls atomic.Int32
	ts := nextCountingServer(t, &nextCalls)
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	writeDebtLedgerEntry(t, r)
	r.noteRecoveryDebt(executor.CleanupDebt{Kind: executor.CleanupCgroup, Resource: "/cg", Err: errors.New("transient")})

	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error { return nil }
	reclaimJobCgroup = func(string) error { return nil }
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run after a clean reclaim = %v", err)
	}
	if nextCalls.Load() == 0 {
		t.Fatal("runner did not resume leasing after the debt was reconciled")
	}
}

// TestQuotaCleanupPendingStopsNewLeases drives the real execute path: the
// first task creates quota cleanup debt, a second task is queued, and the
// same runner must never lease it.
func TestQuotaCleanupPendingStopsNewLeases(t *testing.T) {
	var served, nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case r.URL.Path == "/api/v1/runners/runner-1/next":
			nextCalls.Add(1)
			if served.Add(1) <= 2 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(server.Task{
					Job:        model.Job{ID: fmt.Sprintf("job-%d", served.Load()), Key: "build", Trusted: false, DiskRequest: 1 << 20, Pipeline: payloadPipeline},
					LeaseToken: "tok", LeaseGeneration: 1,
				})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }

	pending := executor.QuotaCleanupPendingError{
		Assignment: executor.WorkspaceQuotaAssignment{MountPoint: "/mnt/xfs", FsKey: "8:70", XQ: "/usr/sbin/xfs_quota", ProjectID: 777},
		Cause:      errors.New("simulated timeout"),
	}
	origInstall := installWorkspaceDiskQuota
	installWorkspaceDiskQuota = func(workspace string, limit int64, onAllocated func(executor.WorkspaceQuotaAssignment) error) (executor.DiskQuotaStatus, func() error, error) {
		pending.Assignment.Workspace = workspace
		if onAllocated != nil {
			if herr := onAllocated(pending.Assignment); herr != nil {
				return executor.DiskQuotaStatus{}, nil, herr
			}
		}
		return executor.DiskQuotaStatus{Detail: "ambiguous"}, nil, &pending
	}
	t.Cleanup(func() { installWorkspaceDiskQuota = origInstall })
	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	// The ambiguous assignment cannot be reclaimed yet: the debt must stay
	// unresolved so the runner exits instead of resuming.
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error { return errors.New("xfs reclaim not yet possible") }
	reclaimJobCgroup = func(string) error { return nil }
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("Run succeeded although the quota debt could not be reconciled")
	}
	if nextCalls.Load() != 1 {
		t.Fatalf("next calls = %d, want 1 (the second queued job must never be leased)", nextCalls.Load())
	}
}

// TestQuotaTeardownFailureStopsNewLeases: a quota teardown failure AFTER a
// successful job retains the ledger, raises debt, and must prevent the next
// queued job from being leased while the reclaim remains unresolved.
func TestQuotaTeardownFailureStopsNewLeases(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "docker.log")
	installFakeDockerForRunner(t, logPath)
	var served, nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case r.URL.Path == "/api/v1/runners/runner-1/next":
			nextCalls.Add(1)
			if served.Add(1) <= 2 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(server.Task{
					Job:        model.Job{ID: fmt.Sprintf("job-%d", served.Load()), Key: "build", Trusted: false, DiskRequest: 1 << 20, Pipeline: payloadPipeline},
					LeaseToken: "tok", LeaseGeneration: 1,
				})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }

	origInstall := installWorkspaceDiskQuota
	installWorkspaceDiskQuota = func(workspace string, limit int64, onAllocated func(executor.WorkspaceQuotaAssignment) error) (executor.DiskQuotaStatus, func() error, error) {
		a := executor.WorkspaceQuotaAssignment{Workspace: workspace, MountPoint: "/mnt/xfs", FsKey: "8:70", XQ: "/usr/sbin/xfs_quota", ProjectID: 999}
		if onAllocated != nil {
			if herr := onAllocated(a); herr != nil {
				return executor.DiskQuotaStatus{}, nil, herr
			}
		}
		return executor.DiskQuotaStatus{Hard: true, Limit: limit, Assignment: &a, Detail: "stub"}, func() error {
			return errors.New("teardown fails")
		}, nil
	}
	t.Cleanup(func() { installWorkspaceDiskQuota = origInstall })
	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error { return errors.New("still unreclaimable") }
	reclaimJobCgroup = func(string) error { return nil }
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("Run succeeded with unresolved quota-teardown debt")
	}
	if nextCalls.Load() != 1 {
		t.Fatalf("next calls = %d, want 1 (the queued second job must not be leased)", nextCalls.Load())
	}
}

// TestArtifactCaptureRemoveFailureRetainsLedgerAndStopsLeases: a failed
// artifact-scratch removal must keep the ledger entry (the only durable
// coordinates) and quarantine the runner; a restart must reclaim it.
func TestArtifactCaptureRemoveFailureRetainsLedgerAndStopsLeases(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "docker.log")
	installFakeDockerForRunner(t, logPath)
	scratchRoot := t.TempDir()
	var served, nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case r.URL.Path == "/api/v1/runners/runner-1/next":
			nextCalls.Add(1)
			if served.Add(1) == 1 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(server.Task{
					Job:        model.Job{ID: "job-art", Key: "build", Trusted: true, Pipeline: artifactScratchPipeline},
					LeaseToken: "tok", LeaseGeneration: 1,
				})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: scratchRoot, GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }

	origRemove := removeArtifactScratch
	removeArtifactScratch = func(string) error { return errors.New("scratch is undeletable") }
	origReclaimRemove := removeLedgerPath
	removeLedgerPath = func(string) error { return errors.New("scratch is undeletable") }
	t.Cleanup(func() { removeArtifactScratch = origRemove; removeLedgerPath = origReclaimRemove })
	// Recovery cannot clear the scratch debt: keep the runner quarantined.
	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error { return nil }
	reclaimJobCgroup = func(string) error { return nil }
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("Run succeeded although the artifact scratch could not be removed")
	}
	entries, _ := filepath.Glob(filepath.Join(r.runtimeLedgerDir(), "*.json"))
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want the retained scratch coordinates", len(entries))
	}
	if nextCalls.Load() != 1 {
		t.Fatalf("next calls = %d, want 1", nextCalls.Load())
	}
}

// artifactScratchPipeline declares one artifact so the runner creates (and
// must later remove) a capture directory.
const artifactScratchPipeline = `version: 1
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi > out.txt
    artifacts:
      - name: out
        paths: ["out.txt"]
`

// TestConcurrentDebtCancelsInFlightPoll pins the concurrency>1 race: when one
// worker raises debt while another /next request is already in flight, that
// request is canceled and the fill loop must not lease further slots.
func TestConcurrentDebtCancelsInFlightPoll(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "docker.log")
	installFakeDockerForRunner(t, logPath)
	secondPoll := make(chan struct{})
	var nextCalls, served atomic.Int32
	var completions atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case fullPathNext(r):
			n := nextCalls.Add(1)
			switch n {
			case 1:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(server.Task{
					Job:        model.Job{ID: "job-debt", Key: "build", Trusted: false, DiskRequest: 1 << 20, Pipeline: payloadPipeline},
					LeaseToken: "tok", LeaseGeneration: 1,
				})
				return
			case 2:
				// Hold the response until the debt has been raised; the
				// runner's poll cancellation must abort this request.
				w.Header().Set("Content-Type", "application/json")
				select {
				case <-secondPoll:
				case <-time.After(2 * time.Second):
				}
				if served.Add(1) == 1 {
					_ = json.NewEncoder(w).Encode(server.Task{
						Job:        model.Job{ID: "job-2", Key: "build", Trusted: false, DiskRequest: 1 << 20, Pipeline: payloadPipeline},
						LeaseToken: "tok", LeaseGeneration: 1,
					})
					return
				}
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		case r.URL.Path == "/api/v1/jobs/job-2/complete":
			completions.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 4,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }

	origInstall := installWorkspaceDiskQuota
	installWorkspaceDiskQuota = func(workspace string, limit int64, onAllocated func(executor.WorkspaceQuotaAssignment) error) (executor.DiskQuotaStatus, func() error, error) {
		// Fresh per call: this test runs concurrent workers, so a shared
		// pending struct would be a data race.
		pending := executor.QuotaCleanupPendingError{
			Assignment: executor.WorkspaceQuotaAssignment{Workspace: workspace, MountPoint: "/mnt/xfs", FsKey: "8:70", XQ: "/usr/sbin/xfs_quota", ProjectID: 321},
			Cause:      errors.New("ambiguous"),
		}
		if onAllocated != nil {
			if herr := onAllocated(pending.Assignment); herr != nil {
				return executor.DiskQuotaStatus{}, nil, herr
			}
		}
		return executor.DiskQuotaStatus{Detail: "ambiguous"}, nil, &pending
	}
	t.Cleanup(func() { installWorkspaceDiskQuota = origInstall })
	origXFS, origCG := reclaimWorkspaceQuota, reclaimJobCgroup
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error { return errors.New("unresolved") }
	reclaimJobCgroup = func(string) error { return nil }
	t.Cleanup(func() { reclaimWorkspaceQuota, reclaimJobCgroup = origXFS, origCG })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	// Wait until the second poll is in flight, then release it and let the
	// debt/cancellation decide the outcome.
	// Release the held response only after the debt is OBSERVED: releasing
	// earlier could let the fill loop start the raced task before the worker
	// reports, which is not the interleaving under test.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (nextCalls.Load() < 2 || !r.recoveryDebt.Load()) {
		time.Sleep(5 * time.Millisecond)
	}
	close(secondPoll)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not exit after the unresolved debt")
	}
	// A third poll would mean the fill loop kept leasing after the debt.
	time.Sleep(200 * time.Millisecond)
	if nextCalls.Load() > 2 {
		t.Fatalf("next calls = %d, want at most 2 (no polling after debt)", nextCalls.Load())
	}
	if completions.Load() != 0 {
		t.Fatal("the raced second job was started after the debt")
	}
}

func fullPathNext(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, "/next")
}

// TestWorkspaceRemoveFailureStopsNewLeases: a failed workspace removal after
// a successful job retains the ledger and quarantines the runner.
func TestWorkspaceRemoveFailureStopsNewLeases(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "docker.log")
	installFakeDockerForRunner(t, logPath)
	var served, nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case r.URL.Path == "/api/v1/runners/runner-1/next":
			nextCalls.Add(1)
			if served.Add(1) <= 2 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(server.Task{
					Job:        model.Job{ID: fmt.Sprintf("job-%d", served.Load()), Key: "build", Trusted: true, Pipeline: payloadPipeline},
					LeaseToken: "tok", LeaseGeneration: 1,
				})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }

	origRemove := removeJobWorkspace
	removeJobWorkspace = func(string) error { return errors.New("workspace busy") }
	t.Cleanup(func() { removeJobWorkspace = origRemove })
	origXFS, origCG, origLedgerRemove := reclaimWorkspaceQuota, reclaimJobCgroup, removeLedgerPath
	reclaimWorkspaceQuota = func(executor.WorkspaceQuotaAssignment) error { return nil }
	reclaimJobCgroup = func(string) error { return nil }
	removeLedgerPath = func(string) error { return errors.New("workspace busy") }
	t.Cleanup(func() {
		reclaimWorkspaceQuota, reclaimJobCgroup, removeLedgerPath = origXFS, origCG, origLedgerRemove
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("Run succeeded although the workspace could not be removed")
	}
	if nextCalls.Load() != 1 {
		t.Fatalf("next calls = %d, want 1", nextCalls.Load())
	}
	entries, _ := filepath.Glob(filepath.Join(r.runtimeLedgerDir(), "*.json"))
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}
}

// TestRunBackgroundDrainTimeoutPoisonsRunner: a worker that ignores
// cancellation past the drain grace means Kiwi can no longer prove the old
// execution authority is gone; the Runner instance must be poisoned.
func TestRunBackgroundDrainTimeoutPoisonsRunner(t *testing.T) {
	var nextCalls, registerCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			registerCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case strings.HasSuffix(r.URL.Path, "/next"):
			nextCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	origGrace := backgroundDrainGrace
	backgroundDrainGrace = 200 * time.Millisecond
	t.Cleanup(func() { backgroundDrainGrace = origGrace })
	origHook := runBackgroundTestHook
	runBackgroundTestHook = func(wg *sync.WaitGroup) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {} // ignores cancellation entirely
		}()
	}
	t.Cleanup(func() { runBackgroundTestHook = origHook })

	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.Run(ctx)
	if !r.lifecyclePoisoned.Load() {
		t.Fatal("runner not poisoned after the background drain grace expired")
	}
	// A SECOND Run on the same instance must be refused before it can
	// register, reconcile, or take identity ownership.
	if err := r.Run(context.Background()); !errors.Is(err, ErrRunnerRequiresProcessRestart) {
		t.Fatalf("second Run = %v, want ErrRunnerRequiresProcessRestart", err)
	}
	if registerCalls.Load() != 1 {
		t.Fatalf("register calls = %d, want 1 (the refused second Run must not register)", registerCalls.Load())
	}
	// A FRESH Runner (a restarted process) with its own identity still works.
	fresh := &Runner{ID: "runner-2", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := fresh.Run(ctx2); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("fresh process Run = %v", err)
	}
}

// TestRunnerRefusesStartupWhenInstanceEntropyFails: the incarnation ID is an
// ownership namespace, so missing secure randomness must refuse startup
// before registration/reconciliation instead of degrading to a timestamp.
func TestRunnerRefusesStartupWhenInstanceEntropyFails(t *testing.T) {
	var registerCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/register") {
			registerCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	origRand := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = origRand })

	// r.ID preset so the failure is unambiguously the INSTANCE identity.
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	err := r.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "randomness") {
		t.Fatalf("Run with failing entropy = %v, want an instance-identity refusal", err)
	}
	if registerCalls.Load() != 0 {
		t.Fatalf("registration happened despite failed instance entropy (%d calls)", registerCalls.Load())
	}
}
