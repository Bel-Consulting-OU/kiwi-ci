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
