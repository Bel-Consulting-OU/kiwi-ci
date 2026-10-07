package runner

// Cross-package crash-recovery proof for a SIGKILL between cache publication
// renames. internal/cache proves the exact on-disk residue with a real killed
// child process; these tests prove the RUNNER side of the contract:
//
//   - the abandoned workspace is reclaimed BEFORE the first lease is served,
//   - a new job for the same runner gets a fresh kiwi-run-* path and never
//     the crashed directory or its partial cache files,
//   - two lease generations never share a workspace path,
//   - a failed reclaim keeps the runtime-ledger entry (the durable ownership
//     mark naming the crashed workspace) and refuses to lease any work until
//     the removal is proven; the retry only retires the entry after success.
//
// The production ownership mark is the durable ledger entry written by
// Runner.ledgerAdd (runtimeLedgerEntry.Workspace) and reclaimed by
// Runner.reconcileRuntimeLedger via reconcileIncarnation before the lease
// loop; a workspace directory itself carries no marker file.

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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// seedCrashedRestoreResidue plants exactly what the cache crash test observed
// from a real killed process: a kiwi-run-* workspace with the published
// member(s), a .kiwi-cache-stage-* sibling with the never-published member(s)
// and a ledger entry naming the workspace.
func seedCrashedRestoreResidue(t *testing.T, r *Runner, parent string) (ws, stage string) {
	t.Helper()
	var err error
	ws, err = os.MkdirTemp(parent, "kiwi-run-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "published-cache.txt"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	stage, err = os.MkdirTemp(parent, cache.StagePrefixForWorkspace(ws)+"*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "unpublished-cache.txt"), []byte("staged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ledgerAdd(runtimeLedgerEntry{
		Instance:  "crashed-incarnation",
		JobID:     "job-crashed",
		Workspace: ws,
	}); err != nil {
		t.Fatalf("ledgerAdd: %v", err)
	}
	return ws, stage
}

func ledgerEntryFiles(t *testing.T, r *Runner) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(r.runtimeLedgerDir(), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestAbandonedCacheRestoreResidueReclaimedBeforeFirstLease drives the real
// Run startup: the crashed workspace + ledger entry exist before Run, and by
// the time the control plane serves the FIRST lease the workspace is proven
// removed. Every new execution gets a distinct fresh workspace with none of
// the crashed residue.
func TestAbandonedCacheRestoreResidueReclaimedBeforeFirstLease(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "docker.log")
	installFakeDockerForRunner(t, logPath)

	wsParent := t.TempDir()
	var crashedPath atomic.Pointer[string]
	var residueGoneAtFirstLease atomic.Bool
	var residuePresentAtFirstLease atomic.Bool
	var leaseChecks, served, nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case r.URL.Path == "/api/v1/runners/runner-1/next":
			nextCalls.Add(1)
			// The assertion that matters: reclaim (reconcileIncarnation)
			// runs strictly before the lease loop, so the crashed workspace
			// must already be gone when the FIRST lease is handed out. Only
			// the first check counts: a later lease seeing it gone must not
			// mask a first lease that saw it present.
			if p := crashedPath.Load(); p != nil && leaseChecks.Add(1) == 1 {
				if _, statErr := os.Lstat(*p); os.IsNotExist(statErr) {
					residueGoneAtFirstLease.Store(true)
				} else {
					residuePresentAtFirstLease.Store(true)
				}
			}
			n := served.Add(1)
			if n <= 2 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(server.Task{
					Job: model.Job{
						ID: fmt.Sprintf("job-%d", n), Key: "build", Trusted: true,
						Pipeline: payloadPipeline,
					},
					LeaseToken:      "tok",
					LeaseGeneration: int64(n),
				})
				return
			}
			w.Header().Set("X-Kiwi-Draining", "true")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}

	crashedWS, crashedStage := seedCrashedRestoreResidue(t, r, wsParent)
	crashedPath.Store(&crashedWS)

	var mu sync.Mutex
	workspaces := map[string]string{}
	var violations []string
	r.Cfg.CheckoutFn = func(_ context.Context, j model.Job, dir string) error {
		var got []string
		if dir == crashedWS {
			got = append(got, "new job was handed the crashed workspace path")
		}
		if _, err := os.Lstat(filepath.Join(dir, "published-cache.txt")); err == nil {
			got = append(got, "new job workspace contains the partial published cache file")
		}
		if _, err := os.Lstat(filepath.Join(dir, "unpublished-cache.txt")); err == nil {
			got = append(got, "new job workspace contains an unpublished staging file")
		}
		if !strings.HasPrefix(filepath.Base(dir), "kiwi-run-") {
			got = append(got, "new job workspace is not a fresh kiwi-run-* directory: "+dir)
		}
		mu.Lock()
		workspaces[j.ID] = dir
		violations = append(violations, got...)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want a clean drain", err)
	}

	if !residueGoneAtFirstLease.Load() || residuePresentAtFirstLease.Load() {
		t.Fatal("the first lease was served while the crashed workspace still existed: reclaim must precede any new lease")
	}
	if _, err := os.Lstat(crashedWS); !os.IsNotExist(err) {
		t.Fatalf("crashed workspace survived reconciliation (err=%v)", err)
	}
	if _, err := os.Lstat(crashedStage); !os.IsNotExist(err) {
		t.Fatalf("crashed staging sibling survived reconciliation (err=%v): a SIGKILL mid-publish must not leak staged cache data", err)
	}
	if entries := ledgerEntryFiles(t, r); len(entries) != 0 {
		t.Fatalf("ledger entries after Run = %v, want none (crash entry reclaimed, job entries retired)", entries)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(violations) != 0 {
		t.Fatalf("reuse-safety violations: %v", violations)
	}
	if len(workspaces) != 2 {
		t.Fatalf("workspaces = %v, want two executions", workspaces)
	}
	if workspaces["job-1"] == workspaces["job-2"] {
		t.Fatalf("two lease generations shared the workspace path %q", workspaces["job-1"])
	}
	if nextCalls.Load() < 3 {
		t.Fatalf("next calls = %d, want the two leases plus the drain poll", nextCalls.Load())
	}
}

// TestReclaimFailureRetainsLedgerEntryAndRefusesNewLeases pins the other half
// of the contract: a removal that cannot be proven keeps the ledger entry
// (the crash mark) and the runner refuses to lease ANY work; only a retry
// whose removal succeeds retires the entry.
func TestReclaimFailureRetainsLedgerEntryAndRefusesNewLeases(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "docker.log")
	installFakeDockerForRunner(t, logPath)

	var nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/runners/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case r.URL.Path == "/api/v1/runners/runner-1/next":
			nextCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}

	crashedWS, _ := seedCrashedRestoreResidue(t, r, t.TempDir())
	entries := ledgerEntryFiles(t, r)
	if len(entries) != 1 {
		t.Fatalf("seeded ledger entries = %v, want one", entries)
	}
	entryPath := entries[0]
	// The ledger entry IS the production ownership mark: it names the
	// crashed workspace and job.
	var entry runtimeLedgerEntry
	if b, err := os.ReadFile(entryPath); err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(b, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Workspace != crashedWS || entry.JobID != "job-crashed" || entry.RunnerID != "runner-1" {
		t.Fatalf("ledger mark = %+v, want workspace=%s job=job-crashed runner=runner-1", entry, crashedWS)
	}

	origRemove := removeLedgerPath
	removeLedgerPath = func(p string) error {
		if p == crashedWS {
			return errors.New("workspace busy")
		}
		return os.RemoveAll(p)
	}
	t.Cleanup(func() { removeLedgerPath = origRemove })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("Run leased work although the crashed workspace could not be reclaimed")
	}
	if nextCalls.Load() != 0 {
		t.Fatalf("next calls = %d, want 0: an unproven reclaim must refuse every lease", nextCalls.Load())
	}
	if _, serr := os.Lstat(crashedWS); serr != nil {
		t.Fatalf("crashed workspace vanished without a proven removal: %v", serr)
	}
	if got := ledgerEntryFiles(t, r); len(got) != 1 {
		t.Fatalf("ledger entries after the failed reclaim = %v, want the entry retained", got)
	}
	if _, serr := os.Stat(entryPath + ".reclaimed"); !os.IsNotExist(serr) {
		t.Fatalf("reclaim marker exists although removal failed (err=%v)", serr)
	}

	// Retry with the real removal: the entry may only disappear after the
	// workspace is proven gone.
	removeLedgerPath = os.RemoveAll
	res, rerr := r.reconcileRuntimeLedger("next-incarnation")
	if rerr != nil {
		t.Fatalf("retry reconcile = %v", rerr)
	}
	if res.Reclaimed != 1 {
		t.Fatalf("retry reclaimed %d entries, want 1", res.Reclaimed)
	}
	if _, serr := os.Lstat(crashedWS); !os.IsNotExist(serr) {
		t.Fatalf("crashed workspace survived the successful retry (err=%v)", serr)
	}
	if got := ledgerEntryFiles(t, r); len(got) != 0 {
		t.Fatalf("ledger entries after the successful retry = %v, want none", got)
	}
}
