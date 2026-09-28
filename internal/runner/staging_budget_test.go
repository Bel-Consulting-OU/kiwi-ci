package runner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// stagedBytes sums the sizes of the staging spool files currently present in
// dir. It is the physical counterpart of Budget.Used() for the serialization
// test: the ledger can only be trusted to state occupancy if the directory
// really holds no more bytes.
func stagedBytes(t *testing.T, dir string) int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || !hasSpoolPrefix(e.Name()) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		total += info.Size()
	}
	return total
}

func hasSpoolPrefix(name string) bool {
	const prefix = "kiwi-stage-"
	return len(name) >= len(prefix) && name[:len(prefix)] == prefix
}

// TestDependencyStagingBudgetSerializesConcurrentRestores is the P1
// concurrency regression: several dependency restores run at once, but the
// runner-wide staging budget admits only as many spools as fit. With a
// budget of exactly one artifact, one restore stages while the others block
// in Acquire, and the aggregate staged bytes — ledger AND physical directory
// — can never exceed the budget.
func TestDependencyStagingBudgetSerializesConcurrentRestores(t *testing.T) {
	body := tarGzWithFile(t, "app.txt", "serialized-dependency")
	reserve := int64(len(body))

	// The server sends the full Content-Length, half the body, then blocks
	// until released. The restore that acquired the budget is therefore
	// parked mid-spool with its reservation held; the rest wait in Acquire.
	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("Content-Type", "application/gzip")
		half := len(body) / 2
		_, _ = w.Write(body[:half])
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		entered <- struct{}{}
		<-release
		_, _ = w.Write(body[half:])
	}))
	defer srv.Close()

	r := testRunnerFor(t, srv, Config{StagingMaxBytes: reserve})
	workspace := t.TempDir()
	inputs := make([]pipeline.ArtifactInput, 0, 4)
	for i := 0; i < 4; i++ {
		inputs = append(inputs, pipeline.ArtifactInput{From: "build", Name: "bin", Path: fmt.Sprintf("deps/%d", i)})
	}

	var wg sync.WaitGroup
	errs := make([]error, len(inputs))
	for i, in := range inputs {
		wg.Add(1)
		go func(i int, in pipeline.ArtifactInput) {
			defer wg.Done()
			errs[i] = r.restoreDownloads(context.Background(), downloadTask(), []pipeline.ArtifactInput{in}, workspace)
		}(i, in)
	}

	// Wait until at least one restore has actually reached its spool phase
	// (the server observed the first body read) and the ledger is charged.
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("no dependency restore reached the staging phase")
	}
	budget, berr := r.dependencyStaging()
	if berr != nil {
		close(release)
		wg.Wait()
		t.Fatal(berr)
	}
	// Wait for the admitted restore to charge its reservation.
	acquireDeadline := time.Now().Add(10 * time.Second)
	for budget.Used() != reserve {
		if time.Now().After(acquireDeadline) {
			close(release)
			wg.Wait()
			t.Fatalf("staging ledger = %d while one spool is blocked mid-stream, want exactly %d", budget.Used(), reserve)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The one admitted spool holds its reservation while it streams; the
	// other three are blocked in Acquire. Give the budget waiters a window to
	// (incorrectly) admit themselves before the final assertions.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if used := budget.Used(); used > budget.MaxBytes() {
			close(release)
			wg.Wait()
			t.Fatalf("staging ledger = %d bytes, budget is %d", used, budget.MaxBytes())
		}
		if got := stagedBytes(t, budget.Dir()); got > budget.MaxBytes() {
			close(release)
			wg.Wait()
			t.Fatalf("staged bytes on disk = %d, budget is %d", got, budget.MaxBytes())
		}
		// Exactly one reservation fits: no second spool may appear.
		if n := len(spoolFilesIn(t, budget.Dir())); n > 1 {
			close(release)
			wg.Wait()
			t.Fatalf("%d spool files staged concurrently, budget admits one", n)
		}
		time.Sleep(20 * time.Millisecond)
	}

	close(release)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("dependency restores did not finish after the budget was released")
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("restore %d failed: %v", i, err)
		}
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("staging ledger = %d after all restores, want 0", used)
	}
	if left := spoolFilesIn(t, budget.Dir()); len(left) != 0 {
		t.Fatalf("spool files left behind: %v", left)
	}
	for i := range inputs {
		got, rerr := os.ReadFile(filepath.Join(workspace, fmt.Sprintf("deps/%d", i), "app.txt"))
		if rerr != nil || string(got) != "serialized-dependency" {
			t.Fatalf("restore %d content = %q, %v", i, got, rerr)
		}
	}
}

// TestDependencyStagingBudgetDefaultsToOneArtifact proves the conservative
// default: without an explicit bound the runner admits exactly one
// maximum-size spool, and a configured StagingMaxBytes wins.
func TestDependencyStagingBudgetDefaultsToOneArtifact(t *testing.T) {
	prev := dependencyArtifactMaxBytes
	dependencyArtifactMaxBytes = 1 << 20
	t.Cleanup(func() { dependencyArtifactMaxBytes = prev })

	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{})
	budget, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	if budget.MaxBytes() != 1<<20 {
		t.Fatalf("default staging budget = %d, want one maximum artifact %d", budget.MaxBytes(), int64(1<<20))
	}
	if want := filepath.Join(r.Cfg.CacheRoot, runnerStagingInstanceID(r.ID)); budget.Dir() != want {
		t.Fatalf("staging dir = %q, want %q", budget.Dir(), want)
	}

	configured := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingDir: t.TempDir(), StagingMaxBytes: 3 << 20})
	b2, err := configured.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	if b2.MaxBytes() != 3<<20 {
		t.Fatalf("configured staging budget = %d, want 3 MiB", b2.MaxBytes())
	}
}

// chargeDependencyCleanupDebt creates REAL cleanup debt through the public
// staging API: a spool path whose removal fails (a non-empty directory
// carrying the spool prefix under the budget directory) keeps its bytes
// charged until a retry succeeds. No private seam is involved, so the test
// exercises exactly the production accounting.
func chargeDependencyCleanupDebt(t *testing.T, b *staging.Budget, n int64) string {
	t.Helper()
	res, err := b.Acquire(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(b.Dir(), staging.FilePrefix+"debt")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b.CleanupSpool(path, res) {
		t.Fatalf("CleanupSpool(%s) reported success for a non-empty directory; the test cannot create cleanup debt", path)
	}
	if used := b.Used(); used != n {
		t.Fatalf("staging ledger = %d after the failed removal, want %d charged", used, n)
	}
	if pending := b.PendingCleanup(); pending != 1 {
		t.Fatalf("pending cleanup = %d after the failed removal, want 1", pending)
	}
	return path
}

// releaseDependencyCleanupDebt empties the debt path so a retry can remove it.
func releaseDependencyCleanupDebt(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(filepath.Join(path, "keep")); err != nil {
		t.Fatal(err)
	}
}

// metricCounter reads a raw counter for assertions (same-package test helper).
func metricCounter(m *Metrics, name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

// TestDependencyCleanupFailureKeepsBytesCharged pins the fail-closed half of
// the cleanup contract the runner leans on: bytes whose removal failed stay
// charged (Used includes them and Acquire cannot admit against them) until a
// retry actually removes the file.
func TestDependencyCleanupFailureKeepsBytesCharged(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingMaxBytes: 1024})
	b, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	chargeDependencyCleanupDebt(t, b, 1024)
	if used := b.Used(); used != 1024 {
		t.Fatalf("staging ledger = %d, want the full debt charged", used)
	}
	// A one-byte reservation cannot fit below the unreclaimable bytes: the
	// ledger can never advertise capacity that is still physically held.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire under a full-budget debt = %v, want DeadlineExceeded (bytes must stay charged)", err)
	}
}

// TestDependencyCleanupRetryRestoresCapacity pins the recovery half: the
// runner maintenance pass retries the failed removal, counts the still-failing
// attempt, and — once removal succeeds — releases the charged bytes so a
// full-budget restore can proceed again. Without the maintenance pass the
// debt would consume staging capacity for the life of the runner.
func TestDependencyCleanupRetryRestoresCapacity(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingMaxBytes: 1024})
	b, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	path := chargeDependencyCleanupDebt(t, b, 1024)

	// The directory still holds data: the retry fails, the bytes stay
	// charged, and the failure is counted.
	r.maintainStaging(context.Background())
	if b.PendingCleanup() != 1 || b.Used() != 1024 {
		t.Fatalf("failed retry changed the ledger: pending=%d used=%d", b.PendingCleanup(), b.Used())
	}
	if got := metricCounter(r.Metrics, "kiwi_runner_staging_cleanup_failures_total"); got != 1 {
		t.Fatalf("cleanup failure counter = %v, want 1", got)
	}

	// Removal can now succeed: the same maintenance entry point reclaims the
	// spool and restores capacity.
	releaseDependencyCleanupDebt(t, path)
	r.maintainStaging(context.Background())
	if b.PendingCleanup() != 0 || b.Used() != 0 {
		t.Fatalf("successful retry did not drain the debt: pending=%d used=%d", b.PendingCleanup(), b.Used())
	}
	res, err := b.Acquire(context.Background(), 1024)
	if err != nil {
		t.Fatalf("full-budget Acquire after cleanup = %v, want capacity restored", err)
	}
	res.Release()
}

// TestRunnerRetriesDependencyStagingCleanupDebt is the integrated regression:
// a transient removal failure after a restore charges the full staging
// budget, a second restore blocks in Acquire, the runner maintenance pass
// reclaims the debt once removal succeeds, and the blocked restore then
// proceeds to completion.
func TestRunnerRetriesDependencyStagingCleanupDebt(t *testing.T) {
	body := tarGzWithFile(t, "app.txt", "cleanup-retry")
	reserve := int64(len(body))
	// The budget is exactly one artifact; the debt consumes all of it.
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("Content-Type", "application/gzip")
		half := len(body) / 2
		_, _ = w.Write(body[:half])
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		entered <- struct{}{}
		<-release
		_, _ = w.Write(body[half:])
	}))
	defer srv.Close()

	r := testRunnerFor(t, srv, Config{StagingMaxBytes: reserve})
	b, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	debtPath := chargeDependencyCleanupDebt(t, b, reserve)
	workspace := t.TempDir()
	done := make(chan error, 1)
	go func() {
		done <- r.restoreDownloads(context.Background(), downloadTask(), []pipeline.ArtifactInput{{From: "build", Name: "bin", Path: "deps/x"}}, workspace)
	}()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("dependency restore never reached the server")
	}
	// The ledger is exhausted by the debt, so the restore must be parked in
	// Acquire rather than staging a byte.
	select {
	case err := <-done:
		close(release)
		t.Fatalf("restore completed despite full-budget cleanup debt: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// A maintenance pass while the directory is still non-empty keeps the
	// debt and records the failure.
	r.maintainStaging(context.Background())
	if b.PendingCleanup() != 1 {
		close(release)
		t.Fatalf("pending cleanup = %d, want the debt retained", b.PendingCleanup())
	}
	if got := metricCounter(r.Metrics, "kiwi_runner_staging_cleanup_failures_total"); got != 1 {
		close(release)
		t.Fatalf("cleanup failure counter = %v, want 1", got)
	}

	// Removal succeeds: the runner maintenance retry drains the debt and the
	// parked restore acquires the capacity it was waiting for. The ledger may
	// show the restore's own reservation again as soon as the waiter wakes,
	// so the debt check is PendingCleanup (and the drained-budget assertion
	// comes after the restore finishes).
	releaseDependencyCleanupDebt(t, debtPath)
	r.maintainStaging(context.Background())
	if pending := b.PendingCleanup(); pending != 0 {
		close(release)
		t.Fatalf("pending cleanup = %d after the successful retry, want 0", pending)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("parked restore failed after the debt was reclaimed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("parked restore did not proceed after the debt was reclaimed")
	}
	if used := b.Used(); used != 0 {
		t.Fatalf("staging ledger = %d after the restore, want 0", used)
	}
	got, rerr := os.ReadFile(filepath.Join(workspace, "deps/x", "app.txt"))
	if rerr != nil || string(got) != "cleanup-retry" {
		t.Fatalf("restored content = %q, %v", got, rerr)
	}
}

// TestRunClosesStagingOwnership pins the lifecycle hand-off: a fully joined
// Run retires the runner-wide staging ownership (registry entry and
// directory lock), so an in-process restart can construct a budget for the
// same root/instance even with a different bound. Without the close, that
// construction fails with "already owned with a different bound".
func TestRunClosesStagingOwnership(t *testing.T) {
	root := t.TempDir()
	err := runMaintenance(t, Config{GCInterval: time.Hour, PrewarmInterval: time.Hour, StagingDir: root, StagingMaxBytes: 1 << 20}, 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context cancellation", err)
	}
	b, err := staging.NewReplicaBudget(root, runnerStagingInstanceID("runner-1"), 2<<20)
	if err != nil {
		t.Fatalf("staging ownership was not retired by a fully joined Run: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRunRestartReusesStagingWithCleanupDebt pins the retained-ledger
// lifecycle: a shutdown blocked by cleanup debt must keep the budget OPEN
// and registered, so a same-bound restart reuses that exact ledger (instead
// of deadlocking against the retained directory lock with
// ErrStagingDirOwned), maintenance keeps retrying the debt, and a later
// shutdown retires ownership normally once the debt clears.
func TestRunRestartReusesStagingWithCleanupDebt(t *testing.T) {
	root := t.TempDir()
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingDir: root, StagingMaxBytes: 1 << 20})
	b, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	path := chargeDependencyCleanupDebt(t, b, 1<<20)

	// Shutdown cannot retire a ledger whose bytes are still charged.
	r.closeStaging()
	if got := r.currentStaging(); got != b {
		t.Fatal("closeStaging dropped a budget that still holds cleanup debt")
	}

	// A same-bound restart reuses the retained ledger.
	if err := r.configureStaging(); err != nil {
		t.Fatalf("restart with the same bound: %v", err)
	}
	if got := r.currentStaging(); got != b {
		t.Fatal("restart did not reuse the retained staging ledger")
	}

	// The retained ledger is still open AND still full: Acquire waits rather
	// than failing with ErrClosed.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx, 1); errors.Is(err, staging.ErrClosed) {
		t.Fatal("retained staging budget was marked closed")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire on the retained full budget = %v, want DeadlineExceeded", err)
	}

	// Once the debt clears, maintenance reclaims it and the next shutdown
	// retires ownership.
	releaseDependencyCleanupDebt(t, path)
	r.maintainStaging(context.Background())
	if used := b.Used(); used != 0 {
		t.Fatalf("staging ledger = %d after cleanup, want 0", used)
	}
	r.closeStaging()
	if r.currentStaging() != nil {
		t.Fatal("staging ownership was not retired after the debt cleared")
	}
	// The directory is genuinely free: a different bound can now be owned.
	fresh, err := staging.NewReplicaBudget(root, runnerStagingInstanceID(r.ID), 2<<20)
	if err != nil {
		t.Fatalf("directory still locked after retirement: %v", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestFailedStagingCloseDoesNotMarkRetainedBudgetUnusable is the narrower
// regression for the close-state transition itself: a failed hand-off must
// leave a usable OPEN ledger behind (a closed budget would reject Acquire
// with ErrClosed while still holding the directory lock).
func TestFailedStagingCloseDoesNotMarkRetainedBudgetUnusable(t *testing.T) {
	root := t.TempDir()
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingDir: root, StagingMaxBytes: 1 << 20})
	b, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	chargeDependencyCleanupDebt(t, b, 1<<20)

	r.closeStaging()
	if err := r.configureStaging(); err != nil {
		t.Fatalf("reconfigure after a retained hand-off: %v", err)
	}
	if r.currentStaging() != b {
		t.Fatal("reconfigure replaced the retained open ledger")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(ctx, 1); errors.Is(err, staging.ErrClosed) {
		t.Fatal("retained budget is unusable: CloseWithContext was called with debt still charged")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire = %v, want DeadlineExceeded (open ledger, bytes still charged)", err)
	}
}

// TestRestartWithChangedStagingBoundFailsClearlyWhileDebtRemains pins the
// operator-facing error: a logical restart that asks for a different bound
// while the retained ledger still holds debt fails with a clear message
// instead of an opaque ErrStagingDirOwned deadlock.
func TestRestartWithChangedStagingBoundFailsClearlyWhileDebtRemains(t *testing.T) {
	root := t.TempDir()
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingDir: root, StagingMaxBytes: 1 << 20})
	b, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	chargeDependencyCleanupDebt(t, b, 1<<20)

	r.closeStaging()
	r.Cfg.StagingMaxBytes = 2 << 20
	err = r.configureStaging()
	if err == nil {
		t.Fatal("changed-bound restart succeeded while the retained ledger held debt")
	}
	if !strings.Contains(err.Error(), "retained") || !strings.Contains(err.Error(), "same bound") {
		t.Fatalf("changed-bound restart error = %v, want the retained-ownership explanation", err)
	}
	if r.currentStaging() != b {
		t.Fatal("failed reconfigure disturbed the retained ledger")
	}
}

// TestFailedStagingCloseClearsPointerAndReconfigures pins the hand-off
// failure branch: when CloseWithContext cannot release ownership (only
// reachable after a full join, when the release itself fails), the budget is
// finalized/CLOSING — never the OPEN retained ledger a restart may reuse.
// The runner must drop the pointer so the next configureStaging obtains a
// usable ledger (or fails loudly if the directory lock really leaked),
// instead of "reusing" a closed budget whose Acquire returns ErrClosed.
func TestFailedStagingCloseClearsPointerAndReconfigures(t *testing.T) {
	orig := closeStagingBudget
	closeStagingBudget = func(*staging.Budget, context.Context) error {
		return errors.New("test: lock release failed")
	}
	t.Cleanup(func() { closeStagingBudget = orig })

	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingDir: t.TempDir(), StagingMaxBytes: 1 << 20})
	if _, err := r.dependencyStaging(); err != nil {
		t.Fatal(err)
	}
	r.closeStaging()
	if got := r.currentStaging(); got != nil {
		t.Fatalf("failed close left a finalized ledger installed: %v", got)
	}
	// The seam did not actually close the real ledger, so the next configure
	// re-obtains the same open budget from the process registry; the point is
	// that the runner no longer short-circuits on a stale pointer.
	if err := r.configureStaging(); err != nil {
		t.Fatalf("reconfigure after a failed close: %v", err)
	}
	got := r.currentStaging()
	if got == nil {
		t.Fatal("reconfigure left the runner without a staging ledger")
	}
	res, err := got.Acquire(context.Background(), 1)
	if err != nil {
		t.Fatalf("reconfigured ledger is unusable: %v", err)
	}
	res.Release()
}
