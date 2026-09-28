package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
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
