//go:build !windows

package cache

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Crash-recovery contract for a process death between cache publication
// renames (publish A, publish B, SIGKILL before C). Normal Go rollback never
// runs on SIGKILL, so the exact residue a later incarnation must understand
// and reclaim is pinned here with a real process:
//
//   - the already-published members are live in the workspace,
//   - the never-published members stay in a .kiwi-cache-stage-* tree that is
//     a SIBLING of the workspace (same filesystem, outside the workspace),
//   - pre-existing workspace content is untouched,
//   - the workspace itself survives so the durable owner of the residue (the
//     runner's runtime-ledger entry naming this path) keeps pointing at a
//     real directory until the runner reclaims it.
//
// Production workspaces carry NO in-directory marker: the ownership record
// is Runner.ledgerAdd's runtimeLedgerEntry.Workspace (internal/runner), and
// Runner.reconcileRuntimeLedger reclaims it before the next lease. The
// cross-package half of this proof lives in
// internal/runner/crash_restore_reuse_test.go.
const (
	cacheCrashAfterEnv = "KIWI_TEST_CACHE_CRASH_AFTER"
	cacheCrashRootEnv  = "KIWI_TEST_CACHE_CRASH_ROOT"
	cacheCrashWSEnv    = "KIWI_TEST_CACHE_CRASH_WS"
	cacheCrashKeyEnv   = "KIWI_TEST_CACHE_CRASH_KEY"
)

// TestCacheCrashHelperProcess is not a test: it is the helper entry point
// that runs a REAL restore in a child process and SIGKILLs itself in the
// rename seam right after the Nth publish rename. The parent
// (TestRestoreMidPublishCrash...) re-execs this test binary with the crash
// environment set.
func TestCacheCrashHelperProcess(t *testing.T) {
	raw := os.Getenv(cacheCrashAfterEnv)
	if raw == "" {
		t.Skip("helper process entry point")
	}
	crashAfter, err := strconv.Atoi(raw)
	if err != nil || crashAfter <= 0 {
		fmt.Fprintf(os.Stderr, "helper: bad %s=%q\n", cacheCrashAfterEnv, raw)
		os.Exit(90)
	}
	root := os.Getenv(cacheCrashRootEnv)
	ws := os.Getenv(cacheCrashWSEnv)
	key := os.Getenv(cacheCrashKeyEnv)
	canonicalWS, err := filepath.EvalSymlinks(ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: resolve workspace %q: %v\n", ws, err)
		os.Exit(91)
	}
	prefix := canonicalWS + string(os.PathSeparator)
	publishes := 0
	// The seam performs the REAL rename first and kills the process after
	// the Nth publish rename returns, so the killed member is already live
	// in the workspace: "exactly the first N published members" is the
	// documented post-crash state.
	renameFn = func(oldpath, newpath string) error {
		if err := os.Rename(oldpath, newpath); err != nil {
			return err
		}
		if newpath == canonicalWS || strings.HasPrefix(newpath, prefix) {
			publishes++
			if publishes == crashAfter {
				// SIGKILL: no deferred function, no rollback, no close.
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		}
		return nil
	}
	s := &Store{Root: root}
	if _, err := s.RestoreContext(context.Background(), key, ws, []string{"."}); err != nil {
		fmt.Fprintf(os.Stderr, "helper: restore returned before the crash seam: %v\n", err)
		os.Exit(92)
	}
	fmt.Fprintln(os.Stderr, "helper: restore completed without reaching the crash seam")
	os.Exit(93)
}

// TestRestoreMidPublishCrashLeavesExactDocumentedState kills a real child
// mid-publish and asserts the exact post-crash state documented above.
func TestRestoreMidPublishCrashLeavesExactDocumentedState(t *testing.T) {
	const crashAfter = 2
	// Production shape: the workspace is a random kiwi-run-* directory whose
	// restore staging tree is a SIBLING (same parent, same filesystem).
	base := t.TempDir()
	ws, err := os.MkdirTemp(base, "kiwi-run-*")
	if err != nil {
		t.Fatal(err)
	}
	canonicalWS, err := filepath.EvalSymlinks(ws)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(canonicalWS)
	cacheRoot := t.TempDir()
	// Pre-existing checkout content must survive the partial restore.
	if err := os.WriteFile(filepath.Join(ws, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	order := []string{"a.txt", "b.txt", "c.txt", "d.txt"}
	entries := make([]cacheTarEntry, 0, len(order))
	for _, name := range order {
		entries = append(entries, cacheTarEntry{name: name, data: []byte(strings.ToUpper(name[:1])), typeflag: tar.TypeReg})
	}
	s := &Store{Root: cacheRoot}
	writeCacheArchive(t, s, "crashkey", cacheTarGz(t, entries))

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestCacheCrashHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		cacheCrashAfterEnv+"="+strconv.Itoa(crashAfter),
		cacheCrashRootEnv+"="+cacheRoot,
		cacheCrashWSEnv+"="+ws,
		cacheCrashKeyEnv+"=crashkey",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var werr error
	select {
	case werr = <-waited:
	case <-time.After(60 * time.Second):
		// The child hung instead of crashing: kill it so the test fails with
		// the real diagnostic instead of a SIGKILL look-alike.
		_ = cmd.Process.Kill()
		<-waited
		t.Fatalf("helper did not reach the crash seam within 60s (stderr: %s)", stderr.String())
	}
	ee, ok := werr.(*exec.ExitError)
	if !ok {
		t.Fatalf("helper exit = %v, want death by SIGKILL (stderr: %s)", werr, stderr.String())
	}
	st, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !st.Signaled() || st.Signal() != syscall.SIGKILL {
		t.Fatalf("helper termination = %v, want SIGKILL (stderr: %s)", ee.Sys(), stderr.String())
	}

	// 1. The staging sibling exists OUTSIDE the workspace and still holds
	// exactly the members that were never published.
	siblings := crashStageSiblings(t, parent)
	if len(siblings) != 1 {
		t.Fatalf("staging siblings after the crash = %v, want exactly one %s* tree", siblings, cacheStagePrefix)
	}
	stage := siblings[0]
	if stage == canonicalWS || strings.HasPrefix(stage, canonicalWS+string(os.PathSeparator)) {
		t.Fatalf("staging tree %s is inside the workspace %s", stage, canonicalWS)
	}
	if got := crashDirNames(t, stage); len(got) != 2 || got[0] != "c.txt" || got[1] != "d.txt" {
		t.Fatalf("staging residue = %v, want exactly [c.txt d.txt] (the never-published members)", got)
	}

	// 2. The workspace contains exactly the first N published members, with
	// intact bytes, and none of the later ones.
	for i, name := range order {
		got, rerr := os.ReadFile(filepath.Join(ws, name))
		want := strings.ToUpper(name[:1])
		if i < crashAfter {
			if rerr != nil || string(got) != want {
				t.Fatalf("published member %s = %q, %v; want %q (a live restored member was lost)", name, got, rerr, want)
			}
			continue
		}
		if !os.IsNotExist(rerr) {
			t.Fatalf("member %s was published although the process died after %d renames (err=%v)", name, crashAfter, rerr)
		}
	}
	if got, rerr := os.ReadFile(filepath.Join(ws, "keep.txt")); rerr != nil || string(got) != "keep" {
		t.Fatalf("pre-existing keep.txt = %q, %v; want it untouched", got, rerr)
	}
	wantWS := []string{"a.txt", "b.txt", "keep.txt"}
	if got := crashDirNames(t, ws); len(got) != len(wantWS) {
		t.Fatalf("workspace entries = %v, want exactly %v", got, wantWS)
	} else {
		for i := range wantWS {
			if got[i] != wantWS[i] {
				t.Fatalf("workspace entries = %v, want exactly %v", got, wantWS)
			}
		}
	}

	// 3. Ownership mark (documented gap): there is no marker file inside a
	// production workspace. The durable "belongs to crashed job/runner" mark
	// is the runner's runtime-ledger entry naming this path; the residue must
	// therefore survive cache-level machinery untouched so that entry keeps
	// naming a real directory. internal/runner proves the ledger marks and
	// reclaims it before the next lease.
	if _, err := os.Lstat(ws); err != nil {
		t.Fatalf("crashed workspace does not survive for ledger reclaim: %v", err)
	}
}

// crashStageSiblings returns the .kiwi-cache-stage-* trees in dir, sorted.
func crashStageSiblings(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), cacheStagePrefix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// crashDirNames returns the sorted entry names directly inside dir.
func crashDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}
