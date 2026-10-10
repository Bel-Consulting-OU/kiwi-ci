//go:build !windows

package executor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// TestWorkspaceCleanupMarkerArms covers the no-directory and missing-marker
// no-ops plus the refusal once the durable marker exists.
func TestWorkspaceCleanupMarkerArms(t *testing.T) {
	if err := workspaceCleanupRequired(""); err != nil {
		t.Fatalf("empty dir = %v, want nil", err)
	}
	dir := t.TempDir()
	if err := workspaceCleanupRequired(dir); err != nil {
		t.Fatalf("clean dir = %v, want nil", err)
	}
	if err := markWorkspaceNeedsCleanup(""); err == nil {
		t.Fatal("marking an unknown step directory succeeded")
	}
	if err := markWorkspaceNeedsCleanup(dir); err != nil {
		t.Fatal(err)
	}
	if err := workspaceCleanupRequired(dir); err == nil || !strings.Contains(err.Error(), "requires cleanup") {
		t.Fatalf("marked dir = %v, want the refusal", err)
	}
}

// TestRelWithinRootSpellingFallbacks covers the parent-symlink spelling and
// the caller-root spelling fallback, plus the escape predicate edges.
func TestRelWithinRootSpellingFallbacks(t *testing.T) {
	real := t.TempDir()
	linkParent := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, linkParent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root, err := safefs.OpenWorkspaceRoot(real)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	spelled := filepath.Join(linkParent, "out.txt")
	if rel, ok := relWithinRoot(root, real, spelled); !ok || rel != "out.txt" {
		t.Fatalf("symlink-parent spelling = %q/%v", rel, ok)
	}

	// Canonical spelling unrelated to the path but the caller root resolves
	// it: the third (originalRoot) fallback must accept.
	other, err := safefs.OpenWorkspaceRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	callerRoot := t.TempDir()
	path := filepath.Join(callerRoot, "..", filepath.Base(callerRoot), "artifact.bin")
	if rel, ok := relWithinRoot(other, callerRoot, path); !ok || rel != "artifact.bin" {
		t.Fatalf("caller-root fallback = %q/%v", rel, ok)
	}
	if _, ok := relWithinRoot(other, callerRoot, "/etc/passwd"); ok {
		t.Fatal("absolute outside path accepted")
	}

	escapes := map[string]bool{
		"..":          true,
		"../x":        true,
		"/etc/passwd": true,
		"":            false,
		"a":           false,
		"a/b":         false,
	}
	for rel, want := range escapes {
		if got := escapesRoot(rel); got != want {
			t.Errorf("escapesRoot(%q) = %v, want %v", rel, got, want)
		}
	}
}

// TestProvisionWorkspaceTreeFailureArms covers unreadable roots, files as
// roots, and unreadable subtrees, which must all refuse before mutating
// ownership.
func TestProvisionWorkspaceTreeValidationArms(t *testing.T) {
	if _, _, err := lstatOwner(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("lstatOwner on a missing path succeeded")
	}
	if _, err := provisionWorkspaceTree(filepath.Join(t.TempDir(), "missing"), os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("missing workspace resolved")
	}

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionWorkspaceTree(file, os.Getuid(), os.Getgid()); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file workspace = %v, want the not-a-directory refusal", err)
	}

	if os.Geteuid() != 0 {
		root := t.TempDir()
		sub := filepath.Join(root, "sub")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sub, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
		if _, err := provisionWorkspaceTree(root, os.Getuid(), os.Getgid()); err == nil {
			t.Fatal("unreadable subtree accepted")
		}
	}
}

// TestServiceResourceBudgetArms covers the exhausted-plan and post-split
// exhaustion refusals.
func TestServiceResourceBudgetArms(t *testing.T) {
	if _, err := (&serviceResourceBudget{remaining: 0}).allocate(); err == nil {
		t.Fatal("zero remaining accepted")
	}
	if _, err := (&serviceResourceBudget{remaining: 2, CPU: 1, Memory: 1, PIDs: 1}).allocate(); err == nil {
		t.Fatal("unsplittable envelope accepted")
	}
	a, err := (&serviceResourceBudget{remaining: 1, CPU: 2, Memory: 1 << 20, PIDs: 8}).allocate()
	if err != nil || a.PIDs != 8 {
		t.Fatalf("healthy allocate = %+v/%v", a, err)
	}
}

// TestServiceEnvelopeSummaryOversubscribed covers the fail-closed rendering
// when the aggregate cannot be planned.
func TestServiceEnvelopeSummaryOversubscribed(t *testing.T) {
	services := []pipeline.Service{{Name: "a"}, {Name: "b"}}
	summary := serviceEnvelopeSummary(pipeline.Resources{PIDs: 1}, services)
	if !strings.HasPrefix(summary, "oversubscribed: ") {
		t.Fatalf("summary = %q, want the oversubscribed rendering", summary)
	}
	plan, err := serviceAllocationPlan(pipeline.Resources{PIDs: 1}, services)
	if err == nil || plan != nil {
		t.Fatalf("plan = %+v/%v, want the fail-closed error", plan, err)
	}
}

// TestXFSAllocationLockUntrustedFile covers the lock-file trust gate with an
// overridable lock directory.
func TestXFSAllocationLockUntrustedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KIWI_XFS_LOCK_DIR", dir)
	path := filepath.Join(dir, "kiwi-xfs-"+sanitizeXFSLockKey("8:70")+".lock")
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := lockXFSAllocation("8:70"); err == nil || !strings.Contains(err.Error(), "trustworthy") {
		t.Fatalf("writable lock file = %v, want the trust refusal", err)
	}
	if got := sanitizeXFSLockKey(""); got != "unknown" {
		t.Fatalf("sanitizeXFSLockKey(\"\") = %q", got)
	}
	if got := sanitizeXFSLockKey("a/b c"); got != "a_b_c" {
		t.Fatalf("sanitizeXFSLockKey = %q", got)
	}
}

// TestNativeUnreapableWithoutStepDir covers the mark-failure arm: when a
// cancelled command cannot be reaped within the graces and there is no
// recorded step directory, the error names the unmarkable workspace.
func TestNativeUnreapableWithoutStepDir(t *testing.T) {
	origWait, origTerm, origKill, origDrain := nativeWait, nativeTermGrace, killGrace, reapDetached
	nativeTermGrace = 10 * time.Millisecond
	killGrace = 20 * time.Millisecond
	released := make(chan struct{})
	entered := make(chan struct{})
	var enteredOnce sync.Once
	nativeWait = func(*exec.Cmd) error {
		enteredOnce.Do(func() { close(entered) })
		<-released
		return nil
	}
	reapDetached = func(done <-chan error) { go func() { <-done }() }
	t.Cleanup(func() {
		// Run can return before the wait goroutine reaches the seam (child
		// exit races goroutine scheduling), so the seam must observe at
		// least one entry before it is restored: the goroutine reads
		// nativeWait at call time, and nothing after it, so restoring once
		// entry is proven cannot race with that read.
		close(released)
		<-entered
		nativeWait, nativeTermGrace, killGrace, reapDetached = origWait, origTerm, origKill, origDrain
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	err := (&NativeBackend{}).Run(ctx, Command{Shell: "bash", Script: "sleep 30"}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "marking workspace") {
		t.Fatalf("un-reapable command without a step dir = %v", err)
	}
}
