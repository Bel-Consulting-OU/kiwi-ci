package cache

// Crash-reclaim tests for workspace-scoped staging siblings: a SIGKILL
// between publication renames cannot run Go rollback, so the runner's ledger
// reconcile calls RemoveStaleStagesForWorkspace after removing the crashed
// workspace. Only entries carrying EXACTLY that workspace's scoped prefix
// are eligible, and only when they are real directories owned by the
// current user.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveStaleStagesForWorkspaceScopesToWorkspace(t *testing.T) {
	parent := t.TempDir()
	ws := filepath.Join(parent, "kiwi-run-abc123")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	prefix := StagePrefixForWorkspace(ws)

	mine1 := filepath.Join(parent, prefix+"one")
	mine2 := filepath.Join(parent, prefix+"two")
	other := filepath.Join(parent, StagePrefixForWorkspace(filepath.Join(parent, "kiwi-run-other"))+"x")
	generic := filepath.Join(parent, cacheStagePrefix+"unscoped")
	for _, d := range []string{mine1, mine2, other, generic} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A regular file and a symlink carrying the exact prefix must survive:
	// only real directories are reclaimable.
	file := filepath.Join(parent, prefix+"file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, prefix+"link")
	if err := os.Symlink(mine1, link); err != nil {
		t.Fatal(err)
	}

	removed, err := RemoveStaleStagesForWorkspace(ws)
	if err != nil {
		t.Fatalf("reclaim = %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want the two workspace-scoped directories", removed)
	}
	for _, gone := range []string{mine1, mine2} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s survived reclaim", gone)
		}
	}
	for _, kept := range []string{other, generic, file, link} {
		if _, err := os.Lstat(kept); err != nil {
			t.Fatalf("%s was removed but does not belong to this workspace: %v", kept, err)
		}
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveStaleStagesForWorkspaceMissingParentIsClean(t *testing.T) {
	removed, err := RemoveStaleStagesForWorkspace(filepath.Join(t.TempDir(), "gone", "kiwi-run-x"))
	if err != nil || removed != 0 {
		t.Fatalf("missing parent reclaim = %d, %v; want 0, nil", removed, err)
	}
}

func TestStagePrefixForWorkspaceSanitizes(t *testing.T) {
	prefix := StagePrefixForWorkspace(filepath.Join(t.TempDir(), "kiwi run:weird/../name"))
	if !strings.HasPrefix(prefix, cacheStagePrefix) {
		t.Fatalf("prefix = %q, want the stage prefix", prefix)
	}
	base := strings.TrimSuffix(strings.TrimPrefix(prefix, cacheStagePrefix), "-")
	if base == "" || strings.ContainsAny(base, " /:\\") {
		t.Fatalf("sanitized base = %q", base)
	}
	if len(prefix) > len(cacheStagePrefix)+49 {
		t.Fatalf("prefix too long: %q", prefix)
	}
}
