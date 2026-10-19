package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJobWorkspaceRootIsDockerShareable: K12 — the runner must NOT create
// workspaces under TMPDIR (/var/folders), which Docker cannot bind-mount
// (dispatched jobs saw files=0 in /workspace).
func TestJobWorkspaceRootIsDockerShareable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TMPDIR", t.TempDir()) // the trap

	r := &Runner{Cfg: Config{}}
	root, err := r.newJobWorkspaceRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(root, filepath.Join(home, ".kiwi", "workspaces")) {
		t.Fatalf("workspace root %q not under HOME/.kiwi/workspaces", root)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("workspace root missing: %v", err)
	}
}

// TestJobWorkspaceRootPrefersWorkDir: an explicit WorkDir wins.
func TestJobWorkspaceRootPrefersWorkDir(t *testing.T) {
	wd := t.TempDir()
	r := &Runner{Cfg: Config{WorkDir: wd}}
	root, err := r.newJobWorkspaceRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(root, wd) {
		t.Fatalf("workspace root %q not under WorkDir %q", root, wd)
	}
}
