package workspace

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestWorkspaceRootIsDockerShared: K3 — the root must NOT live under TMPDIR
// (which Docker Desktop does not share on macOS).
func TestWorkspaceRootIsDockerShared(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !strings.HasPrefix(m.Root, filepath.Join(home, ".kiwi")) {
		t.Fatalf("workspace root %q not under HOME/.kiwi (Docker-shared)", m.Root)
	}
}
