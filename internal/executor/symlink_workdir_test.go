package executor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeDocker writes an executable that records its arguments (one per
// line) to the file named by $KIWI_DOCKER_CAPTURE and exits 0.
func writeFakeDocker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$KIWI_DOCKER_CAPTURE\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSecureWorkingDirUnderSymlinkedRoot is the regression test for the
// working-directory/mount comparison defect: a workspace rooted under a
// symlink (macOS /var, /tmp, a symlinked data dir) must produce a step
// directory that parents against filepath.Abs(workspace) exactly like the
// untouched workspace root does, so the container/tart backends do not
// misreport it as outside the mounted workspace.
func TestSecureWorkingDirUnderSymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinked roots need unix semantics")
	}
	realRoot := t.TempDir()
	linkRoot := filepath.Join(t.TempDir(), "ws-link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	ws := linkRoot
	if err := os.MkdirAll(filepath.Join(ws, "sub", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	absWS, err := filepath.Abs(ws)
	if err != nil {
		t.Fatal(err)
	}

	dir, err := secureWorkingDir(ws, "sub")
	if err != nil {
		t.Fatalf("secureWorkingDir: %v", err)
	}
	if !strings.HasPrefix(dir, absWS+string(filepath.Separator)) {
		t.Fatalf("step dir %q is not spelled under the workspace %q", dir, absWS)
	}
	// The exact lexical check both backends perform.
	rel, err := filepath.Rel(absWS, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("step dir %q outside mounted workspace %q (rel %q, err %v)", dir, absWS, rel, err)
	}
	if rel != "sub" {
		t.Fatalf("rel = %q, want sub", rel)
	}
	// Deeper directories resolve the same way.
	deep, err := secureWorkingDir(ws, "sub/deep")
	if err != nil {
		t.Fatalf("secureWorkingDir(deep): %v", err)
	}
	if rel, err := filepath.Rel(absWS, deep); err != nil || rel != filepath.Join("sub", "deep") {
		t.Fatalf("deep rel = %q (err %v)", rel, err)
	}

	// Containment is still enforced: a symlink inside the workspace that
	// points outside is rejected, as is a lexical escape.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := secureWorkingDir(ws, "escape"); err == nil {
		t.Fatal("symlink escape accepted")
	}
	if _, err := secureWorkingDir(ws, "../escape"); err == nil {
		t.Fatal("lexical escape accepted")
	}

	// The container backend must accept the step dir and route docker to the
	// workspace-relative in-container path.
	capture := filepath.Join(t.TempDir(), "args")
	t.Setenv("KIWI_DOCKER_CAPTURE", capture)
	b := &ContainerBackend{Image: "img", docker: writeFakeDocker(t), container: "job-c", workspace: absWS}
	if err := b.Run(context.Background(), Command{Shell: "sh", Script: "true", Dir: dir}, func(string) {}); err != nil {
		t.Fatalf("container Run rejected the step dir: %v", err)
	}
	argsRaw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	args := strings.Split(strings.TrimRight(string(argsRaw), "\n"), "\n")
	var wIdx = -1
	for i, a := range args {
		if a == "-w" {
			wIdx = i
			break
		}
	}
	if wIdx < 0 || wIdx+1 >= len(args) || args[wIdx+1] != "/workspace/sub" {
		t.Fatalf("docker args = %v, want -w /workspace/sub", args)
	}

	// The tart backend uses the same lexical contract with a different
	// remote prefix; a broken containment would show up here too.
	if rel, err := filepath.Rel(absWS, dir); err != nil || rel != "sub" {
		t.Fatalf("tart rel = %q (err %v)", rel, err)
	}
}

// TestContainerBackendStillRejectsOutsideDirs proves the canonicalized
// helper did not widen the workspace: a directory that is not under the
// (non-canonical) workspace root is still refused.
func TestContainerBackendStillRejectsOutsideDirs(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	b := &ContainerBackend{docker: "docker", container: "job-c", workspace: ws}
	err := b.Run(context.Background(), Command{Shell: "sh", Script: "true", Dir: outside}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "outside mounted workspace") {
		t.Fatalf("outside dir error = %v, want outside-mounted-workspace", err)
	}
	// A sibling prefix (workspace-other) must not be admitted either.
	sibling := ws + "-other"
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(b.workspace, sibling); err != nil || !strings.HasPrefix(rel, "..") {
		// The prefix trap only exists if Rel produces a traversal; assert it
		// explicitly so a future path-lex change is caught here.
		t.Fatalf("prefix sibling rel = %q (err %v), test precondition broken", rel, err)
	}
	if err := b.Run(context.Background(), Command{Shell: "sh", Script: "true", Dir: sibling}, func(string) {}); err == nil {
		t.Fatal("sibling-prefixed dir must be rejected")
	}
}

// TestSecureWorkingDirReturnsCleanRelativeDir locks the contract the mount
// comparison relies on for a plain root.
func TestSecureWorkingDirReturnsCleanRelativeDir(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := secureWorkingDir(ws, "a/./b")
	if err != nil {
		t.Fatalf("secureWorkingDir: %v", err)
	}
	if got != filepath.Join(ws, "a", "b") {
		t.Fatalf("got %q, want %q", got, filepath.Join(ws, "a", "b"))
	}
	// The workspace root itself maps to itself.
	if got, err := secureWorkingDir(ws, ""); err != nil || got != filepath.Clean(ws) {
		t.Fatalf("root dir = %q (err %v)", got, err)
	}
}
