package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDetectGitRepoFromOrigin(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init")
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.txt", "x")
	run("add", "a.txt")
	run("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-m", "c")
	run("remote", "add", "origin", "https://github.com/acme/widget.git")

	url, full := detectGitRepo(dir)
	if url != "https://github.com/acme/widget.git" {
		t.Fatalf("url = %q", url)
	}
	if full != "acme/widget" {
		t.Fatalf("full = %q, want acme/widget", full)
	}
}
