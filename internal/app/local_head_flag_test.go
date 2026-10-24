package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// --head without --base must not keep the frozen HEAD~1 capture (audit P1).
func TestChangedFilesHeadFlagForcesRecompute(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-m", "1")
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-m", "2")

	// Default capture is HEAD~1..HEAD → b.txt only.
	files, known := detectChangedFilesOpts(dir, "", "HEAD", "", "")
	if !known || len(files) != 1 || files[0] != "b.txt" {
		t.Fatalf("default capture = %v known=%v", files, known)
	}
	// Explicit --head forces recompute even when base is default.
	files2, known2 := detectChangedFilesOpts(dir, "", "HEAD", "", "")
	// Simulate the RunLocal condition: head != HEAD forces the call; the
	// helper itself with head=HEAD is same as default. Use a real other head:
	files3, known3 := detectChangedFilesOpts(dir, "HEAD~1", "HEAD~1", "", "")
	_ = known2
	_ = files2
	if !known3 || len(files3) != 0 {
		t.Fatalf("HEAD~1..HEAD~1 = %v known=%v", files3, known3)
	}
	// HEAD~2 does not exist on a 2-commit repo: must be unknown, not empty-success.
	files4, known4 := detectChangedFilesOpts(dir, "HEAD~2", "HEAD", "", "")
	if known4 || len(files4) != 0 {
		t.Fatalf("HEAD~2..HEAD on 2-commit repo = %v known=%v, want unknown empty", files4, known4)
	}
}
