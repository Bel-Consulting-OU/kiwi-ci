package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFrozenGitThreeStates: NotRepo vs Captured vs CaptureFailed (Unstable)
// are distinct. Unstable must never look like "not a repository" — that is
// the state that used to send RunLocal back to live Git after Freeze.
func TestFrozenGitThreeStates(t *testing.T) {
	notRepo := FrozenGit{}
	if notRepo.CaptureFailed() || notRepo.Captured {
		t.Fatalf("not-repo state wrong: %+v", notRepo)
	}
	captured := FrozenGit{Captured: true, SHA: "abc"}
	if captured.CaptureFailed() {
		t.Fatalf("captured must not be CaptureFailed: %+v", captured)
	}
	unstable := FrozenGit{Unstable: true}
	if !unstable.CaptureFailed() {
		t.Fatalf("unstable must be CaptureFailed: %+v", unstable)
	}
	if unstable.Captured {
		t.Fatal("unstable must not claim Captured")
	}
}

// TestFreezeFailsClosedOnUnstableGitCapture: when the Git identity capture
// reports Unstable (HEAD moved mid-read), Freeze must refuse — never return
// a run-base that would make RunLocal fall back to live Git.
func TestFreezeFailsClosedOnUnstableGitCapture(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Make it look like a repo so a real capture would not short-circuit;
	// the seam forces Unstable regardless.
	orig := captureFrozenGit
	captureFrozenGit = func(string, RefQuery) FrozenGit { return FrozenGit{Unstable: true} }
	t.Cleanup(func() { captureFrozenGit = orig })

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	err = m.Freeze(t.Context())
	if err == nil {
		t.Fatal("Freeze must fail when Git capture is unstable")
	}
	if !strings.Contains(err.Error(), "Git identity") {
		t.Fatalf("error = %v, want Git identity capture failure", err)
	}
	if m.BasePath() != "" {
		t.Fatalf("failed Freeze must not publish a run-base (base=%q)", m.BasePath())
	}
}
