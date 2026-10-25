package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/workspace"
)

// TestRunLocalLinkedWorktreeRepoIdentity is the item-6 end-to-end oracle:
// for a linked worktree, Freeze strips the .git pointer from the run-base,
// so the old post-Freeze detectGitRepo(baseDir) answered nothing and a job
// ran with EMPTY KIWI_REPO / GITHUB_REPOSITORY. The coordinates must be
// captured from the SOURCE remote at Freeze and flow into the job env.
func TestRunLocalLinkedWorktreeRepoIdentity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	main := t.TempDir()
	runGit(t, main, "init", "-b", "main")
	runGit(t, main, "config", "user.email", "t@example.com")
	runGit(t, main, "config", "user.name", "t")
	writeFile(t, filepath.Join(main, "seed.txt"), "x")
	runGit(t, main, "add", ".")
	runGit(t, main, "commit", "-m", "init")
	runGit(t, main, "remote", "add", "origin", "https://github.com/acme/widgets.git")

	wt := filepath.Join(t.TempDir(), "wt")
	runGit(t, main, "worktree", "add", "--detach", wt, "HEAD")

	out := filepath.Join(t.TempDir(), "repo-env.txt")
	path := writePipeline(t, wt, "version: 1\njobs:\n  build:\n    steps:\n      - name: dump\n        run: printf '%s\\n%s\\n%s\\n' \"$KIWI_REPO\" \"$KIWI_REPO_FULL\" \"$GITHUB_REPOSITORY\" > "+out+"\n")
	chdir(t, wt)
	if err := RunLocal(context.Background(), []string{"-f", path, "--max-parallel", "1"}); err != nil {
		t.Fatalf("RunLocal: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("job did not dump repo env: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("dumped lines = %q", b)
	}
	if lines[0] != "https://github.com/acme/widgets.git" {
		t.Fatalf("KIWI_REPO = %q, want the frozen source remote", lines[0])
	}
	if lines[1] != "acme/widgets" {
		t.Fatalf("KIWI_REPO_FULL = %q, want acme/widgets", lines[1])
	}
	if lines[2] != "acme/widgets" {
		t.Fatalf("GITHUB_REPOSITORY = %q, want acme/widgets", lines[2])
	}
}

// TestFrozenHelpersNeverConsultLiveGit pins the item-6 helper contract:
// frozenSHA/frozenBranch/frozenRef answer ONLY from the frozen struct.
// There is no gitDir parameter anymore — a NotRepo or RepoNoHead capture
// can never pick up a branch/SHA from a live repository (the audited race
// where a first commit landed after Freeze and the run reported identity B
// for tree A).
func TestFrozenHelpersNeverConsultLiveGit(t *testing.T) {
	// A REAL repository exists with a live branch and commits…
	live := t.TempDir()
	runGit(t, live, "init", "-b", "live-branch")
	runGit(t, live, "config", "user.email", "t@example.com")
	runGit(t, live, "config", "user.name", "t")
	writeFile(t, filepath.Join(live, "a.txt"), "x")
	runGit(t, live, "add", ".")
	runGit(t, live, "commit", "-m", "live")

	// …but the frozen capture says repo-no-head. Every helper must honor
	// the freeze, not the live directory that used to sit behind gitDir.
	noHead := workspace.FrozenGit{Repo: true, Branch: "main", Ref: "refs/heads/main"}
	if got := frozenSHA(noHead); got != "" {
		t.Fatalf("frozenSHA(repo-no-head) = %q, want \"\" (live repo must be invisible)", got)
	}
	if got := frozenBranch(noHead); got != "main" {
		t.Fatalf("frozenBranch = %q, want the frozen branch", got)
	}
	if got := frozenRef(noHead); got != "refs/heads/main" {
		t.Fatalf("frozenRef = %q, want the frozen ref", got)
	}
	// NotRepo: empty forever, even though live/ is a repository — the
	// helpers receive no directory to fall back to.
	notRepo := workspace.FrozenGit{}
	if got := frozenSHA(notRepo); got != "" {
		t.Fatalf("frozenSHA(not-repo) = %q, want \"\"", got)
	}
	if got := frozenBranch(notRepo); got != "" {
		t.Fatalf("frozenBranch(not-repo) = %q, want \"\"", got)
	}
	// Captured: answer from the struct.
	captured := workspace.FrozenGit{Captured: true, SHA: "abc123", Branch: "feat", Ref: "refs/heads/feat"}
	if frozenSHA(captured) != "abc123" || frozenBranch(captured) != "feat" || frozenRef(captured) != "refs/heads/feat" {
		t.Fatalf("captured helpers wrong: %q %q %q", frozenSHA(captured), frozenBranch(captured), frozenRef(captured))
	}
}
