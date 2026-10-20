package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// TestK12CheckoutRefusesEmptyClonedTree: a git clone that reports success
// but leaves the worktree empty (files=0) must fail closed before the job
// runs — that is the dispatched-run "empty workspace" failure mode.
func TestK12CheckoutRefusesEmptyClonedTree(t *testing.T) {
	testutil.UnixShell(t)
	bin := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "clone" ]; then
  dest=
  for a in "$@"; do dest="$a"; done
  mkdir -p "$dest"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("KIWI_GIT_ALLOWED_HTTPS_HOSTS", "example.com")
	r := &Runner{ID: "r", Cfg: Config{}}
	err := r.checkout(context.Background(), model.Job{ID: "j", RepoURL: "https://example.com/acme/app.git", Ref: "main"}, filepath.Join(t.TempDir(), "clone"), pipeline.Clone{}, pipeline.Workspace{})
	if err == nil || !strings.Contains(err.Error(), "empty workspace") {
		t.Fatalf("checkout(empty tree) = %v, want empty-workspace refusal", err)
	}
}
