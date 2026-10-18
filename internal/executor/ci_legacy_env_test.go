package executor

import (
	"context"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestLegacyCIEnvNames pins the migration aliases: imported scripts use
// CI_COMMIT_* / CI_WORKSPACE, which must track the KIWI_GIT_* values.
func TestLegacyCIEnvNames(t *testing.T) {
	script := `          [ "$CI" = "true" ] || { echo "CI=$CI"; exit 1; }
          [ "$CI_COMMIT_SHA" = "abc123" ] || { echo "CI_COMMIT_SHA=$CI_COMMIT_SHA"; exit 1; }
          [ "$CI_COMMIT_REF" = "refs/heads/main" ] || { echo "CI_COMMIT_REF=$CI_COMMIT_REF"; exit 1; }
          [ "$CI_COMMIT_BRANCH" = "main" ] || { echo "CI_COMMIT_BRANCH=$CI_COMMIT_BRANCH"; exit 1; }
          [ "$CI_WORKSPACE" = "$KIWI_WORKSPACE" ] || { echo "CI_WORKSPACE=$CI_WORKSPACE KIWI_WORKSPACE=$KIWI_WORKSPACE"; exit 1; }
          [ "$CI_REPO" = "acme/widget" ] || { echo "CI_REPO=$CI_REPO"; exit 1; }
          [ "$CI_REPO_NAME" = "acme/widget" ] || { echo "CI_REPO_NAME=$CI_REPO_NAME"; exit 1; }
`
	g := envProbeSpec(nativeScript(script, `          if ($env:CI -ne "true") { "CI missing"; exit 1 }
          if ($env:CI_COMMIT_SHA -ne "abc123") { "CI_COMMIT_SHA wrong"; exit 1 }
`))
	ex := Executor{Opt: Options{
		Workspace:    t.TempDir(),
		GitSHA:       "abc123",
		GitRef:       "refs/heads/main",
		Branch:       "main",
		RepoFullName: "acme/widget",
		RepoURL:      "https://github.com/acme/widget.git",
		Untrusted:    false,
	}}
	res, err := ex.Run(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if r := res["probe"]; r.Status != model.StatusSuccess {
		t.Fatalf("job failed: %v", r.Error)
	}
	_ = pipeline.Spec{}
}
