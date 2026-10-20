package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestK12CheckoutRefusesEmptyRepoURL: a dispatched job with no checkout URL
// must fail closed instead of running against an empty /workspace.
func TestK12CheckoutRefusesEmptyRepoURL(t *testing.T) {
	r := &Runner{Cfg: Config{}}
	err := r.checkout(context.Background(), model.Job{ID: "j1"}, t.TempDir(), pipeline.Clone{}, pipeline.Workspace{})
	if err == nil || !strings.Contains(err.Error(), "no repository URL") {
		t.Fatalf("checkout(empty RepoURL) = %v, want no-repository-URL refusal", err)
	}
}

// TestK12DirIsEmpty: the post-checkout emptiness probe.
func TestK12DirIsEmpty(t *testing.T) {
	empty := t.TempDir()
	got, err := dirIsEmpty(empty)
	if err != nil || !got {
		t.Fatalf("dirIsEmpty(empty) = %v, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(empty, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = dirIsEmpty(empty)
	if err != nil || got {
		t.Fatalf("dirIsEmpty(nonempty) = %v, %v", got, err)
	}
}

// TestK12CheckoutSkipIsExplicit: clone.Skip is the ONLY legal empty workspace,
// and it returns nil without cloning.
func TestK12CheckoutSkipIsExplicit(t *testing.T) {
	r := &Runner{Cfg: Config{}}
	if err := r.checkout(context.Background(), model.Job{ID: "j"}, t.TempDir(), pipeline.Clone{Skip: true}, pipeline.Workspace{}); err != nil {
		t.Fatalf("clone.Skip checkout = %v, want nil", err)
	}
}
