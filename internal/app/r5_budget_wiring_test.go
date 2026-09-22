package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestAppBuiltStagingBudgetInstalledWithoutSecondConstruction pins the R5-C
// app wiring: the budget built from staging.dir/staging.max_bytes is handed to
// the persistent constructor through WithStagingBudget, so the process owns
// exactly one staging directory. The second case is the regression: the
// configured budget resolves to the SAME data-dir default directory but a
// different max, and construction must still succeed because the constructor
// uses the supplied budget instead of building its own default.
func TestAppBuiltStagingBudgetInstalledWithoutSecondConstruction(t *testing.T) {
	dir := t.TempDir()
	budget, _, err := buildStagingBudget(config.StagingConfig{
		Dir: filepath.Join(dir, "configured-root"), InstanceID: "replica-a", MaxBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("buildStagingBudget: %v", err)
	}
	t.Cleanup(func() { _ = budget.Close() })

	srv, err := server.NewPersistent("tok", "tok", dir, server.WithStagingBudget(budget))
	if err != nil {
		t.Fatalf("persistent construction with the configured budget failed: %v", err)
	}
	if srv.Staging != budget {
		t.Fatalf("server staging = %v, want the configured budget %v", srv.Staging, budget)
	}
	if srv.CAS == nil || srv.CAS.Staging != budget {
		t.Fatalf("server CAS did not receive the configured budget: %v", srv.CAS)
	}
	if _, err := os.Stat(filepath.Join(dir, "kiwi-staging")); !os.IsNotExist(err) {
		t.Fatalf("constructor locked a second data-dir staging directory: stat err = %v", err)
	}

	// Regression case: same data-dir default directory, non-default max.
	collideDir := t.TempDir()
	collide, _, err := buildStagingBudget(config.StagingConfig{
		Dir: filepath.Join(collideDir, "kiwi-staging"), MaxBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("colliding buildStagingBudget: %v", err)
	}
	t.Cleanup(func() { _ = collide.Close() })
	srv2, err := server.NewPersistent("tok", "tok", collideDir, server.WithStagingBudget(collide))
	if err != nil {
		t.Fatalf("persistent construction over the owned default directory failed: %v", err)
	}
	if srv2.Staging != collide {
		t.Fatalf("server staging = %v, want the supplied %v", srv2.Staging, collide)
	}
}
