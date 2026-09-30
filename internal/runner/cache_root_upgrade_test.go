package runner

// Upgrade-path regressions for the default cache root move: the default went
// from the user-global cache root (<user cache>/<instance id>) to the
// identity-local one (<identity dir>/cache/<instance id>). The old namespace
// is no longer read, budgeted or pruned after the upgrade, so it must not
// silently become invisible: the runner detects it and warns with the
// explicit reclaim command.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
)

// seedLegacyDefaultCache creates the old default namespace for r with one
// archive file and returns its path.
func seedLegacyDefaultCache(t *testing.T, r *Runner) string {
	t.Helper()
	old := filepath.Join(cache.Default().Root, runnerStagingInstanceID(r.ID))
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "legacy-key.tar.gz"), []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	return old
}

// TestEnrolledRunnerCacheDefaultUpgradeDetectsOldNamespace pins the
// detection: an enrolled runner (identity dir, no explicit CacheRoot) whose
// old user-global namespace still holds content reports that namespace, and
// the new root is a different directory.
func TestEnrolledRunnerCacheDefaultUpgradeDetectsOldNamespace(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	r := &Runner{ID: "runner-legacy", Cfg: Config{IdentityDir: filepath.Join(home, ".kiwi", "runner")}}
	old := seedLegacyDefaultCache(t, r)

	if got := r.cacheRootDir(); got == old {
		t.Fatalf("fixture did not model an upgrade: new cache root %s equals the legacy namespace", got)
	}
	if got := r.legacyDefaultCacheNamespace(); got != old {
		t.Fatalf("legacyDefaultCacheNamespace = %q, want %q", got, old)
	}

	// An explicit CacheRoot is the operator's own layout: no legacy-default
	// detection (and no warning) applies.
	explicit := &Runner{ID: "runner-legacy", Cfg: Config{IdentityDir: filepath.Join(home, ".kiwi", "runner"), CacheRoot: filepath.Join(home, "explicit")}}
	if got := explicit.legacyDefaultCacheNamespace(); got != "" {
		t.Fatalf("explicit CacheRoot still detected a legacy default namespace: %q", got)
	}
}

// TestOldDefaultCacheDoesNotBecomeInvisibleWithoutWarning pins the operator
// notice: configuring the cache manager for an upgraded enrolled runner
// warns with the old path and the reclaim command, and the new manager serves
// the NEW root (the old namespace is not adopted silently).
func TestOldDefaultCacheDoesNotBecomeInvisibleWithoutWarning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	identityDir := filepath.Join(home, ".kiwi", "runner")
	r := &Runner{ID: "runner-legacy", Cfg: Config{IdentityDir: identityDir}}
	old := seedLegacyDefaultCache(t, r)

	var warned []string
	prev := legacyCacheNamespaceWarning
	legacyCacheNamespaceWarning = func(rr *Runner, oldPath, newRoot string) {
		warned = append(warned, oldPath+" -> "+newRoot)
	}
	t.Cleanup(func() { legacyCacheNamespaceWarning = prev })

	if err := r.configureCacheManager(); err != nil {
		t.Fatalf("configureCacheManager: %v", err)
	}
	t.Cleanup(r.closeCacheManager)
	if len(warned) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warned)
	}
	if !strings.Contains(warned[0], old) || !strings.Contains(warned[0], r.cacheRootDir()) {
		t.Fatalf("warning %q must name the old namespace %s and the new root %s", warned[0], old, r.cacheRootDir())
	}
	if r.cacheMgr == nil || r.cacheMgr.Root() != r.cacheRootDir() {
		got := "<nil>"
		if r.cacheMgr != nil {
			got = r.cacheMgr.Root()
		}
		t.Fatalf("manager root = %q, want the identity-local root %s", got, r.cacheRootDir())
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("legacy namespace disappeared without an explicit migration: %v", err)
	}
}
