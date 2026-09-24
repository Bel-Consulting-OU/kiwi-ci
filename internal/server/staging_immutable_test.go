package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// TestStagingBudgetImmutableAfterConstruction is the R2-3 regression: staging
// is installed at construction time and can NEVER be swapped on a live server.
// The previous exported SetStagingBudget let a live server swap budgets, so
// in-flight requests could keep charging the old budget while new ones charged
// the new one — a temporary double bound over the same disk. The installer is
// now unexported and panics after the construction seal, and the persistent
// constructor honours the construction-time WithStagingBudget budget without
// building (and locking) a second data-dir default.
func TestStagingBudgetImmutableAfterConstruction(t *testing.T) {
	dir := t.TempDir()
	b, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging"), 1<<20)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	s, err := NewPersistent("tok", "tok", dir, WithStagingBudget(b))
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	if s.Staging != b || s.CAS.Staging != b {
		t.Fatalf("construction-time wiring = (server %v, cas %v), want %v", s.Staging, s.CAS.Staging, b)
	}
	// The constructor did not build and lock a second data-dir default: the
	// supplied budget is used verbatim.
	if _, err := os.Stat(filepath.Join(dir, "kiwi-staging")); !os.IsNotExist(err) {
		t.Fatalf("constructor locked a second staging directory: stat err = %v", err)
	}

	b2, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging2"), 1<<20)
	if err != nil {
		t.Fatalf("second staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b2.Close() })

	// A post-construction replacement is impossible: the unexported installer
	// panics once the server is sealed.
	assertInstallStagingPanics(t, s, b2)
	// A bare in-memory New is sealed too.
	assertInstallStagingPanics(t, New("tok"), b2)
	// The panicking install must not have mutated the live server.
	if s.Staging != b || s.CAS.Staging != b {
		t.Fatalf("a failed replacement mutated staging: (server %v, cas %v)", s.Staging, s.CAS.Staging)
	}
}

// assertInstallStagingPanics proves the only way to set a server's staging
// budget is at construction: any post-seal install panics.
func assertInstallStagingPanics(t *testing.T, s *Server, b *staging.Budget) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("post-construction installStagingBudget did not panic: staging is still swappable")
		}
	}()
	s.installStagingBudget(b)
}
