// Package surfacecheck is a test-only guard package: it contains no
// production code and no ordinary tests of production code. Every test here
// is an executable, failing-closed definition of "dogfooding covers 100% of
// the repository": package test presence, fuzz-target drift, script
// inventory, the self-hosted pipeline's verification matrix, stub/skip
// hygiene, PostgreSQL integration-lane naming and asset/migration
// accounting. A new surface that does not meet the contract fails
// `go test ./internal/surfacecheck/` immediately.
//
// The guards resolve the repository root from this test file (with a
// working-directory fallback), so they run correctly under `go test` and
// under `-trimpath` builds alike.
package surfacecheck

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/Bel-Consulting-OU/kiwi-ci"

// repoRoot resolves the repository root from this test file, falling back to
// an upward search from the working directory (the package directory under
// `go test`). It fails the test when neither yields a directory containing
// go.mod, so a mis-rooted guard can never pass vacuously.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if ok {
		if root, found := findModuleRoot(filepath.Dir(file)); found {
			return root
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("surfacecheck: getwd: %v", err)
	}
	if root, found := findModuleRoot(wd); found {
		return root
	}
	t.Fatalf("surfacecheck: cannot locate the repository root (no go.mod above %q or %q)", file, wd)
	return ""
}

func findModuleRoot(dir string) (string, bool) {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// walkDir calls fn for every regular file under root with a repo-relative
// slash-separated path. .git, vendor, testdata and dot/underscore
// directories are skipped because Go itself ignores them.
func walkDir(t *testing.T, root string, fn func(rel string, d fs.DirEntry)) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (name == ".git" || name == "vendor" || name == "testdata" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		fn(filepath.ToSlash(rel), d)
		return nil
	})
	if err != nil {
		t.Fatalf("surfacecheck: walk %s: %v", root, err)
	}
}

// testPresenceExempt lists package directories that intentionally carry
// non-test .go files without a *_test.go beside them, with the reason. The
// map is EMPTY on purpose: `internal/executil` and `scripts` gained real
// tests instead of exemptions, and every other package already had them.
var testPresenceExempt = map[string]string{}

// TestEveryGoPackageHasTests fails with the exact list of package
// directories that contain non-test .go files but no *_test.go. Packages are
// discovered under internal/, cmd/ and scripts/ (Go is the only language
// there); testdata trees are not packages and are skipped.
func TestEveryGoPackageHasTests(t *testing.T) {
	root := repoRoot(t)
	type packageFiles struct{ nonTest, tests int }
	pkgs := map[string]*packageFiles{}
	for _, top := range []string{"internal", "cmd", "scripts"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		walkDir(t, base, func(rel string, d fs.DirEntry) {
			if !strings.HasSuffix(rel, ".go") {
				return
			}
			dir := path.Join(top, path.Dir(rel))
			info := pkgs[dir]
			if info == nil {
				info = &packageFiles{}
				pkgs[dir] = info
			}
			if strings.HasSuffix(rel, "_test.go") {
				info.tests++
			} else {
				info.nonTest++
			}
		})
	}
	var uncovered []string
	for dir, info := range pkgs {
		if info.nonTest == 0 || info.tests > 0 {
			continue
		}
		if reason, ok := testPresenceExempt[dir]; ok && strings.TrimSpace(reason) != "" {
			continue
		}
		uncovered = append(uncovered, dir)
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Fatalf("package test presence: %d package dir(s) contain non-test .go files but no *_test.go:\n  %s\nAdd a real test in each directory (or, only for a genuinely untestable package, an entry with a reason in testPresenceExempt in %s).",
			len(uncovered), strings.Join(uncovered, "\n  "), "internal/surfacecheck/surfacecheck_test.go")
	}
	for dir, reason := range testPresenceExempt {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("testPresenceExempt[%q] has an empty reason; exemptions must be justified", dir)
			continue
		}
		info := pkgs[dir]
		if info != nil && info.tests > 0 && info.nonTest > 0 {
			t.Errorf("testPresenceExempt[%q] is stale: the package now has a *_test.go", dir)
		}
	}
}

// TestGuardHelpersExercisePathShape is a small self-check of the helpers
// above: repoRoot must find go.mod and walkDir must produce relative slash
// paths for a known repository file.
func TestGuardHelpersExercisePathShape(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repoRoot did not yield a go.mod directory: %v", err)
	}
	found := false
	walkDir(t, filepath.Join(root, "internal", "surfacecheck"), func(rel string, d fs.DirEntry) {
		if strings.Contains(rel, "\\") {
			t.Errorf("walkDir returned a backslash path: %q", rel)
		}
		if strings.HasSuffix(rel, "_test.go") {
			found = true
		}
	})
	if !found {
		t.Fatal("walkDir found no test files in internal/surfacecheck")
	}
}
