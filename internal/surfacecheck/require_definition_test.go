package surfacecheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryMakeRequireHasDefinition: a release gate that names a test via
// `--require TestFoo` is a phantom guard unless `func TestFoo` exists in the
// tree. `go test -run TestFoo` with no match is a green no-op — the same
// failure mode dogfood-run.sh --require was built to prevent. This gate
// applies that principle to every Makefile --require.
func TestEveryMakeRequireHasDefinition(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	reqRe := regexp.MustCompile(`--require\s+(Test[A-Za-z0-9_]+)`)
	var required []string
	seen := map[string]bool{}
	for _, m := range reqRe.FindAllStringSubmatch(string(raw), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			required = append(required, m[1])
		}
	}
	if len(required) == 0 {
		t.Fatal("Makefile has no --require Test* entries; the release gate would be vacuous")
	}

	// Collect every func TestName definition across the repo.
	defRe := regexp.MustCompile(`func\s+(Test[A-Za-z0-9_]+)\s*\(\s*\w+\s+\*testing\.T\s*\)`)
	defined := map[string]bool{}
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd", "perf"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, m := range defRe.FindAllStringSubmatch(string(b), -1) {
				defined[m[1]] = true
			}
			return nil
		})
	}
	if len(defined) == 0 {
		t.Fatal("no Test* definitions found; the guard would be vacuous")
	}

	for _, name := range required {
		// dogfood-run.sh --require is a PREFIX match (TestDFEVID001 accepts
		// TestDFEVID001Tamper…). A require is satisfied when some func starts
		// with it; a true phantom has no function with that prefix at all.
		found := false
		for def := range defined {
			if def == name || strings.HasPrefix(def, name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Makefile --require %s has NO `func %s…(*testing.T)` in the tree — phantom guard", name, name)
		}
	}
}

// Self-check: a require naming a test that does not exist (even as a prefix)
// must fail. Without this the detector could silently become vacuous.
func TestRequireDefinitionGuardCatchesPhantoms(t *testing.T) {
	defined := map[string]bool{"TestRealThing": true}
	name := "TestPhantomGuard"
	found := false
	for def := range defined {
		if def == name || strings.HasPrefix(def, name) {
			found = true
		}
	}
	if found {
		t.Fatal("guard predicate is fail-open for a phantom name")
	}
}
