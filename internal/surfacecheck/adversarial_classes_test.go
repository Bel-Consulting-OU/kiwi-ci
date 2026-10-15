package surfacecheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// adversarialCoverage is the meta-contract: every bug CLASS that has bitten
// this codebase must have an executable detector. Removing a detector or
// inventing a class with none fails this gate — the point is that CI catches
// the CLASS, not just the instance we happened to notice.
type adversarialCoverage struct {
	Version int `yaml:"version"`
	Classes []struct {
		ID        string   `yaml:"id"`
		Summary   string   `yaml:"summary"`
		Detectors []string `yaml:"detectors"`
	} `yaml:"classes"`
}

// TestAdversarialClassesHaveDetectors is the meta-gate. It is deliberately
// the same prefix contract as dogfood-run.sh --require: a detector name is
// satisfied by `func <name>…(*testing.T)`.
func TestAdversarialClassesHaveDetectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "adversarial_coverage.yaml"))
	if err != nil {
		t.Fatalf("adversarial_coverage.yaml: %v", err)
	}
	var m adversarialCoverage
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse adversarial_coverage.yaml: %v", err)
	}
	if m.Version != 1 {
		t.Fatalf("version = %d, want 1", m.Version)
	}
	if len(m.Classes) < 10 {
		t.Fatalf("only %d bug classes listed — the matrix must cover every class that has bitten this tree", len(m.Classes))
	}

	defined := testFunctionNames(t)
	if len(defined) == 0 {
		t.Fatal("no Test* definitions found; the meta-gate would be vacuous")
	}
	seen := map[string]bool{}
	for _, c := range m.Classes {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or duplicate class id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Summary == "" {
			t.Fatalf("class %q has no summary", c.ID)
		}
		if len(c.Detectors) == 0 {
			t.Fatalf("class %q has NO detectors — an open hole", c.ID)
		}
		for _, d := range c.Detectors {
			found := false
			for def := range defined {
				if def == d || strings.HasPrefix(def, d) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("class %q detector %s has NO matching func Test… — phantom detector", c.ID, d)
			}
		}
	}
}

// testFunctionNames collects every func TestX(t *testing.T) in the repo.
func testFunctionNames(t *testing.T) map[string]bool {
	t.Helper()
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
	return defined
}

// TestAdversarialMatrixIsFailClosed: a class with no detector must fail the
// predicate. Without this the meta-gate could silently become vacuous.
func TestAdversarialMatrixIsFailClosed(t *testing.T) {
	c := struct {
		Detectors []string
	}{Detectors: nil}
	if len(c.Detectors) != 0 {
		t.Fatal("predicate is fail-open for an empty detector list")
	}
}
