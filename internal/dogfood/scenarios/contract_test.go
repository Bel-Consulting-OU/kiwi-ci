package scenarios

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryRegistryScenarioHasATest pins the dogfood matrix contract: every
// closed-registry scenario ID is exercised by at least one test that calls
// Lookup(Scenario…). Deleting a scenario's test without removing the
// registry row (or vice versa) is a deliberate, reviewable act — not a
// silent drift that leaves the matrix claiming proofs that no longer run.
func TestEveryRegistryScenarioHasATest(t *testing.T) {
	root := repoRoot(t)
	pkg := filepath.Join(root, "internal", "dogfood", "scenarios")

	// Map ScenarioFoo -> "DF-…" from registry.go.
	regSrc := readGoSources(t, pkg)
	// Only the non-test sources define the constants.
	constRe := regexp.MustCompile(`(Scenario[A-Za-z0-9]+)\s+ScenarioID\s*=\s*"([^"]+)"`)
	idByConst := map[string]string{}
	for _, m := range constRe.FindAllStringSubmatch(regSrc, -1) {
		idByConst[m[1]] = m[2]
	}
	if len(idByConst) != len(Registry) {
		t.Fatalf("registry constants (%d) disagree with Registry slice (%d)", len(idByConst), len(Registry))
	}

	// Which Scenario constants do the TESTS actually Lookup?
	testSrc := readTestSources(t, pkg)
	lookupRe := regexp.MustCompile(`Lookup\((Scenario[A-Za-z0-9]+)\)`)
	lookedUp := map[string]bool{}
	for _, m := range lookupRe.FindAllStringSubmatch(testSrc, -1) {
		lookedUp[m[1]] = true
	}

	for _, e := range Registry {
		found := false
		for cname, id := range idByConst {
			if id == string(e.ID) && lookedUp[cname] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("scenario %s (%s) has no test calling Lookup(<its constant>)", e.ID, e.Name)
		}
	}
}

// TestMakefileRequiresOnlyExistingTests: every --require name in the
// Makefile dogfood targets must correspond to a real top-level test
// function under internal/dogfood or internal/provenance. This is the
// counterweight to dogfood-run.sh: the suite contract cannot name a test
// that does not exist, and dogfood-run.sh cannot stay green if a named test
// fails to execute.
func TestMakefileRequiresOnlyExistingTests(t *testing.T) {
	root := repoRoot(t)
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	re := regexp.MustCompile(`--require\s+(Test[A-Za-z0-9_]+)`)
	reqs := re.FindAllStringSubmatch(string(mk), -1)
	if len(reqs) == 0 {
		t.Fatal("Makefile declares no --require contracts for dogfood suites")
	}
	all := readTestSources(t, filepath.Join(root, "internal", "dogfood"))
	all += readTestSources(t, filepath.Join(root, "internal", "provenance"))
	// Also accept helpers defined in non-test files (none today).
	all += readGoSources(t, filepath.Join(root, "internal", "dogfood"))
	all += readGoSources(t, filepath.Join(root, "internal", "provenance"))
	fn := regexp.MustCompile(`func\s+(Test[A-Za-z0-9_]+)\s*\(`)
	have := map[string]bool{}
	for _, m := range fn.FindAllStringSubmatch(all, -1) {
		have[m[1]] = true
	}
	seen := map[string]bool{}
	for _, m := range reqs {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		// dogfood-run.sh treats --require TestDFEVID001 as satisfied by
		// TestDFEVID001GenerationAndVerify (prefix match). Mirror that here.
		found := false
		for fn := range have {
			if fn == name || strings.HasPrefix(fn, name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Makefile --require %s has no matching func %s* in internal/dogfood or internal/provenance", name, name)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// scenarios -> dogfood -> internal -> root
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

func readGoSources(t *testing.T, dir string) string {
	t.Helper()
	return walkGo(t, dir, "nontest")
}

func readTestSources(t *testing.T, dir string) string {
	t.Helper()
	return walkGo(t, dir, "test")
}

func walkGo(t *testing.T, dir, mode string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		isTest := strings.HasSuffix(path, "_test.go")
		if mode == "test" && !isTest {
			return nil
		}
		if mode == "nontest" && isTest {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b.Write(data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return b.String()
}
