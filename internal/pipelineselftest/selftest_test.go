package pipelineselftest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/explain"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestSelfTestFixtures loads every fixture under testdata/selftest and
// proves path filters, DAG ordering, toolchains and native services
// validate/compile. A CI migration without pipeline self-tests is how a
// harness deletion loses coverage; these fixtures are the standing guard.
func TestSelfTestFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "selftest")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no selftest fixtures")
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			s, err := pipeline.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			g, err := pipeline.Compile(s)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if len(g.Jobs) == 0 {
				t.Fatal("compiled graph has no jobs")
			}
		})
	}
}

func TestSelfTestPathSelection(t *testing.T) {
	s, err := pipeline.Load(filepath.Join("testdata", "selftest", "path-filter.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	// Site-only change must select site-only, not rust-only.
	site, err := explain.ExplainWhy(s, g, "site-only", explain.ExplainContext{
		Event:        "push",
		Branch:       "main",
		ChangedFiles: []string{"site/content/index.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !site.PathMatched {
		t.Fatalf("site-only path not matched: %+v", site)
	}
	rust, err := explain.ExplainWhy(s, g, "rust-only", explain.ExplainContext{
		Event:        "push",
		Branch:       "main",
		ChangedFiles: []string{"site/content/index.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rust.PathMatched {
		t.Fatalf("rust-only must not match a site change: %+v", rust)
	}
	// Crate change must not select site-only.
	site2, err := explain.ExplainWhy(s, g, "site-only", explain.ExplainContext{
		Event:        "push",
		Branch:       "main",
		ChangedFiles: []string{"rust/crates/api/src/main.rs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if site2.PathMatched {
		t.Fatalf("site-only must not match a rust change: %+v", site2)
	}
	rust2, err := explain.ExplainWhy(s, g, "rust-only", explain.ExplainContext{
		Event:        "push",
		Branch:       "main",
		ChangedFiles: []string{"rust/crates/api/src/main.rs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rust2.PathMatched {
		t.Fatalf("rust-only path not matched: %+v", rust2)
	}
}

func TestSelfTestNeedsOrder(t *testing.T) {
	s, err := pipeline.Load(filepath.Join("testdata", "selftest", "needs-order.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := g.Jobs["c"]
	if !ok {
		t.Fatal("job c missing")
	}
	if len(c.Needs) == 0 {
		t.Fatal("job c has no needs")
	}
	// c needs b (and transitively a is not a direct need unless declared).
	foundB := false
	for _, n := range c.Needs {
		if strings.HasPrefix(n, "b") {
			foundB = true
		}
	}
	if !foundB {
		t.Fatalf("c.Needs = %v, want b", c.Needs)
	}
	b, _ := g.Jobs["b"]
	if len(b.Needs) == 0 || !strings.HasPrefix(b.Needs[0], "a") {
		t.Fatalf("b.Needs = %v, want a", b.Needs)
	}
}

// Empty diff: path-gated jobs must NOT select; unconditional event jobs still do.
func TestSelfTestEmptyDiffSelection(t *testing.T) {
	s, err := pipeline.Load(filepath.Join("testdata", "selftest", "empty-diff.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	ctx := explain.ExplainContext{Event: "pull_request", Branch: "main", ChangedFiles: []string{}}
	for _, id := range []string{"rust-only", "site-only"} {
		w, err := explain.ExplainWhy(s, g, id, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if w.PathMatched {
			t.Fatalf("%s must not path-match an empty diff: %+v", id, w)
		}
	}
	w, err := explain.ExplainWhy(s, g, "always-pr", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !w.EventMatched {
		t.Fatalf("always-pr should event-match: %+v", w)
	}
	if w.PathRule != "" && !w.PathMatched {
		// no path rule on always-pr
	}
}

// Deletion-only: a deleted path still participates in path selection.
func TestSelfTestDeletionOnlySelection(t *testing.T) {
	s, err := pipeline.Load(filepath.Join("testdata", "selftest", "deletion-only.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	deleted := []string{"rust/crates/apex-api/src/lib.rs"}
	w, err := explain.ExplainWhy(s, g, "reacts-to-delete", explain.ExplainContext{
		Event: "pull_request", Branch: "main", ChangedFiles: deleted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !w.PathMatched {
		t.Fatalf("deleted crate path must still select: %+v", w)
	}
	// path_ignore docs/** with empty path docs/** — still not selected without changes
	w2, err := explain.ExplainWhy(s, g, "ignores-elsewhere", explain.ExplainContext{
		Event: "pull_request", Branch: "main", ChangedFiles: []string{"docs/new.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// When both path and path_ignore list docs/**, behavior depends on
	// PathsMatch: ignore should win for docs/new.md.
	if w2.PathMatched {
		t.Fatalf("path_ignore docs/** must suppress docs change: %+v", w2)
	}
}

// Missing declared toolchain: pipeline still COMPILES (declaration is not
// presence); the executor is what fails closed at step 1.
func TestSelfTestMissingToolCompiles(t *testing.T) {
	s, err := pipeline.Load(filepath.Join("testdata", "selftest", "missing-tool.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatalf("missing toolchain binary must still compile: %v", err)
	}
	cj := g.Jobs["uses-missing-tool"]
	if len(cj.Job.BoundToolchains) != 1 {
		t.Fatalf("BoundToolchains = %+v", cj.Job.BoundToolchains)
	}
}

// Failing job graph: dependency gating blocks the child; if:false never runs.
func TestSelfTestFailingJobGates(t *testing.T) {
	s, err := pipeline.Load(filepath.Join("testdata", "selftest", "failing-job.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	child, ok := g.Jobs["never-runs"]
	if !ok || len(child.Needs) == 0 {
		t.Fatalf("never-runs needs = %+v", child)
	}
	if child.Job.If != "success()" {
		t.Fatalf("if = %q", child.Job.If)
	}
	gated := g.Jobs["gated-off"]
	if gated.Job.If != "false" {
		t.Fatalf("gated-off if = %q", gated.Job.If)
	}
}
