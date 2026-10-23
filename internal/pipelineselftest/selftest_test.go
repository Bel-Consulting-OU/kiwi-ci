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
