package surfacecheck

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// scriptInventoryExempt lists files under scripts/ that intentionally have
// no reference from the Makefile, a .woodpecker workflow, or another script,
// with the reason. Every entry needs a non-empty reason. The map is empty:
// every script is wired into the build or carries --selftest.
var scriptInventoryExempt = map[string]string{}

// TestEveryScriptIsReferenced fails with the exact list of scripts/ files
// that no Makefile target, Woodpecker workflow, or sibling script mentions
// (and that carry no --selftest). It is the counterweight to the package
// test-presence guard: no executable file may sit in scripts/ as dead
// weight.
func TestEveryScriptIsReferenced(t *testing.T) {
	root := repoRoot(t)
	scriptsDir := filepath.Join(root, "scripts")

	sources := map[string]string{}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("surfacecheck: read Makefile: %v", err)
	}
	sources["Makefile"] = string(makefile)
	workflows, err := filepath.Glob(filepath.Join(root, ".woodpecker", "*.yml"))
	if err != nil {
		t.Fatalf("surfacecheck: glob .woodpecker/*.yml: %v", err)
	}
	if len(workflows) == 0 {
		t.Fatal("surfacecheck: no .woodpecker/*.yml workflows found; the script inventory guard would pass vacuously")
	}
	for _, wf := range workflows {
		data, err := os.ReadFile(wf)
		if err != nil {
			t.Fatalf("surfacecheck: read %s: %v", wf, err)
		}
		rel, _ := filepath.Rel(root, wf)
		sources[filepath.ToSlash(rel)] = string(data)
	}
	walkDir(t, scriptsDir, func(rel string, d fs.DirEntry) {
		if !d.Type().IsRegular() {
			return
		}
		data, err := os.ReadFile(filepath.Join(scriptsDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("surfacecheck: read scripts/%s: %v", rel, err)
		}
		sources["scripts/"+rel] = string(data)
	})

	var candidates []string
	walkDir(t, scriptsDir, func(rel string, d fs.DirEntry) {
		if !d.Type().IsRegular() {
			return
		}
		if strings.HasSuffix(rel, "_test.go") {
			// *_test.go files are invoked by the test runner itself (and are
			// governed by the package test-presence guard), so they cannot be
			// orphaned build tooling.
			return
		}
		candidates = append(candidates, "scripts/"+rel)
	})
	sort.Strings(candidates)

	var unreferenced []string
	for _, rel := range candidates {
		if strings.Contains(sources[rel], "--selftest") {
			continue
		}
		if scriptReferenced(rel, sources) {
			continue
		}
		if reason, ok := scriptInventoryExempt[rel]; ok && strings.TrimSpace(reason) != "" {
			continue
		}
		unreferenced = append(unreferenced, rel)
	}
	if len(unreferenced) > 0 {
		t.Fatalf("script inventory: %d file(s) under scripts/ are referenced nowhere (Makefile, .woodpecker/*.yml, other scripts) and carry no --selftest:\n  %s\nWire each one into a target/workflow/sibling script, add a --selftest, or add a reason-bearing entry to scriptInventoryExempt in internal/surfacecheck/script_inventory_test.go.",
			len(unreferenced), strings.Join(unreferenced, "\n  "))
	}
	for rel, reason := range scriptInventoryExempt {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("scriptInventoryExempt[%q] has an empty reason; exemptions must be justified", rel)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Errorf("scriptInventoryExempt[%q] is stale: %v", rel, err)
		}
	}
}

// scriptReferenced reports whether any source other than the candidate
// itself textually references it: the repo-relative path (scripts/x.sh), or,
// for top-level files, the bare basename; nested Go files are referenced by
// their directory (go run ./scripts/rfc3339check) so a generic main.go token
// cannot produce a false match.
func scriptReferenced(rel string, sources map[string]string) bool {
	tokens := []string{rel}
	base := path.Base(rel)
	if strings.HasSuffix(rel, ".go") && path.Dir(rel) != "scripts" {
		tokens = append(tokens, path.Dir(rel))
	} else {
		tokens = append(tokens, base)
	}
	for src, content := range sources {
		if src == rel {
			continue
		}
		for _, tok := range tokens {
			if strings.Contains(content, tok) {
				return true
			}
		}
	}
	return false
}
