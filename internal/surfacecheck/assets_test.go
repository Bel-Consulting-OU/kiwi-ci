package surfacecheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// embedExempt lists go:embed directives whose directory is intentionally not
// referenced by any test, with the reason. Keyed by repo-relative Go file.
// The map is empty: both embedded assets (migrations SQL, web dashboard
// files) are exercised by tests.
var embedExempt = map[string]string{}

type embedDirective struct {
	file     string // repo-relative producer file
	relDir   string // repo-relative directory of the embed var
	patterns []string
	names    []string
}

// TestEmbeddedAssetsHaveTestReferences scans every go:embed directive in
// non-test Go code and requires at least one test file in the repository to
// textually reference the embed variable, a concrete embedded file, or the
// package directory. Embedded blobs are part of the shipped surface, so an
// asset set with no test is an untested surface.
func TestEmbeddedAssetsHaveTestReferences(t *testing.T) {
	root := repoRoot(t)
	directives := collectEmbedDirectives(t, root)
	if len(directives) == 0 {
		t.Fatal("surfacecheck: no go:embed directives found; the asset guard would pass vacuously")
	}

	var tests strings.Builder
	walkDir(t, root, func(rel string, d fs.DirEntry) {
		if !strings.HasSuffix(rel, "_test.go") {
			return
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("surfacecheck: read %s: %v", rel, err)
		}
		tests.Write(data)
		tests.WriteByte('\n')
	})
	haystack := tests.String()

	var uncovered []string
	for _, d := range directives {
		if hasAnyEmbedReference(haystack, embedTokens(d)) {
			continue
		}
		if reason, ok := embedExempt[d.file]; ok && strings.TrimSpace(reason) != "" {
			continue
		}
		uncovered = append(uncovered, d.file)
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Fatalf("asset accounting: %d go:embed directive(s) have no test reference (name, file or package dir):\n  %s\nAdd a test that reads/verifies the embedded surface, or a reason-bearing entry in embedExempt.",
			len(uncovered), strings.Join(uncovered, "\n  "))
	}
}

func collectEmbedDirectives(t *testing.T, root string) []embedDirective {
	t.Helper()
	var out []embedDirective
	for _, top := range []string{"internal", "cmd", "scripts"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		walkDir(t, base, func(rel string, d fs.DirEntry) {
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
				return
			}
			repoRel := top + "/" + rel
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(repoRel)), nil, parser.ParseComments)
			if err != nil {
				t.Errorf("surfacecheck: parse %s: %v", repoRel, err)
				return
			}
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Doc == nil {
					continue
				}
				var patterns []string
				for _, c := range gd.Doc.List {
					text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
					if strings.HasPrefix(text, "go:embed ") {
						patterns = append(patterns, strings.Fields(strings.TrimPrefix(text, "go:embed "))...)
					}
				}
				if len(patterns) == 0 {
					continue
				}
				var names []string
				for _, spec := range gd.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for _, n := range vs.Names {
							names = append(names, n.Name)
						}
					}
				}
				out = append(out, embedDirective{
					file:     repoRel,
					relDir:   path.Join(top, path.Dir(rel)),
					patterns: patterns,
					names:    names,
				})
			}
		})
	}
	return out
}

// embedTokens returns every text token that counts as a test reference to
// the directive: the Go variable(s), the package dir and import path, and
// each concrete embedded file (patterns with glob metacharacters contribute
// their directory instead).
func embedTokens(d embedDirective) []string {
	tokens := append([]string{}, d.names...)
	if d.relDir != "." {
		tokens = append(tokens, d.relDir, modulePath+"/"+d.relDir)
	}
	glob := regexp.MustCompile(`[*?\[\]{}]`)
	for _, pattern := range d.patterns {
		p := strings.TrimPrefix(pattern, "all:")
		if glob.MatchString(p) {
			if dir := path.Dir(p); dir != "." {
				tokens = append(tokens, path.Join(d.relDir, dir))
			}
			continue
		}
		tokens = append(tokens, p)
		if base := path.Base(p); base != p {
			tokens = append(tokens, base)
		}
	}
	return tokens
}

// hasAnyEmbedReference matches a token on word boundaries so a short
// variable name cannot be satisfied by an unrelated substring.
func hasAnyEmbedReference(haystack string, tokens []string) bool {
	for _, token := range tokens {
		if token == "" {
			continue
		}
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(token) + `\b`)
		if re.MatchString(haystack) {
			return true
		}
	}
	return false
}

// TestEveryMigrationPinnedInDigestsGolden asserts the migration directory and
// internal/storage/migrations/digests.golden are in exact correspondence:
// a new .sql file must be committed together with its digest, and a golden
// entry whose file vanished is stale. The digest test in the package proves
// the recorded digest is correct; this guard proves no file is missing from
// the accounting at all (including files the digest test would never look
// at because All() failed).
func TestEveryMigrationPinnedInDigestsGolden(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "storage", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("surfacecheck: read %s: %v", dir, err)
	}
	goldenData, err := os.ReadFile(filepath.Join(dir, "digests.golden"))
	if err != nil {
		t.Fatalf("surfacecheck: read digests.golden: %v", err)
	}
	golden := map[string]bool{}
	for _, line := range strings.Split(string(goldenData), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 4 {
			t.Fatalf("surfacecheck: digests.golden has a malformed line %q (want `version name digest floor`)", line)
		}
		golden[fields[1]] = true
	}
	var missing, stale []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		if !golden[e.Name()] {
			missing = append(missing, e.Name())
		}
	}
	for name := range golden {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("migration accounting: migration files and digests.golden disagree:\n  .sql files missing from digests.golden (%d):\n    %s\n  golden entries with no .sql file (%d):\n    %s\nRun `go test ./internal/storage/migrations -run TestMigrationDigests -update-migration-digests` and commit digests.golden with the migration.",
			len(missing), strings.Join(missing, "\n    "), len(stale), strings.Join(stale, "\n    "))
	}
}
