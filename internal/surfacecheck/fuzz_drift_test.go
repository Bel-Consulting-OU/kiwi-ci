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

// fuzzTargetsBlock extracts the explicit TARGETS="..." list that
// scripts/fuzz-smoke.sh iterates. A missing or malformed block is a guard
// failure, never a silent pass.
var fuzzTargetsBlock = regexp.MustCompile(`(?s)TARGETS="([^"]*)"`)

// TestFuzzTargetsMatchSmokeScript is the fuzz-drift guard: every
// `func FuzzXxx(f *testing.F)` under internal/ must appear in the smoke
// script's TARGETS list, and every script entry must still exist. The script
// stays explicit (readable, runnable target-by-target); drift between code
// and script fails here with both directions listed.
func TestFuzzTargetsMatchSmokeScript(t *testing.T) {
	root := repoRoot(t)
	declared := map[string]bool{}
	walkDir(t, filepath.Join(root, "internal"), func(rel string, d fs.DirEntry) {
		if !strings.HasSuffix(rel, "_test.go") {
			return
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, "internal", rel), nil, 0)
		if err != nil {
			t.Fatalf("surfacecheck: parse %s: %v", rel, err)
		}
		pkg := path.Join("internal", path.Dir(rel))
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !strings.HasPrefix(fd.Name.Name, "Fuzz") {
				continue
			}
			if !isFuzzSignature(fd.Type.Params) {
				continue
			}
			declared[pkg+":"+fd.Name.Name] = true
		}
	})

	scriptRel := "scripts/fuzz-smoke.sh"
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(scriptRel)))
	if err != nil {
		t.Fatalf("surfacecheck: read %s: %v", scriptRel, err)
	}
	m := fuzzTargetsBlock.FindSubmatch(data)
	if m == nil {
		t.Fatalf("surfacecheck: %s has no TARGETS=\"...\" list; the fuzz-drift guard cannot verify anything (fail closed)", scriptRel)
	}
	inScript := map[string]bool{}
	for _, entry := range strings.Fields(string(m[1])) {
		if !strings.Contains(entry, ":") {
			t.Fatalf("surfacecheck: %s lists malformed fuzz target %q (want package:Target)", scriptRel, entry)
		}
		inScript[entry] = true
	}

	var missing, stale []string
	for target := range declared {
		if !inScript[target] {
			missing = append(missing, target)
		}
	}
	for target := range inScript {
		if !declared[target] {
			stale = append(stale, target)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("fuzz target drift between internal/**/*_test.go and %s:\n  declared but NOT run by the smoke script (%d):\n    %s\n  listed in the script but no longer declared (%d):\n    %s\nKeep the script's TARGETS list explicit and in sync with the Fuzz* functions.",
			scriptRel, len(missing), strings.Join(missing, "\n    "), len(stale), strings.Join(stale, "\n    "))
	}
	if len(declared) == 0 {
		t.Fatal("surfacecheck: found no fuzz targets under internal/; the guard would pass vacuously")
	}
}

// isFuzzSignature reports whether a function's parameter list is exactly one
// `*testing.F`, the Go fuzzing entry-point signature.
func isFuzzSignature(params *ast.FieldList) bool {
	if params == nil || len(params.List) != 1 {
		return false
	}
	star, ok := params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "testing" && sel.Sel.Name == "F"
}
