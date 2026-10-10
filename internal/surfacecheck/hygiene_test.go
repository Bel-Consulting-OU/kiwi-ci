package surfacecheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// skipAllowlist names helper-process entry-point subtests whose
// t.Skip/t.Skipf is a re-execution sentinel rather than a precondition. Such
// files are exempt from the "skip must sit inside an if" rule, because the
// skip IS the control flow: the parent re-execs the same test binary, and
// the helper must no-op during a normal package run. Every other skip in
// internal/ and cmd/ must be inside an if (environment/precondition).
//
// The three entries are genuine entry points: each is re-executed via
// os.Executable with an environment variable and returns immediately without
// it.
var skipAllowlist = map[string]string{
	"internal/cache/namespace_lock_test.go":          "helper-process entry point: re-executed as a real second process (KIWI_CACHE_LOCK_HELPER) to hold the namespace flock",
	"internal/cache/crash_publish_test.go":           "helper-process entry point: re-executed to SIGKILL itself in the publish rename seam (KIWI_TEST_CACHE_CRASH_AFTER)",
	"internal/runner/runtime_ledger_process_test.go": "process-boundary entry point: builds and runs real kiwi binaries, skipped under -short",
}

// stubWordRe matches the deliberate stub marker STUB as a standalone word in
// a non-test comment. TODO(stub) is matched literally because the closing
// parenthesis is not a word character.
var stubWordRe = regexp.MustCompile(`\bSTUB\b`)

// TestSkippedTestsArePreconditionGuarded walks every test file under
// internal/ and cmd/ and fails on a t.Skip/t.Skipf call that is not inside
// an if statement, unless the file is a documented helper-process entry
// point in skipAllowlist. This makes "tests that never run" a build failure:
// a stub test cannot silently skip itself out of the suite.
func TestSkippedTestsArePreconditionGuarded(t *testing.T) {
	root := repoRoot(t)
	var unguarded []string
	totalSkips := 0
	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		walkDir(t, base, func(rel string, d fs.DirEntry) {
			if !strings.HasSuffix(rel, "_test.go") {
				return
			}
			repoRel := top + "/" + rel
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(repoRel)), nil, 0)
			if err != nil {
				t.Errorf("surfacecheck: parse %s: %v", repoRel, err)
				return
			}
			totalSkips += countSkipCalls(file)
			for _, pos := range skipsOutsideIf(fset, file) {
				if _, ok := skipAllowlist[repoRel]; ok {
					continue
				}
				p := fset.Position(pos)
				loc, _ := filepath.Rel(root, p.Filename)
				unguarded = append(unguarded, fmt.Sprintf("%s:%d", filepath.ToSlash(loc), p.Line))
			}
		})
	}
	if totalSkips == 0 {
		t.Fatal("skip hygiene: found no t.Skip/t.Skipf calls in internal/ and cmd/; the detector would pass vacuously")
	}
	sort.Strings(unguarded)
	if len(unguarded) > 0 {
		t.Fatalf("skip hygiene: %d t.Skip/t.Skipf call(s) outside an if statement (only precondition/environment skips are allowed):\n  %s\nGuard the skip with an explicit if, or add the file to skipAllowlist with a reason if it is a genuine helper-process entry point.",
			len(unguarded), strings.Join(unguarded, "\n  "))
	}
	for rel, reason := range skipAllowlist {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("skipAllowlist[%q] has an empty reason; exemptions must be justified", rel)
		}
		if !strings.HasSuffix(rel, "_test.go") {
			t.Errorf("skipAllowlist[%q] is not a test file", rel)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("skipAllowlist[%q] is stale: %v", rel, err)
			continue
		}
		if !strings.Contains(string(data), ".Skip") {
			t.Errorf("skipAllowlist[%q] is stale: the file contains no t.Skip", rel)
		}
	}
}

// skipsOutsideIf returns the positions of method calls named Skip or Skipf
// on an identifier receiver (the testing.TB shape) that have no enclosing
// if statement. The AST walk tracks ancestry explicitly: every accepted
// call either sits in an if body/init/condition (including inside a closure
// declared there) or is rejected.
func skipsOutsideIf(fset *token.FileSet, file *ast.File) []token.Pos {
	var out []token.Pos
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Skip" && sel.Sel.Name != "Skipf") {
			return true
		}
		if _, ok := sel.X.(*ast.Ident); !ok {
			return true
		}
		for _, ancestor := range stack[:len(stack)-1] {
			if _, ok := ancestor.(*ast.IfStmt); ok {
				return true
			}
		}
		out = append(out, call.Pos())
		return true
	})
	return out
}

// countSkipCalls counts t.Skip/t.Skipf-shaped calls in a file, regardless of
// nesting; the guard fails when it is zero because an empty scan would pass
// vacuously.
func countSkipCalls(file *ast.File) int {
	n := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if _, ok := sel.X.(*ast.Ident); ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf") {
			n++
		}
		return true
	})
	return n
}

// TestSkipsOutsideIfMechanism proves the detector itself: an if-guarded
// skip (including inside a closure within the if) is accepted, a bare skip
// is reported at its exact line, and all three calls are counted.
func TestSkipsOutsideIfMechanism(t *testing.T) {
	const src = `package p

import "testing"

func TestA(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	t.Skipf("always %d", 1)
	f := func() {
		if true {
			t.Skip("inner")
		}
	}
	_ = f
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p_test.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := skipsOutsideIf(fset, file)
	if len(got) != 1 {
		t.Fatalf("skipsOutsideIf = %d unguarded call(s), want exactly the bare t.Skipf", len(got))
	}
	if line := fset.Position(got[0]).Line; line != 9 {
		t.Fatalf("unguarded skip reported at line %d, want 9", line)
	}
	if n := countSkipCalls(file); n != 3 {
		t.Fatalf("countSkipCalls = %d, want 3", n)
	}
}

// TestNoStubMarkersInProductionCode fails on placeholder panics and STUB
// markers in non-test Go code under internal/, cmd/ and scripts/: shipping a
// stub is indistinguishable from shipping a bug, so the marker itself is the
// failure. Test files are excluded because fixtures may legitimately model
// such strings.
func TestNoStubMarkersInProductionCode(t *testing.T) {
	root := repoRoot(t)
	var hits []string
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
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok || id.Name != "panic" || len(call.Args) != 1 {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				msg, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				if msg == "unimplemented" || msg == "not implemented" {
					hits = append(hits, fmt.Sprintf("%s: panic(%q)", posOf(fset, call.Pos()), msg))
				}
				return true
			})
			for _, group := range file.Comments {
				for _, comment := range group.List {
					if strings.Contains(comment.Text, "TODO(stub)") || stubWordRe.MatchString(comment.Text) {
						hits = append(hits, fmt.Sprintf("%s: stub marker %q", posOf(fset, comment.Pos()), strings.TrimSpace(comment.Text)))
					}
				}
			}
		})
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		t.Fatalf("stub hygiene: production code carries placeholder panics or stub markers:\n  %s\nImplement the surface or remove the marker; test-only stubs belong behind test files.",
			strings.Join(hits, "\n  "))
	}
}

// posOf formats a token.Pos as file:line (absolute path is fine for failure
// output; the repository root is visible in the surrounding test context).
func posOf(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return fmt.Sprintf("%s:%d", filepath.ToSlash(p.Filename), p.Line)
}
