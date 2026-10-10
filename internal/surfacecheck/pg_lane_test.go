package surfacecheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// pgGatedHelpers are the entry points that make a test require a real
// PostgreSQL server: each one either dials KIWI_TEST_POSTGRES_URL or skips
// the test when it is unset. A Test function that reaches one of them
// (directly, or through a same-package helper such as pgITSetup) can only
// run in the PostgreSQL integration lane, which selects tests with -run
// Integration, so its name MUST contain "Integration" or it silently skips
// in BOTH lanes: the unit profile has no DSN and the integration lane never
// matches its name. pgITOpen is part of the contract even though no current
// helper uses that spelling yet.
var pgGatedHelpers = map[string]bool{
	"scratchPostgresDSN": true,
	"pgITStore":          true,
	"pgITSetupAtVersion": true,
	"pgITDSN":            true,
	"pgITOpen":           true,
}

// pgGatedEnvVar is the environment variable read directly by some test
// helpers (testPostgresDSN, benchPGStore, ...). A test body that reads it is
// PostgreSQL-gated exactly like one calling the helpers above.
const pgGatedEnvVar = "KIWI_TEST_POSTGRES_URL"

// pgGatedIdent is a non-call marker: any same-package function mentioning the
// pgITEnv type is part of the PostgreSQL harness (for example the
// pgITSetupFresh return type), so its callers are gated too.
const pgGatedIdent = "pgITEnv"

// pgGatedOffender is one Test function that can only run against PostgreSQL
// but whose name the integration lane's -run Integration filter never
// matches.
type pgGatedOffender struct {
	file string
	line int
	name string
}

// pgTestSource is one parsed test file: its package clause and the parsed
// AST with the shared position table.
type pgTestSource struct {
	file *ast.File
	fset *token.FileSet
}

// detectPostgresGatedTests parses the given test sources (repo-relative path
// -> contents), resolves which Test functions are PostgreSQL-gated through
// the helpers above, and returns the offenders whose name lacks
// "Integration" plus the total number of gated Test functions (the
// non-vacuity count). The call closure is same-package only, which is where
// these helpers live by construction.
func detectPostgresGatedTests(sources map[string]string) (offenders []pgGatedOffender, gatedTests int, err error) {
	rels := make([]string, 0, len(sources))
	for rel := range sources {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	type pkgKey struct{ dir, name string }
	pkgs := map[pkgKey][]*pgTestSource{}
	// One FileSet for every parsed file keeps token.Pos values unambiguous:
	// positions from different files must never be resolved against the
	// wrong file's table.
	fset := token.NewFileSet()
	for _, rel := range rels {
		parsed, perr := parser.ParseFile(fset, rel, sources[rel], 0)
		if perr != nil {
			return nil, 0, fmt.Errorf("parse %s: %w", rel, perr)
		}
		key := pkgKey{dir: path.Dir(rel), name: parsed.Name.Name}
		pkgs[key] = append(pkgs[key], &pgTestSource{file: parsed, fset: fset})
	}

	keys := make([]pkgKey, 0, len(pkgs))
	for key := range pkgs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].dir != keys[j].dir {
			return keys[i].dir < keys[j].dir
		}
		return keys[i].name < keys[j].name
	})

	for _, key := range keys {
		files := pkgs[key]
		funcs := map[string]*ast.FuncDecl{}
		var names []string
		for _, src := range files {
			for _, decl := range src.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil {
					continue
				}
				if _, dup := funcs[fn.Name.Name]; !dup {
					names = append(names, fn.Name.Name)
				}
				funcs[fn.Name.Name] = fn
			}
		}

		gated := map[string]bool{}
		for name, fn := range funcs {
			if funcMentionsPostgres(fn) {
				gated[name] = true
			}
		}
		for {
			changed := false
			for name, fn := range funcs {
				if gated[name] || !funcCallsAny(fn, gated) {
					continue
				}
				gated[name] = true
				changed = true
			}
			if !changed {
				break
			}
		}

		sort.Strings(names)
		for _, name := range names {
			if !gated[name] || !strings.HasPrefix(name, "Test") {
				continue
			}
			gatedTests++
			if strings.Contains(name, "Integration") {
				continue
			}
			fn := funcs[name]
			offenders = append(offenders, pgGatedOffender{
				file: posOfFiles(files, fn.Pos()),
				line: posLineOfFiles(files, fn.Pos()),
				name: name,
			})
		}
	}
	sort.Slice(offenders, func(i, j int) bool {
		if offenders[i].file != offenders[j].file {
			return offenders[i].file < offenders[j].file
		}
		return offenders[i].line < offenders[j].line
	})
	return offenders, gatedTests, nil
}

// funcMentionsPostgres reports whether the function body reaches a PostgreSQL
// gate directly: a call to one of the gated helpers, the pgITEnv marker
// identifier, or a direct read of the DSN environment variable.
func funcMentionsPostgres(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			if id, ok := node.Fun.(*ast.Ident); ok && pgGatedHelpers[id.Name] {
				found = true
				return false
			}
			if isEnvRead(node) {
				found = true
				return false
			}
		case *ast.Ident:
			if node.Name == pgGatedIdent {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// isEnvRead reports whether the call is os.Getenv/os.LookupEnv with the
// literal KIWI_TEST_POSTGRES_URL argument. A skip message containing the
// variable name is a string literal too, but it is not an argument to the
// env accessors, so mention-only text never trips the gate.
func isEnvRead(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv") {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "os" {
		return false
	}
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(lit.Value)
		if err == nil && value == pgGatedEnvVar {
			return true
		}
	}
	return false
}

// funcCallsAny reports whether the function body calls any of the given
// same-package functions.
func funcCallsAny(fn *ast.FuncDecl, marked map[string]bool) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && marked[id.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}

// posOfFiles and posLineOfFiles resolve a position against the shared
// FileSet: Position reports the file the position actually belongs to.
func posOfFiles(files []*pgTestSource, pos token.Pos) string {
	for _, src := range files {
		if p := src.fset.Position(pos); p.IsValid() {
			return p.Filename
		}
	}
	return "?"
}

func posLineOfFiles(files []*pgTestSource, pos token.Pos) int {
	for _, src := range files {
		if p := src.fset.Position(pos); p.IsValid() {
			return p.Line
		}
	}
	return 0
}

// TestPostgresGatedTestsCarryIntegrationInName is the 100%-surface contract
// against dead PostgreSQL tests: every Test function under internal/ and cmd/
// that can only pass with a real database MUST carry "Integration" in its
// name, because the integration lane selects tests with -run Integration
// while the unit profile runs without KIWI_TEST_POSTGRES_URL. A gated test
// without the marker never runs in either lane and its assertions rot
// silently.
func TestPostgresGatedTestsCarryIntegrationInName(t *testing.T) {
	root := repoRoot(t)
	sources := map[string]string{}
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
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(repoRel)))
			if err != nil {
				t.Fatalf("surfacecheck: read %s: %v", repoRel, err)
			}
			sources[repoRel] = string(data)
		})
	}
	if len(sources) == 0 {
		t.Fatal("postgres lane guard: found no test sources under internal/ and cmd/; the detector would pass vacuously")
	}
	offenders, gatedTests, err := detectPostgresGatedTests(sources)
	if err != nil {
		t.Fatalf("postgres lane guard: %v", err)
	}
	if gatedTests == 0 {
		t.Fatal("postgres lane guard: no PostgreSQL-gated Test function found; the detector or the harness changed shape and this guard would pass vacuously")
	}
	lines := make([]string, 0, len(offenders))
	for _, off := range offenders {
		lines = append(lines, fmt.Sprintf("%s:%d: %s", off.file, off.line, off.name))
	}
	if len(offenders) > 0 {
		t.Fatalf("postgres lane guard: %d PostgreSQL-gated Test function(s) lack \"Integration\" in the name, so the unit profile skips them (no DSN) and the integration lane's -run Integration never selects them:\n  %s\nRename each to TestIntegration<OldName> so `-run Integration` exercises it against the real database.",
			len(offenders), strings.Join(lines, "\n  "))
	}
}

// TestPostgresGatingDetectorMechanism proves the detector itself against
// synthetic sources: direct helper calls, same-package dispatch through a
// helper, and direct environment reads are gated; "Integration"-named tests
// and ungated tests are accepted; a skip MESSAGE naming the environment
// variable is not a read and must not be flagged.
func TestPostgresGatingDetectorMechanism(t *testing.T) {
	sources := map[string]string{
		"pkg/a_test.go": `package pkg

import (
	"os"
	"testing"
)

func pgHelper(t *testing.T) string { return os.Getenv("KIWI_TEST_POSTGRES_URL") }

func TestDeadViaHelper(t *testing.T) {
	_ = pgIJ(t)
}

func pgIJ(t *testing.T) {
	_ = pgHelper(t)
}

func TestDeadViaDispatch(t *testing.T) {
	pgIJ(t)
}

func TestDeadViaEnv(t *testing.T) {
	if os.Getenv("KIWI_TEST_POSTGRES_URL") == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set")
	}
}

func TestDeadViaSeed(t *testing.T) {
	_ = pgITStore(t)
}

func pgITStore(t *testing.T) string { return pgITDSN(t) }

func pgITDSN(t *testing.T) string { return pgHelper(t) }

func TestIntegrationAlive(t *testing.T) {
	pgIJ(t)
}

func TestAlivePureUnit(t *testing.T) {
	t.Skip("KIWI_TEST_POSTGRES_URL not set; this is only a message")
}

func TestAliveMentionOnly(t *testing.T) {
	t.Skipf("set KIWI_TEST_POSTGRES_URL to run against PostgreSQL")
}
`,
	}
	offenders, gatedTests, err := detectPostgresGatedTests(sources)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	var got []string
	for _, off := range offenders {
		got = append(got, off.name)
	}
	want := []string{"TestDeadViaDispatch", "TestDeadViaEnv", "TestDeadViaHelper", "TestDeadViaSeed"}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("offenders = %v, want %v", got, want)
	}
	if gatedTests != 5 {
		t.Fatalf("gated test count = %d, want 5 (four dead + one Integration)", gatedTests)
	}
	if offenders[0].line == 0 {
		t.Fatalf("offender %+v has no line", offenders[0])
	}
}
