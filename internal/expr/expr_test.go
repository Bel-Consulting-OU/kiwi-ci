package expr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"unknown context", "foo.bar", `unknown context "foo"`},
		{"unknown field", "repo.zzz", `context "repo" has no field "zzz"`},
		{"unknown git field", "git.zzz", `context "git" has no field "zzz"`},
		{"bad function", "nosuch()", `unknown function "nosuch"`},
		{"missing arg", "contains('a')", `function "contains" expects 2, got 1 argument(s)`},
		{"too many args", "always(1)", `function "always" expects 0, got 1 argument(s)`},
		{"bare matrix", "matrix", `context "matrix" requires a field`},
		{"empty expression", "", "empty expression"},
		{"trailing junk", "'a' 'b'", "unexpected token"},
		{"unterminated string", "'abc", "unterminated string literal"},
		{"bad escape", "'\\q'", `invalid escape sequence \q`},
		{"missing close paren", "(contains('a','b')", "missing closing ')'"},
		{"unexpected char", "$", `unexpected character "$"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.src)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want error containing %q", tc.src, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse(%q) error = %q, want it to contain %q", tc.src, err, tc.want)
			}
		})
	}
}

func TestEvalStringContexts(t *testing.T) {
	c := Context{
		Status:   "success",
		Matrix:   map[string]string{"GO": "1.23"},
		Inputs:   map[string]string{"flavor": "vanilla"},
		Needs:    map[string]string{"build.outputs.bin": "/out/bin"},
		Steps:    map[string]string{"build.outputs.x": "42"},
		Runner:   map[string]string{"os": "Linux"},
		Job:      map[string]string{"id": "test"},
		Env:      map[string]string{"VAR": "v1"},
		Kiwi:     map[string]string{"run_id": "r123"},
		Extra:    map[string]string{"k": "e"},
		Event:    "push",
		Branch:   "main",
		Ref:      "refs/heads/main",
		SHA:      "abc123",
		Repo:     "https://git.example/x/y.git",
		RepoFull: "x/y",
	}
	cases := []struct {
		src  string
		want string
	}{
		{"${{ matrix.GO }}", "1.23"},
		{"${{matrix.GO}}", "1.23"},
		{"go ${{ matrix.GO }}!", "go 1.23!"},
		{"${{ inputs.flavor }}", "vanilla"},
		{"${{ needs.build.outputs.bin }}", "/out/bin"},
		{"${{ steps.build.outputs.x }}", "42"},
		{"${{ runner.os }}", "Linux"},
		{"${{ job.id }}", "test"},
		{"${{ env.VAR }}", "v1"},
		{"${{ kiwi.run_id }}", "r123"},
		{"${{ extra.k }}", "e"},
		{"${{ event }}", "push"},
		{"${{ event.name }}", "push"},
		{"${{ branch }}", "main"},
		{"${{ ref }}", "refs/heads/main"},
		{"${{ sha }}", "abc123"},
		{"${{ repo }}", "https://git.example/x/y.git"},
		{"${{ repo.full_name }}", "x/y"},
		{"${{ git.branch }}", "main"},
		{"${{ git.ref }}", "refs/heads/main"},
		{"${{ git.sha }}", "abc123"},
		{"${{ status }}", "success"},
		{"no holes here", "no holes here"},
		{"", ""},
	}
	for _, tc := range cases {
		got, err := EvalString(tc.src, c)
		if err != nil {
			t.Errorf("EvalString(%q) error: %v", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EvalString(%q) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestEvalStringMultipleHoles(t *testing.T) {
	c := Context{Matrix: map[string]string{"A": "1", "B": "2"}}
	got, err := EvalString("${{ matrix.A }}:${{ matrix.B }}", c)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1:2" {
		t.Fatalf("got %q, want %q", got, "1:2")
	}
}

func TestEvalStringMissingKeyIsError(t *testing.T) {
	_, err := EvalString("${{ matrix.NOPE }}", Context{Matrix: map[string]string{"GO": "1.23"}})
	if err == nil {
		t.Fatal("missing map key must be an evaluation error")
	}
}

func TestEvalStringUnterminatedHole(t *testing.T) {
	_, err := EvalString("x ${{ matrix.GO y", Context{})
	if err == nil || !strings.Contains(err.Error(), "missing closing }}") {
		t.Fatalf("want unterminated hole error, got %v", err)
	}
}

func TestEvalStringCompileError(t *testing.T) {
	if _, err := EvalString("${{ foo.bar }}", Context{}); err == nil {
		t.Fatal("unknown context inside a hole must be an error")
	}
}

func TestStringFunctions(t *testing.T) {
	c := Context{}
	cases := []struct {
		src  string
		want string
	}{
		{`${{ contains('hello world', 'lo w') }}`, "true"},
		{`${{ contains('hello', 'x') }}`, "false"},
		{`${{ startsWith('hello', 'he') }}`, "true"},
		{`${{ startsWith('hello', 'lo') }}`, "false"},
		{`${{ endsWith('hello', 'lo') }}`, "true"},
		{`${{ endsWith('hello', 'he') }}`, "false"},
		{`${{ contains('a,b', ',') }}`, "true"},
	}
	for _, tc := range cases {
		got, err := EvalString(tc.src, c)
		if err != nil {
			t.Errorf("EvalString(%q) error: %v", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EvalString(%q) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestJSONFunctions(t *testing.T) {
	c := Context{}
	got, err := EvalString(`${{ fromJSON('{"a": 1, "b": [1, 2], "c": {"d": "e"}}') }}`, c)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"a":1,"b":[1,2],"c":{"d":"e"}}` {
		t.Fatalf("fromJSON = %q", got)
	}
	round, err := EvalString(`${{ toJSON(fromJSON('[1, 2, 3]')) }}`, c)
	if err != nil {
		t.Fatal(err)
	}
	if round != `[1,2,3]` {
		t.Fatalf("toJSON(fromJSON(...)) = %q, want %q", round, `[1,2,3]`)
	}
	for _, bad := range []string{
		`${{ fromJSON('not json') }}`,
		`${{ toJSON('{"a":1} trailing') }}`,
		`${{ fromJSON('[1,]') }}`,
	} {
		if _, err := EvalString(bad, c); err == nil {
			t.Errorf("EvalString(%q) must fail", bad)
		}
	}
}

func TestJSONRoundTripPreservesNumbers(t *testing.T) {
	c := Context{}
	got, err := EvalString(`${{ fromJSON('{"n": 9007199254740993}') }}`, c)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"n":9007199254740993}` {
		t.Fatalf("large integer must round-trip exactly, got %q", got)
	}
}

func TestEvalBool(t *testing.T) {
	c := Context{Branch: "main", Env: map[string]string{"X": "y"}, Status: "success"}
	cases := []struct {
		src  string
		want bool
	}{
		{"'a' == 'a'", true},
		{"'a' == 'b'", false},
		{"'a' != 'b'", true},
		{"branch == 'main'", true},
		{"branch == 'dev'", false},
		{"env.X == 'y'", true},
		{"branch == 'main' && env.X == 'y'", true},
		{"branch == 'main' && env.X == 'z'", false},
		{"branch == 'dev' || env.X == 'y'", true},
		{"branch == 'dev' || env.X == 'z'", false},
		{"!branch == 'dev'", true},
		{"!(branch == 'dev')", true},
		{"!(branch == 'main')", false},
		{"success()", true},
		{"failure()", false},
		{"cancelled()", false},
		{"always()", true},
		{"always() && branch == 'main'", true},
		{"(branch == 'main')", true},
		{"((branch == 'main'))", true},
		{"true", true},
		{"false", false},
		{"1 == 1", true},
		{"1 == 2", false},
		{"contains('abc', 'b')", true},
		{"startsWith('abc', 'a') && endsWith('abc', 'c')", true},
		{"contains('abc', 'b') == false", false},
		{"contains('abc', 'z') == false", true},
		{"success() == false", false},
	}
	for _, tc := range cases {
		got, err := EvalBool(tc.src, c)
		if err != nil {
			t.Errorf("EvalBool(%q) error: %v", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EvalBool(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestEvalBoolStatusFunctions(t *testing.T) {
	cases := []struct {
		status    string
		success   bool
		failure   bool
		cancelled bool
	}{
		{"success", true, false, false},
		{"failure", false, true, false},
		{"blocked", false, true, false},
		{"cancelled", false, false, true},
		{"", true, false, false},
		{"skipped", true, false, false},
	}
	for _, tc := range cases {
		c := Context{Status: tc.status}
		got, err := EvalBool("success()", c)
		if err != nil || got != tc.success {
			t.Errorf("success() with status %q = %v (%v), want %v", tc.status, got, err, tc.success)
		}
		got, err = EvalBool("failure()", c)
		if err != nil || got != tc.failure {
			t.Errorf("failure() with status %q = %v (%v), want %v", tc.status, got, err, tc.failure)
		}
		got, err = EvalBool("cancelled()", c)
		if err != nil || got != tc.cancelled {
			t.Errorf("cancelled() with status %q = %v (%v), want %v", tc.status, got, err, tc.cancelled)
		}
	}
}

func TestEvalBoolTruthiness(t *testing.T) {
	if v, err := EvalBool("'x'", Context{}); err == nil || v {
		t.Fatalf("non-boolean string must be an error, got %v %v", v, err)
	}
	if v, err := EvalBool("env.MISSING", Context{Env: map[string]string{}}); err == nil || v {
		t.Fatalf("missing env key must be an error, got %v %v", v, err)
	}
}

func TestHashFiles(t *testing.T) {
	write := func(t *testing.T, dir, name, content string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	eval := func(t *testing.T, ws, src string) string {
		t.Helper()
		got, err := EvalString(src, Context{Workspace: ws})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	ws1 := t.TempDir()
	write(t, ws1, "go.sum", "sum-1\n")
	write(t, ws1, "sub/a.txt", "hello\n")

	ws2 := t.TempDir()
	write(t, ws2, "go.sum", "sum-1\n")
	write(t, ws2, "sub/a.txt", "hello\n")

	ws3 := t.TempDir()
	write(t, ws3, "go.sum", "sum-1\n")
	write(t, ws3, "sub/a.txt", "world\n")

	h1 := eval(t, ws1, `${{ hashFiles('go.sum', 'sub/a.txt') }}`)
	h2 := eval(t, ws2, `${{ hashFiles('go.sum', 'sub/a.txt') }}`)
	h3 := eval(t, ws3, `${{ hashFiles('go.sum', 'sub/a.txt') }}`)

	if len(h1) != 12 {
		t.Fatalf("hashFiles must return a 12-hex prefix, got %q", h1)
	}
	if h1 != h2 {
		t.Fatalf("identical workspaces must hash identically: %q != %q", h1, h2)
	}
	if h1 == h3 {
		t.Fatal("different content must change the hash")
	}

	comma := eval(t, ws1, `${{ hashFiles('go.sum, sub/a.txt') }}`)
	if comma != h1 {
		t.Fatalf("comma-separated globs must match separate args: %q != %q", comma, h1)
	}

	globbed := eval(t, ws1, `${{ hashFiles('**/*') }}`)
	if globbed == h1 || len(globbed) != 12 {
		t.Fatalf("glob hash = %q", globbed)
	}

	empty := eval(t, ws1, `${{ hashFiles('nomatch-*') }}`)
	if len(empty) != 12 {
		t.Fatalf("empty match set must still hash deterministically, got %q", empty)
	}
	again := eval(t, ws1, `${{ hashFiles('nomatch-*') }}`)
	if empty != again {
		t.Fatal("empty match set hash is not deterministic")
	}
}

func TestHashFilesRequiresWorkspace(t *testing.T) {
	if _, err := EvalString(`${{ hashFiles('go.sum') }}`, Context{}); err == nil {
		t.Fatal("hashFiles without a workspace must fail")
	}
}

func TestLimits(t *testing.T) {
	if _, err := Parse(strings.Repeat("(", 65) + "'x'" + strings.Repeat(")", 65)); err == nil ||
		!strings.Contains(err.Error(), "maximum depth") {
		t.Fatalf("65 nested parens must hit the depth limit, got %v", err)
	}
	if _, err := Parse(strings.Repeat("(", 64) + "'x'" + strings.Repeat(")", 64)); err != nil {
		t.Fatalf("64 nested parens must be accepted, got %v", err)
	}
	if _, err := Parse(strings.Repeat("'a' ", 4097)); err == nil ||
		!strings.Contains(err.Error(), "token limit") {
		t.Fatalf("4097 tokens must hit the token limit, got %v", err)
	}
	if _, err := Parse(strings.Repeat("a", maxExprBytes+1)); err == nil ||
		!strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("expression over 64 KiB must hit the byte limit, got %v", err)
	}
}

func TestParseOnceReuse(t *testing.T) {
	e, err := Parse("matrix.GO")
	if err != nil {
		t.Fatal(err)
	}
	if e.String() != "matrix.GO" {
		t.Fatalf("String() = %q", e.String())
	}
	for _, v := range []string{"1.23", "1.24"} {
		got, err := e.Eval(Context{Matrix: map[string]string{"GO": v}})
		if err != nil {
			t.Fatal(err)
		}
		if got != v {
			t.Fatalf("Eval = %q, want %q", got, v)
		}
	}
}

func TestStringLiteralEscapes(t *testing.T) {
	got, err := EvalString(`${{ 'a\nb\t\'c\\' }}`, Context{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "a\nb\t'c\\" {
		t.Fatalf("escapes = %q", got)
	}
}

func TestHolesQuoteAware(t *testing.T) {
	got, err := EvalString(`${{ hashFiles('x}}y') }}`, Context{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 12 {
		t.Fatalf("quote-aware hole scan failed, got %q", got)
	}
}

func TestNumbersCompareAsText(t *testing.T) {
	if v, _ := EvalBool("1 == 1", Context{}); !v {
		t.Fatal("1 == 1 must be true")
	}
	if v, _ := EvalBool("1 == 1.0", Context{}); v {
		t.Fatal("number comparison is string-based: 1 != 1.0")
	}
	if v, _ := EvalBool("-2 == -2", Context{}); !v {
		t.Fatal("-2 == -2 must be true")
	}
}
