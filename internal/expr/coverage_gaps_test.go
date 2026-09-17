package expr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenStringBranches(t *testing.T) {
	cases := []struct {
		tok  token
		want string
	}{
		{token{kind: tokEOF}, "end of expression"},
		{token{kind: tokIdent, text: "abc"}, `"abc"`},
		{token{kind: tokLParen, text: "("}, `"("`},
		{token{kind: tokLParen}, "'('"},
		{token{kind: tokRParen}, "')'"},
		{token{kind: tokComma}, "','"},
		{token{kind: tokDot}, "'.'"},
		{token{kind: tokAnd}, "'&&'"},
		{token{kind: tokOr}, "'||'"},
		{token{kind: tokNot}, "'!'"},
		{token{kind: tokEq}, "'=='"},
		{token{kind: tokNeq}, "'!='"},
		{token{kind: tokKind(99)}, "token"},
	}
	for _, c := range cases {
		if got := c.tok.String(); got != c.want {
			t.Errorf("token%+v.String() = %q, want %q", c.tok, got, c.want)
		}
	}
}

func TestContextsAndEvaluationMatrix(t *testing.T) {
	c := Context{
		Status:   "success",
		Matrix:   map[string]string{"A": "1", "B": "2"},
		Inputs:   map[string]string{"in": "v"},
		Needs:    map[string]string{"job.outputs.x": "nx"},
		Steps:    map[string]string{"s.outputs.y": "sy"},
		Env:      map[string]string{"E": "e"},
		Runner:   map[string]string{"os": "Linux"},
		Job:      map[string]string{"id": "j"},
		Kiwi:     map[string]string{"run_id": "r"},
		Extra:    map[string]string{"k": "x"},
		Event:    "push",
		Branch:   "main",
		Ref:      "refs/heads/main",
		SHA:      "abc",
		Repo:     "url",
		RepoFull: "o/n",
	}
	evalCases := []struct {
		src  string
		want string
	}{
		{"'lit'", "lit"},
		{"42", "42"},
		{"-1.5", "-1.5"},
		{"true", "true"},
		{"false", "false"},
		{"success()", "true"},
		{"failure()", "false"},
		{"cancelled()", "false"},
		{"always()", "true"},
		{"contains('abc', 'b')", "true"},
		{"startsWith('abc', 'a')", "true"},
		{"endsWith('abc', 'c')", "true"},
		{"fromJSON('[1]')", "[1]"},
		{"toJSON('[1]')", "[1]"},
		{"true && false", "false"},
		{"true || false", "true"},
		{"'a' == 'a'", "true"},
		{"'a' != 'a'", "false"},
		{"success() == true", "true"},
		{"success() != true", "false"},
		{"matrix.A", "1"},
		{"inputs.in", "v"},
		{"needs.job.outputs.x", "nx"},
		{"steps.s.outputs.y", "sy"},
		{"env.E", "e"},
		{"runner.os", "Linux"},
		{"job.id", "j"},
		{"kiwi.run_id", "r"},
		{"extra.k", "x"},
		{"event.name", "push"},
		{"git.branch", "main"},
		{"repo.full_name", "o/n"},
		{"status", "success"},
		{"event", "push"},
		{"branch", "main"},
		{"ref", "refs/heads/main"},
		{"sha", "abc"},
		{"repo", "url"},
	}
	for _, tc := range evalCases {
		got, err := EvalString("${{ "+tc.src+" }}", c)
		if err != nil {
			t.Errorf("EvalString(%q): %v", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EvalString(%q) = %q, want %q", tc.src, got, tc.want)
		}
		boolExpr, err := Parse(tc.src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.src, err)
		}
		if _, err := boolExpr.EvalBool(c); err != nil {
			// Boolean-valued nodes must evaluate; non-boolean values error
			// through ValueError (e.g. "42"), which is asserted separately.
			var ve *ValueError
			if !errors.As(err, &ve) {
				t.Errorf("EvalBool(%q): %v", tc.src, err)
			} else if ve.Error() != `cannot interpret "`+ve.Value+`" as a boolean` {
				t.Errorf("ValueError.Error() = %q", ve.Error())
			}
		}
	}

	contexts := map[string][]string{
		"'lit'":                         nil,
		"42":                            nil,
		"matrix.A":                      {"matrix"},
		"needs.job.outputs.x":           {"needs"},
		"contains(matrix.A, inputs.in)": {"inputs", "matrix"},
		"contains(inputs.in, matrix.A)": {"inputs", "matrix"},
		"success()":                     nil,
		"!matrix.A":                     {"matrix"},
		"'a' == matrix.A":               {"matrix"},
		"matrix.A && inputs.in":         {"inputs", "matrix"},
		"matrix.A || inputs.in":         {"inputs", "matrix"},
	}
	for src, want := range contexts {
		e, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		got := e.Contexts()
		if len(got) != len(want) {
			t.Errorf("Contexts(%q) = %v, want %v", src, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("Contexts(%q) = %v, want %v", src, got, want)
				break
			}
		}
		if s := e.String(); s == "" {
			t.Errorf("String(%q) is empty", src)
		}
	}
}

func TestEvaluationErrorBranches(t *testing.T) {
	c := Context{}
	for _, src := range []string{
		"${{ !matrix.missing }}",
		"${{ contains('a', matrix.missing) }}",
		"${{ contains(matrix.missing, 'a') }}",
		"${{ fromJSON(matrix.missing) }}",
		"${{ matrix.missing && true }}",
		"${{ matrix.missing || true }}",
		"${{ matrix.missing == matrix.missing }}",
		"${{ matrix.missing == success() }}",
		"${{ success() == matrix.missing }}",
		"${{ success() && matrix.missing }}",
		"${{ 'a' == matrix.missing }}",
		"${{ 'lit' == matrix.missing }}",
	} {
		if _, err := EvalString(src, c); err == nil {
			t.Errorf("EvalString(%q) succeeded, want error", src)
		}
	}
	if _, err := EvalBool("", c); err == nil {
		t.Error("EvalBool(empty) must be a parse error")
	}
	for _, src := range []string{"'a' == matrix.missing", "matrix.missing == 'a'"} {
		if _, err := EvalBool(src, c); err == nil {
			t.Errorf("EvalBool(%q) must error", src)
		}
	}
	if got, err := EvalBool("(success() == true) == true", c); err != nil || !got {
		t.Errorf("EvalBool((success() == true) == true) = (%v, %v)", got, err)
	}
	if got, err := EvalBool("(true || false) == true", c); err != nil || !got {
		t.Errorf("EvalBool((true || false) == true) = (%v, %v)", got, err)
	}
	if got, err := EvalBool("success() == true", c); err != nil || !got {
		t.Errorf("EvalBool(success() == true) = (%v, %v)", got, err)
	}
	for src, want := range map[string]bool{
		"false && matrix.missing": false,
		"true || matrix.missing":  true,
		"!matrix.missing":         false,
		"matrix.missing":          false,
	} {
		got, err := EvalBool(src, c)
		if src == "!matrix.missing" || src == "matrix.missing" {
			if err == nil {
				t.Errorf("EvalBool(%q) must error", src)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("EvalBool(%q) = (%v, %v), want %v", src, got, err, want)
		}
	}
	if got, err := EvalBool("'true'", c); err != nil || !got {
		t.Errorf("EvalBool(literal true) = (%v, %v)", got, err)
	}
	if _, err := EvalBool("'nope'", c); err == nil {
		t.Error("EvalBool(literal non-boolean) must error")
	}
	if _, err := EvalBool("1", c); err == nil {
		t.Error("EvalBool(number) must error")
	}
	if _, err := EvalBool("always()", c); err != nil {
		t.Errorf("EvalBool(always()) = %v", err)
	}
	if got, err := EvalBool("fromJSON('true')", c); err != nil || !got {
		t.Errorf("EvalBool(fromJSON('true')) = (%v, %v)", got, err)
	}
	if _, err := EvalBool("fromJSON('nope')", c); err == nil {
		t.Error("EvalBool(fromJSON(bad)) must error")
	}
	if _, err := EvalBool("hashFiles('*')", c); err == nil {
		t.Error("EvalBool(hashFiles without workspace) must error")
	}
	if got, err := EvalBool("toJSON('true')", c); err != nil || !got {
		t.Fatalf("EvalBool(toJSON('true')) = (%v, %v)", got, err)
	}
	if got, err := EvalBool("toJSON('false')", c); err != nil || got {
		t.Fatalf("EvalBool(toJSON('false')) = (%v, %v)", got, err)
	}
}

func TestNotEvalNegates(t *testing.T) {
	e, err := Parse("!false")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := e.Eval(Context{}); err != nil || v != "true" {
		t.Fatalf("not.Eval(!false) = (%q, %v), want (\"true\", nil)", v, err)
	}
	if v, err := e.EvalBool(Context{}); err != nil || !v {
		t.Fatalf("not.EvalBool(!false) = (%v, %v), want true", v, err)
	}
	cases := []struct {
		src  string
		want string
	}{
		{"!true", "false"},
		{"!false", "true"},
		{"!!true", "true"},
		{"!!false", "false"},
		{"!contains('abc', 'z')", "true"},
		{"!(success())", "false"},
	}
	for _, tc := range cases {
		got, err := EvalString("${{ "+tc.src+" }}", Context{Status: "success"})
		if err != nil {
			t.Errorf("EvalString(%q): %v", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EvalString(%q) = %q, want %q", tc.src, got, tc.want)
		}
	}
	// EvalBool agrees with Eval for the same negations.
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"!true", false},
		{"!false", true},
		{"!!true", true},
		{"!!false", false},
		{"!contains('abc', 'z')", true},
		{"!(success())", false},
	} {
		got, err := EvalBool(tc.src, Context{Status: "success"})
		if err != nil {
			t.Errorf("EvalBool(%q): %v", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EvalBool(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestUnreachableASTFallbacks(t *testing.T) {
	unknown := &call{base: base{src: "nope()"}, name: "nope"}
	if _, err := unknown.Eval(Context{}); err == nil || !strings.Contains(err.Error(), "unknown function") {
		t.Errorf("call.Eval(unknown) = %v", err)
	}
	if _, err := unknown.EvalBool(Context{}); err == nil || !strings.Contains(err.Error(), "unknown function") {
		t.Errorf("call.EvalBool(unknown) = %v", err)
	}
	if _, err := lookup(Context{}, "nope", nil); err == nil || !strings.Contains(err.Error(), "unknown context") {
		t.Errorf("lookup(unknown root) = %v", err)
	}
	if got := strconvQuote("x\ny"); got != `"x`+"\n"+`y"` {
		t.Errorf("strconvQuote = %q", got)
	}
	if got := (&ValueError{Value: "v"}).Error(); got != `cannot interpret "v" as a boolean` {
		t.Errorf("ValueError.Error = %q", got)
	}
}

func TestParserErrorBranches(t *testing.T) {
	cases := map[string]string{
		"(":                     "unexpected end of expression",
		")":                     `unexpected token ")"`,
		"matrix.":               "expected field name after '.'",
		"contains(,)":           `unexpected token ","`,
		"contains('a','b'":      "missing closing ')' in contains()",
		"true || )":             `unexpected token ")"`,
		"true && )":             `unexpected token ")"`,
		"! )":                   `unexpected token ")"`,
		"1 == )":                `unexpected token ")"`,
		"'\\":                   "unterminated string literal",
		`'\r'`:                  "",
		`'\'\''`:                "",
		`"a\"b"`:                "",
		"git":                   `context "git" requires a field`,
		"status.x":              `context "status" has no field "x"`,
		"contains('a','b','c')": `function "contains" expects 2, got 3 argument(s)`,
		"hashFiles('a','b','c','d','e','f','g','h','i')": `expects 1, 2, 3, 4, 5, 6, 7 or 8, got 9 argument(s)`,
		"hashFiles('a','b','c','d','e','f','g')":         "",
		"'a' 'b'":                                        "unexpected token",
	}
	for src, want := range cases {
		_, err := Parse(src)
		if want == "" {
			if err != nil {
				t.Errorf("Parse(%q) = %v, want success", src, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("Parse(%q) succeeded, want %q", src, want)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) error = %v, want it to contain %q", src, err, want)
		}
	}
	if _, err := Parse(strings.Repeat("a", maxExprBytes+1)); err == nil {
		t.Error("oversized expression must be rejected")
	}
	if _, err := Parse(strings.Repeat("1 + ", 0) + "(" + strings.Repeat("(", maxDepth+2) + "1" + strings.Repeat(")", maxDepth+2) + ")"); err == nil {
		t.Error("overly deep expression must be rejected")
	}
	deep := "1"
	for i := 0; i < maxDepth+2; i++ {
		deep = "(" + deep + ")"
	}
	if _, err := Parse(deep); err == nil {
		t.Error("nested parentheses depth limit must be enforced")
	}
	tooMany := strings.TrimSpace(strings.Repeat("1 ", maxTokens+2))
	if _, err := Parse(tooMany); err == nil {
		t.Error("token limit must be enforced")
	}
}

func TestHashFilesErrorAndLimitBranches(t *testing.T) {
	if _, err := EvalString("${{ hashFiles('*') }}", Context{Workspace: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("hashFiles with a non-directory workspace must fail")
	}
	ws := t.TempDir()
	if _, err := EvalString("${{ hashFiles(matrix.missing) }}", Context{Workspace: ws}); err == nil {
		t.Error("hashFiles with an unresolvable argument must fail")
	}
	if _, err := EvalString("${{ hashFiles('[') }}", Context{Workspace: ws}); err == nil || !strings.Contains(err.Error(), "invalid glob") {
		t.Errorf("hashFiles with a bad glob = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := EvalString("${{ hashFiles('dir') }}", Context{Workspace: ws}); err == nil {
		t.Errorf("hashFiles matching a directory must fail")
	}

	// A permission-denied open is the only deterministic non-special open
	// failure; root bypasses file modes, so skip there.
	if os.Geteuid() != 0 {
		locked := filepath.Join(ws, "locked.txt")
		if err := os.WriteFile(locked, []byte("x"), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := EvalString("${{ hashFiles('locked.txt') }}", Context{Workspace: ws}); err == nil {
			t.Error("hashFiles with an unreadable match must fail")
		}
		os.Chmod(locked, 0o644)
	}
}

func TestHashFilesFileCountLimit(t *testing.T) {
	ws := t.TempDir()
	for i := 0; i <= hashFilesMaxFiles; i++ {
		name := filepath.Join(ws, "f"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26)))
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := EvalString("${{ hashFiles('*') }}", Context{Workspace: ws}); err == nil || !strings.Contains(err.Error(), "limit is") {
		t.Errorf("hashFiles file-count limit = %v", err)
	}
}
